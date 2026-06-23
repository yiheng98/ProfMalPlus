"""
Declared package-to-package dependency relationships parsed from
``npm ls --all --json``.
"""

from __future__ import annotations

import json
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Any

from loguru import logger

from npm_pipeline.utils.module_root_utils import (
    find_module_root,
    normalize_for_prefix_match,
)


@dataclass
class DependencyTree:
    """Declared dependency relationships parsed from ``npm ls --all --json``."""

    direct_deps: dict[str, set[str]] = field(default_factory=dict)
    closure_by_pkg: dict[str, set[str]] = field(default_factory=dict)

    # ------------------------------------------------------------------
    # Constructors
    # ------------------------------------------------------------------

    @classmethod
    def empty(cls) -> "DependencyTree":
        """Degenerate tree - used when ``npm ls`` failed or the file is missing."""
        return cls(direct_deps={}, closure_by_pkg={})

    @classmethod
    def from_json_file(cls, path: str | None) -> "DependencyTree":
        """Parse ``path`` (``npm ls --all --json`` output).

        Missing file, unreadable JSON, or an unexpected shape all
        degrade to :meth:`empty`; callers treat that as "dep-tree layer
        unavailable" and fall back to other orphan-recovery layers.
        """
        if not path:
            return cls.empty()
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
        except FileNotFoundError:
            logger.info(f"[DependencyTree] dep_tree.json not found at {path}; using empty tree")
            return cls.empty()
        except Exception as e:
            logger.warning(f"[DependencyTree] failed to parse {path}: {e}; using empty tree")
            return cls.empty()

        if not isinstance(data, dict):
            logger.warning(f"[DependencyTree] {path} top-level is not an object; using empty tree")
            return cls.empty()

        return cls.from_json_data(data)

    @classmethod
    def from_json_data(cls, data: dict[str, Any]) -> "DependencyTree":
        """Same as :meth:`from_json_file` but takes the already-parsed dict.

        Mostly useful for tests; production code should prefer the
        file-based constructor.
        """
        direct_deps: dict[str, set[str]] = defaultdict(set)

        def walk(node: dict, parent_name: str | None) -> None:
            if not isinstance(node, dict):
                return
            deps = node.get("dependencies")
            if not isinstance(deps, dict):
                return
            for child_name, child_node in deps.items():
                if not isinstance(child_name, str):
                    continue
                if parent_name is not None:
                    direct_deps[parent_name].add(child_name)
                # Make sure leaves register even when they have no
                # nested ``dependencies`` object; otherwise BFS below
                # won't produce a closure entry for them.
                direct_deps.setdefault(child_name, set())
                walk(child_node, child_name)

        # Top-level node represents the analyzed project itself; its
        # first-level children are the actually-installed top-level pkgs.
        walk(data, None)

        # BFS each pkg to materialise its full transitive closure.
        closure_by_pkg: dict[str, set[str]] = {}
        for pkg in direct_deps:
            closure_by_pkg[pkg] = _bfs_closure(pkg, direct_deps)

        return cls(direct_deps=dict(direct_deps), closure_by_pkg=closure_by_pkg)

    # ------------------------------------------------------------------
    # Queries
    # ------------------------------------------------------------------

    def is_empty(self) -> bool:
        return not self.closure_by_pkg

    def closure_for_pkg(self, pkg_name: str) -> set[str]:
        """Return ``{pkg_name} ∪`` its transitive declared deps.

        Unknown package names degrade to ``{pkg_name}`` so callers can
        still use the answer as a module-root prefix seed without
        special-casing the missing-dep-tree branch.
        """
        if not pkg_name:
            return set()
        return set(self.closure_by_pkg.get(pkg_name, {pkg_name}))

    def closure_for_file(self, file_path: str) -> set[str]:
        """Return ``node_modules/<name>/`` prefixes for *file_path*'s owning
        pkg plus its transitive deps.

        Returns an empty set for files that are not under any
        ``node_modules/`` tree (e.g. the analyzed package's own code).
        Callers that need the analyzed-package root should keep using
        :func:`find_package_root` separately; mixing that in here would
        blur the semantics.
        """
        if not file_path:
            return set()
        primary = find_module_root(file_path)
        if primary is None:
            return set()
        pkg_name = _extract_pkg_name(primary)
        if not pkg_name:
            return {primary}
        deps = self.closure_for_pkg(pkg_name)
        if not deps:
            return {primary}
        prefixes = {f"node_modules/{name}/" for name in deps}
        prefixes.add(primary)
        return prefixes


# ----------------------------------------------------------------------
# Internal helpers
# ----------------------------------------------------------------------


def _bfs_closure(start: str, direct_deps: dict[str, set[str]]) -> set[str]:
    """BFS over *direct_deps* from *start*; returns ``{start} ∪ reachable``.

    Handles cycles gracefully (``visited`` set), which occasionally show
    up in `npm ls` output when peer deps loop back.
    """
    visited: set[str] = {start}
    q: deque[str] = deque([start])
    while q:
        cur = q.popleft()
        for nxt in direct_deps.get(cur, ()):
            if nxt in visited:
                continue
            visited.add(nxt)
            q.append(nxt)
    return visited


def _extract_pkg_name(module_root_prefix: str) -> str | None:
    """Extract the pkg name from a ``node_modules/<name>/`` prefix.

    Handles scoped packages (``node_modules/@scope/pkg/``), nested
    installs (``node_modules/a/node_modules/b/`` -> returns ``b``), and
    degrades gracefully when the prefix shape is unexpected.
    """
    if not module_root_prefix:
        return None
    norm = normalize_for_prefix_match(module_root_prefix).rstrip("/")
    segments = norm.split("/")
    # Walk from the right, find the last `node_modules` and take what
    # follows.  This mirrors ``find_module_root``'s own logic.
    innermost_idx = -1
    for i, seg in enumerate(segments):
        if seg == "node_modules":
            innermost_idx = i
    if innermost_idx < 0:
        return None
    next_idx = innermost_idx + 1
    if next_idx >= len(segments):
        return None
    first = segments[next_idx]
    if first.startswith("@") and next_idx + 1 < len(segments):
        return f"{first}/{segments[next_idx + 1]}"
    return first
