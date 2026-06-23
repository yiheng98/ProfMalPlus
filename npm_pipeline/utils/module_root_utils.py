"""Helpers for resolving a third-party module root or the analyzed-package
root from a file path.

Used by the async-aware orphan recovery to attribute runtime API calls whose
caller locations fall inside (a) a specific ``node_modules/<pkg>/`` tree or
(b) the analyzed package root (nearest ancestor containing ``package.json``).

"""

from __future__ import annotations


def _normalize_sep(path: str) -> str:
    """Return *path* with forward slashes, suitable for prefix comparison."""
    return path.replace("\\", "/")


def normalize_for_prefix_match(path: str) -> str:
    """Normalize *path* into a canonical form for prefix / substring matching.

    Rules:
    - POSIX separators.
    - Strip a leading ``./`` or ``.\\``.
    - Strip a leading ``package/`` segment so both the runtime-logger view
      ("package/..." or bare relative path) and the call-graph view (always
      "package/...") collapse to the same shape.
    """
    if not path:
        return path
    norm = _normalize_sep(path)
    if norm.startswith("./"):
        norm = norm[2:]
    if norm.startswith("package/"):
        norm = norm[len("package/") :]
    return norm


def find_module_root(file_path: str) -> str | None:
    """Return the innermost ``node_modules/<pkg>`` prefix containing *file_path*.

    Scoped packages (``node_modules/@scope/pkg``) are supported - the helper
    walks up until the segment before the final path component is a package
    name (possibly preceded by a scope).

    Returns the prefix with a trailing slash, e.g. ``"node_modules/axios/"``
    or ``"node_modules/@scope/pkg/"``. Returns ``None`` when *file_path* does
    not live under any ``node_modules``.

    The returned prefix is normalized with forward slashes and without a
    leading ``package/`` segment; pair it with :func:`normalize_for_prefix_match`
    when checking against a candidate file path.
    """
    if not file_path:
        return None
    norm = normalize_for_prefix_match(file_path)
    segments = norm.split("/")

    # Walk from the right, looking for the innermost `node_modules` occurrence.
    # The "package root" for the match is then `node_modules/<pkg>` or
    # `node_modules/@scope/<pkg>`.
    innermost_idx = -1
    for i, seg in enumerate(segments):
        if seg == "node_modules":
            innermost_idx = i
    if innermost_idx < 0:
        return None

    # After the `node_modules` segment, consume either `@scope/pkg` or `pkg`.
    next_idx = innermost_idx + 1
    if next_idx >= len(segments):
        return None
    first = segments[next_idx]
    if first.startswith("@") and next_idx + 1 < len(segments):
        # scoped: include @scope/pkg
        tail = segments[next_idx + 1]
        prefix_segments = segments[: next_idx + 2]
        if not tail:
            return None
    else:
        prefix_segments = segments[: next_idx + 1]

    return "/".join(prefix_segments) + "/"


def find_package_root(file_path: str, package_dir: str | None = None) -> str | None:
    """Return the analyzed-package root prefix for *file_path*.

    Strategy:
    1. If *file_path* is under a ``node_modules/`` tree, it is NOT in the
       analyzed package; return ``None``.
    2. Otherwise return the top-level directory prefix (i.e. the whole path
       stripped of any ``package/`` prefix, reduced to its first segment
       followed by ``/``), which corresponds to the analyzed package root.
       When *package_dir* is supplied it is preferred.
    """
    if not file_path:
        return None
    norm = normalize_for_prefix_match(file_path)
    if "/node_modules/" in norm or norm.startswith("node_modules/"):
        return None
    if package_dir:
        return normalize_for_prefix_match(package_dir).rstrip("/") + "/"
    # The analyzed package root is essentially the empty prefix after
    # stripping `package/`; use `""` as a sentinel meaning "anything not
    # under node_modules".
    return ""


def path_is_under(file_path: str, prefix: str) -> bool:
    """Return True when *file_path* is under the canonical *prefix*.

    Both sides are normalized via :func:`normalize_for_prefix_match` first.
    An empty *prefix* matches any non-``node_modules`` path, reflecting the
    "analyzed-package-root" convention used by :func:`find_package_root`.
    """
    norm_path = normalize_for_prefix_match(file_path)
    norm_prefix = normalize_for_prefix_match(prefix) if prefix else ""
    if norm_prefix == "":
        # Analyzed-package root convention: everything that is NOT in a
        # node_modules tree counts.
        return "/node_modules/" not in norm_path and not norm_path.startswith("node_modules/")
    if not norm_prefix.endswith("/"):
        norm_prefix += "/"
    return norm_path.startswith(norm_prefix) or ("/" + norm_prefix) in ("/" + norm_path)


def nested_module_root_depth(prefix: str) -> int:
    """Return the nesting depth of a module root prefix.

    ``node_modules/axios/`` -> 1
    ``node_modules/axios/node_modules/follow-redirects/`` -> 2

    Used by Layer 3.5's "innermost wins" rule for nested node_modules.
    """
    if not prefix:
        return 0
    return normalize_for_prefix_match(prefix).count("node_modules/")
