"""Shared package-local file-read primitives.

This module hosts the resolve / read / classify helpers that used to live
duplicated inside :mod:`npm_pipeline.classes.static_fallback` and
:mod:`npm_pipeline.classes.shell_command_analyzer`.  Three classes of
consumers share the implementation:

* :class:`StaticFallback` / :class:`ShellCommandAnalyzer` — pre-existing
  tool-loop drivers that read files from inside the package's
  ``package/`` directory.
* :class:`StaticJudge` / :class:`DynamicJudge` reread gate — when a
  verifier emits a non-empty ``files_to_read`` list the judge resolves
  + reads the requested files via this class and uses
  :meth:`classify_path_only` / :meth:`classify_with_magic_peek` to
  short-circuit native-binary handoffs to ``malicious`` without any
  LLM call.

Path resolution is anchored at ``<original_package_dir>/package`` (the
real directory shipped on npm).  All real-paths are required to live
inside that root via a ``startswith`` check, matching the legacy
behaviour of the two existing loops.
"""

import os
from dataclasses import dataclass

from loguru import logger

from npm_pipeline.handlers.file_handler import _is_binary_content

# Default extension whitelist used by the static / dynamic reread gate.
DEFAULT_SCRIPT_EXTENSIONS: tuple[str, ...] = (
    ".js",
    ".cjs",
    ".mjs",
    ".json",
    ".sh",
    ".bat",
    ".ps1",
    ".py",
    ".pl",
    ".rb",
)

# Extension-only classification — used by the pre-loop binary
# short-circuit so we can refuse to feed a known native binary into any
# LLM prompt without performing file I/O.
BINARY_EXTENSIONS: frozenset[str] = frozenset(
    {
        ".exe",
        ".dll",
        ".so",
        ".dylib",
        ".bin",
        ".node",
        ".o",
        ".a",
        ".lib",
        ".wasm",
    }
)

SCRIPT_EXTENSIONS_FOR_CLASSIFY: frozenset[str] = frozenset(
    {
        ".js",
        ".cjs",
        ".mjs",
        ".json",
        ".sh",
        ".bash",
        ".zsh",
        ".fish",
        ".bat",
        ".cmd",
        ".ps1",
        ".py",
        ".pl",
        ".rb",
        ".ts",
        ".tsx",
        ".jsx",
        ".yaml",
        ".yml",
        ".toml",
        ".ini",
        ".cfg",
        ".txt",
        ".md",
    }
)

# Index-style candidates probed when a path resolves to a directory.
DEFAULT_INDEX_CANDIDATES: tuple[str, ...] = (
    "index.js",
    "index.cjs",
    "index.mjs",
)

# Magic-byte prefixes for the binary peek.  Limited to widely-known
# executable formats; anything else falls back to a text heuristic.
_MAGIC_PREFIXES: tuple[bytes, ...] = (
    b"\x7fELF",  # ELF (Linux, BSD)
    b"MZ",  # PE (Windows .exe / .dll)
    b"\xca\xfe\xba\xbe",  # Mach-O fat (32-bit)
    b"\xcf\xfa\xed\xfe",  # Mach-O 64-bit
    b"\xce\xfa\xed\xfe",  # Mach-O 32-bit
    b"\xfe\xed\xfa\xce",  # Mach-O reverse-endian
    b"\xfe\xed\xfa\xcf",  # Mach-O reverse-endian 64-bit
    b"\x00asm",  # WebAssembly (preceded by version word)
)
MAX_PEEK_BYTES: int = 8


@dataclass(frozen=True)
class ResolvedFile:
    """A successfully resolved package-local file."""

    rel_path: str
    content: str


class PackageFileReader:
    """Resolve, read and classify files inside one package directory."""

    def __init__(
        self,
        package_root: str,
        *,
        allowed_extensions: tuple[str, ...] = DEFAULT_SCRIPT_EXTENSIONS,
        index_candidates: tuple[str, ...] = DEFAULT_INDEX_CANDIDATES,
    ):
        # ``realpath`` so the inside-package check works even when the
        # caller hands us a symlinked or non-canonical directory path.
        self._package_root = os.path.realpath(package_root)
        self._allowed_extensions = tuple(allowed_extensions)
        self._index_candidates = tuple(index_candidates)

    # ------------------------------------------------------------------
    # Properties
    # ------------------------------------------------------------------

    @property
    def package_root(self) -> str:
        return self._package_root

    # ------------------------------------------------------------------
    # Pre-loop classification helpers (no LLM, optional cheap I/O)
    # ------------------------------------------------------------------

    @staticmethod
    def classify_path_only(path_literal: str) -> str:
        """Classify a path *literal* by extension alone.

        Returns one of ``"binary"`` / ``"script"`` / ``"unknown"``.
        """
        if not isinstance(path_literal, str) or not path_literal.strip():
            return "unknown"
        _, ext = os.path.splitext(path_literal.strip())
        ext = ext.lower()
        if ext in BINARY_EXTENSIONS:
            return "binary"
        if ext in SCRIPT_EXTENSIONS_FOR_CLASSIFY:
            return "script"
        return "unknown"

    def classify_with_magic_peek(self, path_literal: str) -> str:
        """Peek at the first ``MAX_PEEK_BYTES`` of a path to detect binaries.

        Only called when :meth:`classify_path_only` returned
        ``"unknown"``; the file *body* is never read past the header,
        and the bytes are never handed to the LLM.  Returns the same
        three-valued string as :meth:`classify_path_only`.
        """
        resolved = self.resolve_within_package(path_literal)
        if resolved is None:
            return "unknown"
        real = resolved
        try:
            with open(real, "rb") as f:
                header = f.read(MAX_PEEK_BYTES)
        except OSError as e:
            logger.warning(f"[PackageFileReader] Magic peek failed for {real}: {e}")
            return "unknown"

        for prefix in _MAGIC_PREFIXES:
            if header.startswith(prefix):
                return "binary"

        # Heuristic: if the header contains a NUL byte we treat it as
        # binary too (common for ad-hoc binary blobs that don't carry a
        # recognised magic prefix).
        if b"\x00" in header:
            return "binary"

        return "script"

    # ------------------------------------------------------------------
    # Path predicates
    # ------------------------------------------------------------------

    def is_bare_specifier(self, path: str) -> bool:
        """Return True for npm / built-in style imports."""
        if not path:
            return True
        if path.startswith(("./", "../", "/")):
            return False
        first, sep, _rest = path.partition("/")
        if first.startswith("@"):
            return True
        if not sep:
            return not first.endswith(self._allowed_extensions)
        return False

    def is_bare_command(self, path: str) -> bool:
        """Return True for single-segment names that look like shell commands."""
        if not path:
            return True
        if path.startswith(("./", "../")):
            return False
        if "/" in path:
            return False
        return not path.endswith(self._allowed_extensions)

    # ------------------------------------------------------------------
    # Resolution
    # ------------------------------------------------------------------

    def resolve_within_package(self, rel_path: str) -> str | None:
        """Resolve *rel_path* to a real file path inside the package root."""
        if not rel_path:
            return None

        candidate = os.path.join(self._package_root, rel_path)
        candidates: list[str] = []

        if os.path.isdir(candidate):
            for idx in self._index_candidates:
                candidates.append(os.path.join(candidate, idx))
        else:
            candidates.append(candidate)
            _, ext = os.path.splitext(candidate)
            if ext == "":
                for e in self._allowed_extensions:
                    candidates.append(candidate + e)
                for idx in self._index_candidates:
                    candidates.append(os.path.join(candidate, idx))

        for path in candidates:
            real = os.path.realpath(path)
            if not real.startswith(self._package_root + os.sep) and real != self._package_root:
                continue
            if os.path.isfile(real):
                return real
        return None

    def read_resolved(self, rel_path: str) -> ResolvedFile | None:
        """Resolve *and* read a file as UTF-8 text."""
        real = self.resolve_within_package(rel_path)
        if real is None:
            return None
        try:
            with open(real, "r", encoding="utf-8", errors="replace") as f:
                content = f.read()
        except OSError as e:
            logger.warning(f"[PackageFileReader] Failed to read {real}: {e}")
            return None

        rel = os.path.relpath(real, self._package_root).replace(os.sep, "/")
        return ResolvedFile(rel_path=rel, content=content)

    # ------------------------------------------------------------------
    # Tool-loop turn handler
    # ------------------------------------------------------------------

    def read_files_turn(
        self,
        requested: list,
        visited_files: set[str],
        *,
        max_files_per_hop: int,
        max_total_files: int,
        reject_disallowed_extensions: tuple[str, ...] = (),
        bare_specifier_predicate: str = "specifier",
    ) -> list[dict]:
        """Resolve and read a batch of paths for one ``read_files`` turn.

        Mutates ``visited_files`` to record anything newly served
        (including binaries, which are visited but not returned with
        content).  The result list mirrors the per-entry shape produced
        by the legacy :class:`StaticFallback._handle_read_files`:

        - ``status="ok"`` with ``content`` for a successful text read.
        - ``status="binary"`` for an in-scope file whose contents look
          binary.  (The pre-loop short-circuit means this status should
          rarely fire for *spawn* targets, because those are filtered
          out before the loop runs.  It still applies to incidental
          binaries the LLM might request, e.g. a ``.png`` asset.)
        - ``status="not_found"`` / ``"out_of_scope"`` / ``"already_visited"`` /
          ``"budget_exhausted"`` — same semantics as the legacy loops.

        Parameters
        ----------
        reject_disallowed_extensions:
            Extensions that should be answered with ``out_of_scope``
            even when they exist on disk.  Used by the shell-command
            loop to forward ``.js`` etc. to the downstream JS analyser
            instead of inlining them.
        bare_specifier_predicate:
            ``"specifier"`` selects :meth:`is_bare_specifier`,
            ``"command"`` selects :meth:`is_bare_command`.
        """
        results: list[dict] = []
        paths = [p for p in requested if isinstance(p, str) and p.strip()]

        if len(paths) > max_files_per_hop:
            logger.info(
                f"[PackageFileReader] Trimming {len(paths)} requested paths to {max_files_per_hop}"
            )
            paths = paths[:max_files_per_hop]

        predicate = (
            self.is_bare_command
            if bare_specifier_predicate == "command"
            else self.is_bare_specifier
        )

        for raw_path in paths:
            normalized = raw_path.strip()

            if len(visited_files) >= max_total_files:
                results.append(
                    {
                        "path": normalized,
                        "status": "budget_exhausted",
                        "note": (
                            f"total-file cap ({max_total_files}) reached; "
                            "no more files can be served"
                        ),
                    }
                )
                continue

            if predicate(normalized):
                if bare_specifier_predicate == "command":
                    note = (
                        "bare command name; reason about it from documented "
                        "semantics + its arguments instead of requesting source"
                    )
                else:
                    note = (
                        "bare specifier refers to a third-party or Node "
                        "built-in module; reason about it from documented "
                        "semantics instead"
                    )
                results.append({"path": normalized, "status": "out_of_scope", "note": note})
                continue

            if os.path.isabs(normalized):
                results.append(
                    {
                        "path": normalized,
                        "status": "out_of_scope",
                        "note": "absolute paths are not allowed",
                    }
                )
                continue

            if reject_disallowed_extensions:
                _, ext = os.path.splitext(normalized)
                if ext.lower() in tuple(e.lower() for e in reject_disallowed_extensions):
                    results.append(
                        {
                            "path": normalized,
                            "status": "out_of_scope",
                            "note": (
                                "this file kind is handled by another stage; do not request it here"
                            ),
                        }
                    )
                    continue

            real = self.resolve_within_package(normalized)
            if real is None:
                results.append({"path": normalized, "status": "not_found"})
                continue

            rel_path = os.path.relpath(real, self._package_root).replace(os.sep, "/")
            if rel_path in visited_files:
                results.append(
                    {
                        "path": normalized,
                        "resolved_path": rel_path,
                        "status": "already_visited",
                        "note": "this file was already served earlier",
                    }
                )
                continue

            try:
                with open(real, "r", encoding="utf-8", errors="replace") as f:
                    content = f.read()
            except OSError as e:
                logger.warning(f"[PackageFileReader] Failed to read {real}: {e}")
                results.append({"path": normalized, "status": "not_found"})
                continue

            if _is_binary_content(content):
                visited_files.add(rel_path)
                results.append(
                    {
                        "path": normalized,
                        "resolved_path": rel_path,
                        "status": "binary",
                    }
                )
                continue

            visited_files.add(rel_path)
            results.append(
                {
                    "path": normalized,
                    "resolved_path": rel_path,
                    "status": "ok",
                    "content": content,
                }
            )

        return results
