"""LLM-driven analyzer for install-time shell commands with inner-script reads."""

import os

from loguru import logger

from llm import llm_shell_command_turn
from npm_pipeline.utils.local_file_reader import PackageFileReader

MAX_HOPS = 2
MAX_FILES_PER_HOP = 5
MAX_TOTAL_FILES = 8

_VALID_LABELS = {"benign", "warning", "malicious"}
# Conservative default returned when the LLM call cannot produce a usable
# verdict (connection failure, unparseable response, etc.). Mirrors the
# legacy single-shot interpreter's fallback semantics.
_DEFAULT_RESULT: tuple[str, str, list[str]] = ("warning", "", [])

_DISALLOWED_EXTENSIONS = (".js", ".mjs", ".cjs")


class ShellCommandAnalyzer:
    """Run an iterative LLM analysis of one shell command.

    Parameters
    ----------
    package_root:
        Absolute filesystem path to the directory that contains
        ``package.json`` (i.e. ``<original_package_dir>/package``). All
        LLM-requested file reads are resolved relative to and confined
        within this directory.
    """

    def __init__(self, package_root: str):
        self._package_root = os.path.realpath(package_root)
        # Shared resolver/reader with the shell-script extension set
        # the legacy ``_resolve_within_package`` used. ``index.{js,...}``
        # is intentionally absent — directories never resolve to a
        # script for this loop.
        self._file_reader = PackageFileReader(
            self._package_root,
            index_candidates=(),
        )

    # ------------------------------------------------------------------
    # Public entry point
    # ------------------------------------------------------------------

    def analyse(self, shell_command: str) -> tuple[str, str, list[str]]:
        """Classify *shell_command* with optional inner-script reads.

        Returns ``(label, explanation, executed_js_files)``. ``label`` is
        always one of ``"benign"`` / ``"warning"`` / ``"malicious"``. On
        any unrecoverable error the function falls back to the same
        defaults as the legacy single-shot interpreter (``warning`` with
        an empty explanation and JS-file list).
        """
        visited_files: set[str] = set()
        prior_reads: list[dict] = []
        read_results: list[dict] = []
        hops_used = 0
        turn = 1
        forced_final_pending = False
        invalid_retries = 0
        last_response_error: str | None = None

        logger.info(f"[ShellCmd] Begin analysing shell command: {shell_command}")

        while True:
            remaining_hops = 0 if forced_final_pending else max(0, MAX_HOPS - hops_used)
            payload = self._build_payload(
                turn=turn,
                shell_command=shell_command,
                visited_files=visited_files,
                remaining_hops=remaining_hops,
                prior_reads=prior_reads,
                read_results=read_results,
                previous_response_error=last_response_error,
            )

            try:
                response = llm_shell_command_turn(payload)
            except ConnectionError as e:
                logger.warning(f"[ShellCmd] LLM connection failed: {e}; returning default result")
                return self._default_result()
            except Exception as e:
                logger.warning(f"[ShellCmd] LLM call raised {type(e).__name__}: {e}")
                return self._default_result()

            kind, invalid_reason = self._classify_response(response)

            if kind == "invalid":
                invalid_retries += 1
                logger.warning(
                    f"[ShellCmd] Turn {turn} invalid response "
                    f"(attempt {invalid_retries}): {invalid_reason}"
                )
                if invalid_retries >= 2:
                    logger.warning(
                        "[ShellCmd] Two invalid responses in a row; returning default result"
                    )
                    return self._default_result()

                last_response_error = invalid_reason
                continue
            invalid_retries = 0
            last_response_error = None

            action = response.get("action")
            logger.info(
                f"[ShellCmd] Turn {turn}: LLM chose action={action!r} "
                f"(hops_used={hops_used}/{MAX_HOPS}, remaining_hops={remaining_hops})"
            )

            if kind == "final":
                return self._parse_final(response)

            # kind == "read_files"
            if forced_final_pending:
                logger.warning(
                    f"[ShellCmd] Turn {turn}: LLM ignored the forced-final directive and "
                    "asked for files again; returning default result"
                )
                return self._default_result()

            requested_paths = self._extract_requested_paths(response)
            reason_text = response.get("reason") if isinstance(response, dict) else ""
            if not isinstance(reason_text, str):
                reason_text = ""

            if remaining_hops <= 0:
                logger.info(
                    f"[ShellCmd] Turn {turn}: hop budget exhausted "
                    f"({hops_used}/{MAX_HOPS}); forcing a final turn"
                )
                self._archive_read_turn(
                    prior_reads,
                    turn=turn,
                    requested_paths=requested_paths,
                    served_summary=[],
                )
                read_results = [
                    {
                        "status": "budget_exhausted",
                        "note": "no hops remain; you MUST respond with action='final' now",
                    }
                ]
                forced_final_pending = True
                turn += 1
                continue

            logger.info(
                f"[ShellCmd] Turn {turn} requesting more files: "
                f"paths={requested_paths!r}, reason={reason_text!r}, "
                f"hops_used={hops_used}/{MAX_HOPS}, visited_total={len(visited_files)}"
            )

            fresh_results = self._handle_read_files(requested_paths, visited_files)
            served_summary = [self._strip_content(r) for r in fresh_results]
            self._archive_read_turn(
                prior_reads,
                turn=turn,
                requested_paths=requested_paths,
                served_summary=served_summary,
            )
            read_results = fresh_results
            hops_used += 1

            status_counts: dict[str, int] = {}
            for r in fresh_results:
                status_counts[r.get("status", "unknown")] = (
                    status_counts.get(r.get("status", "unknown"), 0) + 1
                )
            logger.info(
                f"[ShellCmd] Turn {turn}: served {len(fresh_results)} read request(s) "
                f"[{', '.join(f'{k}={v}' for k, v in sorted(status_counts.items())) or 'none'}]; "
                f"visited_total={len(visited_files)}, hops_used={hops_used}/{MAX_HOPS}"
            )
            turn += 1

    # ------------------------------------------------------------------
    # Per-turn helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _build_payload(
        *,
        turn: int,
        shell_command: str,
        visited_files: set[str],
        remaining_hops: int,
        prior_reads: list[dict],
        read_results: list[dict],
        previous_response_error: str | None = None,
    ) -> dict:
        """Construct the per-turn user payload for the shell-command LLM.

        The outer ``shell_command`` is included on every turn so the LLM
        never loses sight of the install-time context that motivated any
        inner-script reads. ``prior_reads`` and ``read_results`` only
        carry from turn >= 2.
        """
        payload: dict = {
            "turn": turn,
            "shell_command": shell_command,
            "remaining_hops": remaining_hops,
            "visited_files": sorted(visited_files),
        }
        if turn >= 2:
            payload["prior_reads"] = prior_reads
            payload["read_results"] = read_results
        if previous_response_error:
            payload["previous_response_error"] = previous_response_error
        return payload

    @staticmethod
    def _classify_response(response: object) -> tuple[str, str]:
        """Classify *response* as ``"final"``, ``"read_files"`` or ``"invalid"``."""
        if not isinstance(response, dict) or "action" not in response:
            return "invalid", (
                "your previous response could not be parsed as one of "
                "the two allowed JSON shapes (read_files / final); please retry"
            )
        action = response.get("action")
        if action == "final":
            return "final", ""
        if action == "read_files":
            return "read_files", ""
        return "invalid", (
            f"unknown action {action!r}; allowed actions are 'read_files' or 'final'"
        )

    @staticmethod
    def _extract_requested_paths(response: dict) -> list[str]:
        raw = response.get("paths") or []
        if not isinstance(raw, list):
            return []
        return [p for p in raw if isinstance(p, str) and p.strip()]

    @staticmethod
    def _strip_content(read_result: dict) -> dict:
        """Return *read_result* without the bulky ``content`` field."""
        return {k: v for k, v in read_result.items() if k != "content"}

    @staticmethod
    def _archive_read_turn(
        prior_reads: list[dict],
        *,
        turn: int,
        requested_paths: list[str],
        served_summary: list[dict],
    ) -> None:
        prior_reads.append(
            {
                "turn": turn,
                "requested_paths": list(requested_paths),
                "served_summary": served_summary,
            }
        )

    # ------------------------------------------------------------------
    # Final-verdict parsing
    # ------------------------------------------------------------------

    @staticmethod
    def _default_result() -> tuple[str, str, list[str]]:
        label, explanation, executed = _DEFAULT_RESULT
        return label, explanation, list(executed)

    @staticmethod
    def _parse_final(response: dict) -> tuple[str, str, list[str]]:
        label = response.get("label", "benign")
        if not isinstance(label, str) or label not in _VALID_LABELS:
            logger.warning(f"[ShellCmd] Unknown label {label!r}; defaulting to 'warning'")
            label = "warning"

        explanation = response.get("explanation", "")
        if not isinstance(explanation, str):
            explanation = str(explanation)

        executed = response.get("executed_js_files", [])
        if not isinstance(executed, list):
            executed = []
        executed = [f for f in executed if isinstance(f, str) and f.strip()]

        logger.info(
            f"[ShellCmd] Final verdict: label={label!r}, "
            f"executed_js_files={executed!r}, explanation={explanation!r}"
        )
        return label, explanation, executed

    # ------------------------------------------------------------------
    # Read-files tool
    # ------------------------------------------------------------------

    def _handle_read_files(
        self,
        requested: list,
        visited_files: set[str],
    ) -> list[dict]:
        """Resolve and read the paths requested in a ``read_files`` turn.

        Delegates to :meth:`PackageFileReader.read_files_turn` with the
        shell-style allowed-extension whitelist and the disallowed-JS
        extension filter that routes JavaScript files to the downstream
        analyzers.
        """
        return self._file_reader.read_files_turn(
            requested,
            visited_files,
            max_files_per_hop=MAX_FILES_PER_HOP,
            max_total_files=MAX_TOTAL_FILES,
            reject_disallowed_extensions=_DISALLOWED_EXTENSIONS,
            bare_specifier_predicate="command",
        )
