"""LLM-driven fallback for the static-analysis stage.

When the deterministic static pipeline (``static_helper.generate_static_info``
plus PDG slicing) fails — typically due to a timeout or a helper-tool error —
this module takes over. It reads each entry script as raw source, asks the
LLM to interpret it in the style of ``static_stage_interpreter_prompt``, and
allows the LLM to request additional *local* files (inside the same package)
via a JSON-based tool loop. Up to ``MAX_HOPS`` read-turns are granted before
the LLM must finalize its verdict.

The fallback deliberately operates on text only: there is no PBG, no node
IDs, no classification of third-party/conditional/unresolved nodes. If the
LLM lands on ``undetermined`` the package is treated as benign, matching the
pre-existing post-exception behaviour of :class:`Package.analyse`.
"""

import os
import traceback
from dataclasses import dataclass, field

from loguru import logger

from llm import llm_static_fallback_turn
from npm_pipeline.classes.detection_state import AnalysisStep, DetectionState
from npm_pipeline.classes.localization_store import LocalizationStore
from npm_pipeline.classes.malicious_localizer import MaliciousLocalizer
from npm_pipeline.handlers.file_handler import _is_binary_content
from npm_pipeline.utils.finding import safe_entry_name, status_to_result_str
from npm_pipeline.utils.local_file_reader import PackageFileReader
from status import STATUS_BENIGN, STATUS_CODE_MALICIOUS

MAX_HOPS = 3
MAX_FILES_PER_HOP = 5
MAX_TOTAL_FILES = 12

_ALLOWED_EXTENSIONS = (".js", ".cjs", ".mjs", ".json")
_INDEX_CANDIDATES = ("index.js", "index.cjs", "index.mjs")


@dataclass
class _EntryResult:
    entry: str
    judgement: str  # "benign" | "malicious" | "undetermined"
    reason: str = ""
    key_evidence: list[dict] = field(default_factory=list)


class StaticFallback:
    """Run an LLM-driven fallback pass over one package's entry scripts."""

    def __init__(
        self,
        package_name: str,
        original_package_dir: str,
        detection_state: DetectionState,
        *,
        localizer: MaliciousLocalizer | None = None,
        localization_store: LocalizationStore | None = None,
    ):
        self._package_name = package_name
        self._original_package_dir = original_package_dir
        self._detection_state = detection_state
        self._package_root = os.path.realpath(os.path.join(original_package_dir, "package"))
        # Shared resolver/reader with the same JS-centric allowed
        # extension set the legacy ``_resolve_within_package`` used.
        self._file_reader = PackageFileReader(
            self._package_root,
            allowed_extensions=_ALLOWED_EXTENSIONS,
            index_candidates=_INDEX_CANDIDATES,
        )
        self._localizer = localizer
        self._localization_store = localization_store

    # ------------------------------------------------------------------
    # Public entry point
    # ------------------------------------------------------------------

    def run(self, entry_scripts: set[str]) -> str:
        """Analyse every entry script and return an aggregate verdict.

        Any malicious entry short-circuits to ``STATUS_CODE_MALICIOUS``.
        Benign and undetermined entries both map to ``STATUS_BENIGN`` per
        the configured undetermined policy.
        """
        if not entry_scripts:
            logger.info("[Fallback] No entry scripts; returning benign")
            return STATUS_BENIGN

        logger.info(
            f"[Fallback] Running LLM static fallback for {self._package_name} "
            f"over {len(entry_scripts)} entry script(s)"
        )

        for entry in sorted(entry_scripts):
            result = self._analyze_entry(entry)
            self._record_step(result)

            if result.judgement == "malicious":
                logger.info(
                    f"[Fallback] Entry {entry} judged malicious; short-circuiting package verdict"
                )
                return STATUS_CODE_MALICIOUS

        logger.info(f"[Fallback] No malicious entry for {self._package_name}; returning benign")
        return STATUS_BENIGN

    # ------------------------------------------------------------------
    # Per-entry analysis
    # ------------------------------------------------------------------

    def _analyze_entry(self, entry: str) -> _EntryResult:
        resolved = self._file_reader.read_resolved(entry)
        if resolved is None:
            logger.warning(
                f"[Fallback] Could not resolve entry {entry} under "
                f"{self._package_root}; marking undetermined"
            )
            return _EntryResult(
                entry=entry,
                judgement="undetermined",
                reason=f"entry file {entry} could not be resolved inside the package",
            )

        entry_rel, entry_content = resolved.rel_path, resolved.content
        if _is_binary_content(entry_content):
            logger.info(f"[Fallback] Entry {entry_rel} appears to be binary; marking undetermined")
            return _EntryResult(
                entry=entry,
                judgement="undetermined",
                reason=f"entry file {entry_rel} is binary; static review skipped",
            )

        context_summary = self._detection_state.to_entry_context_summary(entry)

        visited_files: set[str] = {entry_rel}
        served_contents: dict[str, str] = {entry_rel: entry_content}
        prior_reads: list[dict] = []
        running_synthesis: str = ""
        read_results: list[dict] = []
        hops_used = 0
        turn = 1
        forced_final_pending = False
        invalid_retries = 0
        last_response_error: str | None = None

        logger.info(
            f"[Fallback] Begin analyzing entry {entry_rel} "
            f"(size={len(entry_content)} chars, max_hops={MAX_HOPS})"
        )

        while True:
            remaining_hops = 0 if forced_final_pending else max(0, MAX_HOPS - hops_used)
            payload = self._build_user_payload(
                turn=turn,
                entry_rel=entry_rel,
                entry_content=entry_content,
                visited_files=visited_files,
                remaining_hops=remaining_hops,
                prior_reads=prior_reads,
                running_synthesis=running_synthesis,
                read_results=read_results,
                previous_response_error=last_response_error,
            )

            try:
                response = llm_static_fallback_turn(payload, context_summary=context_summary)
            except Exception as e:
                logger.warning(
                    f"[Fallback] LLM call failed for entry {entry_rel}: {e}; marking undetermined"
                )
                return _EntryResult(
                    entry=entry,
                    judgement="undetermined",
                    reason=f"LLM call failed during fallback: {e}",
                )

            kind, invalid_reason = self._classify_response(response)

            if kind == "invalid":
                invalid_retries += 1
                logger.warning(
                    f"[Fallback] Entry {entry_rel} turn {turn} invalid response "
                    f"(attempt {invalid_retries}): {invalid_reason}"
                )
                if invalid_retries >= 2:
                    return _EntryResult(
                        entry=entry,
                        judgement="undetermined",
                        reason=f"two invalid LLM responses in a row: {invalid_reason}",
                    )
                # Stay on the same logical turn: re-send the exact same payload
                # (entry_content / prior_reads / read_results) plus an explicit
                # `previous_response_error` note so the LLM can correct its JSON
                # without losing the file contents it needs to reason about.
                last_response_error = invalid_reason
                continue
            invalid_retries = 0
            last_response_error = None

            action = response.get("action")
            logger.info(
                f"[Fallback] Entry {entry_rel} turn {turn}: "
                f"LLM chose action={action!r} (hops_used={hops_used}/{MAX_HOPS}, "
                f"remaining_hops={remaining_hops})"
            )

            if kind == "final":
                final_synthesis = self._extract_synthesis(response) or running_synthesis
                self._log_synthesis(entry_rel, turn, final_synthesis, label="final synthesis")
                final_result = self._parse_final(entry, response)
                logger.info(
                    f"[Fallback] Entry {entry_rel} finished after {turn} turn(s) "
                    f"({hops_used}/{MAX_HOPS} hop(s) used): "
                    f"judgement={final_result.judgement}, "
                    f"reason={final_result.reason or '<none>'}"
                )
                if final_result.judgement == "malicious":
                    self._localize_malicious(
                        entry=entry,
                        entry_rel=entry_rel,
                        files=served_contents,
                        result=final_result,
                        running_synthesis=final_synthesis,
                        context_summary=context_summary,
                    )
                return final_result

            # kind == "read_files"
            if forced_final_pending:
                logger.warning(
                    f"[Fallback] Entry {entry_rel} turn {turn}: LLM ignored the "
                    f"forced-final directive and asked for files again; "
                    f"terminating with undetermined"
                )
                return _EntryResult(
                    entry=entry,
                    judgement="undetermined",
                    reason=(
                        "LLM kept requesting more files after the hop budget "
                        "was exhausted; forced termination"
                    ),
                )

            requested_paths = self._extract_requested_paths(response)
            observations = self._extract_observations(response)
            new_synthesis = self._extract_synthesis(response)
            if new_synthesis:
                running_synthesis = new_synthesis
            else:
                logger.warning(
                    f"[Fallback] Entry {entry_rel} turn {turn}: read_files response "
                    "missing 'running_synthesis'; carrying over previous value"
                )
            self._log_synthesis(entry_rel, turn, running_synthesis)

            if remaining_hops <= 0:
                logger.info(
                    f"[Fallback] Entry {entry_rel} turn {turn}: hop budget "
                    f"exhausted ({hops_used}/{MAX_HOPS}); forcing a final turn"
                )
                self._archive_read_turn(
                    prior_reads,
                    turn=turn,
                    requested_paths=requested_paths,
                    served_summary=[],
                    observations=observations,
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

            reason_text = response.get("reason") if isinstance(response, dict) else ""
            if not isinstance(reason_text, str):
                reason_text = ""
            logger.info(
                f"[Fallback] Entry {entry_rel} turn {turn} requesting more files: "
                f"paths={requested_paths!r}, reason={reason_text!r}, "
                f"hops_used={hops_used}/{MAX_HOPS}, visited_total={len(visited_files)}"
            )

            fresh_results = self._handle_read_files(requested_paths, visited_files)
            for r in fresh_results:
                if (
                    r.get("status") == "ok"
                    and isinstance(r.get("resolved_path"), str)
                    and isinstance(r.get("content"), str)
                ):
                    served_contents[r["resolved_path"]] = r["content"]
            served_summary = [self._strip_content(r) for r in fresh_results]
            self._archive_read_turn(
                prior_reads,
                turn=turn,
                requested_paths=requested_paths,
                served_summary=served_summary,
                observations=observations,
            )
            read_results = fresh_results
            hops_used += 1

            status_counts: dict[str, int] = {}
            for r in fresh_results:
                status_counts[r.get("status", "unknown")] = (
                    status_counts.get(r.get("status", "unknown"), 0) + 1
                )
            logger.info(
                f"[Fallback] Entry {entry_rel} turn {turn}: served "
                f"{len(fresh_results)} read request(s) "
                f"[{', '.join(f'{k}={v}' for k, v in sorted(status_counts.items())) or 'none'}]; "
                f"visited_total={len(visited_files)}, hops_used={hops_used}/{MAX_HOPS}"
            )
            turn += 1

    # ------------------------------------------------------------------
    # Per-turn helpers
    # ------------------------------------------------------------------

    def _build_user_payload(
        self,
        *,
        turn: int,
        entry_rel: str,
        entry_content: str,
        visited_files: set[str],
        remaining_hops: int,
        prior_reads: list[dict],
        running_synthesis: str,
        read_results: list[dict],
        previous_response_error: str | None = None,
    ) -> dict:
        """Construct the per-turn user payload for the fallback LLM.

        Turn 1 carries the raw entry source. Turn >= 2 carries the
        accumulated structured history (``prior_reads``) plus the most
        recent batch of served files (``read_results``). The LLM-managed
        ``running_synthesis`` string is sent every turn.
        """
        payload: dict = {
            "turn": turn,
            "package_name": self._package_name,
            "entry_file": entry_rel,
            "remaining_hops": remaining_hops,
            "visited_files": sorted(visited_files),
            "running_synthesis": running_synthesis,
        }
        if turn == 1:
            payload["entry_content"] = entry_content
        else:
            payload["prior_reads"] = prior_reads
            payload["read_results"] = read_results
        if previous_response_error:
            payload["previous_response_error"] = previous_response_error
        return payload

    @staticmethod
    def _classify_response(response: object) -> tuple[str, str]:
        """Classify *response* as ``"final"``, ``"read_files"`` or ``"invalid"``.

        For invalid responses the second tuple element is a short, LLM-
        addressed reason string suitable for echoing back as feedback.
        """
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
    def _extract_observations(response: dict) -> str:
        obs = response.get("observations")
        return obs if isinstance(obs, str) else ""

    @staticmethod
    def _extract_synthesis(response: dict) -> str:
        synth = response.get("running_synthesis")
        if isinstance(synth, str) and synth.strip():
            return synth
        return ""

    @staticmethod
    def _strip_content(read_result: dict) -> dict:
        """Return *read_result* without the bulky ``content`` field.

        The result is suitable for archival into ``prior_reads`` so that
        prior file source text is not replayed every subsequent turn.
        """
        return {k: v for k, v in read_result.items() if k != "content"}

    @staticmethod
    def _archive_read_turn(
        prior_reads: list[dict],
        *,
        turn: int,
        requested_paths: list[str],
        served_summary: list[dict],
        observations: str,
    ) -> None:
        """Append a structured record of *turn*'s ``read_files`` request.

        ``served_summary`` carries each entry's ``status`` / ``path`` /
        ``resolved_path`` (no content), allowing later turns to see which
        of the LLM's previous requests actually returned source code and
        which were rejected as ``not_found`` / ``out_of_scope`` / etc.
        """
        prior_reads.append(
            {
                "turn": turn,
                "requested_paths": list(requested_paths),
                "served_summary": served_summary,
                "observations": observations,
            }
        )

    @staticmethod
    def _log_synthesis(
        entry_rel: str,
        turn: int,
        synthesis: str,
        *,
        label: str = "synthesis",
        max_chars: int | None = None,
    ) -> None:
        """Emit a compact INFO log of the LLM's running synthesis.

        By default the full synthesis is logged; pass ``max_chars`` to truncate.
        """
        if not synthesis:
            return
        if max_chars is not None and len(synthesis) > max_chars:
            snippet = synthesis[:max_chars] + "..."
        else:
            snippet = synthesis
        snippet = snippet.replace("\n", " ").replace("\r", " ")
        logger.info(f"[Fallback] Entry {entry_rel} turn {turn} {label}: {snippet}")

    # ------------------------------------------------------------------
    # Read-files tool
    # ------------------------------------------------------------------

    def _handle_read_files(
        self,
        requested: list,
        visited_files: set[str],
    ) -> list[dict]:
        """Resolve and read the paths requested in a ``read_files`` turn.

        Delegates the per-request resolve / read / status mechanics to
        :meth:`PackageFileReader.read_files_turn`, preserving the exact
        legacy behaviour (same allowed extensions, same bare-specifier
        predicate, same status codes).
        """
        return self._file_reader.read_files_turn(
            requested,
            visited_files,
            max_files_per_hop=MAX_FILES_PER_HOP,
            max_total_files=MAX_TOTAL_FILES,
            bare_specifier_predicate="specifier",
        )

    # ------------------------------------------------------------------
    # Result recording
    # ------------------------------------------------------------------

    def _parse_final(self, entry: str, response: dict) -> _EntryResult:
        judgement = response.get("judgement", "undetermined")
        if judgement not in {"benign", "malicious", "undetermined"}:
            logger.warning(
                f"[Fallback] Entry {entry}: unknown judgement "
                f"{judgement!r}; coercing to undetermined"
            )
            judgement = "undetermined"

        reason = response.get("reason", "")
        if not isinstance(reason, str):
            reason = str(reason)

        key_evidence = response.get("key_evidence", [])
        if not isinstance(key_evidence, list):
            key_evidence = []

        return _EntryResult(
            entry=entry,
            judgement=judgement,
            reason=reason,
            key_evidence=key_evidence,
        )

    def _record_step(self, result: _EntryResult) -> None:
        status_label = (
            STATUS_CODE_MALICIOUS
            if result.judgement == "malicious"
            else STATUS_BENIGN
            if result.judgement == "benign"
            else "undetermined"
        )

        finding = self._build_finding(result)

        self._detection_state.add_step(
            AnalysisStep(
                stage="static_fallback",
                entry=result.entry,
                result=status_to_result_str(status_label),
                finding=finding,
            )
        )
        logger.info(
            f"[Fallback] Recorded static_fallback step for "
            f"{safe_entry_name(result.entry)} -> {result.judgement}"
        )

    @staticmethod
    def _build_finding(result: _EntryResult) -> str:
        parts: list[str] = []
        if result.reason:
            parts.append(f"reason: {result.reason}")
        if result.key_evidence:
            claims: list[str] = []
            for ev in result.key_evidence:
                if not isinstance(ev, dict):
                    continue
                claim = ev.get("claim")
                file = ev.get("file")
                if claim and file:
                    claims.append(f"{file}: {claim}")
                elif claim:
                    claims.append(str(claim))
            if claims:
                parts.append(f"evidence: {'; '.join(claims)}")
        return " | ".join(parts) if parts else "no findings"

    # ------------------------------------------------------------------
    # Malicious-code localization
    # ------------------------------------------------------------------

    def _localize_malicious(
        self,
        *,
        entry: str,
        entry_rel: str,
        files: dict[str, str],
        result: _EntryResult,
        running_synthesis: str,
        context_summary: str,
    ) -> None:
        """Run the localizer over the source files served during fallback.

        Failure here must never alter the upstream verdict — we wrap
        the whole call in a broad except and only log.
        """
        if not (self._localizer and self._localization_store):
            return
        try:
            payload = self._localizer.localize_from_files(
                package_name=self._package_name,
                entry=entry_rel,
                files=files,
                reason=result.reason,
                key_evidence=result.key_evidence,
                running_synthesis=running_synthesis,
                context_summary=context_summary,
            )
            self._localization_store.persist(entry=entry, payload=payload)
        except Exception as e:
            logger.warning(
                f"[Localization] {entry_rel} stage=static_fallback failed: {e}\n"
                + traceback.format_exc()
            )
