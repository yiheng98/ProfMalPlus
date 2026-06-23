from loguru import logger

from llm import (
    llm_locate_malicious_code,
    llm_locate_malicious_code_from_files,
)
from npm_pipeline.types import ComponentResult


class MaliciousLocalizer:
    """Stateless LLM driver for malicious-code localization."""

    # ------------------------------------------------------------------
    # Slice path (EntryPipeline)
    # ------------------------------------------------------------------

    def localize(
        self,
        *,
        package_name: str,
        entry: str,
        components: list[ComponentResult],
        final_result: dict,
        context_summary: str = "",
    ) -> dict | None:
        """Locate malicious snippets using already-built component slices.

        Returns the validated ``{"package", "entry", "summary",
        "locations": [...]}`` dict on success or ``None`` when the LLM
        fails to return a parseable / well-formed response. Failure
        never raises; the caller can safely ignore ``None``.
        """
        if not components:
            logger.info(f"[Localization] {entry}: no components, skipping")
            return None

        relevant = self._select_relevant_components(components)
        slice_text_by_file = self._build_slice_text_index(relevant)
        if not slice_text_by_file:
            logger.info(f"[Localization] {entry}: empty slice index, skipping")
            return None

        synthesis_view = self._synthesis_view(final_result)

        payload = {
            "package": package_name,
            "entry": entry,
            "synthesis": synthesis_view,
            "components": [self._component_view(c) for c in relevant],
        }

        response = llm_locate_malicious_code(payload, context_summary=context_summary)
        if response is None:
            logger.warning(f"[Localization] {entry}: LLM returned no parseable response")
            return None

        return self._validate_response(
            response,
            package_name=package_name,
            entry=entry,
            allowed_text_by_file=slice_text_by_file,
            raw_response=response,
        )

    @staticmethod
    def _select_relevant_components(
        components: list[ComponentResult],
    ) -> list[ComponentResult]:
        """Prefer components individually judged malicious; fall back to all."""
        malicious = [c for c in components if (c.result or {}).get("judgement") == "malicious"]
        if malicious:
            return malicious
        return list(components)

    @staticmethod
    def _build_slice_text_index(
        components: list[ComponentResult],
    ) -> dict[str, str]:
        """For each file, the concatenation of every relevant slice's snippet.

        Used by the localizer only to know which file names are valid
        ``location.file`` targets; the contents are no longer matched
        against ``location.code`` so the LLM is free to quote, trim, or
        lightly rewrite the snippet.
        """
        index: dict[str, list[str]] = {}
        for comp in components:
            sliced_code = (comp.code_slice or {}).get("sliced_code", [])
            if not isinstance(sliced_code, list):
                continue
            for entry_dict in sliced_code:
                if not isinstance(entry_dict, dict):
                    continue
                for file_name, body in entry_dict.items():
                    if not isinstance(body, dict):
                        continue
                    code_snippet = body.get("code_snippet")
                    if isinstance(code_snippet, list):
                        text = "\n".join(str(line) for line in code_snippet)
                    elif isinstance(code_snippet, str):
                        text = code_snippet
                    else:
                        continue
                    index.setdefault(file_name, []).append(text)
        return {file_name: "\n".join(texts) for file_name, texts in index.items()}

    @staticmethod
    def _synthesis_view(final_result: dict) -> dict:
        """Project ``final_result`` to the keys the localizer prompt cares about."""
        if not isinstance(final_result, dict):
            return {}
        keep = {
            "judgement",
            "explanation",
            "reason",
            "key_evidence",
            "cross_component_evidence",
            "node_to_be_checked",
        }
        return {k: v for k, v in final_result.items() if k in keep}

    @staticmethod
    def _component_view(comp: ComponentResult) -> dict:
        result = comp.result or {}
        return {
            "component_id": comp.component_id,
            "judgement": result.get("judgement"),
            "explanation": result.get("explanation") or result.get("reason"),
            "key_evidence": result.get("key_evidence", []),
            "sliced_code": (comp.code_slice or {}).get("sliced_code", []),
        }

    # ------------------------------------------------------------------
    # Fallback path (StaticFallback)
    # ------------------------------------------------------------------

    def localize_from_files(
        self,
        *,
        package_name: str,
        entry: str,
        files: dict[str, str],
        reason: str,
        key_evidence: list[dict],
        running_synthesis: str,
        context_summary: str = "",
    ) -> dict | None:
        """Locate malicious snippets from the source files served during fallback.

        Filters ``files`` down to entries actually relevant to the
        verdict (entry file plus any file cited in ``key_evidence``)
        before calling the LLM, to keep token usage bounded.
        """
        if not files:
            logger.info(f"[Localization] {entry}: no files in fallback context, skipping")
            return None

        relevant_files = self._select_relevant_files(entry, files, key_evidence)
        if not relevant_files:
            logger.info(f"[Localization] {entry}: no relevant fallback files, skipping")
            return None

        clean_evidence = self._sanitize_key_evidence(key_evidence)

        payload = {
            "package": package_name,
            "entry": entry,
            "reason": reason or "",
            "running_synthesis": running_synthesis or "",
            "key_evidence": clean_evidence,
            "files": relevant_files,
        }

        response = llm_locate_malicious_code_from_files(payload, context_summary=context_summary)
        if response is None:
            logger.warning(f"[Localization] {entry}: fallback LLM returned no parseable response")
            return None

        return self._validate_response(
            response,
            package_name=package_name,
            entry=entry,
            allowed_text_by_file=relevant_files,
            raw_response=response,
        )

    @staticmethod
    def _select_relevant_files(
        entry: str, files: dict[str, str], key_evidence: list[dict]
    ) -> dict[str, str]:
        """Keep entry + any file cited by ``key_evidence``; fall back to entry only."""
        keep: set[str] = set()
        if entry in files:
            keep.add(entry)
        if isinstance(key_evidence, list):
            for ev in key_evidence:
                if not isinstance(ev, dict):
                    continue
                file_name = ev.get("file")
                if isinstance(file_name, str) and file_name in files:
                    keep.add(file_name)
        if not keep and entry in files:
            keep.add(entry)
        return {f: files[f] for f in keep}

    @staticmethod
    def _sanitize_key_evidence(key_evidence: list[dict]) -> list[dict]:
        if not isinstance(key_evidence, list):
            return []
        clean: list[dict] = []
        for ev in key_evidence:
            if not isinstance(ev, dict):
                continue
            item: dict = {}
            claim = ev.get("claim")
            if isinstance(claim, str):
                item["claim"] = claim
            file_name = ev.get("file")
            if isinstance(file_name, str):
                item["file"] = file_name
            if item:
                clean.append(item)
        return clean

    # ------------------------------------------------------------------
    # Response validation (shared)
    # ------------------------------------------------------------------

    def _validate_response(
        self,
        response: dict,
        *,
        package_name: str,
        entry: str,
        allowed_text_by_file: dict[str, str],
        raw_response: dict,
    ) -> dict | None:
        """Filter and shape the LLM response into the canonical schema."""
        if not isinstance(response, dict):
            logger.warning(f"[Localization] {entry}: response is not a JSON object")
            return None

        raw_locations = response.get("locations", [])
        if not isinstance(raw_locations, list):
            raw_locations = []

        allowed_files = set(allowed_text_by_file.keys())

        kept: list[dict] = []
        dropped = 0
        for loc in raw_locations:
            if not isinstance(loc, dict):
                dropped += 1
                continue
            file_name = loc.get("file")
            code = loc.get("code")
            reason = loc.get("reason", "")
            if not isinstance(file_name, str) or not isinstance(code, str):
                dropped += 1
                continue
            if file_name not in allowed_files:
                dropped += 1
                logger.warning(
                    f"[Localization] {entry}: dropped location with unknown file {file_name!r}"
                )
                continue
            if not code.strip():
                dropped += 1
                continue
            kept.append(
                {
                    "file": file_name,
                    "code": code,
                    "reason": reason if isinstance(reason, str) else str(reason),
                }
            )

        if dropped:
            logger.info(f"[Localization] {entry}: dropped {dropped} location(s); kept {len(kept)}")

        if not kept:
            logger.warning(
                f"[Localization] {entry}: no valid locations after validation; "
                f"raw response will not be persisted"
            )
            return None

        summary = response.get("summary", "")
        if not isinstance(summary, str):
            summary = str(summary)

        result = {
            "package": package_name,
            "entry": entry,
            "summary": summary,
            "locations": kept,
        }
        self._log_localization_result(entry, result)
        return result

    @staticmethod
    def _log_localization_result(entry: str, payload: dict) -> None:
        """Emit a full INFO-level dump of the validated localization.

        Every kept ``location`` is printed in its entirety — file, reason,
        and the verbatim ``code`` block — so the malicious snippets show
        up alongside the verdict in the work-flow log without having to
        open the persisted JSON. This is intentionally chatty: callers
        that find it noisy can suppress it via a loguru filter.
        """
        locations = payload.get("locations") or []
        summary = payload.get("summary") or ""
        header = f"[Localization] {entry}: kept {len(locations)} location(s)"
        if summary:
            header += f"\n  summary: {summary}"
        logger.info(header)
        total = len(locations)
        for idx, loc in enumerate(locations, 1):
            file_name = loc.get("file", "<unknown>")
            reason = loc.get("reason", "") or ""
            code = loc.get("code", "") or ""
            logger.info(
                f"[Localization]\n{entry}: location {idx}/{total} "
                f"file={file_name}\n"
                f"reason: {reason}\n"
                f"code:\n{code}"
            )
