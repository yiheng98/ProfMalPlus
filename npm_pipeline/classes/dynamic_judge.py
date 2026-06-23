"""DynamicJudge — dynamic behaviour judgement with multi-hop reread pass."""

import json

from loguru import logger

from llm import (
    llm_dynamic_behavior_judgment,
    llm_dynamic_reread,
    llm_validate_dynamic_behavior_report,
)
from npm_pipeline.classes.detection_state import AnalysisStep, DetectionState
from npm_pipeline.classes.static_judge import (
    MAX_REREAD_HOPS,
    _any_ok,
    _coerce_paths,
    _detect_binary,
    _status_counts,
    _verdict_to_result_label,
)
from npm_pipeline.types import ComponentResult, DynamicContext
from npm_pipeline.utils.local_file_reader import PackageFileReader


class DynamicJudge:
    """Stateless driver for the dynamic LLM pipeline plus optional multi-hop reread."""

    def __init__(
        self,
        *,
        package_name: str = "",
        file_reader: PackageFileReader | None = None,
        detection_state: DetectionState | None = None,
    ):
        self._package_name = package_name
        self._file_reader = file_reader
        self._detection_state = detection_state

    # ------------------------------------------------------------------
    # Public entry point
    # ------------------------------------------------------------------

    def judge(
        self,
        components: list[ComponentResult],
        ctx: DynamicContext,
        *,
        context_summary: str = "",
        entry: str | None = None,
    ) -> list[ComponentResult]:
        if not components:
            logger.info("[Dynamic] No dynamic components found")
            return []

        results: list[ComponentResult] = []
        for comp in components:
            cr = self._judge(comp, ctx, context_summary, entry=entry)
            if cr is None:
                continue
            results.append(cr)
        return results

    # ------------------------------------------------------------------
    # Per-component path
    # ------------------------------------------------------------------

    def _judge(
        self,
        comp: ComponentResult,
        ctx: DynamicContext,
        context_summary: str,
        *,
        entry: str | None,
    ) -> ComponentResult | None:
        file_io_records_serialised = [r.to_dict() for r in ctx.file_io_records]
        judgment_input: dict = {
            "sliced_code": comp.code_slice.get("sliced_code", []),
            "file_io_records": file_io_records_serialised,
            "file_inspections": ctx.file_inspections,
        }

        report = llm_dynamic_behavior_judgment(judgment_input, context_summary=context_summary)
        logger.info(
            f"[Dynamic] Raw LLM result for component {comp.component_id}:\n"
            f"{json.dumps(report, indent=2, ensure_ascii=False, default=str)}"
        )
        if not report or "judgement" not in report:
            logger.warning(f"[Dynamic] Judgment failed for component {comp.component_id}")
            return None

        verified = llm_validate_dynamic_behavior_report(
            judgment_input, report, context_summary=context_summary
        )
        if verified and "judgement" in verified:
            logger.info(
                f"[Dynamic] Verifier result for component {comp.component_id} "
                f"({report['judgement']} -> {verified['judgement']}):\n"
                f"{json.dumps(verified, indent=2, ensure_ascii=False, default=str)}"
            )
            base_report = verified
        else:
            logger.warning(
                f"[Dynamic] Verifier failed for component {comp.component_id}; "
                "falling back to unverified judger report"
            )
            base_report = report

        prior_result: dict = {
            "judgement": base_report["judgement"],
            "explanation": base_report.get("explanation", ""),
        }
        if isinstance(base_report.get("files_to_read"), list):
            prior_result["files_to_read"] = base_report["files_to_read"]

        new_result = self._maybe_reread(
            comp=comp,
            prior_result=prior_result,
            ctx=ctx,
            file_io_records_serialised=file_io_records_serialised,
            context_summary=context_summary,
            entry=entry,
        )

        logger.info(f"[Dynamic] Component {comp.component_id} -> {new_result.get('judgement')}")
        return comp.with_result(new_result)

    # ------------------------------------------------------------------
    # Multi-hop reread gate
    # ------------------------------------------------------------------

    def _maybe_reread(
        self,
        *,
        comp: ComponentResult,
        prior_result: dict,
        ctx: DynamicContext,
        file_io_records_serialised: list[dict],
        context_summary: str,
        entry: str | None,
    ) -> dict:
        """Run up to :data:`MAX_REREAD_HOPS` hops of the dynamic reread pass."""
        if self._file_reader is None:
            return _strip_files_to_read_dynamic(prior_result)

        current_report: dict = prior_result
        visited: set[str] = set()
        accumulated_reads: list[dict] = []

        for hop in range(1, MAX_REREAD_HOPS + 1):
            remaining_hops = MAX_REREAD_HOPS - hop
            requested_raw = _coerce_paths(current_report.get("files_to_read"))
            if not requested_raw:
                break

            new_requested = [p for p in requested_raw if p not in visited]
            if not new_requested:
                logger.info(
                    f"[DynamicJudge] Reread hop {hop} for component {comp.component_id}: "
                    "all requested paths already visited; stopping"
                )
                break

            logger.info(
                f"[DynamicJudge] Reread hop {hop}/{MAX_REREAD_HOPS} for component "
                f"{comp.component_id} (entry={entry}, requested={new_requested})"
            )

            binary = _detect_binary(self._file_reader, new_requested)
            if binary is not None:
                rel_path, classifier = binary
                new_result = _binary_malicious_dynamic(rel_path)
                self._record_history(
                    entry=entry,
                    prior=current_report,
                    new=new_result,
                    requested=new_requested,
                    read_log=[],
                    binary_short_circuit_path=rel_path,
                    classifier=classifier,
                    hop=hop,
                )
                current_report = new_result
                break

            read_results = self._file_reader.read_files_turn(
                new_requested,
                visited,
                max_files_per_hop=len(new_requested),
                max_total_files=len(new_requested) + len(accumulated_reads),
                bare_specifier_predicate="specifier",
            )
            _log_reread_file_results_dynamic(comp.component_id, read_results)
            # Tag each newly-read file with its originating hop so the LLM
            # can reason about *when* each piece of evidence was fetched.
            for r in read_results:
                r.setdefault("hop", hop)
            accumulated_reads.extend(read_results)

            if not _any_ok(read_results) and not _any_ok(accumulated_reads):
                logger.info(
                    f"[DynamicJudge] Reread hop {hop} for component {comp.component_id}: "
                    "no readable files this hop and none accumulated; stopping"
                )
                self._record_history(
                    entry=entry,
                    prior=current_report,
                    new=current_report,
                    requested=new_requested,
                    read_log=read_results,
                    binary_short_circuit_path=None,
                    classifier=None,
                    hop=hop,
                )
                break

            payload = {
                "package_name": self._package_name,
                "entry_file": entry or "",
                "component_id": comp.component_id,
                "hop": hop,
                "max_hops": MAX_REREAD_HOPS,
                "remaining_hops": remaining_hops,
                "sliced_code": comp.code_slice.get("sliced_code", []),
                "file_io_records": file_io_records_serialised,
                "file_inspections": ctx.file_inspections,
                "prior_report": current_report,
                "read_files": accumulated_reads,
            }
            try:
                reread = llm_dynamic_reread(payload, context_summary=context_summary)
            except Exception as e:
                logger.warning(
                    f"[DynamicJudge] Reread LLM call failed at hop {hop} for component "
                    f"{comp.component_id}: {e}; keeping prior verdict"
                )
                reread = None

            logger.info(
                f"[DynamicJudge] Reread LLM raw output at hop {hop} for component "
                f"{comp.component_id}:\n"
                f"{json.dumps(reread, indent=2, ensure_ascii=False, default=str)}"
            )

            new_result = _reconcile_dynamic(
                current_report, reread, force_drop_files_to_read=(remaining_hops == 0)
            )
            self._record_history(
                entry=entry,
                prior=current_report,
                new=new_result,
                requested=new_requested,
                read_log=read_results,
                binary_short_circuit_path=None,
                classifier=None,
                hop=hop,
            )
            current_report = new_result

            if reread is None:
                break

        return _strip_files_to_read_dynamic(current_report)

    # ------------------------------------------------------------------
    # History recording
    # ------------------------------------------------------------------

    def _record_history(
        self,
        *,
        entry: str | None,
        prior: dict,
        new: dict,
        requested: list[str],
        read_log: list[dict],
        binary_short_circuit_path: str | None,
        classifier: str | None,
        hop: int | None = None,
    ) -> None:
        if self._detection_state is None:
            return

        prior_verdict = prior.get("judgement", "undetermined")
        new_verdict = new.get("judgement", prior_verdict)

        parts: list[str] = []
        if hop is not None:
            parts.append(f"hop {hop}/{MAX_REREAD_HOPS}")
        parts.append(f"requested={requested}")
        if binary_short_circuit_path is not None:
            parts.append(f"binary-short-circuit ({classifier}): {binary_short_circuit_path}")
            parts.append("no LLM call")
        else:
            status_counts = _status_counts(read_log)
            parts.append(
                "statuses=[" + ", ".join(f"{k}={v}" for k, v in sorted(status_counts.items())) + "]"
            )
        parts.append(f"verdict {prior_verdict} -> {new_verdict}")

        metadata: dict = {
            "candidate_paths": list(requested),
            "visited_files": [
                r.get("resolved_path") or r.get("path", "")
                for r in read_log
                if r.get("status") == "ok"
            ],
            "prior_judgement": prior_verdict,
            "new_judgement": new_verdict,
        }
        if hop is not None:
            metadata["hop"] = hop
            metadata["max_hops"] = MAX_REREAD_HOPS
        if binary_short_circuit_path is not None:
            metadata["binary_short_circuit_path"] = binary_short_circuit_path
            metadata["binary_classifier"] = classifier

        self._detection_state.add_step(
            AnalysisStep(
                stage="dynamic_local_read",
                entry=entry,
                result=_verdict_to_result_label(new_verdict),
                finding="; ".join(parts),
                metadata=metadata,
            )
        )


# ---------------------------------------------------------------------------
# Dynamic-schema helpers
# ---------------------------------------------------------------------------


def _strip_files_to_read_dynamic(report: dict) -> dict:
    """Drop the prompt-only ``files_to_read`` field from a dynamic report."""
    if not isinstance(report, dict) or "files_to_read" not in report:
        return report
    cleaned = dict(report)
    cleaned.pop("files_to_read", None)
    return cleaned


def _reconcile_dynamic(
    prior_result: dict,
    reread: dict | None,
    *,
    force_drop_files_to_read: bool = False,
) -> dict:
    """Overlay *reread* on top of *prior_result* using the dynamic verifier schema.

    The reread schema now mirrors the verifier schema (including
    ``files_to_read``) so multi-hop reread chains can keep iterating
    until the LLM stops requesting more files. Set
    ``force_drop_files_to_read=True`` to forcibly clear the field on
    the final hop, defending against an LLM that ignores the budget.
    """
    if not isinstance(reread, dict):
        return _strip_files_to_read_dynamic(prior_result)

    judgement = reread.get("judgement")
    if judgement not in {"benign", "malicious", "undetermined"}:
        judgement = prior_result.get("judgement", "undetermined")

    explanation = reread.get("explanation")
    if not isinstance(explanation, str) or not explanation.strip():
        explanation = prior_result.get("explanation", "")

    out: dict = {
        "judgement": judgement,
        "explanation": explanation,
    }

    if not force_drop_files_to_read:
        files = _coerce_paths(reread.get("files_to_read"))
        if files:
            out["files_to_read"] = files

    return out


def _binary_malicious_dynamic(rel_path: str) -> dict:
    return {
        "judgement": "malicious",
        "explanation": (
            f"Dynamic reread short-circuited to malicious: the slice hands "
            f"control to the native binary `{rel_path}` and source-based "
            "review cannot inspect compiled artefacts. Per the pipeline "
            "policy any package-bundled native binary execution is treated "
            "as malicious."
        ),
    }


def _log_reread_file_results_dynamic(component_id: int, read_log: list[dict]) -> None:
    """Log per-path resolve/read outcomes for the dynamic reread gate."""
    if not read_log:
        logger.info(f"[DynamicJudge] Reread file read results for component {component_id}: none")
        return
    entries: list[str] = []
    for r in read_log:
        path = r.get("path", "?")
        status = r.get("status", "unknown")
        resolved = r.get("resolved_path")
        if resolved and resolved != path:
            entry = f"{path} -> {resolved}: {status}"
        else:
            entry = f"{path}: {status}"
        note = r.get("note")
        if note:
            entry += f" ({note})"
        entries.append(entry)
    logger.info(
        f"[DynamicJudge] Reread file read results for component {component_id}: "
        + "; ".join(entries)
    )
