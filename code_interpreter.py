import asyncio
import json
from concurrent.futures import ThreadPoolExecutor
from functools import partial

from loguru import logger

from llm import (
    llm_generate_static_stage_report,
    llm_synthesize_cross_component,
    llm_validate_static_stage_report,
)


def _fmt_json(obj) -> str:
    if obj is None:
        return "None"
    try:
        return json.dumps(obj, ensure_ascii=False, indent=2)
    except (TypeError, ValueError):
        return str(obj)


_DYNAMIC_CHECKABLE_TYPES = {"conditional_api", "third_party", "unresolved"}


def _sanitize_verifier_report(report: dict | None) -> dict | None:
    """Drop ``node_to_be_checked`` entries whose ``key_evidence`` node_type is
    not one of ``conditional_api`` / ``third_party`` / ``unresolved``.

    The verifier prompt forbids fully-resolved types (``sensitive_api``,
    ``sensitive_property``, ``third_party_with_metadata``) from appearing in
    ``node_to_be_checked``, but the LLM occasionally violates this. We
    enforce it here so logs and downstream consumers see a consistent
    report.
    """
    if not isinstance(report, dict):
        return report

    raw_nodes = report.get("node_to_be_checked")
    if not isinstance(raw_nodes, list) or not raw_nodes:
        return report

    type_by_id: dict[int, str] = {}
    for ev in report.get("key_evidence", []) or []:
        if not isinstance(ev, dict):
            continue
        nid = ev.get("node_id")
        ntype = ev.get("node_type")
        if isinstance(nid, (int, float)) and isinstance(ntype, str):
            type_by_id[int(nid)] = ntype

    kept: list = []
    dropped: list[tuple] = []
    for nid in raw_nodes:
        try:
            nid_int = int(nid)
        except (TypeError, ValueError):
            kept.append(nid)
            continue
        ntype = type_by_id.get(nid_int)
        if ntype is None or ntype in _DYNAMIC_CHECKABLE_TYPES:
            kept.append(nid)
        else:
            dropped.append((nid_int, ntype))

    if not dropped:
        return report

    logger.info(
        f"[Verifier] Sanitized node_to_be_checked: dropped {len(dropped)} entry(ies) "
        f"with disallowed node_type {dropped}"
    )
    report["node_to_be_checked"] = kept
    if report.get("judgement") == "undetermined" and not kept:
        logger.info(
            "[Verifier] node_to_be_checked became empty after sanitization; "
            "downgrading judgement 'undetermined' -> 'benign'"
        )
        report["judgement"] = "benign"
    return report


def interpret_static_evidence(
    sliced_code: dict,
    *,
    context_summary: str = "",
    enriched: bool = False,
) -> dict | None:
    """Run the 3x-generate + verify pipeline on *sliced_code*.

    Both the bare and the enriched static passes use the same prompts —
    the prompts detect which pass is active by inspecting the slice for
    type (f) annotations. ``enriched`` here only adjusts log labels so
    the two passes remain distinguishable in the workflow log.
    """
    log_prefix = "[Enriched] " if enriched else ""

    report_list = _generate_initial_reports(
        sliced_code, context_summary=context_summary, enriched=enriched
    )
    valid_report_list = [report for report in report_list if report is not None]
    for report in report_list:
        logger.info(f"{log_prefix}The static stage report is: {_fmt_json(report)}")
    if not valid_report_list:
        return None

    verified_report = _verify_initial_reports(sliced_code, valid_report_list, enriched=enriched)
    verified_report = _sanitize_verifier_report(verified_report)
    logger.info(f"{log_prefix}The verified report is: {_fmt_json(verified_report)}")
    return verified_report if verified_report else None


def _generate_initial_reports(
    sliced_code: dict, *, context_summary: str = "", enriched: bool = False
):
    return asyncio.run(
        _generate_initial_reports_async(
            sliced_code, context_summary=context_summary, enriched=enriched
        )
    )


async def _generate_initial_reports_async(
    sliced_code: dict, *, context_summary: str = "", enriched: bool = False
):
    loop = asyncio.get_event_loop()
    fn = partial(
        llm_generate_static_stage_report,
        sliced_code,
        context_summary=context_summary,
        enriched=enriched,
    )
    with ThreadPoolExecutor(max_workers=3) as executor:
        tasks = [loop.run_in_executor(executor, fn) for _ in range(3)]
        results = await asyncio.gather(*tasks)
    return list(results)


def _verify_initial_reports(sliced_code: dict, report_list: list, *, enriched: bool = False):
    return llm_validate_static_stage_report(sliced_code, report_list, enriched=enriched)


# ---------------------------------------------------------------------------
# Cross-component synthesis
# ---------------------------------------------------------------------------


def synthesize_cross_component_evidence(
    components_with_results: list[dict],
    ordering_edges: list[dict],
) -> dict | None:
    """Perform LLM-powered cross-component synthesis.

    Each element of *components_with_results* should carry
    ``component_id``, ``cfg_order``, ``code_slice`` and
    ``individual_result`` (the per-component LLM judgement).

    Returns the holistic judgement dict or ``None`` on failure.
    """
    result = llm_synthesize_cross_component(components_with_results, ordering_edges)
    if result:
        logger.info(f"[Cross-Component] Synthesis result: {_fmt_json(result)}")
    return result
