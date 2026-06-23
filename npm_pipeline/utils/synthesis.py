"""Cross-component synthesis and node classification utilities."""

from loguru import logger

from base_classes.pbg import PBG
from call_type_dict import CONDITIONAL_CALL, THIRD_PARTY_CALL, UNRESOLVED_CALL
from code_interpreter import synthesize_cross_component_evidence
from npm_pipeline.types import ClassifiedNodes, ComponentResult, SynthesisOutcome
from status import STATUS_BENIGN, STATUS_CODE_MALICIOUS


def _judgement_to_status(judgement: str) -> int | str:
    """Map an LLM judgement string to the pipeline status code."""
    if judgement == "malicious":
        return STATUS_CODE_MALICIOUS
    if judgement == "undetermined":
        return "undetermined"
    return STATUS_BENIGN


def _judgement_of(cr: ComponentResult) -> str:
    return cr.result.get("judgement", "benign")


def _rule_based_synthesis(component_results: list[ComponentResult]) -> int | str:
    """Fallback rule-based aggregation when the LLM synthesis is unavailable."""
    judgements = [_judgement_of(cr) for cr in component_results]
    if any(j == "malicious" for j in judgements):
        return STATUS_CODE_MALICIOUS
    if all(j == "benign" for j in judgements):
        return STATUS_BENIGN
    if any(j == "undetermined" for j in judgements):
        return "undetermined"
    return STATUS_BENIGN


def _normalize_node_ids(raw: list) -> list[int]:
    """Coerce LLM-returned node IDs (may be str or float) to int."""
    result: list[int] = []
    for n in raw:
        if isinstance(n, int):
            result.append(n)
        elif isinstance(n, float):
            result.append(int(n))
        elif isinstance(n, str) and n.strip().isdigit():
            result.append(int(n.strip()))
    return result


def evaluate_syntheses(syntheses: list) -> int | str:
    """Determine final verdict from a list of per-entry synthesis values."""
    if any(s == STATUS_CODE_MALICIOUS for s in syntheses):
        return STATUS_CODE_MALICIOUS
    if all(s == STATUS_BENIGN for s in syntheses):
        return STATUS_BENIGN
    if any(s == "undetermined" for s in syntheses):
        return "undetermined"
    return STATUS_BENIGN


def _build_synthesis_input(sorted_components: list[ComponentResult]) -> list[dict]:
    """Flatten sorted components into the LLM cross-synthesis input payload."""
    return [
        {
            "component_id": comp.component_id,
            "cfg_order": comp.cfg_order,
            "code_slice": comp.code_slice,
            "individual_result": comp.result,
        }
        for comp in sorted_components
    ]


def _build_ordering_edges(sorted_components: list[ComponentResult]) -> list[dict]:
    """Emit ``{from, to}`` edges from each component's successor list."""
    edges: list[dict] = []
    for comp in sorted_components:
        for succ in comp.successors:
            edges.append({"from": comp.component_id, "to": succ})
    return edges


def _single_component_outcome(cr: ComponentResult) -> SynthesisOutcome:
    """Shortcut for the single-component case: use the component's own verdict."""
    judgement = _judgement_of(cr)
    status = _judgement_to_status(judgement)
    logger.info(
        f"[Synthesis] Single component shortcut: component_id={cr.component_id}, "
        f"judgement={judgement}, status={status}"
    )
    return SynthesisOutcome(status=status, cross_nodes=[], final_result=cr.result)


def _log_cross_component_result(
    cross_result: dict, cross_nodes: list[int], raw_nodes: list
) -> None:
    judgement = cross_result.get("judgement", "benign")
    status = _judgement_to_status(judgement)
    explanation = cross_result.get("explanation", "")
    evidence = cross_result.get("cross_component_evidence", [])
    logger.info(
        f"[Cross-Component] LLM synthesis finished: judgement={judgement}, "
        f"status={status}, node_to_be_checked(raw={len(raw_nodes)}, "
        f"normalized={len(cross_nodes)})"
    )
    logger.info(f"[Cross-Component] explanation: {explanation}")
    logger.info(f"[Cross-Component] cross_component_evidence ({len(evidence)} item(s)):")
    for idx, item in enumerate(evidence):
        pattern = item.get("pattern", "")
        involved = item.get("involved_components", [])
        description = item.get("description", "")
        logger.info(
            f"  - [{idx}] pattern={pattern}, involved_components={involved}, "
            f"description={description}"
        )
    logger.info(f"[Cross-Component] node_to_be_checked(raw)={raw_nodes}")


def synthesize_component_results(
    component_results: list[ComponentResult],
) -> SynthesisOutcome:
    """Aggregate per-component results into a final judgement.

    Uses LLM cross-component synthesis when there are 2+ components;
    short-circuits on a single component; falls back to rule-based
    aggregation when the LLM is unavailable.
    """
    if not component_results:
        logger.info("No code slice found, skip the interpretation")
        return SynthesisOutcome(status=STATUS_BENIGN)

    logger.info(f"[Synthesis] Start aggregating results from {len(component_results)} component(s)")

    if len(component_results) == 1:
        return _single_component_outcome(component_results[0])

    sorted_components = sorted(component_results, key=lambda c: c.cfg_order)
    sorted_summary = [(c.component_id, c.cfg_order) for c in sorted_components]
    logger.debug(f"[Synthesis] Sorted components by cfg_order: {sorted_summary}")

    synthesis_input = _build_synthesis_input(sorted_components)
    individual_judgements = [(c.component_id, _judgement_of(c)) for c in sorted_components]
    logger.info(f"[Synthesis] Individual judgements per component: {individual_judgements}")

    ordering_edges = _build_ordering_edges(sorted_components)

    logger.info(f"[Cross-Component] Invoking LLM synthesis with {len(synthesis_input)}")
    cross_result = synthesize_cross_component_evidence(synthesis_input, ordering_edges)

    if cross_result:
        raw_nodes = cross_result.get("node_to_be_checked", [])
        cross_nodes = _normalize_node_ids(raw_nodes)
        _log_cross_component_result(cross_result, cross_nodes, raw_nodes)
        status = _judgement_to_status(cross_result.get("judgement", "benign"))
        return SynthesisOutcome(status=status, cross_nodes=cross_nodes, final_result=cross_result)

    logger.warning(
        "[Cross-Component] LLM synthesis returned None, falling back to rule-based aggregation"
    )
    fallback_status = _rule_based_synthesis(component_results)
    logger.info(f"[Synthesis] Rule-based fallback status={fallback_status}")
    return SynthesisOutcome(status=fallback_status)


def classify_node_ids(node_ids: list[int], program_behavior: PBG) -> ClassifiedNodes:
    """Classify a flat list of node IDs by call type."""
    classified = ClassifiedNodes()
    pdg_nodes = program_behavior.get_pdg_nodes()
    for node_id in node_ids:
        pdg_node = pdg_nodes.get(node_id)
        if pdg_node is None:
            continue
        call_type = pdg_node.get_call_type()
        if call_type == CONDITIONAL_CALL:
            classified.conditional.append(node_id)
        elif call_type == THIRD_PARTY_CALL:
            classified.third_party.append(node_id)
        elif call_type == UNRESOLVED_CALL:
            classified.unresolved.append(node_id)
    return classified


def classify_nodes_to_check(
    component_results: list[ComponentResult], program_behavior: PBG
) -> ClassifiedNodes:
    """Collect node_to_be_checked from all per-component results and classify."""
    all_node_ids: list[int] = []
    for cr in component_results:
        all_node_ids.extend(cr.result.get("node_to_be_checked", []))
    return classify_node_ids(all_node_ids, program_behavior)
