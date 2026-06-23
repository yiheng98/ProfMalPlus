"""Routing agent for the per-entry analysis pipeline."""

from loguru import logger

from llm import llm_route_decision
from npm_pipeline.classes.detection_state import DetectionState
from npm_pipeline.classes.phase_result import PhaseResult
from npm_pipeline.types import ComponentResult
from npm_pipeline.utils.component_index import build_node_to_component_index

# Cap on flagged-node details passed to the router prompt (prevents
# blowing up tokens on pathologically noisy packages).
MAX_ROUTER_FLAGGED_NODES: int = 10

# Priority order used when truncating flagged nodes for the router
# prompt. Third-party nodes come first because their full context
# (``module`` / ``property_method`` / ``source``) is the decisive
# signal for whether enrichment can help; conditional / unresolved
# nodes are individually less informative and their counts are
# already summarised in ``classified_nodes``.
FLAGGED_BUCKET_PRIORITY: tuple = ("third_party", "conditional", "unresolved")

VALID_ACTIONS: frozenset = frozenset({"try_enrichment", "try_dynamic"})

FALLBACK_ACTION: str = "try_enrichment"


class RouteDecider:
    """Encapsulates the single router-agent call between static and follow-up phases."""

    def __init__(
        self,
        detection_state: DetectionState,
        *,
        max_flagged_nodes: int = MAX_ROUTER_FLAGGED_NODES,
    ):
        self._detection_state = detection_state
        self._max_flagged_nodes = max_flagged_nodes

    def decide(self, result: PhaseResult, entry: str) -> str:
        """Routing agent — pick between ``try_enrichment`` and ``try_dynamic``.

        Called once, immediately after static analysis, and only when
        both branches are genuinely available (third-party nodes exist
        *and* dynamic execution is allowed — the caller enforces these
        preconditions so the LLM never has to). The router sees only
        static-phase artifacts — classification counts, prior analysis
        narrative, and the key code slices around the still-suspicious
        nodes — so it can answer the single question:

            *"Would knowing the npm metadata of these third-party
            modules be enough to explain the behavior of this code?"*

        Falls back to ``try_enrichment`` when the LLM is unavailable or
        returns an invalid action, because enrichment is the cheaper of
        the two and still auto-falls through to dynamic if it stays
        undetermined.
        """
        route_ctx = {
            "classified_nodes": {
                "conditional": len(result.classified.conditional),
                "third_party": len(result.classified.third_party),
                "unresolved": len(result.classified.unresolved),
            },
            "prior_analysis": self._summarize_prior_analysis(result),
            "flagged_nodes": self._build_flagged_node_details(
                result, limit=self._max_flagged_nodes
            ),
        }

        context_summary = self._detection_state.to_entry_context_summary(entry)
        decision = llm_route_decision(route_ctx, context_summary=context_summary)
        action = (decision or {}).get("next_action")
        reason = (decision or {}).get("reason", "")

        if action in VALID_ACTIONS:
            logger.info(f"[Router] LLM decision: {action} (reason: {reason})")
            self._detection_state.set_last_next_step_reason(
                f"router chose {action}: {reason}" if reason else f"router chose {action}"
            )
            return action

        logger.warning(
            f"[Router] LLM returned invalid action {action!r}; falling back to {FALLBACK_ACTION}"
        )
        self._detection_state.set_last_next_step_reason(f"router fallback: {FALLBACK_ACTION}")
        return FALLBACK_ACTION

    @staticmethod
    def _summarize_prior_analysis(result: PhaseResult) -> dict:
        """Extract verifier / synthesis signals from the most recent phase.

        Surfaces the free-text reason, bullet-style key evidence, and any
        cross-component patterns so the routing LLM can see *why* the
        phase was undetermined rather than just node-count buckets.
        Per-component individual verdicts are summarised as ``component_id
        → judgement`` so cross-component disagreements are visible.
        """
        final = result.final_result or {}
        key_evidence = [
            ev.get("claim", "") for ev in final.get("key_evidence", []) if ev.get("claim")
        ]
        cross_patterns = [
            ce.get("pattern", "")
            for ce in final.get("cross_component_evidence", [])
            if ce.get("pattern")
        ]
        per_component: list[dict] = []
        for cr in result.component_results or []:
            cr_result = cr.result or {}
            per_component.append(
                {
                    "component_id": cr.component_id,
                    "judgement": cr_result.get("judgement", "unknown"),
                    "explanation": cr_result.get("explanation", "") or cr_result.get("reason", ""),
                }
            )

        return {
            "reason": final.get("reason", "") or final.get("explanation", ""),
            "key_evidence": key_evidence,
            "cross_component_patterns": cross_patterns,
            "component_verdicts": per_component,
        }

    @staticmethod
    def _build_flagged_node_details(result: PhaseResult, *, limit: int) -> list[dict]:
        """Produce a list of structured node descriptions for the router.

        For each still-suspicious PDG node, collects:

        - ``node_id``, ``call_type`` (``conditional`` / ``third_party`` /
          ``unresolved``).
        - ``module`` / ``property_method`` — the third-party call this
          node corresponds to (third-party nodes only); lets the router
          judge whether npm metadata would be informative.
        - ``source`` — the component's per-file code slice plus the
          ``[Node ID: N]`` ``callee_info`` annotation lines so the
          router sees exactly what the interpreter saw (this already
          contains the line surrounding the node).

        Results are capped at *limit* entries to keep prompt size
        bounded. Third-party nodes are always filled first; if anything is dropped, a
        trailing ``{"_truncated": N, "_truncated_by_bucket": {...}}``
        entry tells the router which call types lost detail.
        """
        pbg = result.pbg
        classified = result.classified
        ordered_ids: list[tuple[int, str]] = []
        for bucket in FLAGGED_BUCKET_PRIORITY:
            for nid in getattr(classified, bucket):
                ordered_ids.append((nid, bucket))
        if not ordered_ids or pbg is None:
            return []

        component_results = result.component_results or []
        node_to_comp = build_node_to_component_index(component_results)
        comp_by_id: dict[int, ComponentResult] = {cr.component_id: cr for cr in component_results}

        pdg_nodes = pbg.get_pdg_nodes()
        details: list[dict] = []
        kept_by_bucket: dict[str, int] = {b: 0 for b in FLAGGED_BUCKET_PRIORITY}
        for node_id, bucket in ordered_ids[:limit]:
            entry: dict = {"node_id": node_id, "call_type": bucket}
            pdg_node = pdg_nodes.get(node_id)
            if pdg_node is not None:
                tpc = pdg_node.get_third_party_call_dict()
                if tpc:
                    entry["module"] = tpc.get("module", "")
                    entry["property_method"] = tpc.get("property_method", "")

            cid = node_to_comp.get(node_id)
            if cid is not None:
                entry["component_id"] = cid
                comp = comp_by_id.get(cid)
                if comp is not None:
                    entry["source"] = RouteDecider._extract_node_source(comp.code_slice, node_id)

            details.append(entry)
            kept_by_bucket[bucket] = kept_by_bucket.get(bucket, 0) + 1

        if len(ordered_ids) > limit:
            truncated_by_bucket: dict[str, int] = {}
            for bucket in FLAGGED_BUCKET_PRIORITY:
                total = len(getattr(classified, bucket))
                dropped = total - kept_by_bucket.get(bucket, 0)
                if dropped > 0:
                    truncated_by_bucket[bucket] = dropped
            details.append(
                {
                    "_truncated": len(ordered_ids) - limit,
                    "_truncated_by_bucket": truncated_by_bucket,
                }
            )
        return details

    @staticmethod
    def _extract_node_source(code_slice: dict, node_id: int) -> dict:
        """Pull the component slice (per-file snippet + matching callee_info lines)
        surrounding *node_id*.

        Keeps only ``callee_info`` entries that explicitly reference
        ``[Node ID: <node_id>]`` to avoid shipping unrelated annotations.
        """
        needle = f"[Node ID: {node_id}]"
        files_out: list[dict] = []
        for file_entry in code_slice.get("sliced_code", []):
            for fname, fdata in file_entry.items():
                code_snippet = fdata.get("code_snippet", [])
                callee_info = [info for info in fdata.get("callee_info", []) if needle in str(info)]
                files_out.append(
                    {
                        "file": fname,
                        "code_snippet": code_snippet,
                        "relevant_callee_info": callee_info,
                    }
                )
        return {"files": files_out}
