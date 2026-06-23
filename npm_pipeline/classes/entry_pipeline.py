"""EntryPipeline — per-entry orchestration of static / enrichment / dynamic phases.

Responsibility split:

- :class:`SliceBuilder` + :class:`SliceStore` — component slice build + persist
- :class:`StaticJudge` — static / enriched-static LLM judgement
- :class:`DynamicEvidenceCollector` + :class:`DynamicJudge` — dynamic single-pass
- :class:`RouteDecider` — post-static branch selection
- :class:`ThirdPartyEnricher` — npm metadata fetch and PDG node enrichment
- :class:`PBGProvider` (injected) — PBG construction and dynamic
  info generation (supplied by :class:`Package` so the orchestration layer
  stays independent of filesystem concerns)
"""

import json
import os
import traceback
from dataclasses import asdict
from typing import Protocol

from loguru import logger

from base_classes.pbg import PBG
from custom_exception import (
    DynamicCallGraphEmptyException,
    DynamicRunningException,
    JoernGenerationExceptionInDynamic,
)
from npm_pipeline.classes.analysis_context import AnalysisContext
from npm_pipeline.classes.detection_state import AnalysisStep, DetectionState
from npm_pipeline.classes.dynamic_evidence import DynamicEvidenceCollector
from npm_pipeline.classes.dynamic_judge import DynamicJudge
from npm_pipeline.classes.localization_store import LocalizationStore
from npm_pipeline.classes.malicious_localizer import MaliciousLocalizer
from npm_pipeline.classes.phase_result import PhaseResult
from npm_pipeline.classes.router import RouteDecider
from npm_pipeline.classes.slice_builder import SliceBuilder
from npm_pipeline.classes.slice_store import SliceStore
from npm_pipeline.classes.static_judge import StaticJudge
from npm_pipeline.classes.third_party_enricher import ThirdPartyEnricher
from npm_pipeline.types import (
    ClassifiedNodes,
    ComponentResult,
    Stage,
)
from npm_pipeline.utils.behavior_gen_utils import run_pending_behavior_generation
from npm_pipeline.utils.component_index import build_node_to_component_index
from npm_pipeline.utils.finding import (
    build_finding_summary,
    status_to_result_str,
)
from npm_pipeline.utils.synthesis import (
    classify_node_ids,
    classify_nodes_to_check,
    synthesize_component_results,
)
from status import STATUS_BENIGN, STATUS_CODE_MALICIOUS

MAX_STATIC_FALLBACK_ENTRIES = 5


class PBGProvider(Protocol):
    """Adapter the EntryPipeline depends on to build / persist PBG artifacts.

    Implemented by :class:`Package`, which owns the filesystem-heavy
    concerns (joern / jelly) that the orchestration layer
    deliberately stays out of.
    """

    def generate_program_behavior(self, entry: str, stage: Stage) -> "PBG | None": ...

    def generate_dynamic_info(self, entry: str) -> None: ...

    def reset_pdg_nodes_for_new_entry(self) -> None: ...

    def static_fallback_for_entry(self, entry: str) -> "int | str | None": ...


class EntryPipeline:
    """Orchestrate the static -> enrichment/dynamic pipeline for one entry at a time.

    The same instance is reused across all entries of a package; the
    per-entry static cache is keyed by the entry path, mirroring the
    pre-refactor ``ComponentInterpreter._last_static_component_results``.
    """

    def __init__(
        self,
        *,
        package_name: str,
        slice_builder: SliceBuilder,
        slice_store: SliceStore,
        static_judge: StaticJudge,
        dynamic_judge: DynamicJudge,
        evidence_collector: DynamicEvidenceCollector,
        router: RouteDecider,
        third_party_enricher: ThirdPartyEnricher,
        detection_state: DetectionState,
        analysis_context: AnalysisContext,
        pbg_provider: PBGProvider,
        enable_orphan_recovery: bool,
        parallel_workers: int,
        localizer: MaliciousLocalizer,
        localization_store: LocalizationStore,
    ):
        self._package_name = package_name
        self._slice_builder = slice_builder
        self._slice_store = slice_store
        self._static_judge = static_judge
        self._dynamic_judge = dynamic_judge
        self._evidence_collector = evidence_collector
        self._router = router
        self._third_party_enricher = third_party_enricher
        self._detection_state = detection_state
        self._analysis_context = analysis_context
        self._pbg_provider = pbg_provider
        self._enable_orphan_recovery = enable_orphan_recovery
        self._parallel_workers = parallel_workers
        self._localizer = localizer
        self._localization_store = localization_store

        self._static_cache: dict[str, list[ComponentResult]] = {}

        # Number of entries that have already triggered the LLM static
        # fallback in this package. Bounded by MAX_STATIC_FALLBACK_ENTRIES.
        self._static_fallback_count = 0

    # ------------------------------------------------------------------
    # Top-level per-entry flow
    # ------------------------------------------------------------------

    def run(self, entry: str, dynamic_support: bool) -> int | str:
        """Run the full analysis pipeline for a single entry script.

        After static analysis yields an *undetermined* verdict the
        pipeline picks exactly one follow-up branch:

        - ``try_enrichment`` -> run enrichment + cross-component
          synthesis. If terminal (benign / malicious), stop there.
          If still undetermined, fall through to dynamic (or benign
          when ``dynamic_support`` is disabled).
        - ``try_dynamic``    -> skip enrichment and run dynamic
          directly.

        The router LLM is only consulted when both branches are
        feasible; otherwise we short-circuit on deterministic rules.
        """
        static_result = self._run_static(entry)
        if static_result.is_terminal():
            if static_result.status == STATUS_CODE_MALICIOUS:
                self._localize_malicious(
                    entry,
                    "static",
                    components=static_result.component_results,
                    final_result=static_result.final_result,
                )
            return static_result.status

        has_third_party = bool(static_result.classified.third_party)

        if not has_third_party:
            if dynamic_support:
                logger.info(
                    "[Router] No third-party nodes after static; "
                    "skipping router and going straight to dynamic"
                )
                self._detection_state.set_last_next_step_reason(
                    "no third-party nodes; enrichment inapplicable, running dynamic"
                )
                return self._run_dynamic(entry, static_result.classified)
            logger.info(
                "[Router] No third-party nodes and dynamic_support disabled; treating as benign"
            )
            return STATUS_BENIGN

        if not dynamic_support:
            logger.info(
                "[Router] dynamic_support disabled; forcing try_enrichment "
                "(only feasible branch with third-party nodes present)"
            )
            self._detection_state.set_last_next_step_reason(
                "dynamic disabled; forcing enrichment branch"
            )
            action = "try_enrichment"
        else:
            action = self._router.decide(static_result, entry)

        if action == "try_enrichment":
            enrichment_result = self._run_enrichment(entry, static_result)
            if enrichment_result.is_terminal():
                if enrichment_result.status == STATUS_CODE_MALICIOUS:
                    self._localize_malicious(
                        entry,
                        "enrichment",
                        components=enrichment_result.component_results,
                        final_result=enrichment_result.final_result,
                    )
                return enrichment_result.status

            if dynamic_support:
                logger.info(
                    "[Router] Enrichment returned undetermined; "
                    "falling through to dynamic without a second router call"
                )
                return self._run_dynamic(entry, enrichment_result.classified)
            logger.info(
                "[Router] Enrichment undetermined but dynamic_support disabled; treating as benign"
            )
            return STATUS_BENIGN

        return self._run_dynamic(entry, static_result.classified)

    # ------------------------------------------------------------------
    # Static phase
    # ------------------------------------------------------------------

    def _run_static(self, entry: str) -> PhaseResult:
        self._pbg_provider.reset_pdg_nodes_for_new_entry()
        self._analysis_context.global_visited.clear()
        self._analysis_context.loaded_history.clear()
        self._analysis_context.third_party_module_name.clear()
        self._analysis_context.static_third_party_visited_nodes.clear()

        static_pbg = self._pbg_provider.generate_program_behavior(entry, "static")
        if not static_pbg:
            logger.info(f"No program behavior generated for {entry}")
            if self._static_fallback_count >= MAX_STATIC_FALLBACK_ENTRIES:
                logger.info(
                    f"[Fallback] Static fallback cap "
                    f"({MAX_STATIC_FALLBACK_ENTRIES}) reached for "
                    f"{self._package_name}; skipping fallback for {entry} "
                    f"and treating as benign"
                )
                return PhaseResult(status=STATUS_BENIGN)
            self._static_fallback_count += 1
            logger.info(
                f"[Fallback] Invoking static fallback for {entry} "
                f"({self._static_fallback_count}/{MAX_STATIC_FALLBACK_ENTRIES})"
            )
            fallback_status = self._pbg_provider.static_fallback_for_entry(entry)
            if fallback_status is not None:
                return PhaseResult(status=fallback_status)
            return PhaseResult(status=STATUS_BENIGN)

        context_summary = self._detection_state.to_entry_context_summary(entry)
        components = self._slice_builder.build(
            static_pbg, "static", self._analysis_context.current_code_info.files
        )
        self._slice_store.persist_all(components, "static")

        component_results = self._static_judge.interpret(
            components, context_summary=context_summary, entry=entry
        )
        self._static_cache[entry] = component_results

        outcome = synthesize_component_results(component_results)
        classified = self._classify_after(outcome, component_results, static_pbg)

        finding = build_finding_summary(outcome.final_result, classified)
        self._detection_state.add_step(
            AnalysisStep(
                stage="static",
                entry=entry,
                result=status_to_result_str(outcome.status),
                finding=finding,
            )
        )

        return PhaseResult(
            status=outcome.status,
            classified=classified,
            pbg=static_pbg,
            finding=finding,
            component_results=component_results,
            final_result=outcome.final_result,
        )

    # ------------------------------------------------------------------
    # Third-party enrichment phase
    # ------------------------------------------------------------------

    def _run_enrichment(self, entry: str, static_result: PhaseResult) -> PhaseResult:
        static_pbg = static_result.pbg
        classified = static_result.classified
        third_party_node_ids = classified.third_party

        needed_modules = ThirdPartyEnricher.extract_needed_modules(static_pbg, third_party_node_ids)
        if not needed_modules:
            return PhaseResult(
                status="undetermined",
                classified=classified,
                pbg=static_pbg,
                enrichment_info={
                    "fully_enriched": set(),
                    "module_only": set(),
                    "api_only": set(),
                    "not_enriched": set(),
                },
                finding=static_result.finding,
                component_results=static_result.component_results,
                final_result=static_result.final_result,
            )

        self._detection_state.set_last_next_step_reason(
            f"undetermined due to third-party nodes: {needed_modules}"
        )
        logger.info(
            f"[Enrichment] Entry {entry}: fetching metadata for "
            f"modules referenced by third-party nodes: {needed_modules}"
        )
        metadata_cache = self._third_party_enricher.fetch(needed_modules)

        context_summary = self._detection_state.to_entry_context_summary(entry)

        logger.info(f"[Enrichment] Running enriched static analysis for {entry}")
        enrichment_info = self._third_party_enricher.enrich_nodes(
            static_pbg, metadata_cache, third_party_node_ids
        )

        # Rebuild slices against the now-enriched PBG; only the components
        # actually touching an enriched third-party node get their
        # updated slice persisted and re-interpreted, mirroring the
        # pre-refactor selective-persist / selective-LLM behaviour.
        components = self._slice_builder.build(
            static_pbg, "static", self._analysis_context.current_code_info.files
        )
        affected_cids = self._affected_component_ids(components, third_party_node_ids)
        logger.info(
            f"[Enrichment] Affected components: {sorted(affected_cids)} / "
            f"total {len(components)} (entry={entry or '?'})"
        )
        affected_components = [c for c in components if c.component_id in affected_cids]
        self._slice_store.persist_all(affected_components, "static")

        enriched_components = self._static_judge.interpret_enriched(
            components,
            affected_cids,
            self._static_cache.get(entry, []),
            context_summary=context_summary,
            entry=entry,
        )

        outcome = synthesize_component_results(enriched_components)
        outcome_json = json.dumps(
            asdict(outcome),
            indent=2,
            ensure_ascii=False,
            default=str,
        )
        logger.info(f"[Enrichment] Entry {entry}: enriched_synthesis=\n{outcome_json}")

        if outcome.status == "undetermined":
            classified = self._classify_after(outcome, enriched_components, static_pbg)

        enrichment_meta = ThirdPartyEnricher.summarize(enrichment_info, needed_modules)
        enriched_finding = build_finding_summary(outcome.final_result, classified)
        finding = f"{enrichment_meta} | {enriched_finding}" if enriched_finding else enrichment_meta

        self._detection_state.add_step(
            AnalysisStep(
                stage="third_party_info_enrichment",
                entry=entry,
                result=status_to_result_str(outcome.status),
                finding=finding,
            )
        )

        return PhaseResult(
            status=outcome.status,
            classified=classified,
            pbg=static_pbg,
            enrichment_info=enrichment_info,
            finding=finding,
            component_results=enriched_components,
            final_result=outcome.final_result,
        )

    # ------------------------------------------------------------------
    # Dynamic phase
    # ------------------------------------------------------------------

    def _run_dynamic(self, entry: str, classified: ClassifiedNodes) -> int | str:
        self._detection_state.set_last_next_step_reason(
            "still undetermined after static/enrichment analysis"
        )
        logger.info(
            f"[Dynamic] Entry {entry} remaining nodes — "
            f"conditional: {classified.conditional}, "
            f"third_party: {classified.third_party}, "
            f"unresolved: {classified.unresolved}"
        )

        self._seed_dynamic_context(classified)
        try:
            dynamic_pbg = self._prepare_dynamic_pbg(entry)
            if dynamic_pbg is None:
                return STATUS_BENIGN
            return self._judge_dynamic(entry, dynamic_pbg)
        except DynamicRunningException as e:
            logger.warning(f"Dynamic Analysis Failed: {e}")
        except JoernGenerationExceptionInDynamic as e:
            logger.warning(f"Joern Generation Failed in Dynamic: {e}")
        except DynamicCallGraphEmptyException:
            logger.info("Dynamic Call Graph Generation Failed")
        except Exception as e:
            logger.warning(f"Exception caught in dynamic analysis: {e}")
            logger.warning("Execution trace:\n" + traceback.format_exc())
        return STATUS_BENIGN

    def _seed_dynamic_context(self, classified: ClassifiedNodes) -> None:
        self._analysis_context.clear()
        self._analysis_context.conditional_node.update(classified.conditional)
        self._analysis_context.third_party_node.update(classified.third_party)
        self._analysis_context.unresolved_node.update(classified.unresolved)

    def _prepare_dynamic_pbg(self, entry: str) -> "PBG | None":
        """Generate dynamic info, build PBG, run async-aware Phase B.

        Dynamic-specific exceptions propagate to :meth:`_run_dynamic`
        where they are centrally handled with the original log messages.
        Phase B here refers to the behavior-generation pipeline
        (orphan recovery + parallel LLM interpretation), not the
        removed dynamic-judgement phase2.
        """
        normalized_path = os.path.normpath(entry)
        self._analysis_context.file_in_cg.add(os.path.join("package", normalized_path))
        self._pbg_provider.generate_dynamic_info(entry)
        dynamic_pbg = self._pbg_provider.generate_program_behavior(entry, "dynamic")
        if dynamic_pbg is None:
            return None

        # Phase B of the async-aware behavior pipeline: run global
        # orphan recovery, deduped parallel LLM interpretation, and
        # stitch results back onto the PDG.
        run_pending_behavior_generation(
            self._analysis_context,
            enable_orphan_recovery=self._enable_orphan_recovery,
            parallel_workers=self._parallel_workers,
        )
        return dynamic_pbg

    def _judge_dynamic(self, entry: str, dynamic_pbg: "PBG") -> int | str:
        """Single-pass dynamic judgment + synthesis + history step.

        File-content summaries are pre-computed by
        :class:`DynamicEvidenceCollector`, so the dynamic LLM sees all
        the evidence it needs in one shot.
        """
        context_summary = self._detection_state.to_entry_context_summary(entry)

        components = self._slice_builder.build(
            dynamic_pbg,
            "dynamic",
            self._analysis_context.current_code_info.files,
            self._analysis_context,
        )
        self._slice_store.persist_all(components, "dynamic")
        ctx = self._evidence_collector.collect(dynamic_pbg)

        results = self._dynamic_judge.judge(
            components, ctx, context_summary=context_summary, entry=entry
        )
        outcome = synthesize_component_results(results)
        logger.info(f"[Dynamic] Synthesis for {entry}: {outcome.status}")

        self._detection_state.add_step(
            AnalysisStep(
                stage="dynamic",
                entry=entry,
                result=status_to_result_str(outcome.status),
                finding=build_finding_summary(outcome.final_result),
            )
        )

        if outcome.status == "undetermined":
            return STATUS_BENIGN
        if outcome.status == STATUS_CODE_MALICIOUS:
            self._localize_malicious(
                entry,
                "dynamic",
                components=results,
                final_result=outcome.final_result,
            )
        return outcome.status

    # ------------------------------------------------------------------
    # Malicious-code localization
    # ------------------------------------------------------------------

    def _localize_malicious(
        self,
        entry: str,
        stage: str,
        *,
        components: list[ComponentResult],
        final_result: dict,
    ) -> None:
        """Run the malicious-code localizer for *entry* and persist its output.

        Failure here must never alter the upstream verdict — we wrap
        the whole call in a broad except and only log.
        """
        try:
            context_summary = self._detection_state.to_entry_context_summary(entry)
            payload = self._localizer.localize(
                package_name=self._package_name,
                entry=entry,
                components=components,
                final_result=final_result or {},
                context_summary=context_summary,
            )
            self._localization_store.persist(entry=entry, payload=payload)
        except Exception as e:
            logger.warning(
                f"[Localization] {entry} stage={stage} failed: {e}\n" + traceback.format_exc()
            )

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _classify_after(
        outcome,
        component_results: list[ComponentResult],
        pbg: "PBG",
    ) -> ClassifiedNodes:
        """Choose classification source: cross-component nodes if present,
        otherwise the union of per-component ``node_to_be_checked``.
        """
        if outcome.cross_nodes:
            return classify_node_ids(outcome.cross_nodes, pbg)
        return classify_nodes_to_check(component_results, pbg)

    @staticmethod
    def _affected_component_ids(
        components: list[ComponentResult], third_party_node_ids: list[int]
    ) -> set[int]:
        """Components whose slice mentions any of *third_party_node_ids*."""
        node_to_comp = build_node_to_component_index(components)
        return {node_to_comp[nid] for nid in third_party_node_ids if nid in node_to_comp}
