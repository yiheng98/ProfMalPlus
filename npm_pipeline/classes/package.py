import os
import sys
import traceback

from loguru import logger

import dynamic_helper
import static_helper
from base_classes.pbg import PBG
from npm_pipeline.classes.analysis_context import AnalysisContext
from npm_pipeline.classes.code_Info import CodeInfo
from npm_pipeline.classes.dependency_tree import DependencyTree
from npm_pipeline.classes.detection_state import DetectionState
from npm_pipeline.classes.dynamic_evidence import DynamicEvidenceCollector
from npm_pipeline.classes.dynamic_judge import DynamicJudge
from npm_pipeline.classes.entry_pipeline import EntryPipeline
from npm_pipeline.classes.localization_store import LocalizationStore
from npm_pipeline.classes.malicious_localizer import MaliciousLocalizer
from npm_pipeline.classes.package_json import PackageJson
from npm_pipeline.classes.program_context import ProgramContext
from npm_pipeline.classes.router import RouteDecider
from npm_pipeline.classes.slice_builder import SliceBuilder
from npm_pipeline.classes.slice_store import SliceStore
from npm_pipeline.classes.static_fallback import StaticFallback
from npm_pipeline.classes.static_judge import StaticJudge
from npm_pipeline.classes.third_party_enricher import ThirdPartyEnricher
from npm_pipeline.types import Stage
from npm_pipeline.utils.behavior_gen_utils import gen_behavior
from npm_pipeline.utils.local_file_reader import PackageFileReader
from npm_pipeline.utils.pdg_utils import find_pdg_by_file
from npm_pipeline.utils.synthesis import evaluate_syntheses
from status import STATUS_BENIGN, STATUS_CODE_MALICIOUS

sys.setrecursionlimit(20000)


class Package:
    """Top-level per-package orchestration.

    Responsibilities:

    - Entry-script discovery (``_collect_entry_scripts`` / ``_check_existence``).
    - Static and dynamic code-info generation (delegated to the
      ``static_helper`` / ``dynamic_helper`` modules).
    - PBG construction and dot-graph output (implements the
      :class:`PBGProvider` protocol consumed by :class:`EntryPipeline`).
    - LLM-based static fallback when the deterministic static pipeline
      cannot run.
    - Cross-entry aggregation via :func:`evaluate_syntheses`.

    Per-entry pipeline logic (static / enrichment / dynamic) is owned by
    :class:`EntryPipeline`; this class only wires its dependencies.
    """

    def __init__(
        self,
        package_name: str,
        original_package_dir: str,
        workspace_dir: str,
        package_json: PackageJson,
        detection_state: DetectionState | None = None,
        enable_orphan_recovery: bool = True,
        parallel_workers: int = 8,
    ):
        self.package_name: str = package_name
        self.workspace_dir: str = workspace_dir
        self.original_package_dir: str = original_package_dir
        self.package_json: PackageJson = package_json
        self.static_code_info: CodeInfo | None = None
        self.dynamic_code_info: CodeInfo | None = None
        self.current_code_info: CodeInfo | None = None

        self.analysis_context = AnalysisContext(self.package_name, self.package_json)
        self.detection_state: DetectionState = detection_state or DetectionState(
            package_name=package_name
        )

        self.enable_orphan_recovery: bool = enable_orphan_recovery
        self.parallel_workers: int = max(1, int(parallel_workers))

        self._pdg_missing_entries: set[str] = set()

        self._localizer = MaliciousLocalizer()
        self._localization_store = LocalizationStore(self.workspace_dir, self.package_name)

        self._entry_pipeline = self._build_entry_pipeline()

    # ------------------------------------------------------------------
    # Dependency wiring
    # ------------------------------------------------------------------

    def _build_entry_pipeline(self) -> EntryPipeline:
        """Construct :class:`EntryPipeline` with all its collaborators injected.

        Leaf components are stateless (or carry only long-lived state
        like the npm metadata cache) so a single instance is reused
        across all entries of this package.
        """
        slice_builder = SliceBuilder()
        slice_store = SliceStore(self.workspace_dir, self.package_name)

        # Shared file reader for the static / dynamic reread gate.  One
        # instance is anchored at the original package root and reused
        # across every entry's verifier-driven reread.
        package_root = os.path.join(self.original_package_dir, "package")
        file_reader = PackageFileReader(package_root)

        static_judge = StaticJudge(
            package_name=self.package_name,
            file_reader=file_reader,
            detection_state=self.detection_state,
        )
        dynamic_judge = DynamicJudge(
            package_name=self.package_name,
            file_reader=file_reader,
            detection_state=self.detection_state,
        )
        evidence_collector = DynamicEvidenceCollector()
        router = RouteDecider(self.detection_state)
        third_party_enricher = ThirdPartyEnricher(self.package_name, self.workspace_dir)

        return EntryPipeline(
            package_name=self.package_name,
            slice_builder=slice_builder,
            slice_store=slice_store,
            static_judge=static_judge,
            dynamic_judge=dynamic_judge,
            evidence_collector=evidence_collector,
            router=router,
            third_party_enricher=third_party_enricher,
            detection_state=self.detection_state,
            analysis_context=self.analysis_context,
            pbg_provider=self,
            enable_orphan_recovery=self.enable_orphan_recovery,
            parallel_workers=self.parallel_workers,
            localizer=self._localizer,
            localization_store=self._localization_store,
        )

    # ------------------------------------------------------------------
    # Top-level analysis orchestration
    # ------------------------------------------------------------------

    def analyse(self, dynamic_support: bool) -> int | str:
        entry_scripts = self._collect_entry_scripts()
        if not entry_scripts:
            return STATUS_BENIGN

        logger.info(f"Entry Scripts: {entry_scripts}")
        try:
            self._generate_static_info(entry_scripts)
        except TimeoutError as e:
            logger.warning(f"Static generation timed out: {e}; entering LLM fallback")
            return self._run_static_fallback(entry_scripts, reason=f"timeout: {e}")
        except Exception as e:
            logger.info(f"Exception caught in generate_static_info: {e}.")
            logger.warning("Execution trace:\n" + traceback.format_exc())
            return self._run_static_fallback(entry_scripts, reason=f"exception: {e}")

        entry_results: dict[str, int | str] = {}
        for entry in entry_scripts:
            result = self._entry_pipeline.run(entry, dynamic_support)
            entry_results[entry] = result
            if result == STATUS_CODE_MALICIOUS:
                return STATUS_CODE_MALICIOUS

        return evaluate_syntheses(list(entry_results.values()))

    # ------------------------------------------------------------------
    # Entry script collection
    # ------------------------------------------------------------------

    def _collect_entry_scripts(self) -> set[str]:
        entry_script = self.package_json.get_install_time_entry_files()
        if self.package_json.get_main():
            entry_script.update(self.package_json.get_main())
        if self.package_json.get_exports_entries():
            entry_script.update(self.package_json.get_exports_entries())
        if self.package_json.get_bin_scrip():
            entry_script.update(self.package_json.get_bin_scrip())
        return self._check_existence(entry_script, self.original_package_dir)

    @staticmethod
    def _check_existence(entry_script_set: set[str], package_dir: str) -> set[str]:
        return {
            s for s in entry_script_set if os.path.exists(os.path.join(package_dir, "package", s))
        }

    # ------------------------------------------------------------------
    # Code-info generation (static / dynamic)
    # ------------------------------------------------------------------

    def _generate_static_info(self, entry_script_set: set[str]) -> None:
        formatted_package_dir = os.path.join(
            self.workspace_dir, self.package_name, "static", "format"
        )
        joern_dir = os.path.join(self.workspace_dir, self.package_name, "static", "joern")
        pdg_dir = os.path.join(joern_dir, "pdg")
        cfg_dir = os.path.join(joern_dir, "cfg")
        cpg_dir = os.path.join(joern_dir, "cpg")
        jelly_cg_path = os.path.join(
            self.workspace_dir, self.package_name, "static", "jelly", "cg.json"
        )
        self.static_code_info = static_helper.generate_static_info(
            cfg_dir,
            cpg_dir,
            formatted_package_dir,
            jelly_cg_path,
            joern_dir,
            self.original_package_dir,
            pdg_dir,
            entry_script_set,
        )

    def generate_dynamic_info(self, entry_script: str) -> None:
        """Implements :class:`PBGProvider`.

        Populates ``self.dynamic_code_info`` and loads the dependency
        tree onto ``self.analysis_context``.
        """
        formatted_package_dir = os.path.join(
            self.workspace_dir, self.package_name, "dynamic", "format"
        )
        joern_dir = os.path.join(self.workspace_dir, self.package_name, "dynamic", "joern")
        pdg_dir = os.path.join(joern_dir, "pdg")
        cfg_dir = os.path.join(joern_dir, "cfg")
        cpg_dir = os.path.join(joern_dir, "cpg")
        jelly_cg_dir = os.path.join(self.workspace_dir, self.package_name, "dynamic", "jelly")
        api_info_dir = os.path.join(self.workspace_dir, self.package_name, "dynamic", "api")
        dep_tree_dir = os.path.join(self.workspace_dir, self.package_name, "dynamic", "dep_tree")

        self.dynamic_code_info = dynamic_helper.generate_dynamic_info(
            self.original_package_dir,
            formatted_package_dir,
            joern_dir,
            pdg_dir,
            cfg_dir,
            cpg_dir,
            jelly_cg_dir,
            api_info_dir,
            dep_tree_dir,
            entry_script,
            self.static_code_info,
        )

        dep_tree_path = os.path.join(dep_tree_dir, "dep_tree.json")
        self.analysis_context.dependency_tree = DependencyTree.from_json_file(dep_tree_path)

    # ------------------------------------------------------------------
    # PBGProvider implementation
    # ------------------------------------------------------------------

    def generate_program_behavior(self, entry_script_: str, stage: Stage) -> PBG | None:
        if stage == "static":
            self.current_code_info = self.static_code_info
        else:
            self.current_code_info = self.dynamic_code_info
        file_relative_path = os.path.normpath(os.path.join("package", entry_script_))
        if not (
            file_relative_path.endswith(".js")
            or file_relative_path.endswith(".mjs")
            or file_relative_path.endswith(".cjs")
        ):
            file_relative_path = file_relative_path + ".js"

        if self.current_code_info is None:
            return None
        if file_relative_path in self.analysis_context.analyzed_script:
            return None

        self.analysis_context.analyzed_script.add(file_relative_path)
        self.analysis_context.file_in_cg.add(file_relative_path)
        pdg_of_script = find_pdg_by_file(file_relative_path, self.current_code_info)
        if pdg_of_script is None:
            logger.info(
                f"Can not find the pdg of the script: {entry_script_} "
                f"in abs path: {file_relative_path}"
            )
            if stage == "static":
                self._pdg_missing_entries.add(entry_script_)
            return None

        logger.info(f"▶️{stage.upper()} ANALYSIS OF {entry_script_}")
        program_behavior = PBG(
            self.current_code_info.cpg,
            self.current_code_info.pdg_dict,
            self.current_code_info.formatted_package_dir,
            self.package_name,
        )
        self.program_context = ProgramContext(self.current_code_info.js_file_list)
        self.analysis_context.program_context = self.program_context
        self._add_global_object(program_behavior)
        self.analysis_context.current_code_info = self.current_code_info
        script_behavior = gen_behavior(
            filename=file_relative_path,
            pdg=pdg_of_script,
            pdg_type="implicit main",
            program_behavior=program_behavior,
            parameter_list=None,
            analysis_context=self.analysis_context,
            stage=stage,
        )
        logger.info(f"🆗{stage.upper()} FINISHED OF {entry_script_}")
        return script_behavior

    def reset_pdg_nodes_for_new_entry(self) -> None:
        """Implements :class:`PBGProvider`."""
        if self.static_code_info is None:
            return
        for pdg in self.static_code_info.pdg_dict.values():
            for pdg_node in pdg.get_nodes().values():
                pdg_node.reset_for_new_entry()

    # ------------------------------------------------------------------
    # Static-analysis fallback
    # ------------------------------------------------------------------

    def _run_static_fallback(self, entry_scripts: set[str], reason: str) -> int | str:
        """Run the LLM-driven static fallback for *entry_scripts*.

        Invoked from :meth:`analyse` when the deterministic static pipeline
        raises (timeout or generic tool-call error). The fallback reads the
        entry file(s) as raw source, lets the LLM walk up to a few local
        files via a JSON tool loop, and returns either
        :data:`STATUS_CODE_MALICIOUS` (any entry judged malicious) or
        :data:`STATUS_BENIGN` (all entries benign / undetermined).
        """
        self.detection_state.set_last_next_step_reason(
            f"static pipeline failed ({reason}); running LLM fallback"
        )
        return self._make_static_fallback().run(entry_scripts)

    def static_fallback_for_entry(self, entry: str) -> int | str | None:
        """Implements :class:`PBGProvider`.

        Invoked by :class:`EntryPipeline` when static PBG generation
        yields no behavior for *entry*. Only entries whose static-stage
        ``:program`` PDG was missing, run the LLM fallback
        """
        if entry not in self._pdg_missing_entries:
            return None
        self._pdg_missing_entries.discard(entry)
        self.detection_state.set_last_next_step_reason(
            "static PDG missing for entry; running LLM fallback"
        )
        return self._make_static_fallback().run({entry})

    def _make_static_fallback(self) -> StaticFallback:
        return StaticFallback(
            self.package_name,
            self.original_package_dir,
            self.detection_state,
            localizer=self._localizer,
            localization_store=self._localization_store,
        )

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _add_global_object(self, program_behavior: PBG) -> None:
        for obj in self.analysis_context.program_context.get_global_object_list():
            program_behavior.add_object(obj)
