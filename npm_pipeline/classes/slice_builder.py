"""SliceBuilder — PBG -> list[ComponentResult] conversion.

Pure computation: walks the behaviour graph, converts per-file code
slices into the JSON-serialisable shape consumed by LLM interpreters,
and attaches ordering metadata (cfg_order / predecessors / successors).
"""

from loguru import logger

from base_classes.pbg import PBG
from npm_pipeline.classes.analysis_context import AnalysisContext
from npm_pipeline.types import ComponentResult, Stage


class SliceBuilder:
    """Build :class:`ComponentResult` slices from a :class:`PBG`.

    Stateless — the same instance can be reused across entries / stages.
    """

    def build(
        self,
        pbg: PBG,
        stage: Stage,
        files: dict,
        analysis_context: AnalysisContext | None = None,
    ) -> list[ComponentResult]:
        """Slice *pbg* into per-component :class:`ComponentResult` entries.

        ``analysis_context`` is only required for the ``"dynamic"`` stage,
        where the underlying slicer consults runtime-only state.
        """
        raw_slices, component_ordering = self._raw_slices(pbg, stage, files, analysis_context)
        log_label = "Dynamic Component" if stage == "dynamic" else "Component"

        components: list[ComponentResult] = []
        for idx, file_code_slice_dict in enumerate(raw_slices):
            sliced_code = self._sliced_code(file_code_slice_dict, idx, log_label)
            if not sliced_code:
                continue

            ordering_meta = component_ordering[idx] if idx < len(component_ordering) else {}
            components.append(
                ComponentResult(
                    component_id=idx,
                    code_slice={"sliced_code": sliced_code},
                    cfg_order=ordering_meta.get("cfg_order", 0),
                    predecessors=ordering_meta.get("predecessors", []),
                    successors=ordering_meta.get("successors", []),
                )
            )

        return components

    @staticmethod
    def _raw_slices(
        pbg: PBG,
        stage: Stage,
        files: dict,
        analysis_context: AnalysisContext | None,
    ) -> tuple[list[dict], list[dict]]:
        if stage == "dynamic":
            if analysis_context is None:
                raise ValueError(
                    "SliceBuilder.build requires an AnalysisContext for stage='dynamic'"
                )
            return pbg.behavior_graph_to_slice_dynamic(files, analysis_context)
        return pbg.behavior_graph_to_slice_static(files)

    @staticmethod
    def _sliced_code(file_code_slice_dict: dict, idx: int, log_label: str) -> list[dict]:
        """Convert a ``{file_name: FileCodeSlice}`` dict into LLM payload entries."""
        sliced_code: list[dict] = []
        for file_name, file_code_slice in file_code_slice_dict.items():
            file_json = file_code_slice.toJson()
            code_lines = file_json[file_name]
            callee_info = file_json.get("Callee Info", [])

            code_str = "\n".join(code_lines) if isinstance(code_lines, list) else code_lines
            logger.info(f"[{log_label} {idx}] Code Slice of {file_name}:\n{code_str}")
            logger.info(f"[{log_label} {idx}] Callee Info of {file_name}:\n{callee_info}")

            sliced_code.append(
                {
                    file_name: {
                        "code_snippet": code_lines,
                        "callee_info": callee_info,
                    }
                }
            )
        return sliced_code
