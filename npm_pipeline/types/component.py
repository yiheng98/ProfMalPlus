"""ComponentResult — a single per-component slice + LLM judgement."""

from dataclasses import dataclass, field


@dataclass
class ComponentResult:
    """Per-component slice plus its LLM-produced judgement.

    Flows between :class:`SliceBuilder` (producer), :class:`StaticJudge`
    and :class:`DynamicJudge` (consumers that attach / update
    ``result``), :func:`synthesize_component_results`, :class:`RouteDecider`
    and :class:`EntryPipeline`.
    """

    component_id: int
    code_slice: dict
    result: dict = field(default_factory=dict)
    cfg_order: int = 0
    predecessors: list[int] = field(default_factory=list)
    successors: list[int] = field(default_factory=list)

    def with_result(self, result: dict) -> "ComponentResult":
        """Return a copy with ``result`` replaced (keeps ordering metadata)."""
        return ComponentResult(
            component_id=self.component_id,
            code_slice=self.code_slice,
            result=result,
            cfg_order=self.cfg_order,
            predecessors=list(self.predecessors),
            successors=list(self.successors),
        )
