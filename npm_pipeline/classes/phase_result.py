"""PhaseResult — typed return value for per-entry analysis phases."""

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from npm_pipeline.types import ClassifiedNodes, ComponentResult
from status import STATUS_BENIGN, STATUS_CODE_MALICIOUS

if TYPE_CHECKING:
    from base_classes.pbg import PBG


@dataclass
class PhaseResult:
    status: int | str
    classified: ClassifiedNodes = field(default_factory=ClassifiedNodes)
    pbg: "PBG | None" = None
    enrichment_info: dict | None = None
    finding: str = ""
    # Structured artifacts surfaced to the routing agent so it can reason
    # beyond node IDs: the aggregated per-component results and the top-
    # level verifier / cross-component synthesis output of this phase.
    component_results: list[ComponentResult] = field(default_factory=list)
    final_result: dict = field(default_factory=dict)

    def is_terminal(self) -> bool:
        """Whether this result already dictates a final pipeline answer."""
        return self.status in (STATUS_BENIGN, STATUS_CODE_MALICIOUS)
