"""DynamicContext — shared evidence for the dynamic judgement."""

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from npm_pipeline.classes.serialized_types import FileIORecord

if TYPE_CHECKING:
    from base_classes.pdg_node import PDGNode


@dataclass
class DynamicContext:
    """Shared evidence for the dynamic judgement pipeline.

    ``file_inspections`` is pre-populated by
    :class:`DynamicEvidenceCollector` so the dynamic LLM can see file
    content summaries up-front without a follow-up pass.
    """

    file_io_records: list[FileIORecord] = field(default_factory=list)
    node_map: dict[int, "PDGNode"] = field(default_factory=dict)
    file_inspections: list[dict] = field(default_factory=list)
