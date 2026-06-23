"""ClassifiedNodes — typed bucketing of still-suspicious PDG node IDs."""

from dataclasses import dataclass, field


@dataclass
class ClassifiedNodes:
    """Node IDs grouped by the call-type bucket that still needs follow-up."""

    conditional: list[int] = field(default_factory=list)
    third_party: list[int] = field(default_factory=list)
    unresolved: list[int] = field(default_factory=list)

    def is_empty(self) -> bool:
        return not (self.conditional or self.third_party or self.unresolved)

    def all_ids(self) -> list[int]:
        return [*self.conditional, *self.third_party, *self.unresolved]
