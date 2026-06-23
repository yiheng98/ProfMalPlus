"""SynthesisOutcome — typed return value of cross-component synthesis."""

from dataclasses import dataclass, field


@dataclass
class SynthesisOutcome:
    """Aggregated verdict plus cross-component follow-up metadata.

    - ``status`` — pipeline status code or the string ``"undetermined"``.
    - ``cross_nodes`` — node IDs the cross-component LLM asks to re-check.
    - ``final_result`` — raw LLM verifier / cross-component dict (kept
      opaque because its shape is the LLM's contract, not ours).
    """

    status: int | str
    cross_nodes: list[int] = field(default_factory=list)
    final_result: dict = field(default_factory=dict)
