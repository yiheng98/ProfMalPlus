from dataclasses import dataclass, field

from npm_pipeline.types import Stage, StepResult

STAGE_DISPLAY_NAMES: dict[str, str] = {
    "install_script_analysis": "Install-Phase Shell Command Analysis",
    "static": "Static Analysis",
    "static_fallback": "Static Analysis (LLM Fallback)",
    "static_local_read": "Static Local File Read",
    "third_party_info_enrichment": "Third-Party Info Enrichment",
    "dynamic": "Dynamic Analysis",
    "dynamic_local_read": "Dynamic Local File Read",
}


@dataclass
class AnalysisStep:
    stage: Stage
    entry: str | None  # None for install_script_analysis; entry script path otherwise
    result: StepResult
    finding: str
    next_step_reason: str = ""
    metadata: dict = field(default_factory=dict)
    """Structured side-channel for stages whose history downstream stages query.
    """


@dataclass
class DetectionState:
    package_name: str
    history: list[AnalysisStep] = field(default_factory=list)

    def add_step(self, step: AnalysisStep) -> None:
        self.history.append(step)

    def set_last_next_step_reason(self, reason: str) -> None:
        if self.history:
            self.history[-1].next_step_reason = reason

    def to_context_summary(self) -> str:
        return self._format_steps(self.history)

    def to_entry_context_summary(self, entry: str) -> str:
        """Build a context summary scoped to a single entry.

        Only includes global steps (entry is None, e.g. install_script_analysis)
        and steps that belong to the given *entry*.
        """
        filtered = [s for s in self.history if s.entry is None or s.entry == entry]
        return self._format_steps(filtered)

    def _format_steps(self, steps: list["AnalysisStep"]) -> str:
        if not steps:
            return ""

        lines: list[str] = [
            "=== Prior Analysis Context ===",
            f"Package: {self.package_name}",
            "",
        ]

        for idx, step in enumerate(steps, start=1):
            display_name = STAGE_DISPLAY_NAMES.get(step.stage, step.stage)
            header = f"[{idx}] {display_name}"
            if step.entry:
                header += f" ({step.entry})"
            header += f" → {step.result.capitalize()}"
            lines.append(header)

            for finding_line in step.finding.splitlines():
                lines.append(f"    {finding_line}")

            if step.next_step_reason:
                lines.append(f"    → Next step reason: {step.next_step_reason}")

            lines.append("")

        lines.append("==============================")
        return "\n".join(lines)
