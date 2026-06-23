"""Finding-summary and status-string helpers."""

import os
import re

from npm_pipeline.types import ClassifiedNodes, StepResult
from status import STATUS_BENIGN, STATUS_CODE_MALICIOUS


def status_to_result_str(synthesis: int | str) -> StepResult:
    if synthesis == STATUS_CODE_MALICIOUS:
        return "malicious"
    if synthesis == STATUS_BENIGN:
        return "benign"
    if synthesis == "undetermined":
        return "undetermined"
    return "warning"


def safe_entry_name(entry: str) -> str:
    return re.sub(r'[\\/:*?"<>|]', "-", os.path.normpath(entry))


def build_finding_summary(final_result: dict, classified: ClassifiedNodes | None = None) -> str:
    """Build a concise finding summary from a verifier / synthesis result.

    Works uniformly for static verifier output (``reason``,
    ``key_evidence``), cross-component synthesis (``explanation``,
    ``cross_component_evidence``), and dynamic judgment
    (``explanation``).
    """
    parts: list[str] = []

    reason = final_result.get("reason", "") or final_result.get("explanation", "")
    if reason:
        parts.append(f"reason: {reason}")

    key_evidence = final_result.get("key_evidence", [])
    if key_evidence:
        claims = [ev.get("claim", "") for ev in key_evidence if ev.get("claim")]
        if claims:
            parts.append(f"evidence: {'; '.join(claims)}")

    cross_evidence = final_result.get("cross_component_evidence", [])
    if cross_evidence:
        patterns = [ce.get("pattern", "") for ce in cross_evidence if ce.get("pattern")]
        if patterns:
            parts.append(f"cross-component patterns: {', '.join(patterns)}")

    if classified is not None:
        node_parts: list[str] = []
        if classified.conditional:
            node_parts.append(f"conditional={classified.conditional}")
        if classified.third_party:
            node_parts.append(f"third_party={classified.third_party}")
        if classified.unresolved:
            node_parts.append(f"unresolved={classified.unresolved}")
        if node_parts:
            parts.append(f"flagged nodes: {', '.join(node_parts)}")

    return " | ".join(parts) if parts else "no findings"
