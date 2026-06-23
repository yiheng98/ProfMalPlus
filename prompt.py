"""LLM system and user prompt templates."""

from pathlib import Path

_PROMPTS_DIR = Path(__file__).resolve().parent / "prompts"


def _load_prompt(stem: str) -> str:
    return (_PROMPTS_DIR / f"{stem}.md").read_text(encoding="utf-8")


SHELL_COMMAND_SYSTEM_PROMPT = _load_prompt("shell_command_system_prompt")
STATIC_STAGE_INTERPRETER_PROMPT = _load_prompt("static_stage_interpreter_prompt")

# The static verifier and reread share a single body of judgement rules and
# only differ in their input contract / mode-specific output requirements.
# Compose them by concatenating the appropriate header with the shared body.
# The verify-mode prompt is used for BOTH the bare and the enriched static
# passes — it detects which pass is active by inspecting the slice for
# type (f) annotations.
_STATIC_VERIFIER_BODY = _load_prompt("static_verifier_body")
STATIC_STAGE_VERIFIER_SYSTEM_PROMPT = (
    _load_prompt("static_verifier_header_verify") + "\n\n---\n\n" + _STATIC_VERIFIER_BODY
)
STATIC_STAGE_REREAD_SYSTEM_PROMPT = (
    _load_prompt("static_verifier_header_reread") + "\n\n---\n\n" + _STATIC_VERIFIER_BODY
)

PACKAGE_TRUST_SYSTEM_PROMPT = _load_prompt("package_trust_system_prompt")
MODULE_OVERALL_FUNCTIONALITY_SYSTEM_PROMPT = _load_prompt(
    "module_overall_functionality_system_prompt"
)
API_BEHAVIOR_SYSTEM_PROMPT = _load_prompt("api_behavior_system_prompt")
API_SEQUENCE_BEHAVIOR_SYSTEM_PROMPT = _load_prompt("api_sequence_behavior_system_prompt")
FILE_CONTENT_INSPECTION_SYSTEM_PROMPT = _load_prompt("file_content_inspection_system_prompt")
NODE_JS_EXECUTION_SYSTEM_PROMPT = _load_prompt("node_js_execution_system_prompt")
DYNAMIC_BEHAVIOR_JUDGMENT_PROMPT = _load_prompt("dynamic_behavior_judgment_prompt")

# The dynamic verifier and reread share a single body of judgement rules and
# only differ in their input contract / mode-specific output requirements,
# mirroring the static verifier/reread composition above.
_DYNAMIC_VERIFIER_BODY = _load_prompt("dynamic_verifier_body")
DYNAMIC_BEHAVIOR_VERIFIER_SYSTEM_PROMPT = (
    _load_prompt("dynamic_verifier_header_verify") + "\n\n---\n\n" + _DYNAMIC_VERIFIER_BODY
)
DYNAMIC_REREAD_SYSTEM_PROMPT = (
    _load_prompt("dynamic_verifier_header_reread") + "\n\n---\n\n" + _DYNAMIC_VERIFIER_BODY
)

CROSS_COMPONENT_SYNTHESIS_PROMPT = _load_prompt("cross_component_synthesis_prompt")
ROUTING_DECISION_PROMPT = _load_prompt("routing_decision_prompt")
STATIC_FALLBACK_INTERPRETER_PROMPT = _load_prompt("static_fallback_interpreter_prompt")
MALICIOUS_LOCALIZATION_PROMPT = _load_prompt("malicious_localization_prompt")
MALICIOUS_LOCALIZATION_FALLBACK_PROMPT = _load_prompt("malicious_localization_fallback_prompt")

__all__ = [
    "API_BEHAVIOR_SYSTEM_PROMPT",
    "API_SEQUENCE_BEHAVIOR_SYSTEM_PROMPT",
    "CROSS_COMPONENT_SYNTHESIS_PROMPT",
    "DYNAMIC_BEHAVIOR_JUDGMENT_PROMPT",
    "DYNAMIC_BEHAVIOR_VERIFIER_SYSTEM_PROMPT",
    "DYNAMIC_REREAD_SYSTEM_PROMPT",
    "FILE_CONTENT_INSPECTION_SYSTEM_PROMPT",
    "MALICIOUS_LOCALIZATION_FALLBACK_PROMPT",
    "MALICIOUS_LOCALIZATION_PROMPT",
    "MODULE_OVERALL_FUNCTIONALITY_SYSTEM_PROMPT",
    "NODE_JS_EXECUTION_SYSTEM_PROMPT",
    "PACKAGE_TRUST_SYSTEM_PROMPT",
    "ROUTING_DECISION_PROMPT",
    "SHELL_COMMAND_SYSTEM_PROMPT",
    "STATIC_FALLBACK_INTERPRETER_PROMPT",
    "STATIC_STAGE_INTERPRETER_PROMPT",
    "STATIC_STAGE_REREAD_SYSTEM_PROMPT",
    "STATIC_STAGE_VERIFIER_SYSTEM_PROMPT",
]
