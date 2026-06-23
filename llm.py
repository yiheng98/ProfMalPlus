import json
import re
import time
from typing import Callable

import tiktoken
import yaml
from loguru import logger
from openai import OpenAI

from prompt import (
    API_BEHAVIOR_SYSTEM_PROMPT,
    API_SEQUENCE_BEHAVIOR_SYSTEM_PROMPT,
    CROSS_COMPONENT_SYNTHESIS_PROMPT,
    DYNAMIC_BEHAVIOR_JUDGMENT_PROMPT,
    DYNAMIC_BEHAVIOR_VERIFIER_SYSTEM_PROMPT,
    DYNAMIC_REREAD_SYSTEM_PROMPT,
    FILE_CONTENT_INSPECTION_SYSTEM_PROMPT,
    MALICIOUS_LOCALIZATION_FALLBACK_PROMPT,
    MALICIOUS_LOCALIZATION_PROMPT,
    MODULE_OVERALL_FUNCTIONALITY_SYSTEM_PROMPT,
    NODE_JS_EXECUTION_SYSTEM_PROMPT,
    PACKAGE_TRUST_SYSTEM_PROMPT,
    ROUTING_DECISION_PROMPT,
    SHELL_COMMAND_SYSTEM_PROMPT,
    STATIC_FALLBACK_INTERPRETER_PROMPT,
    STATIC_STAGE_INTERPRETER_PROMPT,
    STATIC_STAGE_REREAD_SYSTEM_PROMPT,
    STATIC_STAGE_VERIFIER_SYSTEM_PROMPT,
)

with open("./config.yaml", "r") as file:
    config = yaml.safe_load(file)

_llm_config = config["LLM"]
if isinstance(_llm_config, str):
    raise ValueError(
        "config.yaml should contain a dictionary with 'model', 'api_key', and 'base_url' keys"
    )

model_name: str = _llm_config["model"]
api_key: str = _llm_config["api_key"]
base_url: str = _llm_config["base_url"]

enc = tiktoken.get_encoding("cl100k_base")


def _build_messages(
    system_prompt: str, user_content: str, *, context_summary: str = ""
) -> list[dict]:
    """Build the chat-completions message list.

    If *context_summary* is non-empty it is appended to the system prompt
    so that each LLM call can see the prior analysis trail while keeping
    a single system message for maximum cross-model compatibility.
    """
    system_content = system_prompt
    if context_summary:
        system_content += f"\n\n## Prior Analysis Context\n{context_summary}"
    return [
        {"role": "system", "content": system_content},
        {"role": "user", "content": user_content},
    ]


DEFAULT_NODE_EXEC_RESULT = {"launches_node": False, "js_files": []}


def llm_shell_command_turn(payload: dict) -> dict | None:
    """Run one **stateless** turn of the shell-command LLM loop.

    *payload* carries the per-turn input (``shell_command`` plus the
    ``remaining_hops`` / ``visited_files`` / ``prior_reads`` /
    ``read_results`` fields described in the system prompt). The outer
    ``shell_command`` is re-sent every turn so the LLM never loses sight
    of the install-time context that motivated any inner-script reads.

    Returns the parsed JSON object the LLM produced (one of the two
    ``action`` shapes defined in the prompt) or ``None`` when the
    response cannot be parsed. ``ConnectionError`` from
    :func:`connect_with_retry` is propagated.
    """
    messages = [
        {"role": "system", "content": SHELL_COMMAND_SYSTEM_PROMPT},
        {"role": "user", "content": json.dumps(payload, ensure_ascii=False, indent=2)},
    ]
    logger.info(
        f"[LLM] Shell command turn {payload.get('turn')} "
        f"(remaining_hops={payload.get('remaining_hops')})"
    )
    response = connect_with_retry(messages)
    parsed, _ = extract_json_str_from_response(response)
    return parsed


def _validate_node_execution_shape(parsed: dict) -> str | None:
    if "launches_node" not in parsed:
        return "missing required field 'launches_node' (must be a boolean)"
    return None


def llm_node_execution_interpret(qualified_name: str, command: str):
    """Returns a dict: {"launches_node": bool, "js_files": list[str]}"""
    messages = [
        {
            "role": "system",
            "content": NODE_JS_EXECUTION_SYSTEM_PROMPT,
        },
        {
            "role": "user",
            "content": f"Qualified Name: {qualified_name}\nCommand: {command}",
        },
    ]
    logger.info(f"[LLM] Analyse Node.js execution in subprocess\n {command}")
    try:
        parsed = llm_call_json(
            messages,
            validator=_validate_node_execution_shape,
            log_label="node-execution interpret",
        )
    except ConnectionError:
        logger.warning("[LLM] Connection failed for Node.js execution interpretation")
        return DEFAULT_NODE_EXEC_RESULT.copy()

    if parsed is None:
        return DEFAULT_NODE_EXEC_RESULT.copy()

    launches_node = parsed.get("launches_node", False)
    if not isinstance(launches_node, bool):
        launches_node = False

    js_files = parsed.get("js_files", [])
    if not isinstance(js_files, list):
        js_files = []
    js_files = [f for f in js_files if isinstance(f, str)]

    if not launches_node:
        js_files = []

    result = {"launches_node": launches_node, "js_files": js_files}
    logger.info(f"[LLM] Node.js execution result: {result}")
    return result


def _normalise_sliced_code(sliced_code: dict) -> dict:
    """Return a shallow copy with ``code_snippet`` joined into a single string."""
    sliced_code_copy = sliced_code.copy()
    if "code_snippet" in sliced_code_copy and isinstance(sliced_code_copy["code_snippet"], list):
        sliced_code_copy["code_snippet"] = "\n".join(sliced_code_copy["code_snippet"])
    return sliced_code_copy


def llm_generate_static_stage_report(
    sliced_code: dict, *, context_summary: str = "", enriched: bool = False
):
    """Run the static-stage interpreter on *sliced_code*.

    The same system prompt drives both passes; ``enriched`` only changes
    the log label so that bare-pass and enriched-pass calls remain
    distinguishable in the workflow log.
    """
    sliced_code_str = json.dumps(_normalise_sliced_code(sliced_code), indent=2, ensure_ascii=False)

    messages = _build_messages(
        STATIC_STAGE_INTERPRETER_PROMPT, sliced_code_str, context_summary=context_summary
    )
    if enriched:
        logger.info(
            "[LLM] Analyse code behavior based on enriched static evidence "
            "(with third-party metadata)"
        )
        call_label = "enriched-static interpreter"
    else:
        logger.info("[LLM] Analyse code behavior based on the static evidence")
        call_label = "static-stage interpreter"

    try:
        return llm_call_json(messages, temperature=0.5, log_label=call_label)
    except ConnectionError:
        raise ConnectionError("Failed to establish connection to LLM after maximum attempts")


def llm_validate_static_stage_report(
    sliced_code: dict, report_list: list, *, enriched: bool = False
):
    """Run the static-stage verifier on *sliced_code* + *report_list*.

    The same system prompt drives both passes; ``enriched`` only changes
    the log label.
    """
    sliced_code_str = json.dumps(_normalise_sliced_code(sliced_code), indent=2, ensure_ascii=False)
    report_str = json.dumps(report_list, indent=2, ensure_ascii=False)

    user_content = (
        f"Original sliced code:\n{sliced_code_str}\n\nThree static stage reports:\n{report_str}"
    )
    messages = _build_messages(STATIC_STAGE_VERIFIER_SYSTEM_PROMPT, user_content)
    if enriched:
        logger.info("[LLM] Validate the enriched static stage report")
        call_label = "enriched-static verifier"
    else:
        logger.info("[LLM] Validate the static stage report")
        call_label = "static-stage verifier"

    try:
        return llm_call_json(messages, log_label=call_label)
    except ConnectionError:
        raise ConnectionError("Failed to establish connection to LLM after maximum attempts")


# ---------------------------------------------------------------------------
# Cross-component synthesis
# ---------------------------------------------------------------------------


def llm_synthesize_cross_component(
    components_with_results: list[dict],
    ordering_edges: list[dict],
):
    """Call the LLM to perform cross-component reasoning.

    *components_with_results* should be a list of dicts each containing
    ``component_id``, ``cfg_order``, ``code_slice`` and ``individual_result``.
    *ordering_edges* is a list of ``{"from": int, "to": int}`` pairs.
    """
    payload = {
        "components": components_with_results,
        "ordering": ordering_edges,
    }
    payload_str = json.dumps(payload, indent=2, ensure_ascii=False)

    messages = _build_messages(CROSS_COMPONENT_SYNTHESIS_PROMPT, payload_str)
    logger.info(f"[LLM] Cross-component synthesis over {len(components_with_results)} components")

    try:
        return llm_call_json(messages, log_label="cross-component synthesis")
    except ConnectionError:
        raise ConnectionError("Failed to establish connection to LLM after maximum attempts")


def llm_interpret_package_trust(package_metadata: dict):
    metadata_str = json.dumps(package_metadata, indent=2, ensure_ascii=False)
    messages = [
        {
            "role": "system",
            "content": PACKAGE_TRUST_SYSTEM_PROMPT,
        },
        {
            "role": "user",
            "content": f"The metadata of the package: {metadata_str}",
        },
    ]

    (logger.info("[LLM] Interpret the trust level of the package"),)
    try:
        return llm_call_json(messages, log_label="package trust interpret")
    except ConnectionError:
        raise ConnectionError("Failed to establish connection to LLM after maximum attempts")


def llm_interpret_module_overall_functionality(package_metadata: dict):
    metadata_str = json.dumps(package_metadata, indent=2, ensure_ascii=False)
    messages = [
        {
            "role": "system",
            "content": MODULE_OVERALL_FUNCTIONALITY_SYSTEM_PROMPT,
        },
        {
            "role": "user",
            "content": f"{metadata_str}",
        },
    ]
    logger.info("[LLM] Interpret the overall functionality of the package")
    try:
        return llm_call_json(messages, log_label="module functionality interpret")
    except ConnectionError:
        raise ConnectionError("Failed to establish connection to LLM after maximum attempts")


def llm_interpret_api_behavior(package_metadata: dict):
    metadata_str = json.dumps(package_metadata, indent=2, ensure_ascii=False)
    messages = [
        {
            "role": "system",
            "content": API_BEHAVIOR_SYSTEM_PROMPT,
        },
        {
            "role": "user",
            "content": f"{metadata_str}",
        },
    ]
    logger.info("[LLM] Interpret the API behavior of the package")
    try:
        return llm_call_json(messages, log_label="api behavior interpret")
    except ConnectionError:
        raise ConnectionError("Failed to establish connection to LLM after maximum attempts")


def llm_interpret_api_call_sequence(api_sequence_data: dict) -> dict | None:
    """Describe the end-to-end behavior of a resolved API call sequence.

    Returns ``{"behavior_description": str, "key_files": list}`` or ``None``.
    """
    data_str = json.dumps(api_sequence_data, indent=2, ensure_ascii=False)
    messages = [
        {"role": "system", "content": API_SEQUENCE_BEHAVIOR_SYSTEM_PROMPT},
        {"role": "user", "content": data_str},
    ]
    logger.info("[LLM] Interpret API call sequence behavior")
    try:
        return llm_call_json(messages, log_label="api-sequence behavior")
    except ConnectionError:
        logger.warning("[LLM] Connection failed for API sequence behavior interpretation")
        return None


def llm_inspect_file_content(inspection_data: dict) -> dict | None:
    """Independently analyse file content and extract security signals.

    Returns ``{"content_summary": str, "security_signals": list}`` or ``None``.
    """
    data_str = json.dumps(inspection_data, indent=2, ensure_ascii=False)
    messages = [
        {"role": "system", "content": FILE_CONTENT_INSPECTION_SYSTEM_PROMPT},
        {"role": "user", "content": data_str},
    ]
    logger.info(
        f"[LLM] Inspect file content: {inspection_data.get('file_path', 'unknown')} "
        f"({inspection_data.get('operation', '?')})"
    )
    try:
        return llm_call_json(messages, log_label="file content inspect")
    except ConnectionError:
        logger.warning("[LLM] Connection failed for file content inspection")
        return None


def llm_dynamic_behavior_judgment(judgment_data: dict, *, context_summary: str = "") -> dict | None:
    """Dynamic behavior judgment.

    *judgment_data* must carry ``sliced_code``, ``file_io_records``, and
    the pre-computed ``file_inspections`` summaries. The LLM no longer
    requests further files. Returns ``{"judgement": str, "explanation": str}``
    or ``None``.
    """
    data_str = json.dumps(judgment_data, indent=2, ensure_ascii=False)
    messages = _build_messages(
        DYNAMIC_BEHAVIOR_JUDGMENT_PROMPT, data_str, context_summary=context_summary
    )
    logger.info("[LLM] Dynamic behavior judgment")
    try:
        return llm_call_json(messages, log_label="dynamic behavior judgment")
    except ConnectionError:
        logger.warning("[LLM] Connection failed for dynamic behavior judgment")
        return None


def llm_validate_dynamic_behavior_report(
    judgment_data: dict, report: dict, *, context_summary: str = ""
) -> dict | None:
    """Verifier pass over a single dynamic report.

    Cross-checks the judger's verdict against the runtime-enriched code
    slice, ``file_io_records``, and the pre-computed ``file_inspections``,
    applying the false-positive guardrails that have been moved out of the
    judger prompt. Returns the revised report
    ``{"judgement": str, "explanation": str}`` or ``None`` on failure.
    """
    judgment_str = json.dumps(judgment_data, indent=2, ensure_ascii=False)
    report_str = json.dumps(report, indent=2, ensure_ascii=False)
    user_content = (
        f"Original sliced code, file_io_records, and file_inspections:\n{judgment_str}\n\n"
        f"Dynamic report:\n{report_str}"
    )
    messages = _build_messages(
        DYNAMIC_BEHAVIOR_VERIFIER_SYSTEM_PROMPT,
        user_content,
        context_summary=context_summary,
    )
    logger.info("[LLM] Validate the dynamic report")
    try:
        return llm_call_json(messages, log_label="dynamic verifier")
    except ConnectionError:
        logger.warning("[LLM] Connection failed for dynamic verifier")
        return None


def llm_static_fallback_turn(payload: dict, *, context_summary: str = "") -> dict | None:
    """Run one **stateless** turn of the static-fallback LLM loop.

    *payload* is the per-turn input dict (``turn``, ``entry_file``,
    ``entry_content`` on turn 1, ``prior_observations`` / ``read_results``
    on later turns, etc.). It is serialized as the sole user message; no
    conversation history is kept across turns. The caller carries the
    LLM's prior output forward via ``prior_observations`` entries inside
    *payload*, so raw file contents only have to travel through the
    prompt once.

    Returns the parsed JSON object produced by the LLM (one of the two
    ``action`` shapes defined in the prompt) or ``None`` when the response
    cannot be parsed. Connection / token errors from :func:`connect_with_retry`
    are propagated so the caller can treat them as a per-entry failure.
    """
    messages = _build_messages(
        STATIC_FALLBACK_INTERPRETER_PROMPT,
        json.dumps(payload, ensure_ascii=False, indent=2),
        context_summary=context_summary,
    )
    logger.info(
        f"[LLM] Static fallback turn {payload.get('turn')} "
        f"(remaining_hops={payload.get('remaining_hops')})"
    )
    response = connect_with_retry(messages)
    parsed, _ = extract_json_str_from_response(response)
    return parsed


def llm_static_reread(payload: dict, *, context_summary: str = "") -> dict | None:
    """Run the static reread pass (single-shot).

    Invoked after the static / enriched-static verifier emits a non-empty
    ``files_to_read`` list and the orchestrator has fetched the
    corresponding script bodies. *payload* carries the prior verifier
    report plus the read file contents.

    The reread runs against ``STATIC_STAGE_REREAD_SYSTEM_PROMPT`` —
    composed of the **reread header** plus the **shared verifier body**.
    This way the three-stage interpreter reports stay out of the reread
    context entirely (they are never serialised into ``payload``), and
    all judgement rules / FP guardrails / output schema remain defined
    in a single shared body alongside the initial-verify variant.

    Returns the parsed JSON object or ``None`` on parse failure.
    Connection / token errors from :func:`connect_with_retry` are
    propagated to the caller.
    """
    messages = _build_messages(
        STATIC_STAGE_REREAD_SYSTEM_PROMPT,
        json.dumps(payload, ensure_ascii=False, indent=2),
        context_summary=context_summary,
    )
    logger.info(
        f"[LLM] Static reread for component {payload.get('component_id')} "
        f"(files={len(payload.get('read_files', []))})"
    )
    response = connect_with_retry(messages)
    parsed, _ = extract_json_str_from_response(response)
    return parsed


def llm_dynamic_reread(payload: dict, *, context_summary: str = "") -> dict | None:
    """Run a single hop of the dynamic reread pass.

    Mirror of :func:`llm_static_reread` for the dynamic stage. The system
    prompt is composed from the shared dynamic verifier *body* plus the
    reread-specific *header*, so the rules (judgement definitions, FP
    guardrails, output schema including ``files_to_read``) are identical
    to the verify pass; only the input contract and the hop-budget rules
    differ.

    Receives the prior dynamic verifier (or previous-hop) report plus
    the accumulated ``read_files`` and the hop-budget triple
    (``hop`` / ``max_hops`` / ``remaining_hops``), plus
    ``file_io_records`` / ``file_inspections`` for context. Returns the
    same schema the dynamic verifier uses (``judgement``,
    ``explanation``, ``files_to_read``).
    """
    messages = _build_messages(
        DYNAMIC_REREAD_SYSTEM_PROMPT,
        json.dumps(payload, ensure_ascii=False, indent=2),
        context_summary=context_summary,
    )
    logger.info(
        f"[LLM] Dynamic reread for component {payload.get('component_id')} "
        f"(hop={payload.get('hop')}/{payload.get('max_hops')}, "
        f"files={len(payload.get('read_files', []))})"
    )
    response = connect_with_retry(messages)
    parsed, _ = extract_json_str_from_response(response)
    return parsed


def llm_route_decision(route_ctx: dict, *, context_summary: str = "") -> dict | None:
    """Ask the LLM to pick the next pipeline action for an undetermined phase.

    Returns ``{"next_action": str, "reason": str}`` or ``None`` on failure.
    The caller is responsible for validating ``next_action`` against the
    whitelist of permitted actions and applying any hard constraints.
    """
    data_str = json.dumps(route_ctx, indent=2, ensure_ascii=False)
    messages = _build_messages(ROUTING_DECISION_PROMPT, data_str, context_summary=context_summary)
    logger.info("[LLM] Routing decision")
    try:
        return llm_call_json(messages, log_label="routing decision")
    except ConnectionError:
        logger.warning("[LLM] Connection failed for routing decision")
        return None


def llm_locate_malicious_code(payload: dict, *, context_summary: str = "") -> dict | None:
    """Localize malicious code from already-built per-component code slices.

    Used by the EntryPipeline path (static / enrichment / dynamic). The
    *payload* carries the upstream synthesis result, the per-component
    slices, and PDG-derived hints; the LLM extracts contiguous source
    snippets verbatim from the slices. Returns the parsed JSON object
    (``{"package", "entry", "summary", "locations": [...]}``) or ``None``
    on failure.
    """
    data_str = json.dumps(payload, indent=2, ensure_ascii=False)
    messages = _build_messages(
        MALICIOUS_LOCALIZATION_PROMPT, data_str, context_summary=context_summary
    )
    logger.info("[LLM] Malicious code localization (slice path)")
    try:
        return llm_call_json(messages, log_label="malicious localization (slice)")
    except ConnectionError:
        logger.warning("[LLM] Connection failed for malicious code localization")
        return None


def llm_locate_malicious_code_from_files(
    payload: dict, *, context_summary: str = ""
) -> dict | None:
    """Localize malicious code from full source files served during static fallback.

    Used by the StaticFallback path, which has no PBG / slice. The
    *payload* carries the fallback verdict reasoning plus the source
    contents of files cited as evidence; the LLM extracts contiguous
    source snippets verbatim from those files. Returns the parsed JSON
    object (``{"package", "entry", "summary", "locations": [...]}``) or
    ``None`` on failure.
    """
    data_str = json.dumps(payload, indent=2, ensure_ascii=False)
    messages = _build_messages(
        MALICIOUS_LOCALIZATION_FALLBACK_PROMPT, data_str, context_summary=context_summary
    )
    logger.info("[LLM] Malicious code localization (fallback path)")
    try:
        return llm_call_json(messages, log_label="malicious localization (fallback)")
    except ConnectionError:
        logger.warning("[LLM] Connection failed for malicious code localization (fallback)")
        return None


def extract_json_str_from_response(response: str) -> tuple[dict | list | None, str | None]:
    """Parse a JSON object/array out of an LLM response."""
    match = re.search(r"```(?:json)?\s*([\s\S]*?)\s*```", response)
    if match:
        json_str = match.group(1).strip()
    else:
        json_str = response.strip()

    json_str = json_str.strip()

    try:
        return json.loads(json_str), None
    except json.JSONDecodeError as e:
        err_msg = f"JSONDecodeError: {e}"
        logger.error(f"Failed to parse JSON from response: {e}")
        return None, err_msg
    except Exception as e:
        err_msg = f"{type(e).__name__}: {e}"
        logger.error(f"Unexpected error while parsing JSON: {e}")
        return None, err_msg


def llm_call_json(
    messages: list[dict],
    *,
    validator: Callable[[dict], str | None] | None = None,
    max_repair_attempts: int = 1,
    temperature: float = 0,
    log_label: str = "",
) -> dict | None:
    """Single-shot LLM call that returns a parsed JSON object, with self-repair."""
    label = log_label or "json call"
    answer = connect_with_retry(messages, temperature=temperature)
    parsed, parse_err = extract_json_str_from_response(answer)
    shape_err = validator(parsed) if (parsed is not None and validator) else None

    for attempt in range(1, max_repair_attempts + 1):
        if parsed is not None and shape_err is None:
            return parsed

        if parsed is None:
            err_hint = (
                f"your previous reply could not be parsed as JSON ({parse_err})"
                if parse_err
                else "your previous reply could not be parsed as JSON"
            )
        else:
            err_hint = f"your previous reply did not match the required schema: {shape_err}"
        logger.warning(
            f"[LLM] {label} requires repair (attempt {attempt}/{max_repair_attempts}): {err_hint}"
        )

        repair_messages = list(messages) + [
            {"role": "assistant", "content": answer or ""},
            {
                "role": "user",
                "content": (
                    f"Your previous reply could not be used: {err_hint}. "
                    "Re-emit the same content as a single JSON object that "
                    "matches the schema described in the system prompt. "
                    "Reply with JSON only — no Markdown, no code fences, "
                    "no commentary, no extra text before or after the JSON."
                ),
            },
        ]
        answer = connect_with_retry(repair_messages, temperature=temperature)
        parsed, parse_err = extract_json_str_from_response(answer)
        shape_err = validator(parsed) if (parsed is not None and validator) else None

    if parsed is None or shape_err is not None:
        logger.error(
            f"[LLM] {label} failed after {max_repair_attempts} repair "
            f"attempt(s); giving up and returning None"
        )
        return None
    return parsed


def max_token(input_string):
    tokens = enc.encode(str(input_string))
    if len(tokens) > 127000:
        return True
    else:
        return False


def connect_with_retry(prompt, max_attempts=5, delay=1, model=model_name, temperature=0):
    LLM_client = OpenAI(api_key=api_key, base_url=base_url)
    attempts = 0
    while attempts < max_attempts:
        try:
            completion = LLM_client.chat.completions.create(
                model=model,
                messages=prompt,
                temperature=0,
            )
            answer = completion.choices[0].message.content
            # Attempt to establish the connection here
            if attempts > max_attempts - 1:
                raise ConnectionError("Connection failed")
            else:
                return answer

        except Exception:
            attempts += 1
            if attempts < max_attempts:
                logger.warning(f"Retrying in {delay} seconds...")
                time.sleep(delay)

    # If max attempts are reached without successful connection, raise an exception
    raise ConnectionError("Failed to establish connection to OpenAI after maximum attempts")
