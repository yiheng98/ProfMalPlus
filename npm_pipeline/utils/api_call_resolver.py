"""Unified resolver that extracts structured arguments / return values from
an :class:`APICall` based on its sensitive-call domain.

Each domain delegates to a pure extraction function living in the
corresponding handler module.
"""

from npm_pipeline.classes.api_call import APICall, ResolvedAPICall
from npm_pipeline.handlers.file_handler import extract_file_op_args
from npm_pipeline.handlers.network_handler import extract_network_op_args
from npm_pipeline.handlers.subprocess_handler import extract_command_from_arguments


def resolve_api_call(
    api_call: APICall,
    sensitive_call: dict,
) -> ResolvedAPICall:
    """Build a :class:`ResolvedAPICall` by dispatching to the appropriate
    domain-specific extractor.

    For domains with dedicated extractors (Process / File / Network) the
    resolved arguments and return value are populated when extraction
    succeeds.
    """
    domain: str = sensitive_call["domain"]
    qualified_name: str = sensitive_call["qualified_name"]

    resolved_arguments = None
    resolved_return_value = None

    if domain == "Process":
        if api_call.arguments:
            command = extract_command_from_arguments(qualified_name, api_call.arguments)
            resolved_arguments = command

    elif domain == "File":
        result = extract_file_op_args(qualified_name, api_call.arguments, api_call.result)
        if result:
            resolved_arguments = result.get("arguments")
            resolved_return_value = result.get("return_value")

    elif domain == "Network":
        result = extract_network_op_args(qualified_name, api_call.arguments)
        if result:
            resolved_arguments = result.get("arguments")

    if resolved_arguments is None and api_call.arguments:
        resolved_arguments = api_call.arguments
    if resolved_return_value is None and api_call.result:
        resolved_return_value = api_call.result

    return ResolvedAPICall(
        api_call=api_call,
        qualified_name=qualified_name,
        domain=domain,
        sensitive_info=sensitive_call,
        resolved_arguments=resolved_arguments,
        resolved_return_value=resolved_return_value,
    )
