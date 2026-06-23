import json
import re

from loguru import logger

from base_classes.cpg_node import CPGNode
from base_classes.pdg_node import PDGNode
from call_type_dict import CONDITIONAL_CALL
from npm_pipeline.utils.parameter_utils import get_str_from_parameter_list

logger = logger.bind(node_trace=True)

_NETWORK_OPS = {
    "net.Socket",  # not need to check param
    "net.connect",
    "net.Socket.connect",
    "net.createConnection",
    "net.createServer",  # not need to check param
    "https.get",
    "https.request",
    "https.createServer",
    "http.createServer",
    "http.get",
    "http.request",
    "dns.lookup",
    "dns.lookupService",
    "dns.setServers",
    "dns.resolve",
    "dns.resolve4",
    "dns.resolve6",
    "dns.resolveAny",
    "dns.resolveCaa",
    "dns.resolveCname",
    "dns.resolveMx",
    "dns.resolveNaptr",
    "dns.resolveNs",
    "dns.resolvePtr",
    "dns.resolveSoa",
    "dns.resolveSrv",
    "dns.resolveTxt",
}


def handle_network_op_in_static(
    current_node: PDGNode, qualified_name: str, parameters: list[CPGNode] | None
):
    """Check whether parameters can be statically resolved; mark CONDITIONAL_CALL if not."""
    if qualified_name not in _NETWORK_OPS:
        return

    if qualified_name in ("net.Socket", "net.createServer"):
        return

    if parameters:
        parameter_str_list = get_str_from_parameter_list(parameters)
        if parameter_str_list and None not in parameter_str_list:
            return
    current_node.set_call_type(CONDITIONAL_CALL)
    logger.debug(f"Need Dynamic in Network Operation of code: {current_node.get_code()}")


def extract_network_op_args(qualified_name: str, arguments: str | None) -> dict | None:
    """
    extraction of network-operation arguments.
    """
    if not arguments:
        return None

    if qualified_name == "https.request":
        network_info = _parse_network_arguments(arguments)
        if network_info:
            return {"arguments": network_info}

    elif qualified_name in [
        "net.Socket.connect",
        "dns.resolveAny",
        "dns.resolveCaa",
        "dns.resolveCname",
        "dns.resolveMx",
        "dns.resolveNaptr",
        "dns.resolveNs",
        "dns.resolvePtr",
        "dns.resolveSoa",
        "dns.resolveSrv",
        "dns.resolveTxt",
    ]:
        hostname = _extract_first_str_arg(arguments)
        if hostname:
            return {"arguments": hostname}

    elif qualified_name == "net.connect":
        net_connect_info = _parse_net_connect_arguments(arguments)
        if net_connect_info:
            return {"arguments": net_connect_info}

    elif qualified_name == "net.createConnection":
        first_dict = _extract_first_dict_arg(arguments)
        if first_dict:
            return {"arguments": first_dict}

    elif qualified_name == "https.get":
        parsed = _parse_https_get_arguments(arguments)
        if parsed:
            return {"arguments": parsed}

    elif qualified_name == "dns.lookup":
        return {"arguments": arguments}

    elif qualified_name == "dns.lookupService":
        try:
            parsed = json.loads(arguments)
        except (json.JSONDecodeError, TypeError):
            parsed = arguments
        if isinstance(parsed, dict):
            return {"arguments": parsed}

    elif qualified_name in ["dns.resolve", "dns.resolve4", "dns.resolve6"]:
        args_before_null = _extract_args_before_null(arguments)
        if args_before_null:
            return {"arguments": args_before_null}

    elif qualified_name == "dns.setServers":
        try:
            servers = json.loads(arguments)
        except (json.JSONDecodeError, TypeError):
            servers = None
        if isinstance(servers, list) and servers:
            return {"arguments": servers}

    return None


def _extract_args_before_null(arguments: str) -> list | None:
    """Extract all arguments before the first null from a JSON argument list."""
    try:
        args_list = json.loads(arguments)
    except (json.JSONDecodeError, TypeError):
        return None
    if not isinstance(args_list, list):
        return None
    result = []
    for arg in args_list:
        if arg is None:
            break
        result.append(arg)
    return result or None


def _parse_https_get_arguments(arguments: str) -> dict | None:
    """Parse https.get arguments.

    Two forms:
      1. {"input": {"hostname":..., "port":..., ...}}           -> return {"input": ...}
      2. {"input": "https://...", "options": {"headers": ...}}  -> return {"input": ..., "options": ...}
    """
    try:
        args_obj = json.loads(arguments)
    except (json.JSONDecodeError, TypeError):
        return None
    if not isinstance(args_obj, dict) or "input" not in args_obj:
        return None

    input_val = args_obj["input"]
    if isinstance(input_val, dict):
        return {"input": input_val}
    if isinstance(input_val, str):
        result: dict = {"input": input_val}
        if "options" in args_obj:
            result["options"] = args_obj["options"]
        return result
    return None


def _extract_first_dict_arg(arguments: str) -> dict | None:
    """Extract the first dict argument from a JSON argument list like '[{\"port\":3000,\"host\":\"127.0.0.1\"},null]'."""
    try:
        args_list = json.loads(arguments)
    except (json.JSONDecodeError, TypeError):
        return None
    if isinstance(args_list, list) and len(args_list) > 0 and isinstance(args_list[0], dict):
        return args_list[0]
    return None


def _parse_net_connect_arguments(arguments: str) -> dict | list | None:
    """Parse net.connect arguments.

    Two forms:
      1. [{\"host\":\"127.0.0.1\",\"port\":3000}, null]  -> return the dict
      2. [3000, \"127.0.0.1\", null]                      -> return non-null values as list
    """
    try:
        args_list = json.loads(arguments)
    except (json.JSONDecodeError, TypeError):
        return None
    if not isinstance(args_list, list) or len(args_list) == 0:
        return None

    first_arg = args_list[0]
    if isinstance(first_arg, dict):
        return first_arg
    return [arg for arg in args_list if arg is not None] or None


def _extract_first_str_arg(arguments: str) -> str | None:
    """Extract the first string argument from a JSON argument list like '[\"example.com\",null]'."""
    try:
        args_list = json.loads(arguments)
    except (json.JSONDecodeError, TypeError):
        return None
    if isinstance(args_list, list) and len(args_list) > 0 and isinstance(args_list[0], str):
        return args_list[0]
    return None


_URL_FIELD_PATTERNS = {
    "protocol": re.compile(r'"protocol"\s*:\s*"([^"]*)"'),
    "hostname": re.compile(r'"hostname"\s*:\s*"([^"]*)"'),
    "path": re.compile(r'"path"\s*:\s*"([^"]*)"'),
    "port": re.compile(r'"port"\s*:\s*(?:"([^"]*)"|(\d+)|null)'),
}


def _regex_extract_url_fields(arguments: str) -> dict | None:
    """Best-effort extraction of protocol/hostname/port/path from malformed JSON."""
    result: dict = {}
    for key, pat in _URL_FIELD_PATTERNS.items():
        m = pat.search(arguments)
        if not m:
            continue
        if key == "port":
            val = m.group(1) if m.group(1) is not None else m.group(2)
        else:
            val = m.group(1)
        if val:
            result[key] = val
    return result or None


def _parse_network_arguments(arguments: str) -> dict | None:
    """Parse arguments string into a dict with network request info.

    Handles two calling conventions:
      1. https.request(url[, options][, callback])  -> first arg is a URL string
      2. https.request(options[, callback])          -> first arg is an options object

    """
    try:
        args_list = json.loads(arguments)
    except (json.JSONDecodeError, TypeError):
        logger.info("Failed to JSON-parse network arguments, falling back to regex extraction")
        return _regex_extract_url_fields(arguments)

    if not isinstance(args_list, list) or len(args_list) == 0:
        return None

    first_arg = args_list[0]

    if isinstance(first_arg, str):
        return {"url": first_arg}

    if isinstance(first_arg, dict):
        result = {}
        for key in ("protocol", "hostname", "port", "path"):
            if key in first_arg:
                result[key] = first_arg[key]
        if result:
            return result

    return None
