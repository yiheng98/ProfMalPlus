import json
import re

from loguru import logger

from base_classes.cpg_node import CPGNode
from base_classes.pdg_node import PDGNode
from call_type_dict import CONDITIONAL_CALL
from npm_pipeline.classes.api_call import ResolvedAPICall
from npm_pipeline.classes.serialized_types import SerializedAPIEntry
from npm_pipeline.utils.parameter_utils import get_str_from_parameter_list

logger = logger.bind(node_trace=True)

SMALL_CONTENT_THRESHOLD = 5000


_ARGS_ONLY_FILE_OPS = {
    "fs.createReadStream",
    "fs.createWriteStream",
    "fs.open",
    "fs/promises.open",
    "fs.openSync",
    "fs.readLink",
    "fs/promises.readlink",
    "fs.readlinkSync",
    "fs.glob",
    "fs.globSync",
    "fs/promises.glob",
    "fs.readdirSync",
    "fs.readdir",
    "fs/promises.readdir",
    "fs.rm",
    "fs/promises.rm",
    "fs.rmSync",
    "fs.unlink",
    "fs.unlinkSync",
    "fs/promises.unlink",
    "fs.exists",
    "fs.existsSync",
}

_WRITE_FILE_OPS = {
    "fs.appendFile",
    "fs.appendFileSync",
    "fs/promises.appendFile",
    "fs.writeFile",
    "fs.writeFileSync",
    "fs/promises.writeFile",
}

_READ_FILE_OPS = {
    "fs.readFile",
    "fs/promises.readFile",
    "fs.readFileSync",
}


def handle_file_op_in_static(
    current_node: PDGNode,
    qualified_name: str,
    parameters: list[CPGNode] | None,
):
    """Check whether parameters can be statically resolved; mark CONDITIONAL_CALL if not."""
    parameter_str_list = None
    if parameters:
        parameter_str_list = get_str_from_parameter_list(parameters)

    if not (parameter_str_list and len(parameter_str_list) > 0):
        return

    if qualified_name in _ARGS_ONLY_FILE_OPS:
        if not parameter_str_list[0]:
            current_node.set_call_type(CONDITIONAL_CALL)
            logger.debug(f"Need Dynamic in File Operation of code: {current_node.get_code()}")

    elif qualified_name in _WRITE_FILE_OPS:
        if not (len(parameter_str_list) > 1 and parameter_str_list[0] and parameter_str_list[1]):
            current_node.set_call_type(CONDITIONAL_CALL)
            logger.debug(f"Need Dynamic in File Operation of code: {current_node.get_code()}")

    elif qualified_name in _READ_FILE_OPS:
        current_node.set_call_type(CONDITIONAL_CALL)
        logger.debug(f"Need Dynamic in File Operation of code: {current_node.get_code()}")


def extract_file_op_args(
    qualified_name: str, arguments: str | None, return_value=None
) -> dict | None:
    """
    Extraction of file-operation arguments and return value.
    Returns ``{"arguments": ..., "return_value": ...}`` or ``None``.
    """
    if not arguments:
        return None

    if qualified_name in _ARGS_ONLY_FILE_OPS:
        return {"arguments": arguments}

    if qualified_name in _WRITE_FILE_OPS:
        try:
            parsed_arguments = json.loads(arguments)
            if isinstance(parsed_arguments, dict):
                path = parsed_arguments.get("path", "")
                data = parsed_arguments.get("data", "")
                if (
                    isinstance(data, dict)
                    and data.get("type") == "Buffer"
                    and isinstance(data.get("data"), list)
                ):
                    data = bytes(data["data"]).decode("utf-8")
                return {"arguments": {"path": path, "data": data}}
        except (json.JSONDecodeError, UnicodeDecodeError, ValueError, TypeError):
            pass
        return {"arguments": arguments}

    if qualified_name in _READ_FILE_OPS:
        return {"arguments": arguments, "return_value": str(return_value)}

    return None


def _is_binary_content(content: str) -> bool:
    if not content:
        return False
    sample = content[:1024]
    if "\x00" in sample:
        return True
    non_ascii = sum(1 for c in sample if ord(c) > 127)
    return (non_ascii / max(len(sample), 1)) > 0.3


_SHEBANG_RE = re.compile(
    r"^#!\s*(?:/usr/(?:local/)?bin/env\s+(?:-\S+\s+)*|/(?:usr/(?:local/)?)?bin/)(\w+)"
)

_SHEBANG_LANG_MAP: dict[str, str] = {
    "bash": "shell",
    "sh": "shell",
    "zsh": "shell",
    "dash": "shell",
    "fish": "shell",
    "node": "javascript",
    "nodejs": "javascript",
    "python": "python",
    "python3": "python",
}

_HTML_RE = re.compile(r"^\s*(?:<!doctype\s|<html[\s>])", re.IGNORECASE)
_XML_RE = re.compile(r"^\s*<\?xml\b", re.IGNORECASE)

_JS_RE = re.compile(
    r"\brequire\s*\("
    r"|\bmodule\.exports\b"
    r"|\bexport\s+(?:default|function|class|const|let|var)\b"
    r"|\bimport\s+.+?\bfrom\s+['\"]"
    r"|\b(?:const|let|var)\s+\w+\s*="
    r"|\bfunction\s+\w+\s*\("
    r"|=>\s*[{(]"
)

_SHELL_RE = re.compile(
    r"^\s*(?:if\s+\[|for\s+\w+\s+in\b|while\s+\[|case\s+\S+\s+in\b)"
    r"|^\s*\w+=\S"
    r"|^\s*(?:echo|export|source|alias|eval)\s+",
    re.MULTILINE,
)


def _classify_text_type(content: str) -> str:
    stripped = content.strip()

    shebang_m = _SHEBANG_RE.match(stripped)
    if shebang_m:
        interp = shebang_m.group(1).lower()
        lang = _SHEBANG_LANG_MAP.get(interp)
        if lang:
            return lang

    if stripped.startswith(("{", "[")):
        try:
            json.loads(stripped)
            return "json"
        except (json.JSONDecodeError, ValueError):
            pass

    if _HTML_RE.match(stripped):
        return "html"
    if _XML_RE.match(stripped):
        return "xml"

    head = content[:1000]
    if _JS_RE.search(head):
        return "javascript"
    if _SHELL_RE.search(head):
        return "shell"

    return "plain_text"


def _preprocess_file_content(content) -> str | dict | None:
    """Return content as-is (Tier 0), a metadata dict (Tier 1 text), or a
    binary indicator string (Tier 1 binary).  Returns ``None`` for empty."""
    if content is None:
        return None
    s = str(content)
    if not s:
        return None
    if len(s) <= SMALL_CONTENT_THRESHOLD:
        return s
    if _is_binary_content(s):
        return f"[binary data, {len(s)} bytes]"
    return {"content_type": _classify_text_type(s), "size": len(s)}


def serialize_file_domain(resolved: ResolvedAPICall, category: str) -> SerializedAPIEntry:
    qname = resolved.qualified_name
    args: dict = {}

    if qname in _WRITE_FILE_OPS:
        if isinstance(resolved.resolved_arguments, dict):
            path = resolved.resolved_arguments.get("path")
            if path:
                args["file_path"] = str(path)
            data = resolved.resolved_arguments.get("data")
            if data is not None:
                processed = _preprocess_file_content(data)
                if processed is not None:
                    args["write_content"] = processed
    elif qname in _READ_FILE_OPS:
        if resolved.resolved_arguments is not None:
            args["file_path"] = str(resolved.resolved_arguments)
        if resolved.resolved_return_value is not None:
            processed = _preprocess_file_content(resolved.resolved_return_value)
            if processed is not None:
                args["read_content"] = processed
    elif qname in _ARGS_ONLY_FILE_OPS:
        if resolved.resolved_arguments is not None:
            args["file_path"] = str(resolved.resolved_arguments)

    return SerializedAPIEntry(
        qualified_name=qname,
        domain="File",
        category=category,
        arguments=args or None,
    )
