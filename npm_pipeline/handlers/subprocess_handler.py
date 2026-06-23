import json
import os
import re

from loguru import logger

import llm
from base_classes.cpg_node import CPGNode
from base_classes.pbg import PBG
from base_classes.pdg_node import PDGNode
from call_type_dict import CONDITIONAL_CALL
from npm_pipeline.classes.analysis_context import AnalysisContext
from npm_pipeline.utils.parameter_utils import get_str_from_parameter_list
from npm_pipeline.utils.pdg_utils import (
    find_pdg_by_file,
    merge_pbg,
)

logger = logger.bind(node_trace=True)

_JS_EXEC_QUALIFIED_NAMES = {
    "child_process.exec",
    "child_process.execSync",
    "child_process.spawn",
    "child_process.spawnSync",
    "child_process.fork",
}

# The dynamic instrumentation (Jelly + nodeprof, see ``profMal_hyh/node`` and
# ``dyn.js``) re-invokes every child process through the Jelly wrapper, which
# substitutes ``process.execPath`` / ``npm_node_execpath`` with the wrapper
# and re-applies its nodeprof flags. As a result the runtime trace captured
# for ``child_process.{fork,spawn,exec,...}`` looks like::
#
#   /usr/lib/node_modules/@cs-au-dk/jelly/bin/node \
#       --log.file=/tmp/truffle.log --jvm --experimental-options --nodeprof \
#       --log.file=/tmp/truffle.log --jvm --experimental-options --nodeprof \
#       <GRAAL>/tools/nodeprof/jalangi.js --analysis <jelly>/lib/dynamic/dyn.js \
#       --exec-path <jelly>/bin/node scripts/rsh.js
#
# Semantically this is just ``node scripts/rsh.js``. ``_strip_jelly_wrapper``
# normalises it so the LLM judge / verifier and the "Resolved arguments:" log
# line see the original user-intended command instead of instrumentation
# noise.
# The wrapper binary and its instrumentation flags always appear as a single
# contiguous block at the head of the argv (the duplicated flag run is just
# ``process.execArgv`` being inherited and re-applied by the wrapper). They
# are matched together as one anchored regex so that:
_JELLY_WRAPPER_NODE = r"(?:\S*@cs-au-dk/jelly/bin/node|\S*graal\S*/bin/node)"
_JELLY_WRAPPER_FLAG = (
    r"(?:"
    r"--log\.file=\S+"
    r"|--jvm"
    r"|--experimental-options"
    r"|--nodeprof"
    r"|--use[-_]strict"
    r"|--analysis(?:=\S+|\s+\S+)"
    r"|--exec-path(?:=\S+|\s+\S+)"
    r"|\S*nodeprof/jalangi\.js"
    r"|\S*jelly/lib/dynamic/dyn\.js"
    r")"
)
_JELLY_WRAPPER_RE = re.compile(rf"{_JELLY_WRAPPER_NODE}(?:\s+{_JELLY_WRAPPER_FLAG})*")


def _strip_jelly_wrapper(command: str | None) -> str | None:
    """Replace the Jelly + nodeprof wrapper preamble with a bare ``node``.

    Anchors on the wrapper binary path and greedily consumes the contiguous
    run of instrumentation flags that always follows it; standalone flags
    in a real user command are left untouched.
    """
    if not command:
        return command
    cleaned = _JELLY_WRAPPER_RE.sub("node", command)
    cleaned = re.sub(r"\s+", " ", cleaned).strip()
    return cleaned


def process_subprocess_command(
    current_node: PDGNode,
    program_behavior: PBG,
    qualified_name: str,
    command_str: str,
    analysis_context: AnalysisContext,
    stage: str,
):
    """
    Uses LLM to determine whether the command launches Node.js to execute JS files.
    If yes, generates and merges behavior for each JS file.
    Otherwise, falls back to LLM-based sensitivity analysis of the command itself.
    """
    js_files = []

    if qualified_name in _JS_EXEC_QUALIFIED_NAMES:
        node_exec_result = llm.llm_node_execution_interpret(qualified_name, command_str)
        js_files = node_exec_result["js_files"]

    if js_files:
        from npm_pipeline.utils.behavior_gen_utils import gen_behavior

        for file_name in js_files:
            file_path = os.path.join("package", file_name)
            if (
                file_path not in analysis_context.current_code_info.files
                or file_path == current_node.get_file_name()
            ):
                continue

            pdg_of_script = find_pdg_by_file(file_path, analysis_context.current_code_info)
            if pdg_of_script:
                subprocess_behavior = PBG(
                    analysis_context.current_code_info.cpg,
                    analysis_context.current_code_info.pdg_dict,
                    analysis_context.current_code_info.formatted_package_dir,
                    analysis_context.package_name,
                )
                program_behavior_of_subprocess = gen_behavior(
                    pdg_of_script.get_file_name(),
                    pdg_of_script,
                    "implicit main",
                    subprocess_behavior,
                    None,
                    analysis_context,
                    stage,
                )
                if program_behavior_of_subprocess:
                    program_behavior.add_pdg_edge(
                        current_node.get_id(),
                        program_behavior_of_subprocess.get_entrance_node().get_id(),
                        ["CFG", "DDG"],
                    )
                    merge_pbg(program_behavior, program_behavior_of_subprocess)
            else:
                logger.warning(
                    f"Can not find the pdg of target file in Process Execution of the command: {command_str}"
                )


def handle_subprocess_in_static(
    current_node: PDGNode,
    program_behavior: PBG,
    qualified_name: str,
    parameters: list[CPGNode] | None,
    analysis_context: AnalysisContext,
    stage: str,
):
    """Handle the subprocess call in static phase."""
    if parameters:
        parameter_str_list = get_str_from_parameter_list(parameters)
        if parameter_str_list and len(parameter_str_list) > 0 and None not in parameter_str_list:
            command_str = " ".join(parameter_str_list)
        else:
            command_str = None
    else:
        command_str = None

    if command_str is None:
        if "pipe" in qualified_name:
            return

        logger.debug("The Command String is None or not a pure command, Need Dynamic")
        current_node.set_call_type(CONDITIONAL_CALL)

        # Fallback: even when the literal command cannot be statically resolved,
        # hand the call-site source snippet to the LLM.
        if qualified_name in _JS_EXEC_QUALIFIED_NAMES:
            code = current_node.get_code()
            if code:
                process_subprocess_command(
                    current_node,
                    program_behavior,
                    qualified_name,
                    code,
                    analysis_context,
                    stage,
                )
        return

    process_subprocess_command(
        current_node, program_behavior, qualified_name, command_str, analysis_context, stage
    )


def extract_command_from_arguments(qualified_name: str, arguments_str: str) -> str | None:
    """Parse the dynamic-trace arguments string and reconstruct the command.

    Arguments formats from dynamic instrumentation:
      - exec / execSync / fork: JSON array, first element is the command / module path
        e.g. '["node script.js", null]' or '["./worker.js", [], null]'
      - spawn / spawnSync: JSON object with "file" and "args" keys
        e.g. '{"file": "node", "args": ["script.js"]}'
        or JSON array where first element is the executable and second is args list
        e.g. '["node", ["script.js"], null]'
    """
    if isinstance(arguments_str, str) and not arguments_str.lstrip().startswith(("[", "{")):
        return _strip_jelly_wrapper(arguments_str)

    try:
        data = json.loads(arguments_str)
    except (json.JSONDecodeError, TypeError):
        logger.warning(f"Failed to parse subprocess arguments: {arguments_str}")
        return _strip_jelly_wrapper(arguments_str)

    if qualified_name in ["child_process.spawn", "child_process.spawnSync"]:
        if isinstance(data, dict):
            file = data.get("file")
            args = data.get("args", [])
        elif isinstance(data, list) and len(data) >= 1:
            file = data[0] if isinstance(data[0], str) else None
            args = data[1] if len(data) >= 2 else []
        else:
            return None

        if not file:
            return None

        parts = [file]
        if isinstance(args, (list, tuple)):
            parts.extend(str(a) for a in args)
        elif isinstance(args, dict):
            for key, value in args.items():
                if key.lower() in ("encoding", "shell"):
                    continue
                parts.append(str(value))
        else:
            parts.append(str(args))
        return _strip_jelly_wrapper(" ".join(parts))

    if isinstance(data, list) and len(data) >= 1 and isinstance(data[0], str):
        return _strip_jelly_wrapper(data[0])

    return None


def handle_subprocess_in_dynamic(
    current_node: PDGNode,
    program_behavior: PBG,
    qualified_name: str,
    arguments_str: str | None,
    analysis_context: AnalysisContext,
    stage: str,
) -> str | None:
    """Handle the subprocess for calling js file in dynamic phase.

    Returns the reconstructed command string, or None if arguments could not be parsed.
    """
    if not arguments_str:
        return None

    command_str = extract_command_from_arguments(qualified_name, arguments_str)

    if command_str is None:
        if "pipe" not in qualified_name:
            logger.debug("Failed to extract command from dynamic arguments")
        return None

    process_subprocess_command(
        current_node, program_behavior, qualified_name, command_str, analysis_context, stage
    )

    return command_str
