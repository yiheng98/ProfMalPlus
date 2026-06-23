import re

from loguru import logger

from base_classes.pbg import PBG
from base_classes.pdg_node import PDGNode
from call_type_dict import UNRESOLVED_CALL
from npm_pipeline.classes.analysis_context import AnalysisContext
from npm_pipeline.classes.file_context import FileContext
from npm_pipeline.classes.object import Object
from npm_pipeline.utils.pdg_utils import (
    find_pdg_by_file,
    merge_pbg,
    resolve_callee_via_call_expression,
)
from object_type_dict import THIRD_PARTY_MODULE

logger = logger.bind(node_trace=True)


def process_require(
    current_node: PDGNode,
    file_context: FileContext,
    program_behavior: PBG,
    analysis_context: AnalysisContext,
    stage: str,
):
    """
    check the `require` and base on the call graph to locate
    """
    require_code = current_node.get_code()
    file = current_node.get_file_name()
    start_line = current_node.get_line_number() - 1
    logger.info(
        f"Require Call of code: {require_code}, in file: {file}, start line: {start_line}, node id: {current_node.get_id()}"
    )
    callees = resolve_callee_via_call_expression(current_node, analysis_context)
    for callee in callees:
        logger.info(
            f"Find the callee in require :{require_code} in file: {current_node.get_file_name()}, line: {current_node.get_line_number()}"
        )
        file_of_callee = callee.file

        # skip recursing into modules located under `node_modules`
        if "node_modules" in file_of_callee.replace("\\", "/").split("/"):
            logger.info(
                f"Skip entering node_modules dependency: {file_of_callee} of {require_code}"
            )
            continue

        # go into the module being required and analyze it
        pdg_of_callee = find_pdg_by_file(file_of_callee, analysis_context.current_code_info)
        if pdg_of_callee is None:
            logger.warning(
                f"Can not find the pdg of the required module: {file_of_callee} of {require_code}"
            )
            logger.info("Need Dynamic of unknown require")
            current_node.set_call_type(UNRESOLVED_CALL)
            current_node.set_unresolved_call_dict("require")
            # analysis_context.need_dynamic = True
            # Do not return in the 1->N case, so other callees and require-argument parsing below can continue.
            continue

        if pdg_of_callee in analysis_context.loaded_history:
            continue
        analysis_context.loaded_history.add(pdg_of_callee)

        # Delay import to avoid circular dependencies.
        from npm_pipeline.utils.behavior_gen_utils import gen_behavior

        new_program_behavior = PBG(
            analysis_context.current_code_info.cpg,
            analysis_context.current_code_info.pdg_dict,
            analysis_context.current_code_info.formatted_package_dir,
            analysis_context.package_name,
        )
        program_behavior_of_require = gen_behavior(
            file_of_callee,
            pdg_of_callee,
            "implicit main",
            new_program_behavior,
            None,
            analysis_context,
            stage,
        )
        program_behavior.add_pdg_edge(
            current_node.get_id(),
            program_behavior_of_require.get_entrance_node().get_id(),
            ["CFG"],
        )

        # merge the behavior of the required module into the current behavior
        merge_pbg(program_behavior, program_behavior_of_require)

    # get the argument of the `require` or the full name is `require`
    parameters = analysis_context.current_code_info.cpg.get_argument_from_joern(
        current_node.get_id()
    )
    if parameters:
        if len(parameters) == 1 and parameters[0].get_value("label") == "LITERAL":
            argument_str = parameters[0].get_value("CODE").strip("\"'")
            pattern = r"node:(.*)"
            match = re.search(pattern, argument_str)
            if match:
                import_module_str = match.group(1)
            else:
                import_module_str = argument_str
            logger.info(
                f"[require] Call with argument of {import_module_str} in file: {current_node.get_file_name()}, line: {current_node.get_line_number()}"
            )
            _is_core_module = is_core_module(import_module_str)
            if _is_core_module:
                core_module_object = file_context.get_core_module_object(import_module_str)
                current_node.set_qualified_path((core_module_object, []))
            else:
                # Determine whether this is a third-party module rather than a local file.
                if is_third_party_module(import_module_str):
                    logger.info(
                        f"[require] Third-party module detected: {import_module_str} in file {current_node.get_file_name()}, line: {current_node.get_line_number()}"
                    )
                    third_party_module_object = Object(
                        name=import_module_str,
                        object_type=THIRD_PARTY_MODULE,
                        source_pdg=current_node.get_source_pdg(),
                    )
                    # Check whether this third-party module exists in dependencies by extracting the base package name first.
                    base_pkg = get_base_package_name(import_module_str)
                    third_party_dependencies = analysis_context.package_json.get_dependencies()
                    if third_party_dependencies and base_pkg in third_party_dependencies:
                        # Normalize qualified_name to dot form: base + "." + subpath.
                        subpath = import_module_str[len(base_pkg) :].lstrip("/")
                        qualified = (
                            base_pkg if not subpath else f"{base_pkg}.{subpath.replace('/', '.')}"
                        )
                        third_party_module_object.set_qualified_name(qualified)
                        analysis_context.third_party_module_name.add(base_pkg)
                    file_context.add_object(third_party_module_object)
                    current_node.set_qualified_path((third_party_module_object, []))
                else:
                    pass

        else:
            logger.info(
                f"The argument of the require is not a string: {require_code} in file: {current_node.get_file_name()}, line: {current_node.get_line_number()}, need dynamic execution."
            )
            # analysis_context.need_dynamic = True
            current_node.set_call_type(UNRESOLVED_CALL)
            current_node.set_unresolved_call_dict("require")


def is_core_module(module_name: str) -> bool:
    """
    check the module is core module
    """
    builtin_module_list = [
        "assert",
        "buffer",
        "child_process",
        "cluster",
        "crypto",
        "dgram",
        "dns",
        "domain",
        "events",
        "fs",
        "fs/promises",
        "http",
        "https",
        "net",
        "os",
        "path",
        "punycode",
        "querystring",
        "readline",
        "stream",
        "string_decoder",
        "timers",
        "tls",
        "tty",
        "url",
        "util",
        "v8",
        "vm",
        "zlib",
    ]
    if module_name in builtin_module_list:
        return True
    else:
        return False


def is_third_party_module(module_name: str) -> bool:
    """
    Determine whether a module is third-party rather than local.
    Check whether the module name contains path-like specifiers.

    True: third-party module.
    False: local file.
    """
    # Path-like specifier checks.
    # Relative path: starts with . or ...
    if module_name.startswith("."):
        return False
    # Absolute path: starts with / on Unix.
    if module_name.startswith("/"):
        return False
    # Windows absolute path, such as C:\path.
    if len(module_name) > 1 and module_name[1] == ":":
        return False
    # No path-like specifier is present, so this is a third-party module.
    return True


def get_base_package_name(module_str: str) -> str:
    """
    Extract the base npm package name from an import specifier.

    `lodash/debounce`  -> `lodash`
    `@scope/pkg/sub`   -> `@scope/pkg`
    `lodash`           -> `lodash`
    """
    parts = module_str.split("/")
    if module_str.startswith("@") and len(parts) >= 2:
        return "/".join(parts[:2])
    return parts[0]
