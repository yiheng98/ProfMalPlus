from loguru import logger

from ast_parser import ASTParser
from base_classes.cpg_node import CPGNode
from base_classes.pbg import PBG
from base_classes.pdg import PDG
from base_classes.pdg_node import PDGNode
from call_type_dict import CONDITIONAL_CALL, THIRD_PARTY_CALL, UNRESOLVED_CALL
from instance_method import is_instance_method
from npm_pipeline.classes.analysis_context import AnalysisContext
from npm_pipeline.classes.file_context import FileContext
from npm_pipeline.classes.object import Object
from npm_pipeline.handlers.file_handler import handle_file_op_in_static
from npm_pipeline.handlers.network_handler import handle_network_op_in_static
from npm_pipeline.handlers.subprocess_handler import handle_subprocess_in_static
from npm_pipeline.processors.require_processor import process_require
from npm_pipeline.utils.parameter_utils import get_parameter_send_list
from npm_pipeline.utils.pdg_utils import (
    find_pdg_by_method_full_name,
    merge_pbg,
)
from object_type_dict import GLOBAL_OBJECT, OBJECT
from sensitive_op import sensitive_call_finder

logger = logger.bind(node_trace=True)


def process_external_or_unresolved_call(
    current_node: PDGNode,
    pdg: PDG,
    file_context: FileContext,
    program_behavior: PBG,
    parameters: list[CPGNode],
    is_lambda: bool,
    lambda_pdg: PDG | None,
    call_name: str | None,
    analysis_context: AnalysisContext,
    stage: str,
):
    """
    Handle built-in module calls or missing call-edge cases:
    - Try to resolve the full call name from the PDG or source code.
    """

    if stage == "dynamic" and current_node.get_resolved_api_call() is None:
        from npm_pipeline.utils.behavior_gen_utils import handle_api_call_in_dynamic

        handle_api_call_in_dynamic(
            current_node,
            pdg,
            call_name,
            file_context,
            program_behavior,
            False,
            None,
            analysis_context,
            stage,
        )
        if (
            current_node.get_resolved_api_call() is not None
            or current_node.get_qualified_path() is not None
        ):
            # Dynamic resolution successfully attached sensitive-call info or
            # a qualified path. Skip the static-style fallback below since it
            # would otherwise overwrite the runtime-derived qualified_path
            # (and may mark the node as UNRESOLVED).
            if is_lambda:
                from npm_pipeline.utils.behavior_gen_utils import process_function_callee

                lambda_behavior = process_function_callee(
                    current_node,
                    lambda_pdg,
                    file_context,
                    pdg,
                    program_behavior,
                    analysis_context,
                    stage,
                    is_lambda=True,
                )
                if lambda_behavior:
                    merge_pbg(program_behavior, lambda_behavior)
                    current_node.set_behavior_of_call(lambda_behavior)
            return

    code = current_node.get_code()
    first_ast_node = analysis_context.current_code_info.cpg.get_first_ast_node_in_call(
        current_node.get_id()
    )
    node_qualified_path = None
    first_ast_pdg_node = None

    if first_ast_node and first_ast_node.get_id() in pdg.get_nodes():
        first_ast_pdg_node = pdg.get_node(first_ast_node.get_id())
        if first_ast_pdg_node.get_node_type() == "IDENTIFIER":
            found_identifier = file_context.find_identifier(
                first_ast_pdg_node.get_name(), current_node.get_line_number()
            )
            if found_identifier:
                node_qualified_path = (found_identifier.get_ref_object(), [])
        else:
            frist_ast_node_qualified_path = first_ast_pdg_node.get_qualified_path()
            if frist_ast_node_qualified_path:
                node_qualified_path = (
                    frist_ast_node_qualified_path[0],
                    list(frist_ast_node_qualified_path[1]),
                )
        current_node.set_qualified_path(node_qualified_path)
        program_behavior.add_pdg_edge(
            first_ast_pdg_node.get_id(),
            current_node.get_id(),
            [f"DDG: {first_ast_pdg_node.get_code()}"],
        )
    else:
        # the ast of the call is not at the pdg
        parser = ASTParser(code.strip())
        single_identifier = parser.get_identifier_in_call_expression()
        if single_identifier:
            found_identifier = file_context.find_identifier(
                single_identifier, current_node.get_line_number()
            )
            if found_identifier:
                ref_object = found_identifier.get_ref_object()
                current_node.set_qualified_path((ref_object, []))
                program_behavior.add_object_to_pdg_edge(ref_object, current_node.get_id())
        else:
            # If no single identifier found, then check for identifier and property in call expression
            identifier, property_identifier = parser.get_identifier_property_in_call_expression()
            if identifier and property_identifier:
                ref_object = file_context.find_global_object(identifier)
                if ref_object:
                    if (
                        ref_object.get_name() == "Object"
                        and ref_object.get_object_type() == GLOBAL_OBJECT
                        and property_identifier == "create"
                    ):
                        # `Object.create(...)` creates a new object.
                        new_object = Object(
                            name=f"Object.create-{current_node.get_id()}",
                            object_type=OBJECT,
                            source_pdg=current_node.get_source_pdg(),
                            qualified_name=None,
                        )
                        file_context.add_object(new_object)
                        node_qualified_path = (new_object, [])
                        current_node.set_qualified_path(node_qualified_path)
                        return
                    else:
                        node_qualified_path = (ref_object, [property_identifier])
                        current_node.set_qualified_path(node_qualified_path)
            else:
                pass

    # If the full call name cannot be determined, mark it for dynamic analysis.
    if current_node.get_qualified_path() is None:
        if call_name is None or not is_instance_method(call_name):
            current_node.set_call_type(UNRESOLVED_CALL)
            current_node.set_unresolved_call_dict(call_name)
            if stage == "static":
                logger.info(
                    f"🔴[Dynamic] The qualified name of the call: {code} is None, need dynamic. "
                    f"Node id: {current_node.get_id()}, pdg: {pdg.pdg_path}"
                )
    else:
        actual_value = current_node.get_qualified_path()[0].get_property_actual_value(
            current_node.get_qualified_path()[1]
        )
        if isinstance(actual_value, Object):
            actual_value = actual_value.get_qualified_name()
            if actual_value is None:
                # A wildcard was hit but qn is still None; fall back to base + property_list.
                # Compose the longest recognizable prefix so sensitive detection is not permanently lost.
                _base, _plist = current_node.get_qualified_path()
                actual_value = _base.compose_qualified_string(_plist)
        else:
            if (
                parameters
                and actual_value is not None
                and (
                    actual_value.endswith("push")
                    or actual_value.endswith("unshift")
                    or actual_value.endswith("splice")
                )
            ):
                program_behavior.add_pdg_to_object_data_edge(
                    current_node.get_id(), node_qualified_path[0]
                )

        if actual_value is None:
            if call_name is not None and is_instance_method(call_name):
                pass
            else:
                current_node.set_call_type(UNRESOLVED_CALL)
                current_node.set_unresolved_call_dict(call_name)
                if stage == "static":
                    logger.info(
                        f"🔴[Dynamic] The qualified name of the call: {code} is None, need dynamic. "
                        f"Node id: {current_node.get_id()}, pdg: {pdg.pdg_path}"
                    )
        else:
            if actual_value.split(".")[0] in analysis_context.third_party_module_name:
                # Current Call is a third-party module call.
                if call_name and call_name not in ["then", "catch", "finally"]:
                    current_node.set_call_type(THIRD_PARTY_CALL)
                    current_node.set_third_party_call_dict(
                        call_name, actual_value.split(".")[0], ".".join(actual_value.split(".")[1:])
                    )
                    if stage == "static":
                        # Record this in the cross-phase set so the dynamic phase can tell whether this node was handled during static analysis.
                        analysis_context.static_third_party_visited_nodes.add(current_node.get_id())
            elif actual_value == "require":
                process_require(
                    current_node,
                    file_context,
                    program_behavior,
                    analysis_context,
                    stage,
                )
            elif actual_value == "eval":
                logger.debug(
                    f"Find `eval` Call, Node id: {current_node.get_id()}, pdg: {pdg.pdg_path}"
                )

                current_node.set_call_type(CONDITIONAL_CALL)
                current_node.set_unresolved_call_dict("eval")
                sensitive_call_info = sensitive_call_finder.query("global.eval")
                if sensitive_call_info:
                    logger.debug(
                        f"[Sensitive Call] code: {code}, qualified name: {sensitive_call_info['qualified_name']}"
                    )
                    current_node.set_sensitive_node(True)
                    current_node.set_sensitive_dict(sensitive_call_info, call_name)
            elif actual_value == "fetch":
                sensitive_call_info = sensitive_call_finder.query("global.fetch")
                if sensitive_call_info:
                    logger.debug(f"[Sensitive Call] code: {code}, qualified name: global.fetch")
                    current_node.set_sensitive_node(True)
                    current_node.set_sensitive_dict(sensitive_call_info, call_name)
            elif actual_value == "Function":
                sensitive_call_info = sensitive_call_finder.query("global.Function")
                if sensitive_call_info:
                    logger.debug(
                        f"[Sensitive Call] code: {code}, qualified name: {sensitive_call_info['qualified_name']}"
                    )
                    current_node.set_sensitive_node(True)
                    current_node.set_sensitive_dict(sensitive_call_info, call_name)
            elif actual_value == "setTimeout":
                function_behavior = handle_set_time_out(
                    current_node,
                    parameters,
                    file_context,
                    program_behavior,
                    pdg,
                    analysis_context,
                    stage,
                )
                if function_behavior:
                    merge_pbg(program_behavior, function_behavior)
            else:
                sensitive_call_info = sensitive_call_finder.query(actual_value)
                if sensitive_call_info:
                    if (
                        sensitive_call_info["qualified_name"] == "http.request.end"
                        or sensitive_call_info["qualified_name"] == "https.request.end"
                    ) and len(parameters) == 0:
                        pass
                    else:
                        logger.debug(
                            f"[Sensitive Call] code: {code}, qualified name: {sensitive_call_info['qualified_name']}"
                        )
                        current_node.set_sensitive_node(True)
                        current_node.set_sensitive_dict(sensitive_call_info, call_name)
                    if first_ast_pdg_node and first_ast_pdg_node.is_sensitive_node():
                        first_ast_pdg_node.set_sensitive_node(False)

                    # If current procedure is in dynamic phase, but the API is not recovered by dynamic, then it follows the static analysis process
                    if sensitive_call_info["domain"] == "Process":
                        # like spawn and fork
                        handle_subprocess_in_static(
                            current_node,
                            program_behavior,
                            sensitive_call_info["qualified_name"],
                            parameters,
                            analysis_context,
                            stage,
                        )
                    if sensitive_call_info["domain"] == "File":
                        # like readFile and writeFile
                        handle_file_op_in_static(
                            current_node, sensitive_call_info["qualified_name"], parameters
                        )
                    if sensitive_call_info["domain"] == "Network":
                        # like http.get
                        handle_network_op_in_static(
                            current_node, sensitive_call_info["qualified_name"], parameters
                        )

    if is_lambda:
        from npm_pipeline.utils.behavior_gen_utils import process_function_callee

        lambda_behavior = process_function_callee(
            current_node,
            lambda_pdg,
            file_context,
            pdg,
            program_behavior,
            analysis_context,
            stage,
            is_lambda=True,
        )
        if lambda_behavior:
            merge_pbg(program_behavior, lambda_behavior)
            current_node.set_behavior_of_call(lambda_behavior)


def handle_set_time_out(
    current_node: PDGNode,
    parameters: list[CPGNode],
    file_context: FileContext,
    program_behavior: PBG,
    pdg: PDG,
    analysis_context: AnalysisContext,
    stage: str,
):
    if parameters and len(parameters) > 1:
        first_parameter = parameters[0]
    else:
        return
    parameter_label = first_parameter.get_value("label")
    function_behavior = None
    if parameter_label == "METHOD_REF":
        method_full_name = first_parameter.get_value("METHOD_FULL_NAME")
        function_pdg = find_pdg_by_method_full_name(
            method_full_name.strip(), analysis_context.current_code_info
        )
        if function_pdg:
            if file_context.function_in_stack(f"{function_pdg.get_full_name()}"):
                logger.info(f"{function_pdg.get_name()} is in loop")
                return
            file_context.add_stack(f"{function_pdg.get_full_name().strip()}")
            analysis_context.current_code_info.pdg_analyzed[function_pdg.get_first_node_id()] = True
            function_call_entrance_id = function_pdg.get_first_node_id()
            program_behavior.add_pdg_edge(
                current_node.get_id(), function_call_entrance_id, ["DDG", "CFG"]
            )
            new_program_behavior = PBG(
                analysis_context.current_code_info.cpg,
                analysis_context.current_code_info.pdg_dict,
                analysis_context.current_code_info.formatted_package_dir,
                analysis_context.package_name,
            )
            from npm_pipeline.utils.behavior_gen_utils import gen_behavior

            # check if there exist parameters
            function_parameters = parameters[2:]
            if function_parameters:
                parameter_send_list = get_parameter_send_list(
                    function_parameters, current_node, file_context, pdg
                )
                function_behavior = gen_behavior(
                    function_pdg.get_file_name(),
                    function_pdg,
                    "function",
                    new_program_behavior,
                    parameter_send_list,
                    analysis_context,
                    stage,
                )
            else:
                function_behavior = gen_behavior(
                    function_pdg.get_file_name(),
                    function_pdg,
                    "function",
                    new_program_behavior,
                    None,
                    analysis_context,
                    stage,
                )
            file_context.delete_last_stack()

    return function_behavior
