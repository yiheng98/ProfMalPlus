from loguru import logger

from base_classes.pbg import PBG
from base_classes.pdg import PDG
from base_classes.pdg_node import PDGNode
from call_type_dict import (
    FUNCTION_CALL,
    NEW_CALL,
)
from npm_pipeline.classes.analysis_context import AnalysisContext
from npm_pipeline.classes.code_Info import CodeInfo
from npm_pipeline.classes.file_context import FileContext
from npm_pipeline.classes.object import Object
from npm_pipeline.utils.pdg_utils import (
    connect_ddg_by_param,
    find_pdg_by_method_full_name,
    get_pdg_of_callee,
    has_ddg_line_of_two_nodes,
    merge_pbg,
)
from object_type_dict import FILE_LEVEL_MODULE, GLOBAL_OBJECT
from sensitive_op import sensitive_call_finder

logger = logger.bind(node_trace=True)


def process_new_operation(
    current_node: PDGNode,
    pdg: PDG,
    file_context: FileContext,
    program_behavior: PBG,
    analysis_context: AnalysisContext,
    stage: str,
):
    current_node.set_call_type(NEW_CALL)

    # get the param by the ast instead of Joern
    parameters = analysis_context.current_code_info.cpg.get_argument_from_joern(
        current_node.get_id()
    )
    connect_ddg_by_param(
        current_node,
        parameters,
        file_context,
        program_behavior,
        pdg,
        analysis_context,
    )

    # find callee(s)
    function_pdgs = get_pdg_of_callee(current_node, analysis_context)
    # Single-value PDG used for the lambda branch; if get_pdg_of_callee hits a lambda,
    # take the first one to preserve the original single-callee-plus-lambda semantics.
    function_pdg: PDG | None = None
    is_lambda = (
        function_pdgs
        and len(parameters) > 0
        and "<lambda>" in parameters[-1].get_value("TYPE_FULL_NAME")
    )
    if is_lambda:
        function_pdg = function_pdgs[0]

    if not function_pdgs:
        if parameters:
            last_parameter = parameters[-1]
            method_full_name = last_parameter.get_value("TYPE_FULL_NAME")
            if "<lambda>" in method_full_name:
                function_pdg = find_pdg_by_method_full_name(
                    method_full_name.strip(), analysis_context.current_code_info
                )
                if function_pdg:
                    is_lambda = True

    if function_pdgs and not is_lambda:
        # the new operation is caller; iterate over polymorphic callees
        # Delay import to avoid circular dependencies.
        from npm_pipeline.utils.behavior_gen_utils import process_function_callee

        current_node.set_call_type(FUNCTION_CALL)
        for fpdg in function_pdgs:
            function_behavior = process_function_callee(
                current_node, fpdg, file_context, pdg, program_behavior, analysis_context, stage
            )
            if function_behavior:
                current_node.add_callee_pdg(fpdg)
                merge_pbg(program_behavior, function_behavior)
                # Single-value field: keep the last callee when multiple callees exist, matching the original single-callee semantics.
                current_node.set_behavior_of_call(function_behavior)
        return

    # the new operation is not a function call
    ast = analysis_context.current_code_info.cpg.get_children_ast(current_node.get_id())
    if len(ast) < 2:
        logger.warning(f"The AST children size is smaller than 2. node id: {current_node.get_id()}")
    else:
        new_object_node = ast[0]
        label_of_new_object_node = new_object_node.get_value("label")
        if label_of_new_object_node == "IDENTIFIER":
            # The base of new is an Identifier.
            found = file_context.find_identifier(
                new_object_node.get_value("CODE"), current_node.get_line_number()
            )
            if found:
                current_node.set_qualified_path((found.get_ref_object(), []))
                if (
                    found.get_identifier_type() != GLOBAL_OBJECT
                    and found.get_identifier_type() != FILE_LEVEL_MODULE
                ):
                    if not has_ddg_line_of_two_nodes(
                        current_node.get_id(), found.get_node_id(), pdg
                    ):
                        program_behavior.add_pdg_edge(
                            found.get_node_id(),
                            current_node.get_id(),
                            [f"DDG: {found.get_name()}"],
                        )
                    else:
                        program_behavior.add_pdg_edge(
                            found.get_node_id(),
                            current_node.get_id(),
                            pdg.get_edges()[
                                (found.get_node_id(), current_node.get_id())
                            ].get_attr(),
                        )
            else:
                pass
        else:
            # The base of new is a call, such as `new net.Socket()`.
            if new_object_node.get_id() in pdg.get_nodes():
                new_object_pdg = pdg.get_node(new_object_node.get_id())
                new_object_node_full_name = new_object_pdg.get_qualified_path()
                if new_object_node_full_name:
                    ref_object = new_object_node_full_name[0]
                    property_list = list(new_object_node_full_name[1])
                    current_node.set_qualified_path((ref_object, property_list))
                else:
                    current_node.set_qualified_path(None)
            else:
                logger.warning(
                    f"The new object pdg node is not found in new operation. node id: {current_node.get_id()}"
                )

    judge_by_qualified_name = True
    if analysis_context.current_code_info.api_call_info:
        if handle_api_call_in_new_expression(current_node, analysis_context.current_code_info):
            judge_by_qualified_name = False
    if judge_by_qualified_name and current_node.get_qualified_path():
        property_actual_value = current_node.get_qualified_path()[0].get_property_actual_value(
            current_node.get_qualified_path()[1]
        )
        if isinstance(property_actual_value, Object):
            property_actual_value = property_actual_value.get_qualified_name()
        if property_actual_value == "Buffer":
            property_actual_value = "global.Buffer"
        sensitive_call = sensitive_call_finder.query(property_actual_value)
        if sensitive_call:
            logger.debug(
                f"Find sensitive New OP, code: {current_node.get_code()}, full name: {sensitive_call['qualified_name']}"
            )
            current_node.set_sensitive_node(True)
            current_node.set_sensitive_dict(sensitive_call, "new")
    if is_lambda:
        # Delay import to avoid circular dependencies.
        from npm_pipeline.utils.behavior_gen_utils import process_function_callee

        lambda_behavior = process_function_callee(
            current_node,
            function_pdg,
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


def handle_api_call_in_new_expression(current_node: PDGNode, current_code_info: CodeInfo):
    """
    Handle API calls that appear in new expressions.
    """
    code = current_node.get_code().strip()
    code_lines = code.splitlines()
    line_offset = len(code_lines) - 1
    col_offset = len(code_lines[-1]) if code_lines else 0
    api_call = current_code_info.api_call_info.find_api_call(
        "function",
        current_node.get_file_name(),
        current_node.get_line_number() - 1,
        current_node.get_column_number(),
        current_node.get_line_number() - 1 + line_offset,
        current_node.get_column_number() + col_offset,
    )
    if api_call is None:
        return False

    current_code_info.api_call_to_pdg_node_mapping[api_call] = current_node.get_id()
    api_call_full_name = f"{api_call.module}.{api_call.function}"
    sensitive_call = sensitive_call_finder.query(api_call_full_name)
    if sensitive_call:
        logger.debug(
            f"Find sensitive New OP, code: {code}, full_name: {sensitive_call['qualified_name']}"
        )
        current_node.set_sensitive_node(True)
        current_node.set_sensitive_dict(sensitive_call)
    return True
