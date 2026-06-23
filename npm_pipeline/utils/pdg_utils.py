from loguru import logger

from base_classes.cpg_node import CPGNode
from base_classes.cpg_pdg_edge import Edge
from base_classes.pbg import PBG
from base_classes.pdg import PDG
from base_classes.pdg_node import PDGNode
from npm_pipeline.classes.analysis_context import AnalysisContext
from npm_pipeline.classes.code_Info import CodeInfo
from npm_pipeline.classes.file_context import FileContext
from object_type_dict import FILE_LEVEL_MODULE, GLOBAL_OBJECT

node_logger = logger.bind(node_trace=True)


def merge_pbg(pbg: PBG, sub_pbg: PBG):
    sub_result_entrance = sub_pbg.get_entrance_node()
    if not pbg.pdg_node_is_in(sub_result_entrance):
        sub_result_nodes = sub_pbg.get_pdg_nodes()
        sub_result_in_edges = sub_pbg.get_pdg_in_edges()
        sub_result_out_edges = sub_pbg.get_pdg_out_edges()
        sub_result_edges = sub_pbg.get_pdg_edges()
        pbg.add_batch_pdg_nodes(sub_result_nodes)
        pbg.add_batch_pdg_in_edges(sub_result_in_edges)
        pbg.add_batch_pdg_out_edges(sub_result_out_edges)
        pbg.add_batch_pdg_edges(sub_result_edges)

        sub_result_object_nodes = sub_pbg.get_object_nodes()
        sub_result_pdg_to_object_edge = sub_pbg.get_pdg_object_data_edge()
        sub_result_object_to_pdg_edge = sub_pbg.get_object_pdg_data_edge()
        pbg.add_batch_object_nodes(sub_result_object_nodes)
        pbg.add_batch_pdg_object_data_edge(sub_result_pdg_to_object_edge)
        pbg.add_batch_object_pdg_data_edge(sub_result_object_to_pdg_edge)


def get_type_of_edge(edge: Edge):
    """
    if the DDG exists in the edge's attr, the edge is DDG
    """
    attr_list = edge.get_attr()
    for attr in attr_list:
        if "DDG" in attr:
            return "DDG"
    return "CFG"


def has_ddg_line_of_two_nodes(current_node_id: int, identifier_id: int, pdg: PDG):
    if (identifier_id, current_node_id) in pdg.get_edges() and get_type_of_edge(
        pdg.get_edges()[(identifier_id, current_node_id)]
    ) == "DDG":
        return True
    return False


def connect_ddg_by_param(
    current_node: PDGNode,
    parameters: list[CPGNode],
    file_context: FileContext,
    program_behavior: PBG,
    pdg: PDG,
    analysis_context: AnalysisContext,
):
    # analyse the param to get extra data flow
    if len(parameters) != 0:
        for parameter in parameters:
            if parameter.get_id() in pdg.get_nodes():
                if not has_ddg_line_of_two_nodes(current_node.get_id(), parameter.get_id(), pdg):
                    program_behavior.add_pdg_edge(
                        parameter.get_id(),
                        current_node.get_id(),
                        [f"DDG: {parameter.get_value('CODE')}"],
                    )
            if parameter.get_value("label") == "IDENTIFIER":
                if parameter.get_value("CODE") != "this":
                    param_found = file_context.find_identifier(
                        parameter.get_value("CODE"), current_node.get_line_number()
                    )
                    if param_found:
                        if (
                            param_found.get_identifier_type() != GLOBAL_OBJECT
                            and param_found.get_identifier_type() != FILE_LEVEL_MODULE
                        ):
                            if not has_ddg_line_of_two_nodes(
                                current_node.get_id(), param_found.get_node_id(), pdg
                            ):
                                program_behavior.add_pdg_edge(
                                    param_found.get_node_id(),
                                    current_node.get_id(),
                                    [f"DDG: {param_found.get_name()}"],
                                )
                                logger.info(
                                    f"Find new data dependency by param: {parameter} to {param_found.get_name()} "
                                    f"of line: {param_found.get_line_number()}"
                                )
                            else:
                                attr = pdg.get_edges()[
                                    param_found.get_node_id(), current_node.get_id()
                                ].get_attr()
                                program_behavior.add_pdg_edge(
                                    param_found.get_node_id(), current_node.get_id(), attr
                                )
                        ref_object = param_found.get_ref_object()
                        program_behavior.add_object_to_pdg_edge(ref_object, current_node.get_id())
            elif parameter.get_value("label") == "BLOCK":
                find_pdg_edge_in_block(
                    current_node,
                    pdg,
                    parameter,
                    program_behavior,
                    file_context,
                    analysis_context.current_code_info,
                )
            elif parameter.get_value("label") == "CALL":
                if parameter.get_id() in pdg.get_nodes() and not has_ddg_line_of_two_nodes(
                    current_node.get_id(), parameter.get_id(), pdg
                ):
                    program_behavior.add_pdg_edge(
                        parameter.get_id(), current_node.get_id(), ["DDG"]
                    )


def find_pdg_edge_in_block(
    current_node: PDGNode,
    pdg: PDG,
    parameter_node: CPGNode,
    program_behavior: PBG,
    file_context: FileContext,
    current_code_info: CodeInfo,
):
    """
    find the missing pdg edge in the block
    """
    ast_of_block = current_code_info.cpg.get_children_ast(parameter_node.get_id())
    for ast in ast_of_block:
        if ast.get_id() in pdg.get_nodes() and not has_ddg_line_of_two_nodes(
            current_node.get_id(), ast.get_id(), pdg
        ):
            program_behavior.add_pdg_edge(
                ast.get_id(), current_node.get_id(), [f"DDG: {ast.get_value('CODE')}"]
            )
        if ast.get_value("label") == "CALL" and ast.get_value("NAME") == "<operator>.assignment":
            ast_children = current_code_info.cpg.get_children_ast(ast.get_id())
            if len(ast_children) > 1:
                right_ast_node = ast_children[1]
                if right_ast_node.get_value("label") == "IDENTIFIER":
                    found_identifier = file_context.find_identifier(
                        right_ast_node.get_value("CODE"), current_node.get_line_number()
                    )
                    if found_identifier:
                        program_behavior.add_object_to_pdg_edge(
                            found_identifier.get_ref_object(), current_node.get_id()
                        )


def estimate_call_end(start_line: int, start_column: int, code: str) -> tuple[int, int]:
    """
    Estimate the end position of a call expression from the joern CODE string and its line breaks.

    The joern CPG ``CODE`` field may be truncated, so the result is a lower bound of the real end position.

    """
    code = code.strip() if code else ""
    line, col = start_line, start_column
    i, n = 0, len(code)
    while i < n:
        ch = code[i]
        if ch == "\n":
            line += 1
            col = 0
            i += 1
        elif ch == "\\" and i + 1 < n and code[i + 1] == "n":
            line += 1
            col = 0
            i += 2
        else:
            col += 1
            i += 1
    return line, col


def resolve_callee_via_call_expression(
    current_node: PDGNode, analysis_context: AnalysisContext
) -> list:
    """
    Given multiple end candidates for ``current_node`` in ``call_expression_dict``,
    select the best matching real callee list.

    There are two semantic levels:

    - Multiple callees for the same (start, end), representing true call-graph polymorphism: the whole list
      is propagated upward as the return value, and the caller handles each callee separately.
    - Multiple end candidates for the same start, such as syntax ambiguity in ``foo()()``: first use
      the literal length of ``current_node.get_code()`` to estimate a lower bound for this call's real end,
      then choose the smallest candidate >= that lower bound by (line, column) lexicographic order across **all** end candidates,
      use it as this call's end, and finally query the callee for that (start, end) in
      ``call_graph`` and return it.

    Return list[Function]; return an empty list when none is found.
    """
    file = current_node.get_file_name()
    start_line = current_node.get_line_number() - 1
    start_column = current_node.get_column_number()
    code_info = analysis_context.current_code_info
    call_expression_dict = code_info.call_expression_dict
    if file not in call_expression_dict:
        return []
    candidates = call_expression_dict[file].get((start_line, start_column))
    if not candidates:
        return []

    call_graph = code_info.call_graph

    # A single candidate is unambiguous; query it directly.
    if len(candidates) == 1:
        end_line, end_column = candidates[0]
        return call_graph.get_callees(file, start_line, start_column, end_line, end_column)

    # Multiple end candidates: first use the lower bound estimated from CODE to locate this call's own end,
    # then query call_graph for the callee at this (start, end).
    code = current_node.get_code() or ""
    est_line, est_col = estimate_call_end(start_line, start_column, code)
    feasible = [c for c in candidates if (c[0], c[1]) >= (est_line, est_col)]
    if feasible:
        feasible.sort()
        chosen_end_line, chosen_end_column = feasible[0]
    else:
        logger.warning(
            f"All end candidates are smaller than the estimated end "
            f"({est_line},{est_col}) for call at {file}:{start_line}:{start_column}; "
            f"falling back to the largest end."
        )
        chosen_end_line, chosen_end_column = max(candidates)

    return call_graph.get_callees(
        file, start_line, start_column, chosen_end_line, chosen_end_column
    )


def get_pdg_of_callee(current_node: PDGNode, analysis_context: AnalysisContext) -> list[PDG]:
    """
    find the callee(s) of current function call.
    return the deduplicated list of PDGs of the callees, in resolution order.
    """
    callees = resolve_callee_via_call_expression(current_node, analysis_context)
    if not callees:
        return []
    node_logger.info(f"Find {len(callees)} callee(s) of call expression: {current_node.get_code()}")
    pdgs: list[PDG] = []
    unresolved_callees: list = []
    for callee in callees:
        pdg = find_pdg_by_file_and_loc(
            callee.file,
            callee.start_line + 1,
            callee.start_column,
            callee.end_line + 1,
            callee.end_column,
            analysis_context,
        )
        if pdg is None:
            unresolved_callees.append(callee)
            continue
        if pdg not in pdgs:
            pdgs.append(pdg)
    if unresolved_callees:
        logger.warning(
            f"Resolved {len(callees)} callee(s) but only mapped to {len(pdgs)} pdg(s) of Node {current_node.get_id()}"
        )
    return pdgs


def find_pdg_by_file_and_loc(
    file_name: str,
    line_number: int,
    column_number: int,
    end_line_number: int,
    end_column_number: int,
    analysis_context: AnalysisContext,
):
    """
    find the pdg by the file name and the loc.

    Prefer exact matching on (file_name, line_number, column_number, end_line_number,
    end_column_number). If no exact match is found, fall back among candidates with the same file_name, line_number,
    and line_number_end to the candidate whose column range strictly contains the input range
    (that is, value.column_number < column_number and
    value.column_number_end > end_column_number）。
    """
    fallback_candidates: list[PDG] = []
    for _, value in analysis_context.current_code_info.pdg_dict.items():
        if value.get_file_name() != file_name:
            continue
        if not (
            value.get_line_number() == line_number
            and value.get_line_number_end() == end_line_number
        ):
            continue
        if (
            value.get_column_number() == column_number
            and value.get_column_number_end() == end_column_number
        ):
            return value
        fallback_candidates.append(value)

    for value in fallback_candidates:
        if (
            value.get_column_number() <= column_number
            and value.get_column_number_end() >= end_column_number
        ):
            return value
    return None


def find_pdg_by_method_full_name(method_full_name: str, current_code_info: CodeInfo):
    """
    find the pdg by the method full name
    """
    for key, value in current_code_info.pdg_dict.items():
        if value.get_full_name().strip() == method_full_name:
            # find the pdg of the file
            return value
    return None


def edge_attr_contain_cfg(edge: Edge):
    """
    If the CFG exists in the edge's attr, the edge is CFG
    """
    attr_list = edge.get_attr()
    for attr in attr_list:
        if "CFG" in attr:
            return True
    return False


def find_pdg_by_file(file_name: str, current_code_info: CodeInfo) -> PDG | None:
    """
    find the pdg by file name
    """
    for key, value in current_code_info.pdg_dict.items():
        if value.get_name() == ":program" and value.get_file_name() == file_name:
            # find the pdg of the file
            return value
    return None


def edge_attr_contain_ddg(edge: Edge):
    """
    If the DDG exists in the edge's attr, the edge is DDG
    """
    attr_list = edge.get_attr()
    for attr in attr_list:
        if "DDG" in attr:
            return True
    return False
