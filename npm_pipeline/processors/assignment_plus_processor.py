from loguru import logger

from base_classes.pbg import PBG
from base_classes.pdg import PDG
from base_classes.pdg_node import PDGNode
from npm_pipeline.classes.analysis_context import AnalysisContext
from npm_pipeline.classes.file_context import FileContext

logger = logger.bind(node_trace=True)


def process_assignment_plus(
    current_node: PDGNode,
    pdg: PDG,
    program_behavior: PBG,
    file_context: FileContext,
    analysis_context: AnalysisContext,
):
    ast = analysis_context.current_code_info.cpg.get_children_ast(current_node.get_id())
    if len(ast) < 2:
        logger.warning(
            f"The AST children size is smaller than 2 in Assignment Plus. node id: {current_node.get_id()}"
        )
        return
    else:
        right_ast_node = ast[1]
        if right_ast_node.get_id() in pdg.get_nodes():
            pdg_node = pdg.get_nodes()[right_ast_node.get_id()]
            program_behavior.add_pdg_edge(
                right_ast_node.get_id(), current_node.get_id(), [f"DDG:{pdg_node.get_code()}"]
            )

    left_ast_node = ast[0]
    left_ast_node_label = left_ast_node.get_value("label")

    if left_ast_node_label == "IDENTIFIER":
        identifier_name = left_ast_node.get_value("CODE")
        found_identifier = file_context.find_identifier(
            identifier_name, current_node.get_line_number()
        )
        if found_identifier:
            ref_object = found_identifier.get_ref_object()
            program_behavior.add_pdg_to_object_data_edge(current_node.get_id(), ref_object)
    else:
        left_ast_pdg_node = (
            pdg.get_node(left_ast_node.get_id())
            if left_ast_node.get_id() in pdg.get_nodes()
            else None
        )
        if left_ast_pdg_node:
            left_ast_pdg_node_qualified_path = left_ast_pdg_node.get_qualified_path()
            if left_ast_pdg_node_qualified_path:
                program_behavior.add_pdg_to_object_data_edge(
                    current_node.get_id(), left_ast_pdg_node_qualified_path[0]
                )
