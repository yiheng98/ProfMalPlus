from loguru import logger

from base_classes.pbg import PBG
from base_classes.pdg import PDG
from base_classes.pdg_node import PDGNode
from call_type_dict import FUNCTION_CALL
from npm_pipeline.classes.analysis_context import AnalysisContext

logger = logger.bind(node_trace=True)


def process_await_call(
    current_node: PDGNode, pdg: PDG, program_behavior: PBG, analysis_context: AnalysisContext
):
    ast = analysis_context.current_code_info.cpg.get_children_ast(current_node.get_id())
    if ast:
        first_ast_node = ast[0]
        if first_ast_node.get_id() in pdg.get_nodes():
            first_ast_pdg_node = pdg.get_node(first_ast_node.get_id())
            if first_ast_pdg_node.get_call_type() == FUNCTION_CALL:
                # If later assignment operations exist, they can be handled as if await were absent.
                current_node.set_behavior_of_call(first_ast_pdg_node.get_behavior_of_call())
            else:
                current_node.set_qualified_path(first_ast_pdg_node.get_qualified_path())

    else:
        logger.warning(
            f"The AST children size is empty in await process. Node id: {current_node.get_id()}"
        )
        return
