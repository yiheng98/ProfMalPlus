from loguru import logger

from base_classes.pbg import PBG
from base_classes.pdg import PDG
from base_classes.pdg_node import PDGNode
from npm_pipeline.classes.analysis_context import AnalysisContext

logger = logger.bind(node_trace=True)


def process_addition(
    current_node: PDGNode, pdg: PDG, program_behavior: PBG, analysis_context: AnalysisContext
):
    ast = analysis_context.current_code_info.cpg.get_children_ast(current_node.get_id())
    if len(ast) < 2:
        logger.warning(
            f"The AST children size is smaller than 2 in Addition. node id: {current_node.get_id()}"
        )
    else:
        left_of_addition = ast[0]
        if left_of_addition.get_id() in pdg.get_nodes():
            pdg_node = pdg.get_nodes()[left_of_addition.get_id()]
            program_behavior.add_pdg_edge(
                left_of_addition.get_id(), current_node.get_id(), [f"DDG:{pdg_node.get_code()}"]
            )
        right_of_addition = ast[1]
        if right_of_addition.get_id() in pdg.get_nodes():
            pdg_node = pdg.get_nodes()[right_of_addition.get_id()]
            program_behavior.add_pdg_edge(
                right_of_addition.get_id(),
                current_node.get_id(),
                [f"DDG:{pdg_node.get_code()}"],
            )
