from base_classes.pbg import PBG
from base_classes.pdg import PDG
from base_classes.pdg_node import PDGNode
from npm_pipeline.classes.analysis_context import AnalysisContext
from npm_pipeline.classes.file_context import FileContext


def process_format_string(
    current_node: PDGNode,
    pdg: PDG,
    program_behavior: PBG,
    file_context: FileContext,
    analysis_context: AnalysisContext,
):
    ast_list = analysis_context.current_code_info.cpg.get_children_ast(current_node.get_id())
    for ast in ast_list:
        if ast.get_id() in pdg.get_nodes():
            pdg_node = pdg.get_nodes()[ast.get_id()]
            program_behavior.add_pdg_edge(
                ast.get_id(), current_node.get_id(), [f"DDG:{pdg_node.get_code()}"]
            )
        if ast.get_value("label") == "IDENTIFIER":
            identifier_name = ast.get_value("CODE")
            found_identifier = file_context.find_identifier(
                identifier_name, current_node.get_line_number()
            )
            if found_identifier:
                ref_object = found_identifier.get_ref_object()
                program_behavior.add_object_to_pdg_edge(ref_object, current_node.get_id())
