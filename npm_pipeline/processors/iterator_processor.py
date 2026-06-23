from base_classes.pbg import PBG
from base_classes.pdg import PDG
from base_classes.pdg_node import PDGNode
from npm_pipeline.classes.analysis_context import AnalysisContext
from npm_pipeline.classes.file_context import FileContext
from npm_pipeline.classes.object import Object
from object_type_dict import OBJECT


def process_iterator(
    current_node: PDGNode,
    pdg: PDG,
    file_context: FileContext,
    program_behavior: PBG,
    analysis_context: AnalysisContext,
):
    # create a dummy object
    iterator_object = Object(
        name=f"{current_node.get_name()}-{current_node.get_id()}",
        object_type=OBJECT,
        source_pdg=current_node.get_source_pdg(),
    )
    file_context.add_object(iterator_object)
    current_node.set_qualified_path((iterator_object, []))
    ast = analysis_context.current_code_info.cpg.get_children_ast(current_node.get_id())
    if len(ast) > 0:
        first_ast = ast[0]
        first_ast_label = first_ast.get_value("label")
        if first_ast_label == "IDENTIFIER":
            found_identifier = file_context.find_identifier(
                first_ast.get_value("CODE"), current_node.get_line_number()
            )
            if found_identifier:
                ref_object = found_identifier.get_ref_object()
                program_behavior.add_object_to_pdg_edge(ref_object, current_node.get_id())
        else:
            if first_ast.get_id() in pdg.get_nodes():
                program_behavior.add_pdg_edge(first_ast.get_id(), current_node.get_id(), ["DDG"])
