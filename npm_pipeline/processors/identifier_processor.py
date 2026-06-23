from base_classes.pbg import PBG
from base_classes.pdg import PDG
from base_classes.pdg_node import PDGNode
from npm_pipeline.classes.analysis_context import AnalysisContext
from npm_pipeline.utils.pdg_utils import has_ddg_line_of_two_nodes
from object_type_dict import FILE_LEVEL_MODULE, GLOBAL_OBJECT


def process_identifier_node(
    current_node: PDGNode,
    pdg: PDG,
    filename: str,
    program_behavior: PBG,
    analysis_context: AnalysisContext,
):
    """
    Handle IDENTIFIER pdg nodes by locating the referenced identifier in the
    enclosing scope (mirroring the IDENTIFIER branch in process_field_access)
    and connecting the definition site to the current node via a DDG edge.
    """
    file_context = analysis_context.program_context.get_file_context(filename)
    identifier_name = current_node.get_code()
    if not identifier_name or identifier_name == "this":
        return

    found_identifier = file_context.find_identifier(identifier_name, current_node.get_line_number())
    if not found_identifier:
        return

    # avoid self-loop when the IDENTIFIER node is the definition itself
    if found_identifier.get_node_id() == current_node.get_id():
        return

    ref_object = found_identifier.get_ref_object()
    if ref_object is None:
        return

    current_node.set_qualified_path((ref_object, []))

    if (
        found_identifier.get_identifier_type() == GLOBAL_OBJECT
        or found_identifier.get_identifier_type() == FILE_LEVEL_MODULE
    ):
        return

    if not has_ddg_line_of_two_nodes(current_node.get_id(), found_identifier.get_node_id(), pdg):
        program_behavior.add_pdg_edge(
            found_identifier.get_node_id(),
            current_node.get_id(),
            [f"DDG: {found_identifier.get_name()}"],
        )
    else:
        program_behavior.add_pdg_edge(
            found_identifier.get_node_id(),
            current_node.get_id(),
            pdg.get_edges()[(found_identifier.get_node_id(), current_node.get_id())].get_attr(),
        )
