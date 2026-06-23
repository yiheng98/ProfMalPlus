from loguru import logger

from base_classes.pbg import PBG
from base_classes.pdg import PDG
from base_classes.pdg_node import PDGNode
from call_type_dict import INDEX_ACCESS
from npm_pipeline.classes.analysis_context import AnalysisContext
from npm_pipeline.classes.file_context import FileContext
from npm_pipeline.classes.object import Object
from npm_pipeline.utils.object_utils import create_wildcard_for_unresolved_path
from npm_pipeline.utils.pdg_utils import has_ddg_line_of_two_nodes
from object_type_dict import FILE_LEVEL_MODULE, GLOBAL_OBJECT
from sensitive_op import sensitive_property_access_finder

logger = logger.bind(node_trace=True)


def process_index_access(
    current_node: PDGNode,
    pdg: PDG,
    file_context: FileContext,
    program_behavior: PBG,
    analysis_context: AnalysisContext,
):
    """
    handle the <operator>.indexAccess
    """
    current_node.set_call_type(INDEX_ACCESS)
    ast = analysis_context.current_code_info.cpg.get_children_ast(current_node.get_id())
    if len(ast) < 2:
        logger.warning(f"The AST children size is smaller than 2. node id: {current_node.get_id()}")
    else:
        left_of_index_access = ast[0]
        right_of_index_access = ast[1]
        left_node_label = left_of_index_access.get_value("label")
        index_type = right_of_index_access.get_value("label")
        left_of_index_qualified_path = None
        index_qualified_name = None
        if index_type == "LITERAL":
            # const value. direct use
            index_qualified_name = right_of_index_access.get_value("CODE").strip("\"'")
        elif index_type == "IDENTIFIER":
            found_identifier = file_context.find_identifier(
                right_of_index_access.get_value("CODE"), current_node.get_line_number()
            )
            if found_identifier:
                ref_object = found_identifier.get_ref_object()
                index_qualified_name = (
                    None if ref_object is None else ref_object.get_qualified_name()
                )
                if (
                    found_identifier.get_identifier_type() != GLOBAL_OBJECT
                    and found_identifier.get_identifier_type() != FILE_LEVEL_MODULE
                ):
                    if not has_ddg_line_of_two_nodes(
                        current_node.get_id(), found_identifier.get_node_id(), pdg
                    ):
                        program_behavior.add_pdg_edge(
                            found_identifier.get_node_id(),
                            current_node.get_id(),
                            [f"DDG: {found_identifier.get_name()}"],
                        )
                    else:
                        program_behavior.add_pdg_edge(
                            found_identifier.get_node_id(),
                            current_node.get_id(),
                            pdg.get_edges()[
                                (found_identifier.get_node_id(), current_node.get_id())
                            ].get_attr(),
                        )
        else:
            right_of_index_access_pdg_node = (
                pdg.get_node(right_of_index_access.get_id())
                if right_of_index_access.get_id() in pdg.get_nodes()
                else None
            )
            if right_of_index_access_pdg_node:
                index_access_pdg_node_qualified_path = (
                    right_of_index_access_pdg_node.get_qualified_path()
                )
                if index_access_pdg_node_qualified_path:
                    index_access_actual_value = index_access_pdg_node_qualified_path[
                        0
                    ].get_property_actual_value(index_access_pdg_node_qualified_path[1])
                    if isinstance(index_access_actual_value, Object):
                        index_qualified_name = index_access_actual_value.get_qualified_name()
                    else:
                        index_qualified_name = index_access_actual_value

        if index_qualified_name is None:
            # the qualified name of index is not interpretable
            current_node.set_qualified_path(None)
        else:
            # Determine the type of the index base.
            if left_node_label == "IDENTIFIER":
                # Index base is an Identifier.
                found_identifier = file_context.find_identifier(
                    left_of_index_access.get_value("CODE"), current_node.get_line_number()
                )
                if found_identifier:
                    left_ref_object = found_identifier.get_ref_object()
                    current_node.set_qualified_path((left_ref_object, [index_qualified_name]))

                    # connect by pdg node
                    if (
                        found_identifier.get_identifier_type() != GLOBAL_OBJECT
                        and found_identifier.get_identifier_type() != FILE_LEVEL_MODULE
                    ):
                        if not has_ddg_line_of_two_nodes(
                            current_node.get_id(), found_identifier.get_node_id(), pdg
                        ):
                            program_behavior.add_pdg_edge(
                                found_identifier.get_node_id(),
                                current_node.get_id(),
                                [f"DDG: {found_identifier.get_name()}"],
                            )
                        else:
                            program_behavior.add_pdg_edge(
                                found_identifier.get_node_id(),
                                current_node.get_id(),
                                pdg.get_edges()[
                                    (found_identifier.get_node_id(), current_node.get_id())
                                ].get_attr(),
                            )
            else:
                # Index base is not an identifier.
                left_of_index_access_pdg_node = (
                    pdg.get_node(left_of_index_access.get_id())
                    if left_of_index_access.get_id() in pdg.get_nodes()
                    else None
                )
                if left_of_index_access_pdg_node:
                    left_of_index_qualified_path = (
                        left_of_index_access_pdg_node.get_qualified_path()
                    )

                    program_behavior.add_pdg_edge(
                        left_of_index_access_pdg_node.get_id(),
                        current_node.get_id(),
                        [f"DDG: {left_of_index_access_pdg_node.get_code()}"],
                    )

            if left_of_index_qualified_path and index_qualified_name:
                left_ref_object = left_of_index_qualified_path[0]
                property_list = list(left_of_index_qualified_path[1])
                property_list.append(index_qualified_name)
                current_node.set_qualified_path((left_ref_object, property_list))

        left_of_index_access_pdg_node = (
            pdg.get_node(left_of_index_access.get_id())
            if left_of_index_access.get_id() in pdg.get_nodes()
            else None
        )
        if left_of_index_access_pdg_node and left_of_index_access_pdg_node.is_sensitive_node():
            program_behavior.add_pdg_edge(
                left_of_index_access_pdg_node.get_id(),
                current_node.get_id(),
                [f"DDG: {left_of_index_access_pdg_node.get_code()}"],
            )
    actual_value = None
    if current_node.get_qualified_path() is not None:
        resolved_qualified_path = current_node.get_qualified_path()[0].resolve_qualified_path(
            current_node.get_qualified_path()[1]
        )
        current_node.set_qualified_path(resolved_qualified_path)
        actual_value = resolved_qualified_path[0].get_property_actual_value(
            resolved_qualified_path[1]
        )

        if actual_value is None:
            # Align with field_access: when read cannot proceed, insert a wildcard placeholder with a partial qn,
            # so sensitive-detection signals survive mixed index/field chained access.
            actual_value = create_wildcard_for_unresolved_path(
                resolved_qualified_path[0],
                resolved_qualified_path[1],
                current_node,
                file_context,
            )

        if isinstance(actual_value, Object):
            program_behavior.add_object_to_pdg_edge(actual_value, current_node.get_id())
        else:
            program_behavior.add_object_to_pdg_edge(
                current_node.get_qualified_path()[0], current_node.get_id()
            )

    sensitive_property_access = sensitive_property_access_finder.query(actual_value)
    if sensitive_property_access:
        logger.debug(
            f"Find sensitive Index Access, code: {current_node.get_code()}, full name: {sensitive_property_access['qualified_name']}"
        )
        current_node.set_sensitive_node(True)
        current_node.set_sensitive_dict(sensitive_property_access, index_qualified_name)
