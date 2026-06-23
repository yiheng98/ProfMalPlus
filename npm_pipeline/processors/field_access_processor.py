from loguru import logger

from base_classes.pbg import PBG
from base_classes.pdg import PDG
from base_classes.pdg_node import PDGNode
from call_type_dict import FIELD_ACCESS
from npm_pipeline.classes.analysis_context import AnalysisContext
from npm_pipeline.classes.file_context import FileContext
from npm_pipeline.classes.object import Object
from npm_pipeline.utils.object_utils import create_wildcard_for_unresolved_path
from npm_pipeline.utils.pdg_utils import has_ddg_line_of_two_nodes
from object_type_dict import FILE_LEVEL_MODULE, GLOBAL_OBJECT
from sensitive_op import sensitive_property_access_finder

logger = logger.bind(node_trace=True)


def process_field_access(
    current_node: PDGNode,
    pdg: PDG,
    file_context: FileContext,
    program_behavior: PBG,
    analysis_context: AnalysisContext,
):
    """
    handle the <operator>.fieldAccess
    """
    current_node.set_call_type(FIELD_ACCESS)
    ast = analysis_context.current_code_info.cpg.get_children_ast(current_node.get_id())
    if len(ast) < 2:
        logger.warning(f"The AST children size is smaller than 2. node id: {current_node.get_id()}")
    else:
        left_of_field_access = ast[0]
        right_of_field_access = ast[1]
        left_node_label = left_of_field_access.get_value("label")
        # the right side in filed access is field identifier
        field_identifier = right_of_field_access.get_value("CODE")
        if left_node_label == "IDENTIFIER":
            # case-1: AST left side is an Identifier.
            code_of_left_node = left_of_field_access.get_value("CODE")
            if code_of_left_node == "this":
                # this.IDENTIFIER
                this_frame = file_context.locate_this_frame(
                    pdg.get_file_name(),
                    "".join(
                        analysis_context.current_code_info.files[pdg.get_file_name()].get_raw_code()
                    ),
                    current_node.get_line_number() - 1,
                    current_node.get_column_number(),
                )
                if this_frame:
                    program_behavior.add_object(this_frame.get_this_object())
                    current_node.set_qualified_path(
                        (this_frame.get_this_object(), [field_identifier])
                    )

            else:
                # IDENTIFIER
                left_identifier = file_context.find_identifier(
                    code_of_left_node, current_node.get_line_number()
                )
                if left_identifier:
                    left_object = left_identifier.get_ref_object()
                    if left_object:
                        current_node.set_qualified_path((left_object, [field_identifier]))

                        # connect by pdg edge
                        if (
                            left_identifier.get_identifier_type() != GLOBAL_OBJECT
                            and left_identifier.get_identifier_type() != FILE_LEVEL_MODULE
                        ):
                            if not has_ddg_line_of_two_nodes(
                                current_node.get_id(), left_identifier.get_node_id(), pdg
                            ):
                                program_behavior.add_pdg_edge(
                                    left_identifier.get_node_id(),
                                    current_node.get_id(),
                                    [f"DDG: {left_identifier.get_name()}"],
                                )
                            else:
                                program_behavior.add_pdg_edge(
                                    left_identifier.get_node_id(),
                                    current_node.get_id(),
                                    pdg.get_edges()[
                                        (left_identifier.get_node_id(), current_node.get_id())
                                    ].get_attr(),
                                )
                else:
                    pass
        else:
            # case-2: AST left side is not an Identifier; check whether it is a known PDG node.
            if left_of_field_access.get_id() in pdg.get_nodes():
                left_pdg_node = pdg.get_node(left_of_field_access.get_id())
                left_node_qualified_path = left_pdg_node.get_qualified_path()
                if left_node_qualified_path:
                    # set the qualified path of the current node
                    left_base_object = left_node_qualified_path[0]
                    property_list = list(left_node_qualified_path[1])
                    property_list.append(field_identifier)
                    current_node_qualified_path = (left_base_object, property_list)
                    current_node.set_qualified_path(current_node_qualified_path)

                # the filed access in on a non field process node
                if left_pdg_node.get_name() != "<operator>.fieldAccess":
                    program_behavior.add_pdg_edge(
                        left_of_field_access.get_id(),
                        current_node.get_id(),
                        [f"DDG: {left_pdg_node.get_code()}"],
                    )
                # the filed access in on a sensitive node
                if left_pdg_node.is_sensitive_node():
                    program_behavior.add_pdg_edge(
                        left_pdg_node.get_id(),
                        current_node.get_id(),
                        [f"DDG: {left_pdg_node.get_code()}"],
                    )
            else:
                logger.warning(
                    f"The left side pdg node is not found in field access, Code: {current_node.get_code()}. "
                    f"Node id: {current_node.get_id()}"
                )
    actual_value = None
    if current_node.get_qualified_path() is not None:
        resolved_qualified_path = current_node.get_qualified_path()[0].resolve_qualified_path(
            current_node.get_qualified_path()[1]
        )

        # update the qualified path of the current node
        current_node.set_qualified_path(resolved_qualified_path)

        actual_value = resolved_qualified_path[0].get_property_actual_value(
            resolved_qualified_path[1]
        )

        if actual_value is None:
            # Insert a wildcard placeholder at base[property_list]. Its
            # qualified_name is composed by compose_qualified_string to preserve the recognizable chain,
            # preventing later reads through the wildcard from losing sensitive-detection signals entirely.
            actual_value = create_wildcard_for_unresolved_path(
                resolved_qualified_path[0],
                resolved_qualified_path[1],
                current_node,
                file_context,
            )

        if isinstance(actual_value, Object):
            # the point to value is an object
            program_behavior.add_object_to_pdg_edge(actual_value, current_node.get_id())
        else:
            # not an object, connect from the base object
            program_behavior.add_object_to_pdg_edge(
                current_node.get_qualified_path()[0], current_node.get_id()
            )

    # sensitive op judgement
    sensitive_property_access = sensitive_property_access_finder.query(actual_value)
    if sensitive_property_access:
        logger.debug(
            f"Find sensitive Filed Access, code: {current_node.get_code()}, qualified name: {sensitive_property_access['qualified_name']}"
        )
        current_node.set_sensitive_node(True)
        current_node.set_sensitive_dict(sensitive_property_access, field_identifier)
