from loguru import logger

from base_classes.cpg_node import CPGNode
from base_classes.pbg import PBG
from base_classes.pdg import PDG
from base_classes.pdg_node import PDGNode
from call_type_dict import ASSIGNMENT
from npm_pipeline.classes.analysis_context import AnalysisContext
from npm_pipeline.classes.file_context import FileContext
from npm_pipeline.classes.identifier import Identifier
from npm_pipeline.classes.object import Object
from npm_pipeline.utils.pdg_utils import has_ddg_line_of_two_nodes
from object_type_dict import FUNCTION_REF, OBJECT

logger = logger.bind(node_trace=True)


def process_assignment(
    current_node: PDGNode,
    pdg: PDG,
    filename: str,
    file_context: FileContext,
    program_behavior: PBG,
    analysis_context: AnalysisContext,
):
    ast = analysis_context.current_code_info.cpg.get_children_ast(current_node.get_id())
    current_node.set_call_type(ASSIGNMENT)

    left_ast_node = ast[0]  # left side of the assignment
    right_ast_node = ast[1]  # right side of the assignment

    left_base_object, left_qualified_path, left_identifier, left_ast_pdg_node = (
        None,
        None,
        None,
        None,
    )
    left_ast_node_label = left_ast_node.get_value("label")
    right_ast_node_label = right_ast_node.get_value("label")

    if left_ast_node_label == "IDENTIFIER":
        # the left side is identifier, create an identifier
        left_is_identifier = True
        identifier_name = left_ast_node.get_value("CODE")
        left_identifier = Identifier(
            name=identifier_name,
            line_number=current_node.get_line_number(),
            column_number=current_node.get_column_number(),
            identifier_type="IDENTIFIER",
            node_id=current_node.get_id(),
            source_pdg=pdg.get_first_node_id(),
            file=filename,
        )

        left_base_object = Object(
            name=f"{identifier_name}-{current_node.get_id()}",
            object_type=OBJECT,
            source_pdg=pdg.get_first_node_id(),
        )
        left_identifier.set_ref_object(left_base_object)
        program_behavior.add_object(left_base_object)
        program_behavior.add_pdg_to_object_data_edge(current_node.get_id(), left_base_object)
        file_context.add_identifier(left_identifier)
        file_context.add_object(left_base_object)

    else:
        left_is_identifier = False
        left_ast_pdg_node = (
            pdg.get_node(left_ast_node.get_id())
            if left_ast_node.get_id() in pdg.get_nodes()
            else None
        )
        if left_ast_pdg_node:
            left_qualified_path = left_ast_pdg_node.get_qualified_path()
            if left_qualified_path:
                base_object = left_qualified_path[0]
                property_list = list(left_qualified_path[1])
                if base_object.get_object_type() == "THIS_OBJECT" and len(property_list) == 1:
                    # the left side of the assignment is like this.a
                    _object = Object(
                        name=f"{property_list[0]}-{current_node.get_id()}",
                        object_type=OBJECT,
                        source_pdg=pdg.get_first_node_id(),
                    )
                    # add the variable to the `this` object's property
                    base_object.set_property(property_list, _object)
                    program_behavior.add_object(_object)
                    program_behavior.add_pdg_to_object_data_edge(current_node.get_id(), _object)
                else:
                    program_behavior.add_pdg_to_object_data_edge(current_node.get_id(), base_object)

    # Process the right-hand node according to its type.
    if right_ast_node_label == "IDENTIFIER":
        # Right-hand node is an identifier.
        handle_right_identifier(
            current_node,
            left_is_identifier,
            left_identifier,
            left_qualified_path,
            right_ast_node,
            pdg,
            program_behavior,
            file_context,
        )
    elif right_ast_node_label == "LITERAL":
        # Right-hand node is a constant string.
        handle_right_literal(
            current_node,
            left_is_identifier,
            left_identifier,
            left_qualified_path,
            right_ast_node,
        )
    elif right_ast_node_label == "BLOCK":
        # Right-hand node is a block.
        handle_right_block(
            current_node,
            left_is_identifier,
            left_identifier,
            left_qualified_path,
            right_ast_node,
            pdg,
            program_behavior,
            file_context,
            analysis_context,
        )
    else:
        handle_right(
            current_node,
            left_is_identifier,
            left_identifier,
            left_qualified_path,
            right_ast_node,
            pdg,
            program_behavior,
        )


def handle_right_literal(
    current_node: PDGNode,
    left_is_identifier: bool,
    left_identifier: Identifier | None,
    left_qualified_path: tuple[Object, list[str]] | None,
    right_ast_node: CPGNode,
):
    if left_is_identifier and left_identifier:
        # Left-hand side is an identifier and right-hand side is a literal.
        left_identifier.get_ref_object().set_qualified_name(
            right_ast_node.get_value("CODE").strip("\"'")
        )
        current_node.set_qualified_path((left_identifier.get_ref_object(), []))
    else:
        if left_qualified_path:
            left_ref_object = left_qualified_path[0]
            property_list = list(left_qualified_path[1])
            actual_value = left_ref_object.get_property_actual_value(property_list)
            if isinstance(actual_value, Object):
                actual_value.set_qualified_name(right_ast_node.get_value("CODE").strip("\"'"))
            else:
                left_ref_object.set_property(
                    property_list, right_ast_node.get_value("CODE").strip("\"'")
                )
            current_node.set_qualified_path((left_ref_object, property_list))


def handle_right_identifier(
    current_node: PDGNode,
    left_is_identifier: bool,
    left_identifier: Identifier | None,
    left_qualified_path: tuple[Object, list[str]] | None,
    right_ast_node: CPGNode,
    pdg: PDG,
    program_behavior: PBG,
    file_context: FileContext,
):
    """
    When the right-hand side is IDENTIFIER, handle it according to whether the left-hand side is also IDENTIFIER.
    """
    right_identifier_name = right_ast_node.get_value("CODE")
    right_identifier = file_context.find_identifier(
        right_identifier_name, current_node.get_line_number()
    )

    if left_is_identifier and left_identifier:
        # case-7: both sides of the assignment are identifiers.
        if right_identifier:
            left_identifier.set_ref_object(right_identifier.get_ref_object())
            current_node.set_qualified_path((right_identifier.get_ref_object(), []))

            # Add an Object-to-PDG edge.
            program_behavior.add_object_to_pdg_edge(
                right_identifier.get_ref_object(), current_node.get_id()
            )

            # Add a PDG edge.
            if right_identifier.get_node_id() is not None:
                if not has_ddg_line_of_two_nodes(
                    current_node.get_id(), right_identifier.get_node_id(), pdg
                ):
                    program_behavior.add_pdg_edge(
                        right_identifier.get_node_id(),
                        current_node.get_id(),
                        [f"DDG: {right_identifier_name}"],
                    )
                else:
                    attr = pdg.get_edges()[
                        (right_identifier.get_node_id(), current_node.get_id())
                    ].get_attr()
                    program_behavior.add_pdg_edge(
                        right_identifier.get_node_id(), current_node.get_id(), attr
                    )
        else:
            # Right-hand identifier does not exist.
            pass

    else:
        # case-8: left-hand side is not an identifier and right-hand side is an identifier.
        if left_qualified_path:
            if right_identifier:
                left_ref_object = left_qualified_path[0]
                property_list = list(left_qualified_path[1])

                # the property str point an object
                left_ref_object.set_property(property_list, right_identifier.get_ref_object())
                current_node.set_qualified_path((right_identifier.get_ref_object(), []))

                # Add a PDG-node-to-object edge.
                program_behavior.add_pdg_to_object_data_edge(current_node.get_id(), left_ref_object)
                # Add an object-to-PDG edge.
                program_behavior.add_object_to_pdg_edge(
                    right_identifier.get_ref_object(), current_node.get_id()
                )

                # Add a PDG edge.
                if right_identifier.get_node_id() is not None:
                    if not has_ddg_line_of_two_nodes(
                        current_node.get_id(), right_identifier.get_node_id(), pdg
                    ):
                        program_behavior.add_pdg_edge(
                            right_identifier.get_node_id(),
                            current_node.get_id(),
                            [f"DDG: {right_identifier_name}"],
                        )
                    else:
                        attr = pdg.get_edges()[
                            (right_identifier.get_node_id(), current_node.get_id())
                        ].get_attr()
                        program_behavior.add_pdg_edge(
                            right_identifier.get_node_id(), current_node.get_id(), attr
                        )
        else:
            if right_identifier:
                program_behavior.add_object_to_pdg_edge(
                    right_identifier.get_ref_object(), current_node.get_id()
                )


def handle_right_block(
    current_node: PDGNode,
    left_is_identifier: bool,
    left_identifier: Identifier | None,
    left_qualified_path: tuple[Object, list[str]] | None,
    right_ast_node: CPGNode,
    pdg: PDG,
    program_behavior: PBG,
    file_context: FileContext,
    analysis_context: AnalysisContext,
):
    right_block_qualified_name = None
    # get the ast of the right block
    ast_list = analysis_context.current_code_info.cpg.get_children_ast(right_ast_node.get_id())
    for ast_node in ast_list:
        if ast_node.get_value("NAME") == "<operator>.assignment":
            if not has_ddg_line_of_two_nodes(current_node.get_id(), ast_node.get_id(), pdg):
                program_behavior.add_pdg_edge(
                    ast_node.get_id(),
                    current_node.get_id(),
                    [f"DDG: {ast_node.get_value('CODE')}"],
                )
        elif ast_node.get_value("label") == "LOCAL":
            local_name = ast_node.get_value("NAME")
            if local_name:
                found_identifier = file_context.find_identifier(
                    local_name, current_node.get_line_number()
                )
                if found_identifier:
                    program_behavior.add_object_to_pdg_edge(
                        found_identifier.get_ref_object(), current_node.get_id()
                    )
        elif ast_node.get_value("label") == "CALL":
            if ast_node.get_id() in pdg.get_nodes():
                right_block_qualified_name = pdg.get_node(ast_node.get_id()).get_qualified_path()

    if left_is_identifier and left_identifier:
        # Left-hand side is an identifier and right-hand side is a block.
        if right_block_qualified_name:
            actual_value = right_block_qualified_name[0].get_property_actual_value(
                right_block_qualified_name[1]
            )
            if isinstance(actual_value, Object):
                left_identifier.set_ref_object(actual_value)
                program_behavior.add_object_to_pdg_edge(actual_value, current_node.get_id())
                current_node.set_qualified_path((actual_value, []))
            else:
                left_identifier.get_ref_object().set_qualified_name(actual_value)
                current_node.set_qualified_path(
                    (right_block_qualified_name[0], right_block_qualified_name[1])
                )
        else:
            left_identifier.get_ref_object().set_qualified_name(None)
            current_node.set_qualified_path((left_identifier.get_ref_object(), []))
    else:
        if left_qualified_path:
            left_ref_object = left_qualified_path[0]
            property_list = list(left_qualified_path[1])
            if property_list:
                if right_block_qualified_name:
                    actual_value = right_block_qualified_name[0].get_property_actual_value(
                        right_block_qualified_name[1]
                    )
                    left_ref_object.set_property(property_list, actual_value)
                    if isinstance(actual_value, Object):
                        program_behavior.add_object_to_pdg_edge(actual_value, current_node.get_id())
                else:
                    left_ref_object.set_property(property_list, None)
            current_node.set_qualified_path((left_ref_object, property_list))


def handle_right(
    current_node: PDGNode,
    left_is_identifier: bool,
    left_identifier: Identifier | None,
    left_qualified_path: tuple[Object, list[str]] | None,
    right_ast_node: CPGNode,
    pdg: PDG,
    program_behavior: PBG,
):
    """
    When the right-hand side is not IDENTIFIER, handle it according to whether it is a function call and whether the left-hand side is IDENTIFIER.
    """
    right_ast_pdg_node = (
        pdg.get_node(right_ast_node.get_id())
        if right_ast_node.get_id() in pdg.get_nodes()
        else None
    )
    if right_ast_pdg_node:
        if right_ast_pdg_node.get_call_type() == "FUNCTION_CALL":
            function_behavior = right_ast_pdg_node.get_behavior_of_call()
            # Right-hand side is a user-defined function call.
            if left_is_identifier and left_identifier:
                # case-1: left-hand side is an identifier and right-hand side is a function call.
                handle_call_return_for_left_identifier(
                    current_node, left_identifier, program_behavior, function_behavior
                )
            else:
                # case-2: left-hand side is not an identifier and right-hand side is a function call.
                handle_call_return_for_left_non_identifier(
                    current_node, left_qualified_path, program_behavior, function_behavior
                )
        else:
            # Right-hand side is CALL but not a user-defined function call, such as a built-in or another case.
            handle_non_function_call(
                current_node,
                left_is_identifier,
                left_identifier,
                left_qualified_path,
                right_ast_node,
                pdg,
                program_behavior,
            )
    else:
        # right ast pdg node not found
        if left_is_identifier and left_identifier:
            current_node.set_qualified_path((left_identifier.get_ref_object(), []))


def handle_call_return_for_left_identifier(
    current_node: PDGNode,
    left_identifier: Identifier,
    program_behavior: PBG,
    function_behavior: PBG | None,
):
    """
    case-1: left-hand side is an identifier and right-hand side is a function call.
    """
    if function_behavior:
        return_value_list = function_behavior.get_return_value()
        if return_value_list:
            # If there is more than one return value, no deterministic full_name can be bound to the left-hand side.
            if len(return_value_list) != 1:
                left_identifier.get_ref_object().set_qualified_name(None)
            else:
                value = return_value_list[0]
                bind_left_identifier_to_value(
                    current_node, left_identifier, value, program_behavior
                )

            # Add DDG edges for all return values.
            for value in return_value_list:
                program_behavior.add_pdg_edge(
                    value.get_id(), current_node.get_id(), [f"DDG: {value.get_code()}"]
                )
        else:
            left_identifier.get_ref_object().set_qualified_name(None)
    else:
        left_identifier.get_ref_object().set_qualified_name(None)

    program_behavior.add_pdg_to_object_data_edge(
        current_node.get_id(), left_identifier.get_ref_object()
    )


def handle_call_return_for_left_non_identifier(
    current_node: PDGNode,
    left_qualified_path: tuple[Object, list[str]] | None,
    program_behavior: PBG,
    function_behavior: PBG | None,
):
    """
    case-2: left-hand side is not an identifier and right-hand side is a function call.
    """
    if left_qualified_path:
        # the left full is not None
        left_base_object = left_qualified_path[0]
        property_list = list(left_qualified_path[1])
        if function_behavior:
            return_value_list = function_behavior.get_return_value()
            if return_value_list:
                if len(return_value_list) != 1:
                    # More than one return value.
                    if property_list:
                        left_base_object.set_property(property_list, None)
                else:
                    # Exactly one return value.
                    value = return_value_list[0]
                    bind_left_object_property(current_node, left_base_object, property_list, value)

                # Add DDG edges for all return values.
                for value in return_value_list:
                    program_behavior.add_pdg_edge(
                        value.get_id(), current_node.get_id(), [f"DDG: {value.get_code()}"]
                    )
            else:
                # Function has no return value.
                if property_list:
                    left_base_object.set_property(property_list, None)

        else:
            # function_behavior does not exist.
            if property_list:
                left_base_object.set_property(property_list, None)

        actual_value = left_base_object.get_property_actual_value(property_list)
        if isinstance(actual_value, Object):
            program_behavior.add_pdg_to_object_data_edge(current_node.get_id(), actual_value)
        else:
            program_behavior.add_pdg_to_object_data_edge(current_node.get_id(), left_base_object)
    else:
        if function_behavior:
            return_value_list = function_behavior.get_return_value()
            if return_value_list:
                # Add DDG edges for all return values.
                for value in return_value_list:
                    program_behavior.add_pdg_edge(
                        value.get_id(), current_node.get_id(), [f"DDG: {value.get_code()}"]
                    )


def handle_non_function_call(
    current_node: PDGNode,
    left_is_identifier: bool,
    left_identifier: Identifier | None,
    left_qualified_path: tuple[Object, list[str]] | None,
    right_ast_node: CPGNode,
    pdg: PDG,
    program_behavior: PBG,
):
    """
    Handle the case where self.is_function_call() returns False, meaning the right-hand side is not a function call.
    """
    right_id = right_ast_node.get_id()
    if right_id not in pdg.get_nodes():
        logger.warning(f"Cannot find the pdg node in assignment. Node id: {current_node.get_id()}")
        return

    right_ast_pdg_node = pdg.get_node(right_id)
    # Add a DDG edge.
    program_behavior.add_pdg_edge(
        right_ast_pdg_node.get_id(),
        current_node.get_id(),
        [f"DDG: {right_ast_pdg_node.get_code()}"],
    )

    # Continue only when the left-hand side has an identifier or qualified_path.
    if not ((left_is_identifier and left_identifier) or left_qualified_path):
        return

    right_node_type = right_ast_pdg_node.get_node_type()
    if right_node_type == "METHOD_REF":
        # case-1: right-hand side is a function definition; mark the left-hand identifier as a function reference.
        if left_is_identifier:
            left_identifier.set_identifier_type(FUNCTION_REF)
        return

    right_node_qualified_path = right_ast_pdg_node.get_qualified_path()
    if right_node_qualified_path:
        # Right-hand side resolved to a qualified path.
        if left_is_identifier:
            # case-3: left-hand side is an identifier and right-hand side is a non-call node.
            actual_value = right_node_qualified_path[0].get_property_actual_value(
                right_node_qualified_path[1]
            )
            if isinstance(actual_value, Object):
                left_identifier.set_ref_object(actual_value)
                program_behavior.add_object_to_pdg_edge(actual_value, current_node.get_id())
                current_node.set_qualified_path((actual_value, []))
            else:
                left_identifier.get_ref_object().set_qualified_name(actual_value)
                current_node.set_qualified_path(
                    (right_node_qualified_path[0], list(right_node_qualified_path[1]))
                )
        else:
            # case-4: left-hand side is not an identifier and right-hand side is a non-call node.
            left_base_object = left_qualified_path[0]
            left_property_list = list(left_qualified_path[1])
            if left_property_list:
                actual_value = right_node_qualified_path[0].get_property_actual_value(
                    right_node_qualified_path[1]
                )
                left_base_object.set_property(left_property_list, actual_value)
            current_node.set_qualified_path(
                (right_node_qualified_path[0], list(right_node_qualified_path[1]))
            )
            program_behavior.add_pdg_to_object_data_edge(current_node.get_id(), left_base_object)
    else:
        # Failed to resolve the right-hand full_name.
        if left_is_identifier:
            # case-5: left-hand side is an identifier.
            if right_ast_pdg_node.get_code() == "__ecma.Array.factory()":
                left_identifier.get_ref_object().set_qualified_name("array")
            else:
                left_identifier.get_ref_object().set_qualified_name(None)
        else:
            # case-6: left-hand side is not an identifier.
            left_base_object = left_qualified_path[0]
            left_property_list = list(left_qualified_path[1])
            # Special handling for __ecma.Array.factory().
            if right_ast_pdg_node.get_code() == "__ecma.Array.factory()":
                actual_value = left_base_object.get_property_actual_value(left_property_list)
                if isinstance(actual_value, Object):
                    actual_value.set_qualified_name("array")
                elif left_property_list:
                    left_base_object.set_property(left_property_list, "array")
            program_behavior.add_pdg_to_object_data_edge(current_node.get_id(), left_base_object)


def bind_left_identifier_to_value(
    current_node: PDGNode,
    left_identifier: Identifier,
    value: Object | tuple | None,
    program_behavior: PBG,
):
    """
    Bind the left-hand identifier to the return value, handling Object and node full name values separately.
    """
    if isinstance(value, Object):
        # Bind the left-hand side directly to the returned Object.
        left_identifier.set_ref_object(value)
        program_behavior.add_object_to_pdg_edge(value, current_node.get_id())
        current_node.set_qualified_path((value, []))
    elif isinstance(value, tuple):
        # Bind the left-hand side to the right-hand full name.
        actual_value = value[0].get_property_actual_value(value[1])
        if isinstance(actual_value, Object):
            # Right-hand side actually points to an Object.
            left_identifier.set_ref_object(actual_value)
            program_behavior.add_object_to_pdg_edge(actual_value, current_node.get_id())
            current_node.set_qualified_path((actual_value, []))
        else:
            left_identifier.get_ref_object().set_qualified_name(actual_value)
            current_node.set_qualified_path(value[0], list(value[1]))
    else:
        # Unrecognized type.
        left_identifier.get_ref_object().set_qualified_name(None)


def bind_left_object_property(
    current_node: PDGNode,
    left_base_object: Object,
    property_list: list[str],
    value: Object | tuple | None,
):
    """
    Bind the return value to a property on the left-hand base_object.
    """
    if isinstance(value, Object):
        if property_list:
            # set the property bind to object
            left_base_object.set_property(property_list, value)
        current_node.set_qualified_path((value, []))
    elif isinstance(value, tuple):
        if property_list:
            actual_value = value[0].get_property_actual_value(value[1])
            left_base_object.set_property(property_list, actual_value)
        current_node.set_qualified_path((value[0], list(value[1])))
    else:
        if property_list:
            left_base_object.set_property(property_list, None)
