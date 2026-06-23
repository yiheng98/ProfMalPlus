from base_classes.pdg_node import PDGNode
from npm_pipeline.classes.file_context import FileContext
from npm_pipeline.classes.object import Object
from object_type_dict import OBJECT


def create_wildcard_for_unresolved_path(
    base_object: Object,
    property_list: list[str],
    current_node: PDGNode,
    file_context: FileContext,
) -> Object:
    """
    Create a wildcard ``Object`` to occupy ``base_object[property_list]`` when
    a read failed to resolve (``actual_value is None``).

    The wildcard's ``qualified_name`` is pre-filled with the best-effort
    composed string of the path so that subsequent reads through the wildcard
    can still recover a usable identifier chain (e.g. for sensitive API
    detection).

    The wildcard is attached to the base via ``set_property`` and registered
    on ``file_context`` so it is visible to file-scope analyses.
    """
    partial_qn = base_object.compose_qualified_string(property_list)
    wildcard = Object(
        name="wildcard",
        object_type=OBJECT,
        source_pdg=current_node.get_source_pdg(),
        qualified_name=partial_qn,
    )
    base_object.set_property(property_list, wildcard)
    file_context.add_object(wildcard)
    return wildcard
