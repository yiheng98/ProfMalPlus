from base_classes.cpg_node import CPGNode
from base_classes.pdg import PDG
from base_classes.pdg_node import PDGNode
from npm_pipeline.classes.file_context import FileContext


def get_str_from_parameter_list(parameter_list: list[CPGNode]):
    """
    extract the literal from the parameter node
    """
    parameter_str_list = []
    for parameter in parameter_list:
        if parameter.get_value("label") == "LITERAL":
            parameter_str_list.append(parameter.get_value("CODE").strip().strip("\"'"))
        elif parameter.get_value("label") == "METHOD_REF":
            pass
        else:
            parameter_str_list.append(None)
    return parameter_str_list


def get_parameter_send_list(
    parameter_list: list[CPGNode], current_node: PDGNode, file_context: FileContext, pdg: PDG
):
    parameter_send_list = []
    if parameter_list:
        for parameter_node in parameter_list:
            label_of_parameter = parameter_node.get_value("label")
            if label_of_parameter == "IDENTIFIER":
                found_identifier = file_context.find_identifier(
                    parameter_node.get_value("CODE"), current_node.get_line_number()
                )
                if found_identifier:
                    bind_object = found_identifier.get_ref_object()
                    if bind_object:
                        parameter_send_list.append(bind_object)
                    else:
                        parameter_send_list.append(None)
                else:
                    parameter_send_list.append(None)
            elif label_of_parameter == "LITERAL":
                if parameter_node.get_value("TYPE_FULL_NAME") == "__ecma.String":
                    array_object = file_context.find_global_object("Array")
                    parameter_send_list.append((array_object, []))
                else:
                    parameter_send_list.append(None)
            else:
                parameter_pdg_node = (
                    pdg.get_node(parameter_node.get_id())
                    if parameter_node.get_id() in pdg.get_nodes()
                    else None
                )
                if parameter_pdg_node:
                    node_full_name = parameter_pdg_node.get_qualified_path()
                    parameter_send_list.append(node_full_name)
                else:
                    parameter_send_list.append(None)
    return parameter_send_list
