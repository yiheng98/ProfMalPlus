from tree_sitter import Node


class Statement:
    def __init__(self, tree_sitter_node: Node, top_method_name: str):
        self.tree_sitter_node = tree_sitter_node
        self.top_method_name = top_method_name
        self.top_mehtod_tree_sitter_node = None
        self.call_info = []  # Sensitive API, third-party API, and unresolved call metadata in this statement.
        self.callee_info = []  # Callee metadata contained in this statement.

    def get_tree_sitter_node(self) -> Node:
        return self.tree_sitter_node

    def add_call_info(self, call_info: str):
        self.call_info.append(call_info)

    def get_call_info(self) -> list[str]:
        return self.call_info

    def add_callee_info(self, callee_info: str):
        self.callee_info.append(callee_info)

    def get_callee_info(self) -> list[str]:
        return self.callee_info

    def get_top_method_name(self) -> str:
        return self.top_method_name

    def set_top_mehtod_tree_sitter_node(self, top_mehtod_tree_sitter_node: Node):
        self.top_mehtod_tree_sitter_node = top_mehtod_tree_sitter_node

    def get_top_mehtod_tree_sitter_node(self) -> Node:
        return self.top_mehtod_tree_sitter_node
