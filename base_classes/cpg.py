from __future__ import annotations

import os
from typing import TYPE_CHECKING

import networkx as nx
from loguru import logger
from tree_sitter import Node

from ast_parser import ASTParser
from base_classes.cpg_node import CPGNode
from base_classes.cpg_pdg_edge import Edge
from base_classes.pdg_node import PDGNode
from base_classes.statement import Statement
from call_type_dict import (
    CONDITIONAL_CALL,
    FIELD_ACCESS,
    FUNCTION_CALL,
    INDEX_ACCESS,
    REQUIRE_CALL,
    THIRD_PARTY_CALL,
    UNRESOLVED_CALL,
)
from custom_exception import GraphReadingException, JoernGenerationException
from npm_pipeline.classes.serialized_types import format_file_io_summary

if TYPE_CHECKING:
    from npm_pipeline.classes.analysis_context import AnalysisContext


_PLACEHOLDER = "<unknown>"


_RESOLVED_ANNOTATION_DOMAINS = frozenset({"Process", "File", "Network"})


def _domain_supports_resolved_annotation(sensitive_dict: dict | None) -> bool:
    if not sensitive_dict:
        return False
    call_info = sensitive_dict.get("call_info") or {}
    return call_info.get("domain") in _RESOLVED_ANNOTATION_DOMAINS


def _format_resolved_args_and_return(resolved) -> tuple[str, str]:
    args_str = str(resolved.resolved_arguments) if resolved.resolved_arguments else "N/A"
    ret_str = str(resolved.resolved_return_value) if resolved.resolved_return_value else "N/A"
    return args_str, ret_str


def _file_io_suffix(pdg_node: PDGNode) -> str:
    """Return a compact file-I/O annotation fragment"""
    records = pdg_node.get_file_io_records()
    if not records:
        return ""
    return " [" + format_file_io_summary(records) + "]"


_EVAL_ARG_MAX_CHARS = 4000
_EVAL_ARG_MAX_UNIQUE = 3


def _flatten_one_line(text: str) -> str:
    """Collapse newlines / CR into spaces so the eval source fits on a single
    annotation line. Long whitespace runs are squeezed to keep the comment
    readable when the source was originally pretty-printed.
    """
    return " ".join(text.replace("\r", "\n").split())


def _format_eval_source_preview(eval_call_dict: dict) -> str:
    """Render the dynamic eval source argument(s) into a single-line preview
    suitable for embedding in a ``// ...`` annotation.
    """
    args = eval_call_dict.get("args") if isinstance(eval_call_dict, dict) else None
    if not args:
        return "<no resolved source captured>"

    truncated_parts: list[str] = []
    shown = args[:_EVAL_ARG_MAX_UNIQUE]
    for arg in shown:
        if not isinstance(arg, str):
            continue
        flat = _flatten_one_line(arg)
        if len(flat) > _EVAL_ARG_MAX_CHARS:
            remaining = len(flat) - _EVAL_ARG_MAX_CHARS
            flat = flat[:_EVAL_ARG_MAX_CHARS] + f"...({remaining} more chars truncated)"
        truncated_parts.append(f"`{flat}`")

    if not truncated_parts:
        return "<no resolved source captured>"

    overflow = len(args) - len(shown)
    if overflow > 0:
        truncated_parts.append(f"...({overflow} additional unique source variant(s) omitted)")
    return " | ".join(truncated_parts)


def _eval_annotation_for_sensitive(
    pdg_node: PDGNode, qualified_name: str, call_name: str
) -> str | None:
    """If *pdg_node* carries dynamic eval-trace info, return a sensitive-API
    annotation enriched with the resolved source argument(s); otherwise None.

    The format mirrors annotation type ``(k)`` in
    ``prompts/dynamic_behavior_judgment_prompt.md``.
    """
    eval_call_dict = pdg_node.get_eval_call_dict()
    if not eval_call_dict:
        return None
    invocations = eval_call_dict.get("invocation_count") or len(eval_call_dict.get("args") or [])
    preview = _format_eval_source_preview(eval_call_dict)
    return (
        f"Method name: {call_name} is a sensitive API call of {qualified_name}. "
        f"Dynamically captured {invocations} invocation(s); "
        f"resolved eval source argument(s): {preview}. "
        f"[Node ID: {pdg_node.get_id()}]"
    )


class CPG:
    def __init__(self, cpg_dir: str, cpg_graph=None):
        self.cpg_dir = cpg_dir
        self.nodes: dict[int, CPGNode] = {}
        self.edges: dict[tuple[int, int], Edge] = {}
        self.out_edges: dict[int, set[int]] = {}
        self.in_edges: dict[int, set[int]] = {}

        if cpg_graph is None:
            cpg_path = os.path.join(cpg_dir, "export.xml")
            if not os.path.exists(cpg_path):
                raise JoernGenerationException(f"export.xml is not found in {cpg_path}")

            try:
                cpg = nx.read_graphml(cpg_path, force_multigraph=True)
            except Exception:
                raise GraphReadingException("GraphML Reading Exception")
        else:
            cpg = cpg_graph
        for node in cpg.nodes:
            # Read node information from the CPG.
            node_id = int(node)
            cpg_node = CPGNode(node_id)
            for key, value in cpg.nodes[node].items():
                format_key = self.transform_key(key)
                cpg_node.set_attr(format_key, value)
            self.nodes[node_id] = cpg_node

        # Read all edges from the CPG.
        for head, tail, key, edge_dict in cpg.edges(data=True, keys=True):
            src = int(head)
            dst = int(tail)
            if (src, dst) not in self.edges:
                cpg_edge = Edge((src, dst))
            else:
                cpg_edge = self.edges[(src, dst)]

            # Add to outgoing edges.
            if src not in self.out_edges:
                self.out_edges[src] = set()
                self.out_edges[src].add(dst)
            else:
                self.out_edges[src].add(dst)

            # Add to incoming edges.
            if dst not in self.in_edges:
                self.in_edges[dst] = set()
                self.in_edges[dst].add(src)
            else:
                self.in_edges[dst].add(src)

            for _key, _value in edge_dict.items():
                cpg_edge.add_attr(_value)
            self.edges[(src, dst)] = cpg_edge

    def get_node(self, node_id: int) -> CPGNode:
        return self.nodes[node_id]

    def get_children_ast(self, node_id: int) -> list[CPGNode]:
        """
        Get AST child nodes.
        """
        if node_id not in self.out_edges:
            return []
        nodes_id = self.out_edges[node_id]
        ast = []
        for tail_id in nodes_id:
            edge = self.edges[(node_id, tail_id)]
            attr = edge.get_attr()
            for item in attr:
                if item == "AST":
                    ast.append(self.nodes[tail_id])

        def sort_key(node):
            order = node.get_value("ORDER")
            # Check if ORDER is a valid non-negative integer
            if order is not None and int(order) >= 0:
                return 0, int(order)  # Valid ORDER: Primary sort
            else:
                return 1, 0  # Invalid ORDER: Secondary sort

        # ascend
        return sorted(ast, key=sort_key)

    def get_parent_ast(self, node_id: int) -> CPGNode | None:
        """
        Get the parent AST node.
        """
        if node_id not in self.in_edges:
            return None

        head_ids = self.in_edges[node_id]
        for head_id in head_ids:
            edge = self.edges[(head_id, node_id)]
            attr = edge.get_attr()
            for item in attr:
                if item == "AST":
                    return self.nodes[head_id]
        return None

    def get_first_ast_node_in_call(self, node_id: int) -> CPGNode | None:
        ast_list = self.get_children_ast(node_id)
        argument_list = self.get_argument_from_joern(node_id)
        ast_list = [node for node in ast_list if node not in argument_list]
        if ast_list and len(ast_list) > 0:
            return ast_list[0]
        else:
            return None

    def get_argument_from_joern(self, node_id: int) -> list[CPGNode]:
        """
        search the cpg edge, which edge property is argument
        """
        if node_id not in self.out_edges:
            return []
        nodes_id = self.out_edges[node_id]
        argument_list = []
        for tail_id in nodes_id:
            edge = self.edges[(node_id, tail_id)]
            attr = edge.get_attr()
            for item in attr:
                if item == "ARGUMENT":
                    argument_list.append(self.nodes[tail_id])
        valid_arguments = [
            node
            for node in argument_list
            if node.get_value("ARGUMENT_INDEX") is not None
            and int(node.get_value("ARGUMENT_INDEX")) >= 1
        ]
        sorted_arguments = sorted(valid_arguments, key=lambda x: int(x.get_value("ARGUMENT_INDEX")))
        return sorted_arguments

    def get_argument_from_joern_index_less_than_one(self, node_id: int) -> list[CPGNode]:
        if node_id not in self.out_edges:
            return []
        nodes_id = self.out_edges[node_id]
        argument_list = []
        for tail_id in nodes_id:
            edge = self.edges[(node_id, tail_id)]
            attr = edge.get_attr()
            for item in attr:
                if item == "ARGUMENT":
                    argument_list.append(self.nodes[tail_id])
        valid_arguments = [
            node
            for node in argument_list
            if node.get_value("ARGUMENT_INDEX") is not None
            and int(node.get_value("ARGUMENT_INDEX")) < 1
        ]
        sorted_arguments = sorted(valid_arguments, key=lambda x: int(x.get_value("ARGUMENT_INDEX")))
        return sorted_arguments

    def get_call(self, node_id: int) -> CPGNode | None:
        """
        Find the CPG child reached by an edge of type CALL.
        """
        nodes_id = self.out_edges[node_id]
        call_node = None
        for tail_id in nodes_id:
            edge = self.edges[(node_id, tail_id)]
            attr = edge.get_attr()
            for item in attr:
                if item == "CALL":
                    call_node = self.nodes[tail_id]
        return call_node

    def get_static_statement_from_node_id(
        self, node_id: int, pdg_node: PDGNode, ast_parser: ASTParser
    ) -> Statement | None:
        current_node = self.nodes[node_id]
        node_line_number = current_node.get_value("LINE_NUMBER")
        node_column_number = current_node.get_value("COLUMN_NUMBER")
        statement_tree_sitter_node = None
        statement = None
        if node_line_number is None or node_column_number is None:
            logger.warning(f"Line number or column number is not found in node {node_id}")
            return None
        else:
            # locate the tree-sitter node
            target_node = ast_parser.find_target_node(
                ast_parser.root, node_line_number - 1, node_column_number
            )
            if target_node:
                statement_tree_sitter_node = self.locate_nearest_statement(target_node)
                if statement_tree_sitter_node:
                    pass
                else:
                    logger.warning(f"No statement tree-sitter node found for node {node_id}")
                    return None
            else:
                logger.warning(f"No tree-sitter node found for node {node_id}")
                return None

        # Search upward for the METHOD node.
        while current_node is not None and current_node.get_value("CODE") != ":program":
            parent_ast_node = self.get_parent_ast(current_node.get_id())
            if parent_ast_node is None:
                # Reached the top level without finding a METHOD node.
                logger.warning(f"No METHOD node found for node {node_id}")
                return None

            if parent_ast_node.get_value("label") == "METHOD":
                if "<lambda>" in parent_ast_node.get_value("NAME"):
                    # Current method is a lambda; continue walking upward.
                    current_node = parent_ast_node
                    continue
                else:
                    # Record the current METHOD.
                    top_method_name = parent_ast_node.get_value("NAME")
                    top_method_line_number = parent_ast_node.get_value("LINE_NUMBER")
                    top_method_column_number = parent_ast_node.get_value("COLUMN_NUMBER")
                    if top_method_name != ":program":
                        if (
                            top_method_line_number is not None
                            and top_method_column_number is not None
                        ):
                            function_node = ast_parser.find_target_node(
                                ast_parser.root,
                                top_method_line_number - 1,
                                top_method_column_number,
                            )
                            if function_node:
                                statement = Statement(statement_tree_sitter_node, top_method_name)
                                statement.set_top_mehtod_tree_sitter_node(function_node)
                    else:
                        statement = Statement(statement_tree_sitter_node, top_method_name)
                    break
            else:
                current_node = parent_ast_node

        if statement is None:
            # No top METHOD was resolved.
            # Fall back to the already located statement tree-sitter node.
            logger.warning(
                f"No top METHOD resolved for node {node_id}; falling back to located statement node"
            )
            statement = Statement(statement_tree_sitter_node, ":program")

        call_type = pdg_node.get_call_type()
        if call_type == FUNCTION_CALL:
            # Current PDG node is a function call.
            for callee_pdg in pdg_node.get_callee_pdgs():
                call_name = pdg_node.get_name()
                call_file_name = pdg_node.get_file_name()
                callee_name = callee_pdg.get_name()
                callee_file_name = callee_pdg.get_file_name()
                statement.add_callee_info(
                    f"{call_name}() in {call_file_name} -> function {callee_name} in {callee_file_name}"
                )
        elif call_type == THIRD_PARTY_CALL:
            third_party_call_dict = pdg_node.get_third_party_call_dict()
            call_name = third_party_call_dict["call_name"]
            module_name = third_party_call_dict["module"]
            property_method = third_party_call_dict["property_method"]
            nid = pdg_node.get_id()
            mod_beh = pdg_node.get_module_behavior()
            api_beh = pdg_node.get_behavior_description()

            if mod_beh and api_beh:
                statement.add_call_info(
                    f"Method name: {call_name}, third-party call of "
                    f"{module_name}.{property_method}. "
                    f"Module: {mod_beh}. API behavior: {api_beh}. "
                    f"[Node ID: {nid}]"
                )
            elif mod_beh:
                statement.add_call_info(
                    f"Method name: {call_name}, third-party call of "
                    f"{module_name}.{property_method}. "
                    f"Module: {mod_beh}. API behavior: not documented. "
                    f"[Node ID: {nid}]"
                )
            elif api_beh:
                statement.add_call_info(
                    f"Method name: {call_name}, third-party call of "
                    f"{module_name}.{property_method}. "
                    f"API behavior: {api_beh}. "
                    f"[Node ID: {nid}]"
                )
            else:
                statement.add_call_info(
                    f"Method name: {call_name}, is a third-party API call of "
                    f"{module_name}.{property_method} with module name: "
                    f"{module_name}. [Node ID: {nid}]"
                )
        elif pdg_node.is_sensitive_node():
            # Current PDG node is a sensitive API call.
            sensitive_dict = pdg_node.get_sensitive_dict()
            if not sensitive_dict:
                logger.warning(
                    f"Sensitive node {pdg_node.get_id()} has no sensitive_dict; "
                    f"emitting placeholder annotation"
                )
                call_name = pdg_node.get_name() or _PLACEHOLDER
                qualified_name = _PLACEHOLDER
            else:
                qualified_name = sensitive_dict["call_info"]["qualified_name"]
                call_name = sensitive_dict["call_name"]
            if pdg_node.get_call_type() == CONDITIONAL_CALL:
                # Sensitive behavior is affected by parameters and return values.
                statement.add_call_info(
                    f"Method name: {call_name} is a conditional sensitive API call of {qualified_name}. [Node ID: {pdg_node.get_id()}]"
                )
            else:
                if pdg_node.get_call_type() == FIELD_ACCESS:
                    statement.add_call_info(
                        f"Method name: {call_name} is a sensitive property access of {qualified_name}. [Node ID: {pdg_node.get_id()}]"
                    )
                elif pdg_node.get_call_type() == INDEX_ACCESS:
                    statement.add_call_info(
                        f"Method name: {call_name} is a sensitive property access of {qualified_name}. [Node ID: {pdg_node.get_id()}]"
                    )
                else:
                    # Regular sensitive API call.
                    statement.add_call_info(
                        f"Method name: {call_name} is a sensitive API call of {qualified_name}. [Node ID: {pdg_node.get_id()}]"
                    )
        elif pdg_node.get_call_type() == UNRESOLVED_CALL:
            unresolved_call_dict = pdg_node.get_unresolved_call_dict()
            unknwon_call_name = unresolved_call_dict["call_name"]
            code = " ".join(pdg_node.get_code().strip().split())
            if unknwon_call_name:
                statement.add_call_info(
                    f"Method name: {unknwon_call_name} is statically unresolved call. [Node ID: {pdg_node.get_id()}]"
                )
            else:
                statement.add_call_info(
                    f"Code: {code} contains statically unresolved call. [Node ID: {pdg_node.get_id()}]"
                )

        return statement

    def get_dynamic_statement_from_node_id(
        self,
        node_id: int,
        pdg_node: PDGNode,
        ast_parser: ASTParser,
        analysis_context: AnalysisContext,
    ) -> Statement | None:
        """Generate a Statement with dynamic-phase annotations.

        Nodes carried over from the static phase (conditional / third-party /
        unresolved) receive context-aware annotations that incorporate runtime
        information when available.  Newly discovered sensitive nodes get
        standard annotations enriched with resolved args/return values.
        """
        current_node = self.nodes[node_id]
        node_line_number = current_node.get_value("LINE_NUMBER")
        node_column_number = current_node.get_value("COLUMN_NUMBER")
        if node_line_number is None or node_column_number is None:
            logger.warning(f"Line number or column number is not found in node {node_id}")
            return None

        target_node = ast_parser.find_target_node(
            ast_parser.root, node_line_number - 1, node_column_number
        )
        if not target_node:
            logger.warning(f"No tree-sitter node found for node {node_id}")
            return None

        statement_tree_sitter_node = self.locate_nearest_statement(target_node)
        if not statement_tree_sitter_node:
            logger.warning(f"No statement tree-sitter node found for node {node_id}")
            return None

        # Walk up the AST to find the enclosing METHOD node
        statement = None
        walk_node = current_node
        while walk_node is not None:
            parent_ast_node = self.get_parent_ast(walk_node.get_id())
            if parent_ast_node is None:
                logger.warning(f"No METHOD node found for node {node_id}")
                return None

            if parent_ast_node.get_value("label") == "METHOD":
                if "<lambda>" in parent_ast_node.get_value("NAME"):
                    walk_node = parent_ast_node
                    continue
                else:
                    top_method_name = parent_ast_node.get_value("NAME")
                    top_method_line_number = parent_ast_node.get_value("LINE_NUMBER")
                    top_method_column_number = parent_ast_node.get_value("COLUMN_NUMBER")
                    if top_method_name != ":program":
                        if (
                            top_method_line_number is not None
                            and top_method_column_number is not None
                        ):
                            function_node = ast_parser.find_target_node(
                                ast_parser.root,
                                top_method_line_number - 1,
                                top_method_column_number,
                            )
                            if function_node:
                                statement = Statement(statement_tree_sitter_node, top_method_name)
                                statement.set_top_mehtod_tree_sitter_node(function_node)
                    else:
                        statement = Statement(statement_tree_sitter_node, top_method_name)
                    break
            else:
                walk_node = parent_ast_node

        if statement is None:
            return None

        nid = pdg_node.get_id()
        is_static_conditional = analysis_context.is_static_pending_conditional(nid)
        is_static_third_party = analysis_context.is_static_pending_third_party(nid)
        is_static_unresolved = analysis_context.is_static_pending_unresolved(nid)

        # --- Conditional nodes from the static phase ---
        if is_static_conditional:
            sensitive_dict = pdg_node.get_sensitive_dict() if pdg_node.is_sensitive_node() else None
            if sensitive_dict:
                qualified_name = sensitive_dict["call_info"]["qualified_name"]
                call_name = sensitive_dict["call_name"]
            else:
                unresolved_call_dict = pdg_node.get_unresolved_call_dict()
                raw_call_name = unresolved_call_dict["call_name"] if unresolved_call_dict else None
                call_name = (
                    raw_call_name if raw_call_name and raw_call_name != "None" else _PLACEHOLDER
                )
                qualified_name = _PLACEHOLDER

            resolved = pdg_node.get_resolved_api_call() if sensitive_dict else None
            if resolved:
                if _domain_supports_resolved_annotation(sensitive_dict):
                    args_str, ret_str = _format_resolved_args_and_return(resolved)
                    statement.add_call_info(
                        f"Method name: {call_name} is a sensitive API call of {qualified_name}. "
                        f"Resolved arguments: {args_str}. Resolved return value: {ret_str}. "
                        f"[Node ID: {nid}]"
                    )
                else:
                    statement.add_call_info(
                        f"Method name: {call_name} is a sensitive API call of {qualified_name}. "
                        f"[Node ID: {nid}]"
                    )
            else:
                eval_annotation = (
                    _eval_annotation_for_sensitive(pdg_node, qualified_name, call_name)
                    if sensitive_dict
                    else None
                )
                if eval_annotation:
                    statement.add_call_info(eval_annotation)
                else:
                    statement.add_call_info(
                        f"Method name: {call_name} is a conditional sensitive API call of "
                        f"{qualified_name}. This node was NOT executed during dynamic analysis. "
                        f"[Node ID: {nid}]"
                    )
            return statement

        # --- Require call nodes ---
        if pdg_node.get_call_type() == REQUIRE_CALL:
            require_call_dict = pdg_node.get_require_call_dict()
            module_name = require_call_dict["module_name"] if require_call_dict else _PLACEHOLDER
            statement.add_call_info(
                f"require() call importing module: {module_name}. [Node ID: {nid}]"
            )
            return statement

        # --- Third-party nodes from the static phase ---
        if is_static_third_party:
            third_party_call_dict = pdg_node.get_third_party_call_dict()
            call_name = (
                third_party_call_dict["call_name"] if third_party_call_dict else _PLACEHOLDER
            )
            module_name = third_party_call_dict["module"] if third_party_call_dict else _PLACEHOLDER
            property_method = (
                third_party_call_dict["property_method"] if third_party_call_dict else _PLACEHOLDER
            )
            behavior_desc = pdg_node.get_behavior_description()
            if behavior_desc:
                suffix = _file_io_suffix(pdg_node)
                statement.add_call_info(
                    f"Method name: {call_name}, third-party call resolved with behavior: "
                    f"[{behavior_desc}]{suffix} [Node ID: {nid}]"
                )
            else:
                statement.add_call_info(
                    f"Method name: {call_name}, third-party API call of "
                    f"{module_name}.{property_method}. "
                    f"No API trace captured in dynamic analysis. [Node ID: {nid}]"
                )
            return statement

        # --- Unresolved nodes from the static phase ---
        if is_static_unresolved:
            unresolved_call_dict = pdg_node.get_unresolved_call_dict()
            raw_call_name = unresolved_call_dict["call_name"] if unresolved_call_dict else None
            # Upstream may pass the literal string "None" when the call has
            # no resolvable name (see resolve_and_process_call); normalize
            # all "missing" forms to a single placeholder so the prompt
            # only has to describe one format.
            call_name = raw_call_name if raw_call_name and raw_call_name != "None" else _PLACEHOLDER
            behavior_desc = pdg_node.get_behavior_description()
            if behavior_desc:
                suffix = _file_io_suffix(pdg_node)
                statement.add_call_info(
                    f"Method name: {call_name}, previously unresolved call resolved "
                    f"with behavior: [{behavior_desc}]{suffix} [Node ID: {nid}]"
                )
            else:
                statement.add_call_info(
                    f"Method name: {call_name}, statically unresolved call. "
                    f"No API trace captured in dynamic analysis. [Node ID: {nid}]"
                )
            return statement

        # --- Newly discovered or existing sensitive nodes ---
        if pdg_node.is_sensitive_node():
            behavior_desc = pdg_node.get_behavior_description()
            sensitive_dict = pdg_node.get_sensitive_dict()

            if behavior_desc:
                if sensitive_dict:
                    call_name = sensitive_dict["call_name"]
                else:
                    call_name = pdg_node.get_name() or _PLACEHOLDER
                suffix = _file_io_suffix(pdg_node)
                statement.add_call_info(
                    f"Method name: {call_name}, sensitive API call with resolved "
                    f"call-chain behavior: [{behavior_desc}]{suffix} [Node ID: {nid}]"
                )
                return statement

            if not sensitive_dict:
                return statement

            qualified_name = sensitive_dict["call_info"]["qualified_name"]
            call_name = sensitive_dict["call_name"]
            resolved = pdg_node.get_resolved_api_call()

            if pdg_node.get_call_type() == CONDITIONAL_CALL:
                if resolved:
                    if _domain_supports_resolved_annotation(sensitive_dict):
                        args_str, ret_str = _format_resolved_args_and_return(resolved)
                        statement.add_call_info(
                            f"Method name: {call_name} is a sensitive API call of "
                            f"{qualified_name}. Resolved arguments: {args_str}. "
                            f"Resolved return value: {ret_str}. [Node ID: {nid}]"
                        )
                    else:
                        statement.add_call_info(
                            f"Method name: {call_name} is a sensitive API call of "
                            f"{qualified_name}. [Node ID: {nid}]"
                        )
                else:
                    eval_annotation = _eval_annotation_for_sensitive(
                        pdg_node, qualified_name, call_name
                    )
                    if eval_annotation:
                        statement.add_call_info(eval_annotation)
                    else:
                        statement.add_call_info(
                            f"Method name: {call_name} is a conditional sensitive API call of "
                            f"{qualified_name}. [Node ID: {nid}]"
                        )
            elif pdg_node.get_call_type() in (FIELD_ACCESS, INDEX_ACCESS):
                statement.add_call_info(
                    f"Method name: {call_name} is a sensitive property access of "
                    f"{qualified_name}. [Node ID: {nid}]"
                )
            else:
                if resolved and _domain_supports_resolved_annotation(sensitive_dict):
                    args_str, ret_str = _format_resolved_args_and_return(resolved)
                    statement.add_call_info(
                        f"Method name: {call_name} is a sensitive API call of {qualified_name}. "
                        f"Resolved arguments: {args_str}. Resolved return value: {ret_str}. "
                        f"[Node ID: {nid}]"
                    )
                else:
                    statement.add_call_info(
                        f"Method name: {call_name} is a sensitive API call of {qualified_name}. "
                        f"[Node ID: {nid}]"
                    )
            return statement

        # --- Function calls and other node types: delegate to static logic ---
        call_type = pdg_node.get_call_type()
        if call_type == FUNCTION_CALL:
            for callee_pdg in pdg_node.get_callee_pdgs():
                call_name = pdg_node.get_name()
                call_file_name = pdg_node.get_file_name()
                callee_name = callee_pdg.get_name()
                callee_file_name = callee_pdg.get_file_name()
                statement.add_callee_info(
                    f"{call_name}() in {call_file_name} -> function {callee_name} in {callee_file_name}"
                )

        return statement

    def locate_nearest_statement(self, tree_sitter_node: Node) -> Node | None:
        if self.node_is_statement(tree_sitter_node):
            return tree_sitter_node
        else:
            parent_node = tree_sitter_node.parent
            if parent_node:
                return self.locate_nearest_statement(parent_node)
            else:
                return None

    def node_is_statement(self, tree_sitter_node: Node) -> bool:
        if tree_sitter_node.type.endswith("declaration") or tree_sitter_node.type.endswith(
            "statement"
        ):
            return True
        else:
            return False

    @staticmethod
    def transform_key(key):
        if key == "labelV":
            return "label"
        elif key == "labelE":
            return "label"
        else:
            return key
