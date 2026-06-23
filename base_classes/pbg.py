from __future__ import annotations

from collections import deque
from typing import TYPE_CHECKING

import networkx as nx
from loguru import logger

from ast_parser import ASTParser
from base_classes.cpg import CPG
from base_classes.cpg_pdg_edge import Edge
from base_classes.file_code_slice import FileCodeSlice
from base_classes.pdg import PDG
from base_classes.pdg_node import PDGNode
from npm_pipeline.classes.code_Info import CodeInfo
from npm_pipeline.classes.file import File
from npm_pipeline.classes.object import Object
from sensitive_op import sensitive_call_finder, sensitive_property_access_finder

if TYPE_CHECKING:
    from npm_pipeline.classes.analysis_context import AnalysisContext


class PBG:
    """
    record the behavior of the program
    """

    def __init__(self, cpg: CPG, pdg_dict: dict[int, PDG], package_dir, package_name):
        self.entrance_node = None  # Entry node of the PBG.
        self.return_node: list[PDGNode] = []  # Return results recorded for the PBG.
        self.pdg_nodes: dict[int, PDGNode] = {}
        self.pdg_edges: dict[tuple[int, int], Edge] = {}
        self.pdg_out_edges: dict[int, set[int]] = {}
        self.pdg_in_edges: dict[int, set[int]] = {}
        self.object_nodes: list[Object] = []
        self.pdg_object_data_edge: dict[int, set[Object]] = {}  # Data-flow edges from PDG nodes to objects.
        self.object_pdg_data_edge: dict[Object, set[int]] = {}  # Data-flow edges from objects to PDG nodes.
        self.cpg = cpg
        self.pdg_dict = pdg_dict
        self.package_dir = package_dir
        self.package_name = package_name
        self.sensitive_graph = None
        self.visited = []

    def extract_sensitive_subgraph(self, code_info: CodeInfo):
        node_id_list = list(self.pdg_nodes.keys())
        sensitive_node_list = []
        for node_id in node_id_list:
            pdg_node = self.pdg_nodes[node_id]
            if pdg_node.is_sensitive_node():
                sensitive_node_list.append(pdg_node)

        G = self.create_networkx_graph()
        sensitive_nodes = [n for n, data in G.nodes(data=True) if data.get("color") == "red"]
        subG = nx.MultiDiGraph()
        for n in sensitive_nodes:
            subG.add_node(n, **G.nodes[n])
            subG.nodes[n]["color"] = "black"

        for u in sensitive_nodes:
            # Find nearest sensitive nodes using only DDG, then add Data_Flow edges.
            v_list_data = self.find_next_sensitive_nodes(
                G, u, sensitive_nodes, label_filter={"DDG"}
            )
            for v in v_list_data:
                # Add the (u -> v) edge if the subgraph does not already contain it.
                if not subG.has_edge(u, v):
                    subG.add_edge(u, v, label="Data_Flow", color="red")

            # Find nearest sensitive nodes using only CFG, then add Control_Flow edges.
            v_list_cfg = self.find_next_sensitive_nodes(G, u, sensitive_nodes, label_filter={"CFG"})
            for v in v_list_cfg:
                has_cf_edge = False

                # If multi-edges already exist, check whether one is labeled Control_Flow.
                if subG.has_edge(u, v):
                    edge_data_dict = subG.get_edge_data(u, v)
                    for _, edge_attrs in edge_data_dict.items():
                        if edge_attrs.get("label") == "Control_Flow":
                            has_cf_edge = True
                            break

                # Add a Control_Flow edge if none exists yet.
                if not has_cf_edge:
                    subG.add_edge(u, v, label="Control_Flow", color="blue")

            # Find nearest sensitive nodes through data flow while respecting CFG order.
            v_list_obj = self.find_next_sensitive_nodes_object_cfg_forward(G, u, sensitive_nodes)
            for v in v_list_obj:
                has_dd_edge = False
                if subG.has_edge(u, v):
                    edge_data_dict = subG.get_edge_data(u, v)
                    for _, edge_attrs in edge_data_dict.items():
                        if edge_attrs.get("label") == "Data_Flow":
                            has_dd_edge = True
                            break

                if not has_dd_edge:
                    subG.add_edge(u, v, label="Data_Flow", color="green")

        # Apply an additional check to each sensitive-node pair (u, v).
        # If they are mutually unreachable in CFG but share an ancestor, check for Object_Data linkage.
        sens_list = list(sensitive_nodes)
        for i in range(len(sens_list)):
            for j in range(i + 1, len(sens_list)):
                u = sens_list[i]
                v = sens_list[j]
                # If neither u -> v nor v -> u is reachable in CFG.
                if not self.has_cfg_path(G, u, v) and not self.has_cfg_path(G, v, u):
                    # Then check for a common ancestor.
                    if self.has_common_cfg_ancestor(G, u, v):
                        # If a common ancestor exists.
                        if self.has_data_flow_path(
                            G, u, v, sens_list, data_labels={"Object_Data", "DDG"}
                        ):
                            if not subG.has_edge(u, v):
                                # If a data-flow path exists, add a (u -> v) data-flow edge.
                                subG.add_edge(u, v, label="Data_Flow", color="green")

        if code_info.api_call_info is not None:
            # under dynamic analysis
            recorded_mapping = code_info.api_call_to_pdg_node_mapping

            # find missing API
            missing_indices = []
            for idx, api_call in enumerate(code_info.api_call_info.collections):
                if api_call not in recorded_mapping and self.is_sensitive(api_call):
                    missing_indices.append(idx)

            # Group successive missing API calls into a group
            groups = []
            current_group = []
            for i in missing_indices:
                if not current_group or i == current_group[-1] + 1:
                    current_group.append(i)
                else:
                    groups.append(current_group)
                    current_group = [i]
            if current_group:
                groups.append(current_group)

            for group in groups:
                first_missing_idx = group[0]
                last_missing_idx = group[-1]

                # Search backward from first_missing_idx for the nearest recorded API call's PDG node.
                prev_recorded = None
                for i in range(first_missing_idx - 1, -1, -1):
                    candidate_api = code_info.api_call_info.collections[i]
                    if candidate_api in recorded_mapping:
                        prev_recorded = recorded_mapping[candidate_api]
                        break

                next_recorded = None
                for i in range(last_missing_idx + 1, len(code_info.api_call_info.collections)):
                    candidate_api = code_info.api_call_info.collections[i]
                    if candidate_api in recorded_mapping:
                        next_recorded = recorded_mapping[candidate_api]
                        break

                # Create and insert a new node in subG for each missing API call in the group.
                previous_node = prev_recorded  # Initially, the previous node is the front boundary, possibly None.
                for missing_idx in group:
                    api_call = code_info.api_call_info.collections[missing_idx]
                    if api_call.type == "function":
                        sensitive_info = sensitive_call_finder.query(
                            f"{api_call.module}.{api_call.function}"
                        )
                    else:
                        sensitive_info = sensitive_property_access_finder.query(
                            f"{api_call.module}.{api_call.function}"
                        )

                    if sensitive_info["domain"] == "Process":
                        degree = 0.5
                    elif sensitive_info["domain"] == "File":
                        degree = 0.5
                    else:
                        degree = 0.5

                    # Generate a unique node ID, such as missing_api_<index>.
                    new_node_id = f"missing_api_{missing_idx}"
                    # Set attributes for the new node; adjust as needed.
                    node_attr = {
                        "label": f"{api_call.module}.{api_call.function}",
                        "color": "green",
                        "full_name": sensitive_info["qualified_name"],
                        "domain": sensitive_info["domain"],
                        "degree": degree,
                    }
                    subG.add_node(new_node_id, **node_attr)
                    # Add a Control Flow edge when the front boundary or previous inserted node exists.
                    if previous_node is not None:
                        subG.add_edge(previous_node, new_node_id, label="Control_Flow")
                        # subG.add_edge(previous_node, new_node_id, label="Data_Flow")
                    previous_node = new_node_id

                # If the back boundary exists, connect the group's last new node to it.
                if next_recorded is not None and previous_node is not None:
                    subG.add_edge(previous_node, next_recorded, label="Control_Flow")
                    # subG.add_edge(previous_node, next_recorded, label="Data_Flow")

        return subG

    def _slice_into_components(
        self,
        slice_builder,
    ) -> tuple[list[dict[str, FileCodeSlice]], list[dict]]:
        """Common slicing logic shared by the static and dynamic pipelines.

        Builds the networkx graph, identifies seed nodes (sensitive / third-party
        / unresolved calls), marks forward/backward data-flow paths, partitions
        the resulting subgraph into connected components, and computes CFG-based
        execution ordering.

        Args:
            slice_builder: Callable ``(component_nodes: set) ->
                dict[str, FileCodeSlice]`` that converts a set of PDG node IDs
                into per-file code slices.  Pass
                ``lambda nodes: self._build_file_code_slices(nodes, files)``
                for the static phase and
                ``lambda nodes: self._build_dynamic_file_code_slices(nodes, files, ctx)``
                for the dynamic phase.

        Returns:
            A tuple ``(component_slices, component_ordering)`` where
            *component_ordering* is aligned with *component_slices* and each
            element carries ``cfg_order``, ``predecessors`` and ``successors``.
        """
        G = self.create_networkx_graph()

        sensitive_call_nodes = [n for n, data in G.nodes(data=True) if data.get("color") == "red"]
        third_party_call_nodes = [
            n for n, data in G.nodes(data=True) if data.get("color") == "yellow"
        ]
        unresolved_call_nodes = [
            n for n, data in G.nodes(data=True) if data.get("color") == "orange"
        ]

        all_seed_nodes = sensitive_call_nodes + third_party_call_nodes + unresolved_call_nodes

        forward_visited: set[int] = set()
        backward_visited: set[int] = set()

        for seed in all_seed_nodes:
            self._mark_forward_paths(G, seed, forward_visited)
        for seed in all_seed_nodes:
            self._mark_backward_paths(G, seed, backward_visited)

        data_flow_labels = {"DDG", "Object_Data"}

        # Object and METHOD nodes are used only as data-flow bridges between PDG
        # nodes and are not included in the final slice.
        bridge_nodes = {n for n, data in G.nodes(data=True) if data.get("in_slice", False)} | set(
            all_seed_nodes
        )

        bridge_graph = nx.Graph()
        for n in bridge_nodes:
            bridge_graph.add_node(n)
        for u, v, _, attrs in G.edges(data=True, keys=True):
            if u in bridge_nodes and v in bridge_nodes:
                if attrs.get("label") in data_flow_labels:
                    bridge_graph.add_edge(u, v)

        component_slices: list[dict[str, FileCodeSlice]] = []
        component_node_lists: list[set] = []
        for raw_component in nx.connected_components(bridge_graph):
            component_nodes = {
                n
                for n in raw_component
                if n in self.pdg_nodes and self.pdg_nodes[n].get_node_type() != "METHOD"
            }
            if not component_nodes:
                continue
            component_file_code_slice_dict = slice_builder(component_nodes)
            if component_file_code_slice_dict:
                component_slices.append(component_file_code_slice_dict)
                component_node_lists.append(component_nodes)

        component_ordering = self._compute_component_ordering(
            G, component_node_lists, set(all_seed_nodes)
        )

        return component_slices, component_ordering

    def behavior_graph_to_slice_static(
        self, files: dict[str, File]
    ) -> tuple[list[dict[str, FileCodeSlice]], list[dict]]:
        """Slice the behaviour graph into connected components (static phase).

        Delegates to :meth:`_slice_into_components` using the static slice
        builder :meth:`_build_file_code_slices`.
        """
        return self._slice_into_components(lambda nodes: self._build_file_code_slices(nodes, files))

    def _compute_component_ordering(
        self,
        G: nx.MultiDiGraph,
        component_node_lists: list[set],
        seed_nodes: set,
    ) -> list[dict]:
        """Compute CFG-based execution ordering metadata for each component.

        For every component the earliest line number among its seed nodes is
        used as ``cfg_order``.  Pairwise *happens-before* relations are
        determined via :meth:`has_cfg_path` between representative seed nodes.

        Returns a list aligned with *component_node_lists* where each element
        is ``{"cfg_order": int, "predecessors": [int, ...], "successors": [int, ...]}``.
        """
        n = len(component_node_lists)

        comp_meta: list[dict] = []
        for comp_nodes in component_node_lists:
            comp_seeds = comp_nodes & seed_nodes
            candidates = comp_seeds or comp_nodes
            min_line = float("inf")
            representative = None
            for nid in candidates:
                if nid in self.pdg_nodes:
                    line = self.pdg_nodes[nid].get_line_number()
                    if line is not None and line < min_line:
                        min_line = line
                        representative = nid
            comp_meta.append(
                {
                    "cfg_order": min_line if min_line != float("inf") else 0,
                    "representative": representative,
                    "predecessors": [],
                    "successors": [],
                }
            )

        for i in range(n):
            ri = comp_meta[i]["representative"]
            if ri is None:
                continue
            for j in range(i + 1, n):
                rj = comp_meta[j]["representative"]
                if rj is None:
                    continue
                if self.has_cfg_path(G, ri, rj):
                    comp_meta[i]["successors"].append(j)
                    comp_meta[j]["predecessors"].append(i)
                if self.has_cfg_path(G, rj, ri):
                    comp_meta[j]["successors"].append(i)
                    comp_meta[i]["predecessors"].append(j)

        for meta in comp_meta:
            meta.pop("representative", None)

        return comp_meta

    def _build_file_code_slices(
        self, node_ids: set, files: dict[str, File]
    ) -> dict[str, FileCodeSlice]:
        slice_dict: dict[str, set] = {}

        for node_id in node_ids:
            if node_id not in self.pdg_nodes:
                continue
            pdg_node = self.pdg_nodes[node_id]
            file_name = (
                pdg_node.get_file_name() if hasattr(pdg_node, "get_file_name") else "unknown"
            )
            if file_name != "unknown":
                if file_name not in slice_dict:
                    slice_dict[file_name] = set()
                slice_dict[file_name].add(node_id)

        # Map each ID to its corresponding statement.
        file_code_slice_dict: dict[str, FileCodeSlice] = {}
        # Track statement IDs already added per file to avoid duplicates.
        added_statement_ids: dict[str, set[int]] = {}

        for file_name, ids in slice_dict.items():
            if file_name not in added_statement_ids:
                added_statement_ids[file_name] = set()

                raw_code = files[file_name].get_raw_code()
                source_code = "".join(raw_code)
                ast_parser = ASTParser(source_code)

            for value in ids:
                pdg_node = self.pdg_nodes[value]
                if pdg_node.get_node_type() == "METHOD_PARAMETER_IN":
                    continue
                statement = self.cpg.get_static_statement_from_node_id(value, pdg_node, ast_parser)
                if statement:
                    statement_tree_sitter_node = statement.get_tree_sitter_node()

                    # Check whether the statement ID already exists.
                    if statement_tree_sitter_node not in added_statement_ids[file_name]:
                        if file_name not in file_code_slice_dict:
                            file_code_slice_dict[file_name] = FileCodeSlice(file_name, [])
                        file_code_slice_dict[file_name].add_statement(statement)
                        added_statement_ids[file_name].add(statement_tree_sitter_node)
                    else:
                        # The statement already exists; merge metadata.
                        existing_statement = file_code_slice_dict[
                            file_name
                        ].get_statement_by_tree_sitter_node(statement_tree_sitter_node)
                        if existing_statement:
                            # Merge call_info entries without duplicates.
                            for call_info in statement.get_call_info():
                                if call_info not in existing_statement.get_call_info():
                                    existing_statement.add_call_info(call_info)

                            # Merge callee_info entries without duplicates.
                            for callee_info in statement.get_callee_info():
                                if callee_info not in existing_statement.get_callee_info():
                                    existing_statement.add_callee_info(callee_info)
                        else:
                            logger.warning(
                                f"Statement ID exist but statement not found in file {file_name}"
                            )

        # Generate code slices for each FileCodeSlice.
        for file_name, file_code_slice in file_code_slice_dict.items():
            raw_code = files[file_name].get_raw_code()
            sliced_code = file_code_slice.generate_sliced_code(raw_code)
            file_code_slice.set_sliced_code(sliced_code)

        return file_code_slice_dict

    # ------------------------------------------------------------------
    # Dynamic slice generation
    # ------------------------------------------------------------------

    def behavior_graph_to_slice_dynamic(
        self, files: dict[str, File], analysis_context: AnalysisContext
    ) -> tuple[list[dict[str, FileCodeSlice]], list[dict]]:
        """Slice the behaviour graph into connected components (dynamic phase).

        Delegates to :meth:`_slice_into_components` using the dynamic slice
        builder :meth:`_build_dynamic_file_code_slices`.
        """
        return self._slice_into_components(
            lambda nodes: self._build_dynamic_file_code_slices(nodes, files, analysis_context)
        )

    def _build_dynamic_file_code_slices(
        self, node_ids: set, files: dict[str, File], analysis_context: AnalysisContext
    ) -> dict[str, FileCodeSlice]:
        """Mirrors ``_build_file_code_slices`` but delegates annotation
        generation to ``CPG.get_dynamic_statement_from_node_id``."""
        slice_dict: dict[str, set] = {}

        for node_id in node_ids:
            if node_id not in self.pdg_nodes:
                continue
            pdg_node = self.pdg_nodes[node_id]
            file_name = (
                pdg_node.get_file_name() if hasattr(pdg_node, "get_file_name") else "unknown"
            )
            if file_name != "unknown":
                if file_name not in slice_dict:
                    slice_dict[file_name] = set()
                slice_dict[file_name].add(node_id)

        file_code_slice_dict: dict[str, FileCodeSlice] = {}
        added_statement_ids: dict[str, set[int]] = {}

        for file_name, ids in slice_dict.items():
            if file_name not in added_statement_ids:
                added_statement_ids[file_name] = set()

                raw_code = files[file_name].get_raw_code()
                source_code = "".join(raw_code)
                ast_parser = ASTParser(source_code)

            for value in ids:
                pdg_node = self.pdg_nodes[value]
                statement = self.cpg.get_dynamic_statement_from_node_id(
                    value, pdg_node, ast_parser, analysis_context
                )
                if statement:
                    statement_tree_sitter_node = statement.get_tree_sitter_node()

                    if statement_tree_sitter_node not in added_statement_ids[file_name]:
                        if file_name not in file_code_slice_dict:
                            file_code_slice_dict[file_name] = FileCodeSlice(file_name, [])
                        file_code_slice_dict[file_name].add_statement(statement)
                        added_statement_ids[file_name].add(statement_tree_sitter_node)
                    else:
                        existing_statement = file_code_slice_dict[
                            file_name
                        ].get_statement_by_tree_sitter_node(statement_tree_sitter_node)
                        if existing_statement:
                            for call_info in statement.get_call_info():
                                if call_info not in existing_statement.get_call_info():
                                    existing_statement.add_call_info(call_info)
                            for callee_info in statement.get_callee_info():
                                if callee_info not in existing_statement.get_callee_info():
                                    existing_statement.add_callee_info(callee_info)
                        else:
                            logger.warning(
                                f"Statement ID exist but statement not found in file {file_name}"
                            )

        for file_name, file_code_slice in file_code_slice_dict.items():
            raw_code = files[file_name].get_raw_code()
            sliced_code = file_code_slice.generate_sliced_code(raw_code)
            file_code_slice.set_sliced_code(sliced_code)

        return file_code_slice_dict

    def _mark_forward_paths(self, G: nx.DiGraph, start_node: int, global_visited: set[int]):
        """
        Starting from ``start_node``, run DFS along Data_Flow edges and mark visited nodes as ``in_slice=True``.

        Args:
            G: NetworkX graph.
            start_node: Start node.
            global_visited: Global visited set to avoid duplicate traversal.
        """
        # Return immediately if the start node has already been visited.
        if start_node in global_visited:
            return

        # Data-flow edge labels.
        data_flow_labels = {"DDG", "Object_Data"}

        def dfs(current):
            """
            Run DFS and mark all visited nodes.

            Args:
                current: Current node.
            """
            # Return immediately if the node has already been visited.
            if current in global_visited:
                return

            # Mark the current node as in_slice.
            G.nodes[current]["in_slice"] = True
            global_visited.add(current)

            # Traverse all valid data-flow successors.
            for successor in G.successors(current):
                if successor in global_visited:
                    continue  # Avoid duplicate visits.

                # Check whether a Data_Flow edge exists.
                edge_data_dict = G.get_edge_data(current, successor, default={})
                for _, attrs in edge_data_dict.items():
                    if attrs.get("label") in data_flow_labels:
                        # Recursively visit the successor.
                        dfs(successor)
                        break

        # Start DFS from the start node.
        dfs(start_node)

    def _mark_backward_paths(self, G: nx.DiGraph, start_node: int, global_visited: set[int]):
        """
        Starting from ``start_node``, run reverse DFS along Data_Flow edges and mark visited nodes as ``in_slice=True``.

        Args:
            G: NetworkX graph.
            start_node: Start node.
            global_visited: Global visited set to avoid duplicate traversal.
        """
        # Return immediately if the start node has already been visited.
        if start_node in global_visited:
            return

        # Data-flow edge labels.
        data_flow_labels = {"DDG", "Object_Data"}

        def backward_dfs(current):
            """
            Run reverse DFS and mark all visited nodes.

            Args:
                current: Current node.
            """
            # Return immediately if the node has already been visited.
            if current in global_visited:
                return

            # Skip nodes whose CODE attribute is :program.
            pdg_node = self.pdg_nodes.get(current)
            if pdg_node is not None and pdg_node.get_code() == ":program":
                global_visited.add(current)
                return

            # Mark the current node as in_slice.
            G.nodes[current]["in_slice"] = True
            global_visited.add(current)

            # Traverse all valid data-flow predecessors.
            for predecessor in G.predecessors(current):
                if predecessor in global_visited:
                    continue  # Avoid duplicate visits.

                # Skip predecessor nodes whose CODE attribute is :program.
                pred_pdg_node = self.pdg_nodes.get(predecessor)
                if pred_pdg_node is not None and pred_pdg_node.get_code() == ":program":
                    continue

                # Check whether a Data_Flow edge exists in the reverse direction.
                edge_data_dict = G.get_edge_data(predecessor, current, default={})
                for _, attrs in edge_data_dict.items():
                    if attrs.get("label") in data_flow_labels:
                        # Recursively visit the predecessor.
                        backward_dfs(predecessor)
                        break

        # Start reverse DFS from the start node.
        backward_dfs(start_node)

    @staticmethod
    def has_cfg_path(G, start, end):
        """Find the node from start to end has cfg path"""
        visited = set()
        queue = deque([start])

        while queue:
            cur = queue.popleft()
            if cur == end:
                return True
            for nxt in G.successors(cur):
                if nxt not in visited:
                    edge_data_dict = G.get_edge_data(cur, nxt, default={})
                    for _, attrs in edge_data_dict.items():
                        if attrs.get("label") == "CFG":
                            visited.add(nxt)
                            queue.append(nxt)
                            break
        return False

    @staticmethod
    def has_data_flow_path(G, start, end, sensitive_list, data_labels):
        """
        Check whether a data-flow path exists from ``start`` to ``end``.

        Traversal uses only directed edges whose label is in ``data_labels``.
        Return True if ``end`` is reachable, otherwise False.
        """
        from collections import deque

        visited = set()
        queue = deque([start])
        visited.add(start)

        while queue:
            cur = queue.popleft()
            if cur == end:
                return True

            for nxt in G.successors(cur):
                if nxt not in visited:
                    if nxt in sensitive_list and nxt != end:
                        visited.add(nxt)
                        continue
                    edge_data_dict = G.get_edge_data(cur, nxt, default={})
                    # Any parallel edge with a label in data_labels is sufficient to advance.
                    for _, attrs in edge_data_dict.items():
                        if attrs.get("label") in data_labels:
                            visited.add(nxt)
                            queue.append(nxt)
                            break
        return False

    @staticmethod
    def get_cfg_ancestors(G, node):
        """
        Search backward along label=CFG edges and return the node's ancestors.
        """
        ancestors = {node}
        queue = deque([node])

        while queue:
            cur = queue.popleft()
            for pre in G.predecessors(cur):
                if pre not in ancestors:
                    edge_data_dict = G.get_edge_data(pre, cur, default={})
                    for _, attrs in edge_data_dict.items():
                        if attrs.get("label") == "CFG":
                            ancestors.add(pre)
                            queue.append(pre)
                            break
        return ancestors

    def has_common_cfg_ancestor(self, G, n1, n2):
        """Judge the node n1 and n2 has the same ancestor"""
        anc1 = self.get_cfg_ancestors(G, n1)
        anc2 = self.get_cfg_ancestors(G, n2)
        return len(anc1.intersection(anc2)) > 0

    @staticmethod
    def get_reachable_nodes(G, source, label):
        """
        Returns the set of nodes reachable from `source` by following
        edges whose "label" attribute matches the passed `label`.
        """
        reachable = {source}
        queue = deque([source])

        while queue:
            cur = queue.popleft()
            for nxt in G.successors(cur):
                # Only explore nxt if it hasn't been visited yet
                if nxt not in reachable:
                    edge_data_dict = G.get_edge_data(cur, nxt, default={})
                    for _, attrs in edge_data_dict.items():
                        # If this edge has the matching label, traverse it
                        if attrs.get("label") in label:
                            reachable.add(nxt)
                            queue.append(nxt)
                            # Break here so we don't consider multiple edges
                            # to the same successor
                            break

        return reachable

    @staticmethod
    def find_next_sensitive_nodes(G, source, sensitive_nodes, label_filter):
        """
        Starting from ``source`` in graph G, traverse only directed edges whose label
        is in ``label_filter``.

        The first sensitive node or nodes encountered are considered the nearest
        sensitive nodes. During search, a branch stops when another sensitive node
        (not ``source``) appears on the path.

        Return all nearest sensitive nodes at the same BFS layer, or an empty list
        when none are found.
        """

        queue = deque([source])
        visited = {source}
        found_sensitive = []

        while queue:
            level_size = len(queue)
            level_nodes = [queue.popleft() for _ in range(level_size)]
            next_layer = []
            for current in level_nodes:
                for nxt in G.successors(current):
                    if nxt not in visited:
                        edge_data_dict = G.get_edge_data(current, nxt, default={})
                        for _, eattrs in edge_data_dict.items():
                            if eattrs.get("label", "") in label_filter:
                                visited.add(nxt)
                                next_layer.append(nxt)
                                break

            new_found = [n for n in next_layer if n != source and n in sensitive_nodes]
            found_sensitive.extend(new_found)
            remaining_nodes = [n for n in next_layer if n not in new_found]
            queue.extend(remaining_nodes)

        return found_sensitive

    def find_next_sensitive_nodes_object_cfg_forward(self, G, source, sensitive_nodes):
        cfg_reachable = self.get_reachable_nodes(G, source, {"CFG"})

        queue = deque([source])
        visited = {source}
        found_sensitive = []

        while queue:
            level_size = len(queue)
            level_nodes = [queue.popleft() for _ in range(level_size)]
            next_layer = []
            for current in level_nodes:
                for nxt in G.successors(current):
                    if nxt not in visited:
                        edge_data_dict = G.get_edge_data(current, nxt, default={})
                        for _, eattrs in edge_data_dict.items():
                            if eattrs.get("label", "") in {"Object_Data", "DDG"}:
                                visited.add(nxt)
                                next_layer.append(nxt)
                                break

            new_found = [
                n for n in next_layer if n != source and n in sensitive_nodes and n in cfg_reachable
            ]
            found_sensitive.extend(new_found)
            remaining_nodes = [n for n in next_layer if n not in new_found]
            queue.extend(remaining_nodes)

        return found_sensitive

    def create_networkx_graph(self):
        G = nx.MultiDiGraph()
        for node_id in self.pdg_nodes.keys():
            pdg_node = self.pdg_nodes[node_id]
            if pdg_node.is_third_party_call():
                color = "yellow"
            elif pdg_node.is_sensitive_node():
                color = "red"
            elif pdg_node.is_unresolved_call():
                color = "orange"
            else:
                color = "black"
            if pdg_node.get_node_type() == "METHOD":
                G.add_node(
                    node_id,
                    color="blue",
                    label=f"{node_id}, {pdg_node.get_line_number()}, {pdg_node.get_name()}\n",
                )
            else:
                if color == "red":
                    sensitive_dict = pdg_node.get_sensitive_dict()
                    call_info = (
                        sensitive_dict.get("call_info")
                        if isinstance(sensitive_dict, dict)
                        else None
                    )
                    if call_info and "qualified_name" in call_info:
                        G.add_node(
                            node_id,
                            color=color,
                            label=f"{node_id}, {pdg_node.get_line_number()}, "
                            f"{pdg_node.get_name()}\n{call_info['qualified_name']}",
                            qualified_name=call_info["qualified_name"],
                            domain=call_info.get("domain"),
                        )
                    else:
                        # Defensive fallback: a node may be marked sensitive
                        # during Phase A (behavior_gen_utils._record_third_party_chain)
                        # before Phase B fills in sensitive_dict via
                        # handle_api_call_in_dynamic. If orphan recovery never
                        # resolves it the dict stays None; render it as sensitive
                        # without crashing.
                        G.add_node(
                            node_id,
                            color=color,
                            label=f"{node_id}, {pdg_node.get_line_number()}, "
                            f"{pdg_node.get_name()}\n<unresolved sensitive>",
                        )
                elif color == "yellow":
                    G.add_node(
                        node_id,
                        color=color,
                        label=f"{node_id}, {pdg_node.get_line_number()}, {pdg_node.get_name()}\n",
                    )
                elif color == "orange":
                    G.add_node(
                        node_id,
                        color=color,
                        label=f"{node_id}, {pdg_node.get_line_number()}, {pdg_node.get_name()}\n",
                    )
                else:
                    G.add_node(
                        node_id,
                        color=color,
                        label=f"{node_id}, {pdg_node.get_line_number()}, {pdg_node.get_name()}\n",
                    )

        for head, tails in self.pdg_out_edges.items():
            for tail in tails:
                pdg_edge = self.pdg_edges[(head, tail)]
                pdg_edge_type = self.get_type_of_edge(pdg_edge)
                if pdg_edge_type == "CFG":
                    G.add_edge(head, tail, label=pdg_edge_type)
                elif pdg_edge_type == "DDG":
                    G.add_edge(head, tail, label=pdg_edge_type, color="red")
                elif pdg_edge_type == "CFG_DDG":
                    G.add_edge(head, tail, label="CFG")
                    G.add_edge(head, tail, label="DDG", color="red")
                elif pdg_edge_type == "REMOVE":
                    pass
                else:
                    G.add_edge(head, tail, label=pdg_edge_type)

        for _object in self.object_nodes:
            G.add_node(_object.get_name(), label=f"{_object.get_name()}\n")

        for head, ref_object_set in self.pdg_object_data_edge.items():
            for ref_object in ref_object_set:
                G.add_edge(head, ref_object.get_name(), label="Object_Data", color="green")

        for ref_object, tails in self.object_pdg_data_edge.items():
            for tail in tails:
                G.add_edge(ref_object.get_name(), tail, label="Object_Data", color="green")

        isolates = list(nx.isolates(G))

        # Remove isolated nodes.
        G.remove_nodes_from(isolates)
        return G

    def pdg_to_dot(self):
        G = self.create_networkx_graph()
        return G

    def add_object(self, ref_object: Object):
        if ref_object in self.object_nodes:
            # the object is already there, skip
            return
        else:
            self.object_nodes.append(ref_object)

    def add_pdg_to_object_data_edge(self, pdg_node_id: int, ref_object: Object):
        """
        add the data edge from the pdg to the Object
        """
        if pdg_node_id in self.pdg_object_data_edge:
            self.pdg_object_data_edge[pdg_node_id].add(ref_object)
        else:
            self.pdg_object_data_edge[pdg_node_id] = set()
            self.pdg_object_data_edge[pdg_node_id].add(ref_object)

    def add_object_to_pdg_edge(self, ref_object: Object, pdg_node_id: int):
        """
        add the data edge from the Object to the pdg node
        """
        if ref_object not in self.object_nodes:
            self.add_object(ref_object)
        if ref_object in self.object_pdg_data_edge:
            self.object_pdg_data_edge[ref_object].add(pdg_node_id)
        else:
            self.object_pdg_data_edge[ref_object] = set()
            self.object_pdg_data_edge[ref_object].add(pdg_node_id)

    def add_pdg_node(self, node: PDGNode):
        """
        Add a new node to the result.
        """
        self.pdg_nodes[node.get_id()] = node

    def add_pdg_edge(self, head: int, tail: int, edge_attr: list):
        """
        add edge to the program behavior graph
        """
        if head in self.pdg_out_edges and tail in self.pdg_out_edges[head]:
            # the edge is already there, update edge attr
            for attr in edge_attr:
                if attr not in self.pdg_edges[(head, tail)].get_attr():
                    self.pdg_edges[(head, tail)].add_attr(attr)
        if (head, tail) not in self.pdg_edges:
            # Create a new edge instance.
            edge = Edge((head, tail))
            for attr in edge_attr:
                edge.add_attr(attr)
            self.pdg_edges[(head, tail)] = edge
        if head in self.pdg_out_edges:
            self.pdg_out_edges[head].add(tail)
        else:
            self.pdg_out_edges[head] = set()
            self.pdg_out_edges[head].add(tail)

        if tail in self.pdg_in_edges:
            self.pdg_in_edges[tail].add(head)
        else:
            self.pdg_in_edges[tail] = set()
            self.pdg_in_edges[tail].add(head)

    @staticmethod
    def is_sensitive(api_call):
        if api_call.type == "function":
            return sensitive_call_finder.query(f"{api_call.module}.{api_call.function}")
        else:
            return sensitive_property_access_finder.query(f"{api_call.module}.{api_call.function}")

    def get_pdg_out_edges(self) -> dict[int, set[int]]:
        return self.pdg_out_edges

    def get_pdg_in_edges(self) -> dict[int, set[int]]:
        return self.pdg_in_edges

    def pdg_node_is_in(self, node: PDGNode):
        return node.get_id() in self.pdg_nodes

    def set_entrance_node(self, node: PDGNode):
        self.entrance_node = node

    def get_entrance_node(self) -> PDGNode:
        return self.entrance_node

    def add_return_node(self, node: PDGNode):
        self.return_node.append(node)

    def get_return_value(self) -> list[PDGNode]:
        return self.return_node

    def get_pdg_nodes(self) -> dict[int, PDGNode]:
        return self.pdg_nodes

    def get_object_nodes(self) -> list[Object]:
        return self.object_nodes

    def get_pdg_object_data_edge(self) -> dict[int, set[Object]]:
        return self.pdg_object_data_edge

    def get_object_pdg_data_edge(self) -> dict[Object, set[int]]:
        return self.object_pdg_data_edge

    def get_pdg_edges(self) -> dict[tuple[int, int], Edge]:
        return self.pdg_edges

    def add_batch_object_nodes(self, nodes: list[Object]):
        for node in nodes:
            if node not in self.object_nodes:
                self.object_nodes.append(node)

    def add_batch_pdg_object_data_edge(self, edges: dict[int, set[Object]]):
        for key, value in edges.items():
            if key not in self.pdg_object_data_edge:
                self.pdg_object_data_edge[key] = value
            else:
                self.pdg_object_data_edge[key].update(value)

    def add_batch_object_pdg_data_edge(self, edges: dict[Object, set[int]]):
        for key, value in edges.items():
            if key not in self.object_pdg_data_edge:
                self.object_pdg_data_edge[key] = value
            else:
                self.object_pdg_data_edge[key].update(value)

    def add_batch_pdg_nodes(self, nodes: dict[int, PDGNode]):
        for key, value in nodes.items():
            if key not in self.pdg_nodes:
                self.pdg_nodes[key] = value

    def add_batch_pdg_edges(self, edges: dict[tuple[int, int], Edge]):
        for key, value in edges.items():
            if key not in self.pdg_edges:
                self.pdg_edges[key] = value

    def add_batch_pdg_in_edges(self, in_edges: dict[int, set[int]]):
        for key, value in in_edges.items():
            if key not in self.pdg_in_edges:
                self.pdg_in_edges[key] = value
            else:
                self.pdg_in_edges[key].update(value)

    def add_batch_pdg_out_edges(self, out_edges: dict[int, set[int]]):
        for key, value in out_edges.items():
            if key not in self.pdg_out_edges:
                self.pdg_out_edges[key] = value
            else:
                self.pdg_out_edges[key].update(value)

    @staticmethod
    def get_type_of_edge(edge: Edge):
        contain_ddg = False
        contain_cfg = False
        contain_remove = False
        attr_list = edge.get_attr()
        for attr in attr_list:
            if "REMOVE" in attr:
                contain_remove = True
            if "DDG" in attr:
                contain_ddg = True
            if "CFG" in attr:
                contain_cfg = True
        # If REMOVE is present, treat it as a higher-priority label.
        if contain_ddg and contain_cfg:
            return "CFG_DDG"
        elif contain_ddg:
            return "DDG"
        elif contain_cfg:
            return "CFG"
        elif contain_remove:
            return "REMOVE"
        else:
            return "CFG"
