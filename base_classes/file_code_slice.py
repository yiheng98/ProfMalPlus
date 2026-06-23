import re

from tree_sitter import Node

from base_classes.statement import Statement


class FileCodeSlice:
    # Tree-sitter node types that behave like functions.
    FUNCTION_NODE_TYPES = frozenset(
        {
            "function_declaration",
            "function_expression",
            "function",  # Function expression type used by older tree-sitter-javascript versions.
            "arrow_function",
            "generator_function",
            "generator_function_declaration",
            "method_definition",
        }
    )

    # Class-like nodes, also rendered as scope shells to avoid extracting unrelated methods together.
    CLASS_NODE_TYPES = frozenset({"class_declaration", "class"})

    # Node types that act as scope containers; their children belong directly to the scope.
    SCOPE_CONTAINER_TYPES = frozenset({"program", "statement_block", "class_body"})

    # Possible body-block node types for a scope.
    BLOCK_BODY_TYPES = frozenset({"statement_block", "class_body"})

    # Boundary node types that stop upward wrapper expansion.
    _WRAPPER_BOUNDARY_TYPES = SCOPE_CONTAINER_TYPES | FUNCTION_NODE_TYPES | CLASS_NODE_TYPES

    def __init__(self, file_name: str, statements: list[Statement]):
        self.file_name = file_name
        self.statements = statements
        self.sliced_code = ""

    def get_file_name(self) -> str:
        return self.file_name

    def get_statements(self) -> list[Statement]:
        return self.statements

    def get_statement_by_tree_sitter_node(
        self, statement_tree_sitter_node: Node
    ) -> Statement | None:
        for statement in self.statements:
            if statement.get_tree_sitter_node() == statement_tree_sitter_node:
                return statement
        return None

    def add_statement(self, statement: Statement):
        self.statements.append(statement)

    def set_sliced_code(self, sliced_code: str):
        self.sliced_code = sliced_code

    def get_sliced_code(self) -> str:
        return self.sliced_code

    # ------------------------------------------------------------------
    # Code slice generation.
    # ------------------------------------------------------------------

    def generate_sliced_code(self, raw_code: list[str]) -> str:
        """Render code slices by byte ranges from the tree-sitter AST.

        Statements are grouped by their tree-sitter top-level function (TLF):

        - **scope shell** (TLF wrapper / kept intermediate function or class nodes
          that are not hits): render only kept direct children of the scope; non-hit
          sibling statements are omitted.
        - **container hit** (the node itself is a hit and its subtree contains deeper
          hits): use plain range-fill, preserve the original source, recursively
          replace maximal hit descendants with their rendered output, and append the
          node's own ``// call_info`` to the last line.
        - **leaf hit**: extract the source and append ``// call_info`` to the last line.

        During assembly, render units are merged by byte-range containment. Each
        TLF=None hit and each scope-shell render is treated as a render unit with
        start and end bytes. A containment tree is built so outer nodes can range-fill
        from the original source while splicing in their direct children. This prevents
        duplicated extraction for both ``const f = () => {...};`` where the declaration
        wraps the arrow function, and ``if (...) { f(); }`` where the top-level
        statement wraps the arrow-function wrapper.
        """
        if not self.statements:
            return ""

        source = "".join(raw_code)
        source_bytes = source.encode("utf-8")

        hits = [
            statement
            for statement in self.statements
            if statement.get_tree_sitter_node().type not in self.FUNCTION_NODE_TYPES
            and statement.get_tree_sitter_node().type not in self.CLASS_NODE_TYPES
        ]
        if not hits:
            return ""

        hits_by_id: dict[int, Statement] = {}
        for statement in hits:
            hits_by_id[statement.get_tree_sitter_node().id] = statement

        # TLF grouping: key is tlf.id or None; value is (tlf_node|None, [statements]).
        groups: dict = {}
        for statement in hits:
            tlf = self._top_level_function(statement.get_tree_sitter_node())
            key = tlf.id if tlf is not None else None
            if key not in groups:
                groups[key] = (tlf, [])
            groups[key][1].append(statement)

        # Pre-render the scope-shell text for each TLF != None group.
        # scope_renders entry: (wrapper_start, wrapper_end, rendered_text, group_key)
        scope_renders: list[tuple[int, int, str, int]] = []
        for key, (tlf, stmts) in groups.items():
            if tlf is None:
                continue
            wrapper = self._scope_wrapper(tlf)
            kept_ids = self._build_kept_set(stmts, tlf)
            rendered = self._render_dispatch(tlf, kept_ids, hits_by_id, source_bytes)
            scope_renders.append((wrapper.start_byte, wrapper.end_byte, rendered, key))

        # Filter TLF=None hits that fall inside a scope-shell wrapper.
        # - Equal ranges mean the hit is the scope wrapper itself, such as
        #   ``const f = ...`` for ``const f = () => {};``; the scope shell already
        #   rendered it as a whole.
        # - Strictly contained ranges are rare, but can happen when a hit is inside a
        #   function body without being recognized as belonging to that TLF; the
        #   scope shell covers it as well.
        # In both cases, move call_info onto the corresponding scope to avoid loss.
        extra_call_info: dict[int, list[str]] = {}
        none_stmts_remaining: list[Statement] = []
        none_stmts = groups.get(None, (None, []))[1]
        for statement in none_stmts:
            node = statement.get_tree_sitter_node()
            consumed_key: int | None = None
            for wrapper_start, wrapper_end, _, key in scope_renders:
                if node.start_byte >= wrapper_start and node.end_byte <= wrapper_end:
                    consumed_key = key
                    break
            if consumed_key is None:
                none_stmts_remaining.append(statement)
                continue
            for info in statement.get_call_info():
                bucket = extra_call_info.setdefault(consumed_key, [])
                if info not in bucket:
                    bucket.append(info)

        # Append deferred call_info to the matching scope shell.
        scope_renders_final: list[tuple[int, int, str]] = []
        for wrapper_start, wrapper_end, text, key in scope_renders:
            extras = extra_call_info.get(key)
            if extras:
                text = self._append_call_info(text, extras)
            scope_renders_final.append((wrapper_start, wrapper_end, text))

        # Collect render elements: scope-shell pre-rendered text plus remaining TLF=None hits.
        # element = (start, end, kind, payload)
        # kind="scope": payload is already-rendered text.
        # kind="hit":   payload is a Statement to splice during range-fill.
        elements: list[tuple[int, int, str, object]] = []
        for start, end, text in scope_renders_final:
            elements.append((start, end, "scope", text))
        for statement in none_stmts_remaining:
            node = statement.get_tree_sitter_node()
            elements.append((node.start_byte, node.end_byte, "hit", statement))

        if not elements:
            return ""

        # Sort by (start, -end), with outer ranges first, to build parent-child containment.
        elements.sort(key=lambda entry: (entry[0], -entry[1]))

        n = len(elements)
        parent_of: list[int] = [-1] * n
        for i in range(n):
            si, ei = elements[i][0], elements[i][1]
            for j in range(i):
                sj, ej = elements[j][0], elements[j][1]
                if sj <= si and ei <= ej and (sj, ej) != (si, ei):
                    # Later j values are more deeply nested than earlier containing
                    # ranges, so the final assignment is the smallest container.
                    parent_of[i] = j

        children_of: list[list[int]] = [[] for _ in range(n)]
        for i in range(n):
            if parent_of[i] != -1:
                children_of[parent_of[i]].append(i)

        def render_element(index: int) -> str:
            start, end, kind, payload = elements[index]
            if kind == "scope":
                return payload  # Already-rendered scope-shell text.
            statement: Statement = payload  # type: ignore[assignment]
            child_entries: list[tuple[int, int, str]] = []
            for child_index in children_of[index]:
                child_start, child_end, _, _ = elements[child_index]
                child_entries.append((child_start, child_end, render_element(child_index)))
            child_entries.sort(key=lambda entry: entry[0])
            parts: list[str] = []
            cursor = start
            for child_start, child_end, child_text in child_entries:
                if child_start < cursor:
                    continue
                parts.append(source_bytes[cursor:child_start].decode("utf-8"))
                parts.append(child_text)
                cursor = child_end
            parts.append(source_bytes[cursor:end].decode("utf-8"))
            text = "".join(parts)
            call_info = statement.get_call_info()
            if call_info:
                text = self._append_call_info(text, call_info)
            return text

        units: list[tuple[int, str]] = []
        for i in range(n):
            if parent_of[i] == -1:
                units.append((elements[i][0], render_element(i)))

        units.sort(key=lambda entry: entry[0])
        text = "\n".join(unit for _, unit in units)
        return self._collapse_blank_lines(text)

    # ------------------------------------------------------------------
    # AST helpers.
    # ------------------------------------------------------------------

    def _top_level_function(self, node: Node) -> Node | None:
        """Find the outermost function/class ancestor; return None if absent."""
        outermost: Node | None = None
        current = node.parent
        while current is not None:
            if current.type in self.FUNCTION_NODE_TYPES or current.type in self.CLASS_NODE_TYPES:
                outermost = current
            current = current.parent
        return outermost

    def _build_kept_set(self, stmts: list[Statement], tlf: Node) -> set[int]:
        """Walk from each hit up to ``tlf`` and add each visited ``node.id`` to the kept set."""
        kept_ids: set[int] = {tlf.id}
        for statement in stmts:
            node = statement.get_tree_sitter_node()
            kept_ids.add(node.id)
            current = node.parent
            while current is not None and current.id != tlf.id:
                kept_ids.add(current.id)
                current = current.parent
        return kept_ids

    def _scope_wrapper(self, scope_node: Node) -> Node:
        """Find the extraction wrapper for a scope node.

        The wrapper is the outermost node containing ``scope_node`` until its parent is
        a scope container (program / statement_block / class_body) or another scope
        boundary is reached.

        - Declaration prefixes such as ``const f = function(){};`` and
          ``const f = () => {};`` are naturally included in the wrapper.
        - method_definition / function_declaration / generator_function_declaration
          / class_declaration are valid standalone member nodes, so return them
          directly without crossing class_body into a larger class_declaration range.
        """
        if scope_node.type in (
            "method_definition",
            "function_declaration",
            "generator_function_declaration",
            "class_declaration",
        ):
            return scope_node

        current = scope_node
        while current.parent is not None:
            parent = current.parent
            if parent.type in self._WRAPPER_BOUNDARY_TYPES:
                return current
            current = parent
        return current

    def _scope_body(self, scope_node: Node) -> Node | None:
        """Return the scope's block body (statement_block / class_body), or None if absent."""
        for child in scope_node.named_children:
            if child.type in self.BLOCK_BODY_TYPES:
                return child
        return None

    def _maximal_hit_descendants(self, node: Node, hits_by_id: dict) -> list[Node]:
        """Use DFS to find maximal hit descendants of ``node``.

        Traversal stops when a hit is reached, and ``node`` itself is excluded.
        """
        result: list[Node] = []

        def walk(current: Node) -> None:
            for child in current.named_children:
                if child.id in hits_by_id:
                    result.append(child)
                else:
                    walk(child)

        walk(node)
        return result

    def _node_has_inner_hit(self, node: Node, hits_by_id: dict) -> bool:
        """Return whether the node subtree contains a hit, excluding the node itself."""

        def walk(current: Node) -> bool:
            for child in current.named_children:
                if child.id in hits_by_id:
                    return True
                if walk(child):
                    return True
            return False

        return walk(node)

    # ------------------------------------------------------------------
    # Rendering.
    # ------------------------------------------------------------------

    def _render_dispatch(
        self,
        node: Node,
        kept_ids: set[int],
        hits_by_id: dict,
        source_bytes: bytes,
    ) -> str:
        is_scope = node.type in self.FUNCTION_NODE_TYPES or node.type in self.CLASS_NODE_TYPES
        if is_scope:
            return self._render_scope_shell_v2(node, kept_ids, hits_by_id, source_bytes)

        is_hit = node.id in hits_by_id
        has_inner = self._node_has_inner_hit(node, hits_by_id)
        if is_hit and has_inner:
            return self._render_container_hit(
                node, kept_ids, hits_by_id, source_bytes, append_own=True
            )
        if is_hit:
            return self._render_leaf(node, hits_by_id, source_bytes)
        if has_inner:
            # Kept but neither hit nor scope: treat it as a container and range-fill
            # inner hits without appending the node's own call_info.
            return self._render_container_hit(
                node, kept_ids, hits_by_id, source_bytes, append_own=False
            )
        # Fallback: this should not be reached; extract the source directly.
        return source_bytes[node.start_byte : node.end_byte].decode("utf-8")

    def _render_leaf(self, node: Node, hits_by_id: dict, source_bytes: bytes) -> str:
        text = source_bytes[node.start_byte : node.end_byte].decode("utf-8")
        statement = hits_by_id.get(node.id)
        if statement is not None:
            call_info = statement.get_call_info()
            if call_info:
                text = self._append_call_info(text, call_info)
        return text

    def _render_container_hit(
        self,
        node: Node,
        kept_ids: set[int],
        hits_by_id: dict,
        source_bytes: bytes,
        append_own: bool = True,
    ) -> str:
        """Plain range-fill: extract ``source[node.start:node.end]`` as-is and replace each maximal hit descendant with its recursive render."""
        inners = self._maximal_hit_descendants(node, hits_by_id)
        inners.sort(key=lambda inner: inner.start_byte)

        parts: list[str] = []
        cursor = node.start_byte
        for inner in inners:
            if inner.start_byte < cursor:
                # Safety guard: adjacent inner nodes should not overlap; skip if they do.
                continue
            parts.append(source_bytes[cursor : inner.start_byte].decode("utf-8"))
            parts.append(self._render_dispatch(inner, kept_ids, hits_by_id, source_bytes))
            cursor = inner.end_byte
        parts.append(source_bytes[cursor : node.end_byte].decode("utf-8"))
        text = "".join(parts)

        if append_own:
            statement = hits_by_id.get(node.id)
            if statement is not None:
                call_info = statement.get_call_info()
                if call_info:
                    text = self._append_call_info(text, call_info)
        return text

    def _render_scope_shell_v2(
        self,
        scope_node: Node,
        kept_ids: set[int],
        hits_by_id: dict,
        source_bytes: bytes,
    ) -> str:
        """Render a scope/TLF as header + body + footer.

        The body renders only kept direct children; non-hit sibling statements are omitted.
        """
        wrapper = self._scope_wrapper(scope_node)
        body = self._scope_body(scope_node)

        if body is None or body.child_count == 0:
            # Expression body or missing block body; fall back to the full wrapper.
            return source_bytes[wrapper.start_byte : wrapper.end_byte].decode("utf-8")

        open_brace = body.child(0)
        close_brace = body.child(body.child_count - 1)
        if open_brace is None or open_brace.type != "{":
            return source_bytes[wrapper.start_byte : wrapper.end_byte].decode("utf-8")
        if close_brace is None or close_brace.type != "}":
            return source_bytes[wrapper.start_byte : wrapper.end_byte].decode("utf-8")

        header = source_bytes[wrapper.start_byte : open_brace.end_byte].decode("utf-8")
        footer = source_bytes[close_brace.start_byte : wrapper.end_byte].decode("utf-8")

        kept_children: list[Node] = [child for child in body.named_children if child.id in kept_ids]

        if not kept_children:
            rendered = header + footer
        else:
            body_parts: list[str] = []
            for child in kept_children:
                indent = " " * child.start_point.column
                rendered_child = self._render_dispatch(child, kept_ids, hits_by_id, source_bytes)
                body_parts.append(indent + rendered_child)
            body_text = "\n".join(body_parts)
            rendered = header + "\n" + body_text + "\n" + footer

        if scope_node.id in hits_by_id:
            statement = hits_by_id[scope_node.id]
            call_info = statement.get_call_info()
            if call_info:
                rendered = self._append_call_info(rendered, call_info)
        return rendered

    @staticmethod
    def _append_call_info(text: str, call_info: list[str]) -> str:
        """Append ``// <call_info...>`` to the end of the last line in ``text``."""
        if not call_info:
            return text
        lines = text.split("\n")
        lines[-1] = lines[-1] + " // " + ", ".join(call_info)
        return "\n".join(lines)

    @staticmethod
    def _collapse_blank_lines(text: str) -> str:
        """Collapse runs of 2 or more blank lines to one and strip trailing whitespace."""
        stripped_lines = [line.rstrip() for line in text.split("\n")]
        joined = "\n".join(stripped_lines)
        joined = re.sub(r"\n{3,}", "\n\n", joined)
        return joined

    # ------------------------------------------------------------------
    # Serialization.
    # ------------------------------------------------------------------

    def toJson(self) -> dict:
        """Convert the file code slice to JSON format."""
        code_lines = self.sliced_code.split("\n") if self.sliced_code else []

        callee_info_set: list[str] = []
        seen: set[str] = set()
        for statement in self.statements:
            callee_info_list = statement.get_callee_info()
            if callee_info_list:
                for info in callee_info_list:
                    if info not in seen:
                        seen.add(info)
                        callee_info_set.append(info)

        return {self.file_name: code_lines, "Callee Info": callee_info_set}
