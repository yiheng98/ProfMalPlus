"""Method-level evidence extraction from TypeScript declaration files (`.d.ts`)."""

from loguru import logger

try:
    import tree_sitter_typescript as tstypescript
    from tree_sitter import Language, Node, Parser

    _TS_AVAILABLE = True
except Exception as e:  # pragma: no cover - import-time environment issue
    logger.warning(f"[DtsParser] tree-sitter TypeScript grammar unavailable: {e}")
    _TS_AVAILABLE = False


# AST node types that introduce a named method/function declaration in a
# `.d.ts` file. The name of each is reachable via the ``name`` field.
_DECLARATION_TYPES = frozenset(
    {
        "function_signature",  # declare function foo(...): T;
        "function_declaration",  # function foo(...) { } (rare in .d.ts)
        "method_signature",  # interface/object/class method: foo(...): T;
        "abstract_method_signature",  # abstract foo(...): T;
        "method_definition",  # class body method
        "property_signature",  # foo: (...) => T;  (function-typed property)
        "public_field_definition",  # class field, possibly a function value
    }
)

# Defensive caps so a single huge declaration file never blows up the prompt.
_MAX_EVIDENCE_CHARS = 4000
_MAX_BLOCKS = 12


class DtsParser:
    """Parse a TypeScript declaration file and extract method-level evidence.

    Parameters
    ----------
    code:
        The raw text of a ``.d.ts`` declaration file.
    """

    def __init__(self, code: str):
        if not _TS_AVAILABLE:
            raise RuntimeError("tree-sitter TypeScript grammar is not available")
        self.LANGUAGE = Language(tstypescript.language_typescript())
        self.parser = Parser(self.LANGUAGE)
        self._code_bytes = bytes(code, "utf-8")
        self.tree = self.parser.parse(self._code_bytes)
        self.root = self.tree.root_node

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def extract_method_evidence(self, method_name: str) -> str | None:
        """Return the declaration block(s) that define *method_name*.

        For every declaration whose name matches *method_name* (function
        signature, interface/class method, or function-typed property), the
        enclosing declaration text is collected together with the JSDoc comment
        immediately preceding it. Overloads produce multiple blocks, which are
        de-duplicated and concatenated. Returns ``None`` when the method is not
        documented anywhere in the file.
        """
        if not method_name:
            return None

        comment_nodes = self._collect_comments()
        seen_blocks: set[str] = set()
        blocks: list[tuple[int, str]] = []

        for node in self._iter_nodes():
            if node.type not in _DECLARATION_TYPES:
                continue
            if self._declaration_name(node) != method_name:
                continue

            decl_text = self._node_text(node).strip()
            if not decl_text:
                continue

            comment_text = self._preceding_comment(node, comment_nodes)
            block = f"{comment_text}\n{decl_text}".strip() if comment_text else decl_text

            if block in seen_blocks:
                continue
            seen_blocks.add(block)
            blocks.append((node.start_byte, block))

            if len(blocks) >= _MAX_BLOCKS:
                break

        if not blocks:
            return None

        blocks.sort(key=lambda item: item[0])
        evidence = "\n\n".join(block for _, block in blocks)
        if len(evidence) > _MAX_EVIDENCE_CHARS:
            evidence = evidence[:_MAX_EVIDENCE_CHARS].rstrip() + "\n/* ...truncated... */"
        return evidence

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _iter_nodes(self):
        """Depth-first traversal yielding every node in the tree."""
        cursor = self.tree.walk()
        visited_children = False
        while True:
            if not visited_children:
                yield cursor.node
                if not cursor.goto_first_child():
                    visited_children = True
            elif cursor.goto_next_sibling():
                visited_children = False
            elif not cursor.goto_parent():
                break

    def _collect_comments(self) -> list["Node"]:
        """All ``comment`` nodes, ordered by position (for JSDoc lookup)."""
        comments = [node for node in self._iter_nodes() if node.type == "comment"]
        comments.sort(key=lambda n: n.start_byte)
        return comments

    def _declaration_name(self, node: "Node") -> str | None:
        name_node = node.child_by_field_name("name")
        if name_node is None:
            for child in node.named_children:
                if child.type in ("identifier", "property_identifier"):
                    name_node = child
                    break
        if name_node is None:
            return None
        return self._node_text(name_node)

    def _preceding_comment(self, node: "Node", comments: list["Node"]) -> str | None:
        """Return the JSDoc/comment whose text immediately precedes *node*.

        A comment "immediately precedes" the declaration when only whitespace
        separates the comment's end from the declaration's start, which is
        robust to the various ways the grammar nests comments inside interface
        and class bodies. The anchor is the outermost ``export``/``declare``
        wrapper, since JSDoc is written above ``export declare function foo``
        rather than above the inner ``function_signature`` node.
        """
        anchor_start = self._statement_start_byte(node)
        best: "Node" | None = None
        for comment in comments:
            if comment.end_byte > anchor_start:
                break
            between = self._code_bytes[comment.end_byte : anchor_start]
            if between.strip() == b"":
                best = comment
        if best is None:
            return None
        return self._node_text(best).strip()

    @staticmethod
    def _statement_start_byte(node: "Node") -> int:
        """Climb through ``export``/``declare`` wrappers to the statement start."""
        current = node
        while current.parent is not None and current.parent.type in (
            "export_statement",
            "ambient_declaration",
        ):
            current = current.parent
        return current.start_byte

    def _node_text(self, node: "Node") -> str:
        return self._code_bytes[node.start_byte : node.end_byte].decode("utf-8", errors="ignore")


def extract_method_evidence_from_files(
    declaration_files: dict[str, str] | None,
    method_name: str,
    *,
    entry_paths: list[str] | None = None,
) -> str | None:
    """Convenience wrapper: search *declaration_files* for *method_name*.

    Files in *entry_paths* (the ones referenced by ``types``/``typings``/
    ``exports.types``) are searched first; the first file that yields a match
    wins so re-exporting barrel files do not drown out the real declaration.
    Returns ``None`` if no file documents the method or parsing fails.
    """
    if not _TS_AVAILABLE or not declaration_files:
        return None

    ordered_paths: list[str] = []
    seen: set[str] = set()
    for path in entry_paths or []:
        if path in declaration_files and path not in seen:
            ordered_paths.append(path)
            seen.add(path)
    for path in declaration_files:
        if path not in seen:
            ordered_paths.append(path)
            seen.add(path)

    for path in ordered_paths:
        text = declaration_files.get(path)
        if not text:
            continue
        try:
            evidence = DtsParser(text).extract_method_evidence(method_name)
        except Exception as e:
            logger.warning(f"[DtsParser] Failed to parse declaration file {path}: {e}")
            continue
        if evidence:
            logger.debug(f"[DtsParser] Found '{method_name}' evidence in {path}")
            return evidence

    return None
