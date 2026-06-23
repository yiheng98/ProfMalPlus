"""Utility for reverse-indexing node IDs to their owning component."""

import re

from npm_pipeline.types import ComponentResult

_NODE_ID_RE = re.compile(r"\[Node ID:\s*(\d+)\]")


def build_node_to_component_index(components: list[ComponentResult]) -> dict[int, int]:
    """Build a ``{node_id: component_id}`` reverse index from built components.

    Node IDs are extracted from the ``[Node ID: N]`` annotations embedded
    in each component's ``callee_info`` strings by the slice builder.
    """
    index: dict[int, int] = {}
    for comp in components:
        for file_entry in comp.code_slice.get("sliced_code", []):
            for _fname, fdata in file_entry.items():
                for info_str in fdata.get("code_snippet", []):
                    for m in _NODE_ID_RE.finditer(str(info_str)):
                        index[int(m.group(1))] = comp.component_id
    return index
