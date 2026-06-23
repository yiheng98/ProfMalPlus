"""DynamicEvidenceCollector — aggregate PBG evidence for dynamic judgement.

Walks every PDG node once and materialises the shared evidence the
dynamic judgement consumes: the flat list of file I/O
records, a map of nodes carrying large-file contents, and the
pre-computed ``file_inspections`` summaries that used to be produced by
the second pass.
"""

from base_classes.pbg import PBG
from npm_pipeline.classes.serialized_types import FileIORecord
from npm_pipeline.types import DynamicContext
from npm_pipeline.utils.file_content_retriever import retrieve_and_inspect_files


class DynamicEvidenceCollector:
    """Pure PBG traversal producing a :class:`DynamicContext`."""

    @staticmethod
    def collect(pbg: PBG) -> DynamicContext:
        """Walk PBG nodes; aggregate file I/O records, large-file node map,
        and pre-computed large-text ``file_inspections``.
        """
        file_io_records: list[FileIORecord] = []
        node_map: dict = {}

        for _node_id, pdg_node in pbg.get_pdg_nodes().items():
            records = pdg_node.get_file_io_records()
            if records:
                file_io_records.extend(records)
            if pdg_node.has_large_file_contents():
                node_map[pdg_node.get_id()] = pdg_node

        files_to_inspect: list[dict] = [
            {
                "file_path": rec.file_path,
                "operation": rec.operation,
                "node_id": rec.node_id,
            }
            for rec in file_io_records
            if rec.content_tier == "large_text"
            and rec.node_id is not None
            and rec.node_id in node_map
        ]
        file_inspections = (
            retrieve_and_inspect_files(files_to_inspect, node_map) if files_to_inspect else []
        )

        return DynamicContext(
            file_io_records=file_io_records,
            node_map=node_map,
            file_inspections=file_inspections,
        )
