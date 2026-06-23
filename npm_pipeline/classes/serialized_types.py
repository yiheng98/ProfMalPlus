"""Dataclasses for serialized API call entries and file I/O metadata.

These types replace ad-hoc ``dict`` construction in the serialization
pipeline, providing IDE-friendly attribute access and self-documenting
field definitions.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class SerializedAPIEntry:
    """A single serialized API call entry destined for LLM consumption.

    ``confidence`` is the provenance tag inherited from the underlying
    :class:`ResolvedAPICall`:

    - ``"bfs"`` - directly reachable from the static call graph (trusted).
    - ``"module_root"`` - caller file lives under the third-party's module
      root; attribution is structurally sound.
    - ``"adjacency"`` - recovered via runtime-order adjacency to a BFS
      anchor (a gap-bounded neighbor of a trusted call).
    - ``"registration_adjacency"`` - recovered using the third-party call's
      own registration point as the anchor (pure-async, no BFS anchor).
    - ``"shared"`` - an ambiguous orphan attributed to multiple chains
      because module-root and nearest-registration tie-breakers were
      inconclusive.
    """

    qualified_name: str
    domain: str
    category: str
    arguments: dict | str | None = None
    confidence: str = "bfs"

    def to_dict(self) -> dict:
        d: dict = {
            "qualified_name": self.qualified_name,
            "domain": self.domain,
            "category": self.category,
        }
        if self.arguments is not None:
            d["arguments"] = self.arguments
        # Always emit confidence so downstream consumers (and the LLM)
        # can reason about attribution certainty uniformly.
        d["confidence"] = self.confidence
        return d


@dataclass
class FileIORecord:
    """Metadata for a large-text file I/O operation observed at runtime.

    Only non-binary files whose content exceeds the inline size threshold
    (``SMALL_CONTENT_THRESHOLD``) produce a record.  Binary and inline
    entries are excluded.
    """

    file_path: str
    operation: str  # "read" | "write"
    content_tier: str = "large_text"
    content_size: int | None = None
    content_type: str | None = None
    node_id: int | None = None

    def to_dict(self) -> dict:
        d: dict = {
            "file_path": self.file_path,
            "operation": self.operation,
            "content_tier": self.content_tier,
        }
        if self.content_size is not None:
            d["content_size"] = self.content_size
        if self.content_type is not None:
            d["content_type"] = self.content_type
        if self.node_id is not None:
            d["node_id"] = self.node_id
        return d


@dataclass
class SerializedAPISequence:
    """Result of :func:`serialize_api_sequence`.

    Bundles the LLM-ready API entry list together with the sidecar
    ``FileIORecord`` list that tracks large-text file operations.
    """

    api_entries: list[SerializedAPIEntry] = field(default_factory=list)
    file_io_records: list[FileIORecord] = field(default_factory=list)

    def to_llm_dict(self) -> dict:
        """Return the ``{"api_sequence": [...], "attribution_notes": ...}`` dict.

        Includes an ``attribution_notes`` block when one or more entries
        carry a confidence tag other than ``"bfs"``; the block enumerates
        which confidence tags appear and gives the LLM a concise cue to
        hedge its language accordingly (see
        ``prompts/api_sequence_behavior_system_prompt.md``).
        """
        entries = [e.to_dict() for e in self.api_entries]
        result: dict = {"api_sequence": entries}
        non_bfs = {e.confidence for e in self.api_entries if e.confidence and e.confidence != "bfs"}
        if non_bfs:
            result["attribution_notes"] = {
                "has_uncertain_attribution": True,
                "confidence_kinds_present": sorted(non_bfs),
                "hedging_required": True,
            }
        return result


def format_file_io_summary(records: list[FileIORecord]) -> str:
    """One-line summary of large-text file I/O records for inline annotations.

    Returns an empty string when *records* is empty so callers can
    unconditionally concatenate the result.
    """
    if not records:
        return ""
    parts: list[str] = []
    for r in records:
        meta: list[str] = []
        if r.content_type:
            meta.append(f"type={r.content_type}")
        if r.content_size is not None:
            meta.append(f"size={r.content_size}")
        desc = f'{r.operation} "{r.file_path}"'
        if meta:
            desc += f" ({', '.join(meta)})"
        parts.append(desc)
    return f"File I/O: {' | '.join(parts)}"
