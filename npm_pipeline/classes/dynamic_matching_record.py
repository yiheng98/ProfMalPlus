"""Pending-work ledger for the two-phase dynamic behavior pipeline.

During Phase A of the dynamic pipeline
(:mod:`npm_pipeline.utils.behavior_gen_utils`) we traverse the PDG and
match API calls against the static call graph / third-party call chains,
**but we do NOT invoke the LLM yet**.  Every match is instead recorded
here so Phase B can

  1. Run global, cross-node orphan recovery once the full traversal is
     over (we know every BFS-matched caller key at that point).
  2. Batch-call the sequence-behavior LLM in parallel, deduplicating by
     sequence fingerprint.
  3. Stitch the results back into PDG nodes.

"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class SingleCallMatch:
    """A one-to-one match between a sensitive-API PDG node and a runtime
    ``APICall``.

    Produced by :func:`handle_api_call_in_dynamic`.  It never needs LLM
    post-processing; we just keep its ``caller_key`` around so Phase B1
    knows this log entry is "claimed" and shouldn't be re-attributed as
    an orphan.
    """

    node_id: int
    caller_key: tuple  # APICallCollection.caller_key(api_call)


@dataclass
class ChainMatch:
    """Phase-A localization record for a third-party call chain.

    Phase-A is strictly a *matching and localization* pass: it records
    where each third-party chain "enters" the call graph (its root
    source file) and which runtime log entries the static BFS already
    claimed.

    Attributes
    ----------
    node_id:
        ID of the PDG node representing the third-party call that owns
        this chain.
    node:
        Direct reference to the PDG node, stashed so Phase B3 can stitch
        behavior results back without having to walk the program context
        to find the node by id.  Kept opaque (``Any``) to avoid an import
        cycle with :mod:`base_classes.pdg_node`.
    chain_root_file:
        Source file of the call-graph callee function that "roots" this
        chain - e.g. the file containing the entry function inside
        ``node_modules/axios/`` for an ``axios.get(...)`` call.  Phase-B
        uses this as the seed for
        :meth:`DependencyTree.closure_for_file` / :func:`find_module_root`
        to compute the chain's actual Layer-2 module-root prefixes.
        ``None`` when the callee's file could not be resolved (the
        chain then silently falls out of Layer 2 in Phase-B).
    bfs_caller_keys:
        Set of :meth:`APICallCollection.caller_key` tuples for every
        call the BFS actually matched - used both as a dedup set when we
        later turn matches into ``ResolvedAPICall`` instances and as the
        "trusted anchor" set for runtime-order adjacency (Layer 3).
    bfs_indices:
        Log-order indices of the BFS-matched calls, kept aligned with
        ``bfs_caller_keys`` so Layer 3 adjacency can run without
        re-querying the collection.
    extra:
        Per-chain scratch space for the specific matcher - typically
        holds the tail-entry metadata needed to build the final entry
        list after orphan recovery (e.g. chain-ending HTTP verbs added
        by :func:`_resolve_third_party_call_chain`).
    """

    node_id: int
    node: Any
    chain_root_file: str | None
    bfs_caller_keys: set[tuple] = field(default_factory=set)
    bfs_indices: list[int] = field(default_factory=list)
    extra: dict[str, Any] = field(default_factory=dict)


@dataclass
class DynamicMatchingRecord:
    """Accumulates all Phase-A matches for a single dynamic run.

    The record is owned by :class:`AnalysisContext` so every dynamic
    entry-point traversal writes into the same structure; Phase B then
    operates over the whole collection at once, which is what makes
    cross-chain orphan recovery and cross-sequence LLM deduplication
    possible.
    """

    single_matches: list[SingleCallMatch] = field(default_factory=list)
    chain_matches: list[ChainMatch] = field(default_factory=list)

    def clear(self) -> None:
        self.single_matches.clear()
        self.chain_matches.clear()

    # ---- accumulation helpers -----------------------------------------

    def add_single_match(self, node_id: int, caller_key: tuple) -> None:
        self.single_matches.append(SingleCallMatch(node_id=node_id, caller_key=caller_key))

    def add_chain_match(self, chain: ChainMatch) -> None:
        self.chain_matches.append(chain)

    # ---- read helpers -------------------------------------------------

    def global_matched_keys(self) -> set[tuple]:
        """Return the union of all caller keys already claimed by Phase A.

        Single matches and BFS-matched chain entries combined - this is
        what Phase B1 uses to decide which log entries are "orphans".
        """
        keys: set[tuple] = {m.caller_key for m in self.single_matches}
        for chain in self.chain_matches:
            keys.update(chain.bfs_caller_keys)
        return keys
