"""StaticJudge — LLM static + enriched-static judgement with supplemental file reads."""

import json
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor

from loguru import logger

from code_interpreter import interpret_static_evidence
from llm import llm_static_reread
from npm_pipeline.classes.detection_state import AnalysisStep, DetectionState
from npm_pipeline.types import ComponentResult
from npm_pipeline.utils.local_file_reader import PackageFileReader

MAX_REREAD_HOPS = 3
MAX_COMPONENT_WORKERS = 3


class StaticJudge:
    """LLM driver for the static / enriched-static passes plus optional reread."""

    def __init__(
        self,
        *,
        package_name: str = "",
        file_reader: PackageFileReader | None = None,
        detection_state: DetectionState | None = None,
    ):
        self._package_name = package_name
        self._file_reader = file_reader
        self._detection_state = detection_state

    # ------------------------------------------------------------------
    # Public entry points
    # ------------------------------------------------------------------

    def interpret(
        self,
        components: list[ComponentResult],
        *,
        context_summary: str = "",
        entry: str | None = None,
    ) -> list[ComponentResult]:
        def process(comp: ComponentResult) -> ComponentResult | None:
            result = interpret_static_evidence(comp.code_slice, context_summary=context_summary)
            if not result:
                return None
            reread = self._maybe_reread(
                comp, prior_result=result, context_summary=context_summary, entry=entry
            )
            return comp.with_result(reread)

        return _run_components_parallel(components, process)

    def interpret_enriched(
        self,
        components: list[ComponentResult],
        affected_cids: set[int],
        cached_first_round: list[ComponentResult],
        *,
        context_summary: str = "",
        entry: str | None = None,
    ) -> list[ComponentResult]:
        cached_by_id: dict[int, ComponentResult] = {
            cr.component_id: cr for cr in cached_first_round
        }

        def process(comp: ComponentResult) -> ComponentResult | None:
            if comp.component_id in affected_cids:
                enriched = interpret_static_evidence(
                    comp.code_slice, context_summary=context_summary, enriched=True
                )
                if not enriched:
                    return None
                reread = self._maybe_reread(
                    comp,
                    prior_result=enriched,
                    context_summary=context_summary,
                    entry=entry,
                )
                return comp.with_result(reread)
            return cached_by_id.get(comp.component_id)

        return _run_components_parallel(components, process)

    # ------------------------------------------------------------------
    # Reread gate
    # ------------------------------------------------------------------

    def _maybe_reread(
        self,
        comp: ComponentResult,
        *,
        prior_result: dict,
        context_summary: str,
        entry: str | None,
    ) -> dict:
        """Run up to :data:`MAX_REREAD_HOPS` hops of the reread pass."""
        if self._file_reader is None:
            return _strip_files_to_read(prior_result)

        current_report: dict = prior_result
        visited: set[str] = set()
        accumulated_reads: list[dict] = []

        for hop in range(1, MAX_REREAD_HOPS + 1):
            remaining_hops = MAX_REREAD_HOPS - hop
            requested_raw = _coerce_paths(current_report.get("files_to_read"))
            if not requested_raw:
                break

            new_requested = [p for p in requested_raw if p not in visited]
            if not new_requested:
                logger.info(
                    f"[StaticJudge] Reread hop {hop} for component {comp.component_id}: "
                    "all requested paths already visited; stopping"
                )
                break

            logger.info(
                f"[StaticJudge] Reread hop {hop}/{MAX_REREAD_HOPS} for component "
                f"{comp.component_id} (entry={entry}, requested={new_requested})"
            )

            binary = _detect_binary(self._file_reader, new_requested)
            if binary is not None:
                rel_path, classifier = binary
                _log_reread_file_results(
                    comp.component_id,
                    _probe_requested_paths(self._file_reader, new_requested, binary_path=rel_path),
                )
                new_result = _binary_malicious_static(current_report, comp, rel_path)
                self._record_history(
                    entry=entry,
                    prior=current_report,
                    new=new_result,
                    requested=new_requested,
                    read_log=[],
                    binary_short_circuit_path=rel_path,
                    classifier=classifier,
                    hop=hop,
                )
                current_report = new_result
                break

            read_results = self._file_reader.read_files_turn(
                new_requested,
                visited,
                max_files_per_hop=len(new_requested),
                max_total_files=len(new_requested) + len(accumulated_reads),
                bare_specifier_predicate="specifier",
            )
            _log_reread_file_results(comp.component_id, read_results)
            accumulated_reads.extend(read_results)

            if not _any_ok(read_results) and not _any_ok(accumulated_reads):
                logger.info(
                    f"[StaticJudge] Reread hop {hop} for component {comp.component_id}: "
                    "no readable files this hop and none accumulated; stopping"
                )
                self._record_history(
                    entry=entry,
                    prior=current_report,
                    new=current_report,
                    requested=new_requested,
                    read_log=read_results,
                    binary_short_circuit_path=None,
                    classifier=None,
                    hop=hop,
                )
                break

            payload = {
                "package_name": self._package_name,
                "entry_file": entry or "",
                "component_id": comp.component_id,
                "hop": hop,
                "max_hops": MAX_REREAD_HOPS,
                "remaining_hops": remaining_hops,
                "sliced_code": comp.code_slice.get("sliced_code", []),
                "prior_report": current_report,
                "read_files": accumulated_reads,
            }
            try:
                reread = llm_static_reread(payload, context_summary=context_summary)
            except Exception as e:
                logger.warning(
                    f"[StaticJudge] Reread LLM call failed at hop {hop} for component "
                    f"{comp.component_id}: {e}; keeping prior verdict"
                )
                reread = None

            logger.info(
                f"[StaticJudge] Reread LLM raw output at hop {hop} for component "
                f"{comp.component_id}:\n"
                f"{json.dumps(reread, indent=2, ensure_ascii=False, default=str)}"
            )

            new_result = _reconcile_static(
                current_report, reread, force_drop_files_to_read=(remaining_hops == 0)
            )
            self._record_history(
                entry=entry,
                prior=current_report,
                new=new_result,
                requested=new_requested,
                read_log=read_results,
                binary_short_circuit_path=None,
                classifier=None,
                hop=hop,
            )
            current_report = new_result

            if reread is None:
                break

        return _strip_files_to_read(current_report)

    # ------------------------------------------------------------------
    # History recording
    # ------------------------------------------------------------------

    def _record_history(
        self,
        *,
        entry: str | None,
        prior: dict,
        new: dict,
        requested: list[str],
        read_log: list[dict],
        binary_short_circuit_path: str | None,
        classifier: str | None,
        hop: int | None = None,
    ) -> None:
        if self._detection_state is None:
            return

        prior_verdict = prior.get("judgement", "undetermined")
        new_verdict = new.get("judgement", prior_verdict)

        parts: list[str] = []
        if hop is not None:
            parts.append(f"hop {hop}/{MAX_REREAD_HOPS}")
        parts.append(f"requested={requested}")
        if binary_short_circuit_path is not None:
            parts.append(f"binary-short-circuit ({classifier}): {binary_short_circuit_path}")
            parts.append("no LLM call")
        else:
            status_counts = _status_counts(read_log)
            parts.append(
                "statuses=[" + ", ".join(f"{k}={v}" for k, v in sorted(status_counts.items())) + "]"
            )
        parts.append(f"verdict {prior_verdict} -> {new_verdict}")

        metadata: dict = {
            "candidate_paths": list(requested),
            "visited_files": [
                r.get("resolved_path") or r.get("path", "")
                for r in read_log
                if r.get("status") == "ok"
            ],
            "prior_judgement": prior_verdict,
            "new_judgement": new_verdict,
        }
        if hop is not None:
            metadata["hop"] = hop
            metadata["max_hops"] = MAX_REREAD_HOPS
        if binary_short_circuit_path is not None:
            metadata["binary_short_circuit_path"] = binary_short_circuit_path
            metadata["binary_classifier"] = classifier

        self._detection_state.add_step(
            AnalysisStep(
                stage="static_local_read",
                entry=entry,
                result=_verdict_to_result_label(new_verdict),
                finding="; ".join(parts),
                metadata=metadata,
            )
        )


# ---------------------------------------------------------------------------
# Shared helpers (also used by DynamicJudge — local module-level functions
# rather than a separate util to keep the change set tight)
# ---------------------------------------------------------------------------


def _run_components_parallel(
    components: list[ComponentResult],
    process: Callable[[ComponentResult], ComponentResult | None],
) -> list[ComponentResult]:
    """Run *process* over independent components in parallel.

    Results keep the input component order; components for which
    *process* returns ``None`` are dropped (same semantics as the
    previous sequential loop).
    """
    if not components:
        return []
    if len(components) == 1:
        out = process(components[0])
        return [out] if out is not None else []

    workers = min(MAX_COMPONENT_WORKERS, len(components))
    with ThreadPoolExecutor(max_workers=workers) as executor:
        outputs = list(executor.map(process, components))
    return [out for out in outputs if out is not None]


def _coerce_paths(value) -> list[str]:
    """Extract a clean list of path strings from a verifier's ``files_to_read``.

    Also normalises a common LLM mistake where the model prepends the
    npm tarball ``package/`` directory to the path (e.g.
    ``package/dist/index.js``).  Our :class:`PackageFileReader` is
    already anchored at ``<pkg_dir>/package`` so the prefix has to go
    or resolution will look one level too deep and return
    ``not_found``.
    """
    if not isinstance(value, list):
        return []
    out: list[str] = []
    seen: set[str] = set()
    for v in value:
        if not isinstance(v, str):
            continue
        cleaned = _strip_package_prefix(v.strip())
        if not cleaned or cleaned in seen:
            continue
        seen.add(cleaned)
        out.append(cleaned)
    return out


def _strip_package_prefix(path: str) -> str:
    """Drop a leading ``package/`` (optionally after ``./``) from *path*.

    Only the *first* such segment is removed; an inner ``package/``
    directory inside the package itself is preserved.
    """
    if not path:
        return path
    candidate = path
    if candidate.startswith("./"):
        candidate = candidate[2:]
    if candidate == "package" or candidate.startswith("package/"):
        stripped = candidate[len("package") :].lstrip("/")
        if stripped and stripped != path:
            logger.info(
                f"[StaticJudge] Stripping spurious 'package/' prefix from requested path: "
                f"{path!r} -> {stripped!r}"
            )
            return stripped
    return path


def _detect_binary(file_reader: PackageFileReader, requested: list[str]) -> tuple[str, str] | None:
    """Return ``(rel_path, classifier)`` of the first binary candidate."""
    for candidate in requested:
        kind = file_reader.classify_path_only(candidate)
        if kind == "binary":
            return candidate, "extension"
        if kind == "unknown":
            peeked = file_reader.classify_with_magic_peek(candidate)
            if peeked == "binary":
                return candidate, "magic_peek"
    return None


def _read_candidates(file_reader: PackageFileReader, requested: list[str]) -> list[dict]:
    """Resolve and read every candidate, returning the standard read-result dicts."""
    visited: set[str] = set()
    return file_reader.read_files_turn(
        requested,
        visited,
        max_files_per_hop=len(requested),
        max_total_files=len(requested),
        bare_specifier_predicate="specifier",
    )


def _any_ok(read_log: list[dict]) -> bool:
    return any(r.get("status") == "ok" for r in read_log)


def _log_reread_file_results(component_id: int, read_log: list[dict]) -> None:
    """Log per-path resolve/read outcomes for the reread gate."""
    if not read_log:
        logger.info(f"[StaticJudge] Reread file read results for component {component_id}: none")
        return
    entries: list[str] = []
    for r in read_log:
        path = r.get("path", "?")
        status = r.get("status", "unknown")
        resolved = r.get("resolved_path")
        if resolved and resolved != path:
            entry = f"{path} -> {resolved}: {status}"
        else:
            entry = f"{path}: {status}"
        note = r.get("note")
        if note:
            entry += f" ({note})"
        entries.append(entry)
    logger.info(
        f"[StaticJudge] Reread file read results for component {component_id}: "
        + "; ".join(entries)
    )


def _probe_requested_paths(
    file_reader: PackageFileReader,
    requested: list[str],
    *,
    binary_path: str | None = None,
) -> list[dict]:
    """Resolve-only probe when the binary short-circuit skips full text reads."""
    results: list[dict] = []
    for path in requested:
        if file_reader.resolve_within_package(path) is None:
            results.append({"path": path, "status": "not_found"})
            continue
        if binary_path is not None and path == binary_path:
            results.append(
                {
                    "path": path,
                    "status": "binary",
                    "note": "short-circuit without text read",
                }
            )
            continue
        results.append({"path": path, "status": "found"})
    return results


def _status_counts(read_log: list[dict]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for r in read_log:
        counts[r.get("status", "unknown")] = counts.get(r.get("status", "unknown"), 0) + 1
    return counts


def _strip_files_to_read(report: dict) -> dict:
    """Return *report* without the prompt-only ``files_to_read`` field.

    The downstream synthesis layers do not consume that field; stripping
    it keeps the per-stage report aligned with the verifier schemas
    documented in :mod:`code_interpreter`.
    """
    if not isinstance(report, dict) or "files_to_read" not in report:
        return report
    cleaned = dict(report)
    cleaned.pop("files_to_read", None)
    return cleaned


def _reconcile_static(
    prior_result: dict,
    reread: dict | None,
    *,
    force_drop_files_to_read: bool = False,
) -> dict:
    """Overlay *reread* on top of *prior_result* using the static verifier schema.

    The reread schema now mirrors the verifier schema (including
    ``files_to_read``) so multi-hop reread chains can keep iterating
    until the LLM stops requesting more files. Set
    ``force_drop_files_to_read=True`` to forcibly clear the field on
    the final hop, defending against an LLM that ignores the budget.
    """
    if not isinstance(reread, dict):
        # No usable reread output — keep the prior fields but drop
        # ``files_to_read`` so the caller does not loop on stale requests.
        return _strip_files_to_read(prior_result)

    judgement = reread.get("judgement")
    if judgement not in {"benign", "malicious", "undetermined"}:
        judgement = prior_result.get("judgement", "undetermined")

    key_evidence = reread.get("key_evidence")
    if not isinstance(key_evidence, list):
        key_evidence = prior_result.get("key_evidence", [])

    reason = reread.get("reason")
    if not isinstance(reason, str) or not reason.strip():
        reason = prior_result.get("reason", "")

    nodes = reread.get("node_to_be_checked")
    if not isinstance(nodes, list):
        nodes = []
    if judgement != "undetermined":
        nodes = []

    out: dict = {
        "judgement": judgement,
        "key_evidence": key_evidence,
        "reason": reason,
        "node_to_be_checked": nodes,
    }

    if not force_drop_files_to_read:
        files = _coerce_paths(reread.get("files_to_read"))
        if files:
            out["files_to_read"] = files

    return out


def _binary_malicious_static(prior_result: dict, comp: ComponentResult, rel_path: str) -> dict:
    """Build the static-schema ``malicious`` result for a binary short-circuit."""
    spawn_node_id = _guess_spawn_node_id(prior_result)

    key_evidence: list[dict] = []
    if spawn_node_id is not None:
        key_evidence.append(
            {
                "node_id": spawn_node_id,
                "node_type": _guess_spawn_node_type(prior_result, spawn_node_id),
                "claim": (
                    f"spawns native binary `{rel_path}`; source-based analysis "
                    "cannot inspect; treated as malicious per pipeline policy"
                ),
            }
        )

    reason = (
        f"Static reread short-circuited to malicious: the slice hands control "
        f"to the native binary `{rel_path}`. Source-based review cannot inspect "
        "compiled artefacts, so per the pipeline policy any package-bundled "
        "native binary execution is treated as malicious."
    )

    return {
        "judgement": "malicious",
        "key_evidence": key_evidence,
        "reason": reason,
        "node_to_be_checked": [],
    }


def _guess_spawn_node_id(prior_result: dict) -> int | None:
    for nid in prior_result.get("node_to_be_checked") or []:
        try:
            return int(nid)
        except (TypeError, ValueError):
            continue
    for ev in prior_result.get("key_evidence") or []:
        if not isinstance(ev, dict):
            continue
        nid = ev.get("node_id")
        if isinstance(nid, (int, float)):
            return int(nid)
    return None


def _guess_spawn_node_type(prior_result: dict, node_id: int) -> str:
    for ev in prior_result.get("key_evidence", []) or []:
        if not isinstance(ev, dict):
            continue
        try:
            if int(ev.get("node_id")) == node_id and isinstance(ev.get("node_type"), str):
                return ev["node_type"]
        except (TypeError, ValueError):
            continue
    return "unresolved"


def _verdict_to_result_label(judgement: str) -> str:
    if judgement == "malicious":
        return "malicious"
    if judgement == "benign":
        return "benign"
    if judgement == "undetermined":
        return "undetermined"
    return "warning"
