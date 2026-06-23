"""Third-party metadata enrichment for PDG nodes."""

import os

from loguru import logger

from base_classes.pbg import PBG
from call_type_dict import THIRD_PARTY_CALL
from npm_pipeline.classes.npm_pkg_metadata import NpmPkgMetadata
from npm_pipeline.utils.npm_metadata_cache import NpmMetadataCache
from npm_pipeline.utils.npm_pkg_metadata_fetcher import fetch_npm_pkg_metadata


class ThirdPartyEnricher:
    """Fetches and applies npm metadata to third-party PDG nodes.

    All metadata lookups go through a persistent on-disk
    :class:`NpmMetadataCache`. The cache directory is taken from
    ``config.yaml`` (key ``npm_metadata_cache.dir``) so it is shared across
    every package and every worker process. Concurrency safety is provided by
    atomic JSON writes plus per-package ``flock``-based fetch de-duplication.
    """

    def __init__(
        self,
        package_name: str,
        workspace_dir: str,
        persistent_cache: NpmMetadataCache | None = None,
    ):
        self._package_name = package_name
        self._workspace_dir = workspace_dir
        self._persistent_cache = persistent_cache or NpmMetadataCache.from_config()

    @staticmethod
    def extract_needed_modules(pbg: PBG, third_party_node_ids: list[int]) -> set[str]:
        """Collect the distinct npm module names referenced by *third_party_node_ids*."""
        pdg_nodes = pbg.get_pdg_nodes()
        modules: set[str] = set()
        for node_id in third_party_node_ids:
            pdg_node = pdg_nodes.get(node_id)
            if pdg_node is None:
                continue
            tpc = pdg_node.get_third_party_call_dict()
            if tpc and tpc.get("module"):
                modules.add(tpc["module"])
        return modules

    def fetch(self, module_names: set[str]) -> dict[str, NpmPkgMetadata | None]:
        """Resolve metadata for every module in *module_names* via the on-disk cache.

        Each lookup goes through:

        1. The persistent on-disk cache (shared across processes and runs).
        2. The upstream fetcher, invoked under a per-package inter-process
           lock so concurrent workers never fetch the same package twice.
        """
        tar_temp_path = os.path.join(
            self._workspace_dir, self._package_name, "static", "pkg_download"
        )

        def _do_fetch(name: str) -> NpmPkgMetadata | None:
            logger.info(f"[Enrichment] Fetching metadata for third-party module: {name}")
            return fetch_npm_pkg_metadata(name, tar_temp_path)

        resolved: dict[str, NpmPkgMetadata | None] = {}
        for module_name in module_names:
            try:
                resolved[module_name] = self._persistent_cache.get_or_fetch(module_name, _do_fetch)
            except Exception as e:
                logger.warning(f"[Enrichment] Failed to fetch metadata for {module_name}: {e}")
                resolved[module_name] = None
        return resolved

    def enrich_nodes(
        self,
        program_behavior: PBG,
        metadata_cache: dict[str, NpmPkgMetadata | None],
        third_party_node_ids: list[int],
    ) -> dict[str, set[int]]:
        """Annotate each third-party node with whatever metadata is available.

        LLM-derived results (``is_trustworthy`` / module-level behavior /
        per-API behavior) are read from and written back to the persistent
        cache under the per-package lock, so each LLM prompt is paid for at
        most once across the entire fleet of analysis processes.

        Returns a partition of *third_party_node_ids* by enrichment level:
        ``fully_enriched`` / ``module_only`` / ``api_only`` / ``not_enriched``.
        """
        result: dict[str, set[int]] = {
            "fully_enriched": set(),
            "module_only": set(),
            "api_only": set(),
            "not_enriched": set(),
        }

        pdg_nodes = program_behavior.get_pdg_nodes()

        # Per-call memo so we don't keep re-reading the same JSON for every
        # node referencing the same module.
        derived_memo: dict[str, dict] = {}

        for node_id in third_party_node_ids:
            pdg_node = pdg_nodes.get(node_id)
            if pdg_node is None or pdg_node.get_call_type() != THIRD_PARTY_CALL:
                continue

            tpc = pdg_node.get_third_party_call_dict()
            if tpc is None:
                continue

            module_name = tpc["module"]
            property_method = tpc["property_method"]

            metadata = metadata_cache.get(module_name)
            if metadata is None:
                result["not_enriched"].add(node_id)
                continue

            if not self._resolve_is_trustworthy(metadata, module_name, derived_memo):
                result["not_enriched"].add(node_id)
                continue

            mod_beh = self._resolve_module_behavior(metadata, module_name, derived_memo)
            api_beh = self._resolve_api_behavior(
                metadata, module_name, property_method, derived_memo
            )

            if mod_beh and api_beh:
                pdg_node.set_module_behavior(mod_beh)
                pdg_node.set_behavior_description(api_beh)
                result["fully_enriched"].add(node_id)
                logger.info(
                    f"[Enrichment] Node {node_id} ({module_name}.{property_method}): "
                    f"module={mod_beh}, api={api_beh}"
                )
            elif mod_beh:
                pdg_node.set_module_behavior(mod_beh)
                result["module_only"].add(node_id)
                logger.info(
                    f"[Enrichment] Node {node_id} ({module_name}.{property_method}): "
                    f"module={mod_beh}, api=unknown"
                )
            elif api_beh:
                pdg_node.set_behavior_description(api_beh)
                result["api_only"].add(node_id)
                logger.info(
                    f"[Enrichment] Node {node_id} ({module_name}.{property_method}): "
                    f"module=unknown, api={api_beh}"
                )
            else:
                result["not_enriched"].add(node_id)
                logger.info(
                    f"[Enrichment] Node {node_id} ({module_name}.{property_method}): "
                    f"no metadata available"
                )

        return result

    # ------------------------------------------------------------------
    # Derived-cache helpers (LLM result memoization)
    # ------------------------------------------------------------------

    def _load_derived(self, module_name: str, memo: dict[str, dict]) -> dict:
        """Lazily load (and memoize for this run) the ``derived`` section."""
        cached = memo.get(module_name)
        if cached is None:
            cached = self._persistent_cache.get_derived(module_name)
            memo[module_name] = cached
        return cached

    def _resolve_is_trustworthy(
        self,
        metadata: NpmPkgMetadata,
        module_name: str,
        memo: dict[str, dict],
    ) -> bool:
        derived = self._load_derived(module_name, memo)
        if "is_trustworthy" in derived:
            return bool(derived["is_trustworthy"])

        is_trust = bool(metadata.is_trustworthy())
        derived["is_trustworthy"] = is_trust
        self._persistent_cache.update_derived(module_name, {"is_trustworthy": is_trust})
        return is_trust

    def _resolve_module_behavior(
        self,
        metadata: NpmPkgMetadata,
        module_name: str,
        memo: dict[str, dict],
    ) -> str | None:
        derived = self._load_derived(module_name, memo)
        if "module_behavior" in derived:
            logger.debug(f"[Cache] module_behavior hit for {module_name}")
            return derived["module_behavior"]

        mod_beh = metadata.get_module_behavior()
        derived["module_behavior"] = mod_beh
        self._persistent_cache.update_derived(module_name, {"module_behavior": mod_beh})
        return mod_beh

    def _resolve_api_behavior(
        self,
        metadata: NpmPkgMetadata,
        module_name: str,
        property_method: str,
        memo: dict[str, dict],
    ) -> str | None:
        derived = self._load_derived(module_name, memo)
        api_map = derived.get("api_behavior")
        if not isinstance(api_map, dict):
            api_map = {}

        if property_method in api_map:
            logger.debug(f"[Cache] api_behavior hit for {module_name}.{property_method}")
            return api_map[property_method]

        api_beh = metadata.get_api_behavior(property_method)
        api_map[property_method] = api_beh
        derived["api_behavior"] = api_map
        self._persistent_cache.update_derived(
            module_name, {"api_behavior": {property_method: api_beh}}
        )
        return api_beh

    @staticmethod
    def summarize(enrichment_info: dict[str, set[int]], modules: set[str]) -> str:
        """Render a compact one-line summary for inclusion in ``AnalysisStep.finding``."""
        parts: list[str] = [f"modules: {', '.join(sorted(modules))}"]
        for level in ("fully_enriched", "module_only", "api_only", "not_enriched"):
            ids = enrichment_info.get(level, set())
            if ids:
                parts.append(f"{level}: nodes {sorted(ids)}")
        return " | ".join(parts)
