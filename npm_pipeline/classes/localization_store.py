"""LocalizationStore — disk persistence for malicious-code localization JSON."""

import json
import os

from loguru import logger

from npm_pipeline.utils.finding import safe_entry_name


class LocalizationStore:
    """Write malicious-code localization JSON next to ``report.json``."""

    def __init__(self, workspace_dir: str, package_name: str):
        self._workspace_dir = workspace_dir
        self._package_name = package_name

    def persist(self, *, entry: str, payload: dict | None) -> None:
        """Write *payload* for the given ``entry``, keyed by entry file name only.

        ``None`` payloads (e.g. validation rejected the LLM output) are
        silently skipped so callers can pass localizer return values
        through unconditionally.
        """
        if not payload:
            return

        path = self._localization_path(entry=entry)
        os.makedirs(os.path.dirname(path), exist_ok=True)

        try:
            with open(path, "w", encoding="utf-8") as f:
                json.dump(payload, f, ensure_ascii=False, indent=2)
            logger.info(f"[Localization] Wrote {path}")
        except OSError as e:
            logger.warning(f"[Localization] Failed to write {path}: {e}")

    def _localization_path(self, *, entry: str) -> str:
        return os.path.join(
            self._workspace_dir,
            self._package_name,
            "localization",
            f"{safe_entry_name(entry)}.json",
        )
