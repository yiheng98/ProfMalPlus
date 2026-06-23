"""SliceStore — disk persistence for code slices."""

import json
import os

from npm_pipeline.types import ComponentResult, Stage


class SliceStore:
    """Append per-component code slices to ``<workspace>/<package>/<stage>/code_slice/code_slice.json``.

    The on-disk format matches the pre-refactor pipeline exactly: a JSON
    list of ``code_slice`` dicts, appended to after each component.
    """

    def __init__(self, workspace_dir: str, package_name: str):
        self._workspace_dir = workspace_dir
        self._package_name = package_name

    def persist_all(self, components: list[ComponentResult], stage: Stage) -> None:
        """Append every component's ``code_slice`` to the stage-specific JSON file."""
        for comp in components:
            self._append(comp.code_slice, stage)

    def _append(self, code_slice: dict, stage: Stage) -> None:
        path = self._slice_path(stage)
        os.makedirs(os.path.dirname(path), exist_ok=True)

        existing: list = []
        if os.path.exists(path):
            with open(path, "r") as f:
                try:
                    loaded = json.load(f)
                    existing = loaded if isinstance(loaded, list) else [loaded]
                except json.JSONDecodeError:
                    existing = []

        existing.append(code_slice)
        with open(path, "w") as f:
            json.dump(existing, f, ensure_ascii=False, indent=2)

    def _slice_path(self, stage: Stage) -> str:
        return os.path.join(
            self._workspace_dir,
            self._package_name,
            stage,
            "code_slice",
            "code_slice.json",
        )
