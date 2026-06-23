import json
import os
import re

from loguru import logger

from custom_exception import PackageJsonReadException
from npm_pipeline.classes.shell_command_analyzer import ShellCommandAnalyzer


class PackageJson:
    def __init__(self, package_json_path):
        self.package_json_path = package_json_path
        # Package root = the directory holding package.json. Used by the
        # shell-command analyzer to resolve in-package script reads.
        self.package_root = os.path.dirname(os.path.realpath(package_json_path))
        self.main = None  # main script (may be a set of candidate paths)
        self.exports_entries = set()  # entry files from "exports" field
        self.all_scripts = {}  # all scripts from the "scripts" field
        self.malicious_script = []  # the malicious script in package.json
        self.install_time_entry_files = set()  # the entry files in install-related scripts
        self.bin = set()  # the bin scripts
        self.directories_bin = (
            None  # the directories.bin path (all files in this dir are executables)
        )
        self.dependencies = {}  # the dependencies dict
        self._shell_analyzer = ShellCommandAnalyzer(self.package_root)
        self.set_metadata()

    def get_main(self):
        return self.main

    def get_install_time_entry_files(self):
        return self.install_time_entry_files

    def get_bin_scrip(self):
        return self.bin

    def get_exports_entries(self):
        return self.exports_entries

    _JS_EXTENSIONS = {".js", ".mjs", ".cjs"}

    @classmethod
    def _is_js_file(cls, path: str) -> bool:
        _, ext = os.path.splitext(path)
        return ext in cls._JS_EXTENSIONS

    @classmethod
    def _has_non_js_extension(cls, path: str) -> bool:
        """True when the path has an extension that is NOT .js/.mjs/.cjs."""
        _, ext = os.path.splitext(path)
        return ext != "" and ext not in cls._JS_EXTENSIONS

    @classmethod
    def _normalise_path(cls, raw: str) -> str | None:
        """Return the path with .js appended if needed, or None if not a JS file."""
        if cls._is_js_file(raw):
            return raw
        if cls._has_non_js_extension(raw):
            return None
        return raw + ".js"

    @classmethod
    def _resolve_main_candidates(cls, raw: str) -> set[str]:
        """
        Mimic Node.js module resolution: for a path without a recognised
        extension, return both  <path>.js  and  <path>/index.js  so that
        check_existence can pick whichever actually exists on disk.
        Non-JS files (e.g. .json, .node) are excluded.
        """
        if cls._is_js_file(raw):
            return {raw}
        if cls._has_non_js_extension(raw):
            return set()
        return {raw + ".js", raw + "/index.js"}

    def _parse_main(self, data: dict):
        raw = data.get("main")
        if isinstance(raw, str) and raw:
            self.main = self._resolve_main_candidates(raw)
        else:
            self.main = {"index.js"}

    def _parse_exports(self, data: dict):
        """Extract file paths from the 'exports' field (all conditional variants)."""
        raw = data.get("exports")
        if raw is None:
            return
        self._collect_export_paths(raw)

    def _collect_export_paths(self, node):
        if isinstance(node, str):
            normalised = self._normalise_path(node)
            if normalised is not None:
                self.exports_entries.add(normalised)
        elif isinstance(node, dict):
            for value in node.values():
                self._collect_export_paths(value)
        elif isinstance(node, list):
            for item in node:
                self._collect_export_paths(item)

    def set_metadata(self):
        try:
            with open(self.package_json_path, "r") as package_json_file:
                package_json_data = json.load(package_json_file)
        except (OSError, json.JSONDecodeError, UnicodeDecodeError) as e:
            raise PackageJsonReadException(
                f"Failed to read package.json ({self.package_json_path}): {e}"
            ) from e

        self._parse_main(package_json_data)
        self._parse_exports(package_json_data)

        if "scripts" in package_json_data.keys():
            self.all_scripts = dict(package_json_data["scripts"])

        if "bin" in package_json_data:
            bin_value = package_json_data["bin"]
            raw_paths = []
            if isinstance(bin_value, str):
                raw_paths.append(bin_value)
            elif isinstance(bin_value, dict):
                raw_paths.extend(v for v in bin_value.values() if isinstance(v, str))
            elif isinstance(bin_value, list):
                raw_paths.extend(v for v in bin_value if isinstance(v, str))
            for raw in raw_paths:
                if self._is_js_file(raw):
                    self.bin.add(raw)
                elif not self._has_non_js_extension(raw):
                    self.bin.add(raw)
                    self.bin.add(raw + ".js")

        if "directories" in package_json_data:
            dirs = package_json_data["directories"]
            if isinstance(dirs, dict) and "bin" in dirs:
                dir_bin = dirs["bin"]
                if isinstance(dir_bin, str):
                    self.directories_bin = dir_bin

        if "dependencies" in package_json_data:
            dependencies_value = package_json_data["dependencies"]
            for module, version in dependencies_value.items():
                self.dependencies[module] = version

    @staticmethod
    def script_regex_extract(script):
        pattern_node = r"node\s+([^\s]+(?:\.js|\.mjs|\.cjs)\b(?:\s+[^\s]+(?:\.js|\.mjs|\.cjs)\b)*)"
        script_file = set()

        match = re.findall(pattern_node, script)
        if len(match) > 0:
            for script in match:
                script_file.add(script)

        return script_file

    INSTALL_HOOK_NAMES = ("preinstall", "install", "postinstall")

    def classify_all_scripts(self):
        """Analyse install-time scripts (preinstall/install/postinstall).

        Returns a dict mapping script name to
        ``{"content": str, "label": str, "explanation": str,
        "executed_js_files": list[str]}`` where ``label`` is one of
        ``"benign" | "warning" | "malicious"``.
        """
        results = {}
        for name in self.INSTALL_HOOK_NAMES:
            content = self.all_scripts.get(name)
            if content is None:
                continue
            label, explanation, llm_js_files = self.classify_script(content)
            results[name] = {
                "content": content,
                "label": label,
                "explanation": explanation,
                "executed_js_files": list(llm_js_files),
            }
            if label == "malicious":
                self.malicious_script.append(content)
            self.install_time_entry_files.update(llm_js_files)

        return results

    def classify_script(self, script):
        """Returns ``(label, explanation, executed_js_files)``.

        ``label`` is one of ``"benign" | "warning" | "malicious"``. The
        classification is delegated to :class:`ShellCommandAnalyzer`,
        which iteratively reads any locally-shipped helper shell scripts
        the command invokes (e.g. ``./main.sh`` in
        ``node index.js && ./main.sh``) before producing a verdict that
        combines the outer command and every read inner script.
        """
        try:
            label, explanation, executed_js_files = self._shell_analyzer.analyse(script)
        except Exception as e:
            logger.warning(f"Shell Command Exception: {e}")
            return "warning", "", self.script_regex_extract(script)

        return label, explanation, set(executed_js_files)

    def get_dependencies(self):
        return self.dependencies
