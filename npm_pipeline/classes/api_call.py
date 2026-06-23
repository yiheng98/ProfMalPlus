import json
from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Optional, Tuple

from sensitive_op import sensitive_call_finder


class APICall:
    def __init__(
        self,
        _type: str,
        timestamp: str,
        module: str,
        function: str,
        caller: Dict[str, Any],
        arguments: List[Any],
        result: Any,
    ):
        """
        Initializes an APICall instance with the provided details.
        """
        self.type = _type
        self.timestamp = timestamp
        self.module = module
        self.function = function
        self.caller = caller  # Expected to be a dict with keys 'file', 'line', 'column'
        self.arguments = arguments
        self.result = result


# Confidence labels.
CONFIDENCE_BFS = "bfs"
CONFIDENCE_MODULE_ROOT = "module_root"
CONFIDENCE_ADJACENCY = "adjacency"
CONFIDENCE_REGISTRATION_ADJACENCY = "registration_adjacency"
CONFIDENCE_SHARED = "shared"
ALL_CONFIDENCES = (
    CONFIDENCE_BFS,
    CONFIDENCE_MODULE_ROOT,
    CONFIDENCE_ADJACENCY,
    CONFIDENCE_REGISTRATION_ADJACENCY,
    CONFIDENCE_SHARED,
)


@dataclass
class ResolvedAPICall:
    """An API call enriched with parsed/resolved arguments and return value.

    ``confidence`` carries the provenance tag assigned by the async-aware
    orphan recovery
    """

    api_call: APICall
    qualified_name: str
    domain: str
    sensitive_info: dict | None = None
    resolved_arguments: Any = None
    resolved_return_value: Any = None
    confidence: str = CONFIDENCE_BFS


class APICallCollection:
    """Ordered collection of API calls observed during dynamic execution.

    ``self.collections`` preserves the order in which the runtime
    instrumentation wrote the entries to ``api_info.csv`` (see
    :func:`dynamic_helper.preprocess_api_call_info`).
    """

    def __init__(self, file_path: str, enable_dedup: bool = True):
        self.file_path = file_path
        self.enable_dedup = enable_dedup
        self.collections: list[APICall] = []
        self._read_api_call_logs(self.file_path)

    def _read_api_call_logs(self, file_path: str):
        """
        Reads the JSON file and returns a list of APICallLog instances.
        """
        with open(file_path, "r", encoding="utf-8") as f:
            data = json.load(f)
            for entry in data:
                _type = entry.get("type", None)
                timestamp = entry.get("timestamp")
                module = entry.get("module")
                function = entry.get("function")
                caller = entry.get("caller", {})
                arguments = entry.get("arguments", [])
                result = entry.get("result")
                if caller:
                    if caller.get("file", None) is not None and caller.get("file", None).startswith(
                        "node"
                    ):
                        pass
                    else:
                        full_name = f"{module}.{function}"
                        if sensitive_call_finder.query(full_name):
                            api_call = APICall(
                                _type, timestamp, module, function, caller, arguments, result
                            )
                            self.add_api_call(api_call)

    def add_api_call(self, api_call: APICall):
        """
        Adds a new API call to the collection. If ``self.enable_dedup`` is
        True and an API call with the same caller's file, line, and column
        already exists, remove the original and append the new one.
        """
        if not self.enable_dedup:
            self.collections.append(api_call)
            return

        new_caller = api_call.caller
        file_val = new_caller.get("file", None)
        start_line_val = new_caller.get("start_line", None)
        start_column_val = new_caller.get("start_column", None)
        end_line_val = new_caller.get("end_line", None)
        end_column_val = new_caller.get("end_column", None)

        # Only perform the check if all caller info is present
        if (
            file_val is not None
            and start_line_val is not None
            and start_column_val is not None
            and end_line_val is not None
            and end_column_val is not None
        ):
            # Remove any API call with matching caller file, line, and column.
            self.collections = [
                call
                for call in self.collections
                if not (
                    call.caller.get("file") == file_val
                    and call.caller.get("start_line") == start_line_val
                    and call.caller.get("start_column") == start_column_val
                    and call.caller.get("end_line") == end_line_val
                    and call.caller.get("end_column") == end_column_val
                )
            ]
        # Append the new API call at the end.
        self.collections.append(api_call)

    def find_api_call(
        self,
        _type: str,
        file: str,
        start_line: int,
        start_column: int,
        end_line: int,
        end_column: int,
    ) -> Optional[Tuple[str, str]]:
        """
        Searches the stored API call logs for an entry with a matching caller location.
        Returns a tuple (module, function) if found, or None otherwise.
        """
        match = self.find_api_call_with_index(
            _type, file, start_line, start_column, end_line, end_column
        )
        return match[1] if match else None

    def find_api_call_with_index(
        self,
        _type: str,
        file: str,
        start_line: int,
        start_column: int,
        end_line: int,
        end_column: int,
    ) -> Optional[Tuple[int, "APICall"]]:
        """Variant of :meth:`find_api_call` that also returns the runtime
        log-order index of the match.

        The log-order index is required by the orphan recovery
        """
        for idx, api_call in enumerate(self.collections):
            caller = api_call.caller
            call_type = api_call.type
            if (
                _type == call_type
                and caller.get("file") == file
                and caller.get("start_line") == start_line
                and caller.get("start_column") == start_column
                and caller.get("end_line") == end_line
                and caller.get("end_column") == end_column
            ):
                return idx, api_call
        return None

    @staticmethod
    def _caller_within_function(
        caller_file: str,
        caller_start_line: int,
        func_file: str,
        func_start_line: int,
        func_end_line: int,
    ) -> bool:
        """Return True if the caller position falls within the function's source range.

        File paths are compared after normalization so that the runtime log
        (``APICall.caller.file``) and the call graph (``Function.file``,
        prefixed with ``package/``) can match even though they don't share
        an exact textual representation.
        """
        from npm_pipeline.utils.module_root_utils import normalize_for_prefix_match

        if normalize_for_prefix_match(caller_file) != normalize_for_prefix_match(func_file):
            return False
        return func_start_line <= caller_start_line <= func_end_line

    def find_api_calls_in_function(
        self,
        file: str,
        func_start_line: int,
        func_start_col: int,
        func_end_line: int,
        func_end_col: int,
    ) -> List["APICall"]:
        """Return all API calls whose caller position is contained within the
        given function source range."""
        return [
            call
            for _, call in self.find_api_calls_in_function_with_indices(
                file, func_start_line, func_start_col, func_end_line, func_end_col
            )
        ]

    def find_api_calls_in_function_with_indices(
        self,
        file: str,
        func_start_line: int,
        func_start_col: int,
        func_end_line: int,
        func_end_col: int,
    ) -> List[Tuple[int, "APICall"]]:
        """Return ``(log_index, api_call)`` pairs for calls inside the given
        function source range.

        The index is the position of the call inside :attr:`collections`,
        which is the authoritative runtime-order proxy used by the
        async-aware orphan recovery.
        """
        result: list[tuple[int, APICall]] = []
        seen: set[tuple] = set()
        for idx, api_call in enumerate(self.collections):
            caller = api_call.caller
            c_file = caller.get("file")
            c_sl = caller.get("start_line")
            c_sc = caller.get("start_column")
            if c_file is None or c_sl is None or c_sc is None:
                continue
            key = (c_file, c_sl, c_sc, caller.get("end_line"), caller.get("end_column"))
            if key in seen:
                continue
            if self._caller_within_function(
                c_file,
                c_sl,
                file,
                func_start_line,
                func_end_line,
            ):
                seen.add(key)
                result.append((idx, api_call))
        return result

    @staticmethod
    def caller_key(api_call: "APICall") -> tuple:
        """Canonical dedup key for an API call based on its caller location.

        Used by both the BFS-matching path (``find_api_calls_in_function``)
        and the orphan-detection path (``find_api_calls_under_path_prefix``)
        so the two sides share the same notion of identity.  ``None`` fields
        are preserved verbatim so entries with missing caller info stay
        distinguishable.
        """
        caller = api_call.caller or {}
        return (
            caller.get("file"),
            caller.get("start_line"),
            caller.get("start_column"),
            caller.get("end_line"),
            caller.get("end_column"),
        )

    def iter_ordered(self) -> Iterable[Tuple[int, "APICall"]]:
        """Iterate over ``(log_index, api_call)`` pairs in runtime order.

        Thin wrapper over ``enumerate(self.collections)`` exposed so callers
        don't have to reach into the internal list representation.
        """
        return enumerate(self.collections)

    def find_api_calls_under_path_prefix(self, prefix: str) -> List[Tuple[int, "APICall"]]:
        """Return ``(log_index, api_call)`` pairs whose ``caller.file`` lives
        under *prefix*.

        *prefix* is matched with :func:`module_root_utils.path_is_under`, so
        both ``node_modules/<pkg>/`` style prefixes and the empty prefix
        (meaning "anything not under node_modules", used for the analyzed
        package root) work.  Returns the pairs in ``log_index`` order.
        """
        # Import here to avoid an import cycle with ``module_root_utils``.
        from npm_pipeline.utils.module_root_utils import path_is_under

        result: list[tuple[int, APICall]] = []
        for idx, api_call in enumerate(self.collections):
            caller_file = (api_call.caller or {}).get("file")
            if caller_file is None:
                continue
            if path_is_under(caller_file, prefix):
                result.append((idx, api_call))
        return result
