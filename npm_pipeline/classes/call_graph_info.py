import os


class Function:
    def __init__(self, file, start_line, start_column, end_line, end_column):
        self.file = file
        self.start_line = start_line
        self.start_column = start_column
        self.end_line = end_line
        self.end_column = end_column

    def __eq__(self, other):
        if not isinstance(other, Function):
            return NotImplemented
        return (
            self.file == other.file
            and self.start_line == other.start_line
            and self.start_column == other.start_column
            and self.end_line == other.end_line
            and self.end_column == other.end_column
        )

    def __hash__(self):
        return hash((self.file, self.start_line, self.start_column, self.end_line, self.end_column))


class Call:
    def __init__(self, file, start_line, start_column, end_line, end_column):
        self.file = file
        self.start_line = start_line
        self.start_column = start_column
        self.end_line = end_line
        self.end_column = end_column
        self.call_to_functions: list[Function] = []


class CallGraph:
    def __init__(self):
        self.entries: list[str] = []
        self.files: list[str] = []

        self.functions: dict[int, Function] = {}
        self.calls: dict[int, Call] = {}
        self.call2funcs: dict[str, dict[str, list[Function]]] = {}

        self.fun2fun_callees: dict[Function, list[Function]] = {}
        self.fun2fun_callers: dict[Function, list[Function]] = {}

    @classmethod
    def from_json(cls, json_data: dict) -> "CallGraph":
        """Build a CallGraph from parsed JSON (used by both static and dynamic pipelines)."""
        cg = cls()

        for entry in json_data["entries"]:
            cg.add_entries(entry)

        for file in json_data["files"]:
            cg.add_file(file)

        functions = json_data["functions"]
        items = functions.items() if isinstance(functions, dict) else enumerate(functions)
        for key, value in items:
            parts = value.split(":")
            cg.add_function(
                int(key),
                int(parts[0]),
                int(parts[1]) - 1,
                int(parts[2]) - 1,
                int(parts[3]) - 1,
                int(parts[4]) - 1,
            )

        calls = json_data["calls"]
        items = calls.items() if isinstance(calls, dict) else enumerate(calls)
        for key, value in items:
            parts = value.split(":")
            cg.add_call(
                int(key),
                int(parts[0]),
                int(parts[1]) - 1,
                int(parts[2]) - 1,
                int(parts[3]) - 1,
                int(parts[4]) - 1,
            )

        for call2func in json_data["call2fun"]:
            cg.add_call_to_function(call2func[0], call2func[1])

        for fun2fun in json_data.get("fun2fun", []):
            cg.add_fun2fun(fun2fun[0], fun2fun[1])

        return cg

    def add_entries(self, entry: str):
        self.entries.append(os.path.join("package", entry))

    def add_file(self, file: str):
        self.files.append(os.path.join("package", file))

    def add_file_from_other_call_graph(self, file: str):
        self.files.append(file)

    def add_function(
        self,
        function_id: int,
        file_index: int,
        start_line: int,
        start_column: int,
        end_line: int,
        end_column: int,
    ):
        self.functions[function_id] = Function(
            self.files[file_index], start_line, start_column, end_line, end_column
        )

    def add_call(
        self,
        call_id: int,
        file_index: int,
        start_line: int,
        start_column: int,
        end_line: int,
        end_column: int,
    ):
        self.calls[call_id] = Call(
            self.files[file_index], start_line, start_column, end_line, end_column
        )

    def add_call_to_function(self, call_id: int, function_id: int):
        call_entity = self.calls[call_id]
        function_entity = self.functions[function_id]
        if function_entity not in call_entity.call_to_functions:
            call_entity.call_to_functions.append(function_entity)
        self.add_call_edge(call_entity, function_entity)

    def add_call_edge(self, caller: Call, callee: Function):
        file_map = self.call2funcs.setdefault(caller.file, {})
        loc_str = f"{caller.start_line}:{caller.start_column}:{caller.end_line}:{caller.end_column}"
        callees = file_map.setdefault(loc_str, [])
        if callee not in callees:
            callees.append(callee)

    def get_callees(
        self, file: str, start_line: int, start_column: int, end_line: int, end_column: int
    ) -> list[Function]:
        """Return all callees mapped from the given call location.

        Returns a shallow copy so callers may iterate / mutate freely without
        affecting the internal storage. Returns an empty list when no edge
        exists for the location.
        """
        loc_str = f"{start_line}:{start_column}:{end_line}:{end_column}"
        if file in self.call2funcs and loc_str in self.call2funcs[file]:
            return list(self.call2funcs[file][loc_str])
        return []

    def add_fun2fun(self, caller_id: int, callee_id: int):

        caller = self.functions[caller_id]
        callee = self.functions[callee_id]
        self._add_fun2fun_direct(caller, callee)

    def _add_fun2fun_direct(self, caller: Function, callee: Function):
        """Store a fun2fun edge using Function objects directly."""
        self.fun2fun_callees.setdefault(caller, []).append(callee)
        self.fun2fun_callers.setdefault(callee, []).append(caller)

    def get_callees_of_function(self, func: Function) -> list[Function]:
        """Return all functions directly called by the given function."""
        return self.fun2fun_callees.get(func, [])

    def get_callers_of_function(self, func: Function) -> list[Function]:
        """Return all functions that directly call the given function."""
        return self.fun2fun_callers.get(func, [])

    def get_transitive_callees(self, start: Function) -> list[Function]:
        """BFS from *start* through fun2fun_callees, returning all reachable
        functions (including *start* itself) in visit order, deduplicated."""
        from collections import deque

        visited: set[Function] = {start}
        queue: deque[Function] = deque([start])
        result: list[Function] = [start]
        while queue:
            current = queue.popleft()
            for callee in self.fun2fun_callees.get(current, []):
                if callee not in visited:
                    visited.add(callee)
                    queue.append(callee)
                    result.append(callee)
        return result

    def get_function_by_id(self, function_id: int) -> Function | None:
        return self.functions.get(function_id)

    def find_function_by_location(
        self, file: str, start_line: int, start_column: int, end_line: int, end_column: int
    ) -> Function | None:
        """Find Function object by its source location."""
        key = Function(file, start_line, start_column, end_line, end_column)
        for func in self.functions.values():
            if func == key:
                return func
        return None

    def get_callee_locations_of_function(self, func: Function) -> list[dict]:
        """Return location info (including file) for all callees of the given function."""
        return [
            {
                "file": callee.file,
                "start_line": callee.start_line,
                "start_column": callee.start_column,
                "end_line": callee.end_line,
                "end_column": callee.end_column,
            }
            for callee in self.get_callees_of_function(func)
        ]

    def get_files(self):
        return self.files
