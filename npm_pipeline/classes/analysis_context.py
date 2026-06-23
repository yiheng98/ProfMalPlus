from npm_pipeline.classes.code_Info import CodeInfo
from npm_pipeline.classes.dependency_tree import DependencyTree
from npm_pipeline.classes.dynamic_matching_record import DynamicMatchingRecord
from npm_pipeline.classes.package_json import PackageJson
from npm_pipeline.classes.program_context import ProgramContext


class AnalysisContext:
    def __init__(self, package_name: str, package_json: PackageJson):
        self.package_name = package_name
        self.package_json = package_json

        self.program_context_backup: dict[int, ProgramContext] = {}  # Temporary program states for branch handling.
        self.program_context: ProgramContext = None  # Program context.
        self.analyzed_script = set()  # Scripts that have already been analyzed.
        self.loaded_history = set()  # Modules already loaded, determined from the call graph.
        self.global_visited = set()  # Prevent repeated analysis of the same node.
        self.file_in_cg = set()  # Files involved in static and dynamic analysis.
        self.current_code_info: CodeInfo = None
        self.third_party_module_name = set()  # Names of third-party modules.
        self.conditional_node = (
            set()
        )  # Conditional-call node IDs from static analysis that need further checks.
        self.unresolved_node = (
            set()
        )  # Unresolved-call node IDs from static analysis that need further checks.
        self.third_party_node = (
            set()
        )  # Third-party-call node IDs from static analysis that need further checks.

        # Node IDs identified as THIRD_PARTY_CALL during static analysis.
        self.static_third_party_visited_nodes: set[int] = set()

        # Phase-A ledger for the batched/parallel dynamic behavior pipeline.
        # Per-traversal single-call and chain matches accumulate here; Phase
        # B reads the whole ledger at once to run global orphan recovery,
        # deduped parallel LLM calls, and stitch-back.
        self.dynamic_matching_record: DynamicMatchingRecord = DynamicMatchingRecord()

        # Declared transitive dependency tree, parsed from
        # ``npm ls --all --json`` during dynamic info generation.  Phase-B
        # orphan recovery consults this to expand a chain's module_roots
        # with packages the static call graph fails to link (e.g. the
        # ``axios -> follow-redirects`` delegation edge).  If the
        # generation step failed, this stays an ``empty()`` tree and
        # Phase-B silently degrades to the old CG-only behavior.
        self.dependency_tree: DependencyTree = DependencyTree.empty()

    def clear(self):
        self.program_context_backup: dict[int, ProgramContext] = {}
        self.program_context: ProgramContext = None
        self.analyzed_script = set()
        self.loaded_history = set()
        self.global_visited = set()
        self.file_in_cg = set()
        self.current_code_info: CodeInfo = None
        self.third_party_module_name = set()
        self.conditional_node = set()
        self.unresolved_node = set()
        self.third_party_node = set()
        self.static_third_party_visited_nodes = set()
        self.dynamic_matching_record = DynamicMatchingRecord()
        self.dependency_tree = DependencyTree.empty()

    def is_static_pending_conditional(self, node_id: int) -> bool:
        """Return whether a node was marked as a conditional call during static analysis and needs dynamic checks."""
        return node_id in self.conditional_node

    def is_static_pending_unresolved(self, node_id: int) -> bool:
        """Return whether a node could not be resolved during static analysis and needs dynamic completion."""
        return node_id in self.unresolved_node

    def is_static_pending_third_party(self, node_id: int) -> bool:
        """Return whether a node was marked as an unresolved third-party call that still needs dynamic analysis."""
        return node_id in self.third_party_node
