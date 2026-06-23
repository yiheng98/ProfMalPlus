from call_type_dict import REQUIRE_CALL, THIRD_PARTY_CALL, UNRESOLVED_CALL
from npm_pipeline.classes.object import Object
from npm_pipeline.classes.serialized_types import FileIORecord


class PDGNode:
    def __init__(self, node_id):
        self.node_id = node_id  # Node ID.
        self.source_pdg = None  # PDG graph this node belongs to.
        self.node_type = None  # PDG node type, matching NODE_TYPE in the PDG.
        self.line_number: int | None = None  # Start line number.
        self.line_number_end: int | None = None  # End line number.
        self.column_number: int | None = None  # Start column number.
        self.column_number_end: int | None = None  # End column number.
        self.name = None  # NAME field in the PDG.
        self.filename = None  # File containing this node.
        self.code = None  # CODE field in the PDG.
        self.sensitive_node = False  # Whether this is a sensitive node.
        self.is_entrance_point = False  # Entry node of the PDG graph.
        self.is_return = False  # Return node of the PDG graph.
        self.call_type = (
            None  # Call type when this PDG node has NODE_TYPE=call, e.g. CALL or FUNCTION_CALL.
        )
        self.function_behavior = None  # Behavior graph (PBG) when this PDG node is a function call.
        self.qualified_path: tuple[Object, list[str]] | None = None  # Qualified path for this node.
        self.return_value = None  # Return content when this is a return node.
        self.branch = False
        self.sensitive_dict = None  # Sensitive API metadata when this node is a sensitive API call.
        self.third_party_call_dict = None  # Third-party API metadata when this node is a third-party API call.
        self.unresolved_call_dict = None  # Unresolved call metadata for this node.
        self.require_call_dict = None  # require() call metadata for this node.
        self.eval_call_dict = None  # eval call metadata collected during dynamic analysis.
        self.resolved_api_call = None  # ResolvedAPICall for a single sensitive API call
        self.resolved_api_call_sequence = None  # list[ResolvedAPICall] for call-chain sequences
        self.behavior_description = None  # Natural-language behavior description for this node.
        self.module_behavior = None  # Overall third-party module behavior from registry metadata.
        self.key_files = None  # LLM-identified key files from API sequence behavior analysis
        self.file_io_records: list[FileIORecord] | None = None
        self._large_file_content_map: dict[tuple[str, str], str] = {}
        self.callee_pdgs: list = []

    def __lt__(self, other):
        return self.line_number < other.line_number

    def reset_for_new_entry(self):
        """Clear per-entry analysis state so this PDG node can be re-analyzed
        cleanly when the pipeline switches to the next entry script.
        """
        self.sensitive_node = False
        self.is_return = False
        self.call_type = None
        self.function_behavior = None
        self.qualified_path = None
        self.return_value = None
        self.branch = False
        self.sensitive_dict = None
        self.third_party_call_dict = None
        self.unresolved_call_dict = None
        self.require_call_dict = None
        self.eval_call_dict = None
        self.resolved_api_call = None
        self.resolved_api_call_sequence = None
        self.behavior_description = None
        self.module_behavior = None
        self.key_files = None
        self.file_io_records = None
        self._large_file_content_map = {}
        self.callee_pdgs = []

    def set_source_pdg(self, pdg_id):
        self.source_pdg = pdg_id

    def get_source_pdg(self):
        return self.source_pdg

    def get_call_type(self):
        return self.call_type

    def set_call_type(self, call_type):
        self.call_type = call_type

    def get_behavior_of_call(self):
        return self.function_behavior

    def set_behavior_of_call(self, diagram):
        self.function_behavior = diagram

    def get_id(self):
        return self.node_id

    def get_node_type(self):
        return self.node_type

    def set_node_type(self, label):
        self.node_type = label

    def get_line_number(self) -> int:
        return self.line_number

    def set_line_number(self, line_number: int | None):
        self.line_number = line_number

    def get_line_number_end(self) -> int:
        return self.line_number_end

    def set_line_number_end(self, line_number_end: int | None):
        self.line_number_end = line_number_end

    def get_column_number(self) -> int:
        return self.column_number

    def set_column_number(self, column_number: int | None):
        self.column_number = column_number

    def get_column_number_end(self):
        return self.column_number_end

    def set_column_number_end(self, column_number_end: int | None):
        self.column_number_end = column_number_end

    def set_sensitive_node(self, bool_value):
        self.sensitive_node = bool_value

    def is_sensitive_node(self):
        return self.sensitive_node

    def set_entrance(self, bool_value):
        self.is_entrance_point = bool_value

    def is_entrance(self):
        return self.is_entrance_point

    def set_is_return(self, bool_value):
        self.is_return = bool_value

    def is_return_value(self):
        return self.is_return

    def set_file_name(self, filename):
        self.filename = filename

    def get_file_name(self) -> str:
        return self.filename

    def set_qualified_path(self, qualified_path):
        self.qualified_path = qualified_path

    def get_qualified_path(self):
        return self.qualified_path

    def set_name(self, name):
        self.name = name

    def get_name(self):
        return self.name

    def set_code(self, code):
        self.code = code

    def get_code(self):
        return self.code

    def set_return_value(self, return_value):
        self.return_value = return_value

    def get_return_value(self):
        return self.return_value

    def set_the_branch(self):
        self.branch = True

    def is_branch(self):
        return self.branch

    def set_sensitive_dict(self, call_info, call_name):
        self.sensitive_dict = {"call_info": call_info, "call_name": call_name}

    def get_sensitive_dict(self):
        return self.sensitive_dict

    def is_third_party_call(self):
        return self.call_type == THIRD_PARTY_CALL

    def is_unresolved_call(self):
        return self.call_type == UNRESOLVED_CALL

    def is_require_call(self):
        return self.call_type == REQUIRE_CALL

    def set_callee_pdgs(self, pdgs: list):
        self.callee_pdgs = list(pdgs)

    def add_callee_pdg(self, pdg):
        if pdg is None:
            return
        if pdg not in self.callee_pdgs:
            self.callee_pdgs.append(pdg)

    def get_callee_pdgs(self) -> list:
        return self.callee_pdgs

    def set_third_party_call_dict(self, call_name, module, property_method):
        self.third_party_call_dict = {
            "call_name": call_name,
            "module": module,
            "property_method": property_method,
        }

    def get_third_party_call_dict(self):
        return self.third_party_call_dict

    def set_unresolved_call_dict(self, call_name):
        self.unresolved_call_dict = {"call_name": call_name}

    def get_unresolved_call_dict(self):
        return self.unresolved_call_dict

    def get_require_call_dict(self):
        return self.require_call_dict

    def set_require_call_dict(self, module_name):
        self.require_call_dict = {"module_name": module_name}

    def set_eval_call_dict(self, eval_call_dict: dict | None):
        self.eval_call_dict = eval_call_dict

    def get_eval_call_dict(self) -> dict | None:
        return self.eval_call_dict

    def set_resolved_api_call(self, resolved):
        self.resolved_api_call = resolved

    def get_resolved_api_call(self):
        return self.resolved_api_call

    def set_resolved_api_call_sequence(self, sequence):
        self.resolved_api_call_sequence = sequence

    def get_resolved_api_call_sequence(self):
        return self.resolved_api_call_sequence

    def set_behavior_description(self, behavior_description):
        self.behavior_description = behavior_description

    def get_behavior_description(self):
        return self.behavior_description

    def set_module_behavior(self, module_behavior):
        self.module_behavior = module_behavior

    def get_module_behavior(self):
        return self.module_behavior

    def set_key_files(self, key_files):
        self.key_files = key_files

    def get_key_files(self):
        return self.key_files

    def set_file_io_records(self, file_io_records: list[FileIORecord] | None):
        self.file_io_records = file_io_records

    def get_file_io_records(self) -> list[FileIORecord] | None:
        return self.file_io_records

    def set_large_file_content(self, file_path: str, operation: str, content: str):
        self._large_file_content_map[(file_path, operation)] = content

    def get_large_file_content(self, file_path: str, operation: str) -> str | None:
        return self._large_file_content_map.get((file_path, operation))

    def has_large_file_contents(self) -> bool:
        return bool(self._large_file_content_map)
