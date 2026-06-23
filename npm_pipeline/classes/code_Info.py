import json
import os

from loguru import logger

from ast_parser import ASTParser
from base_classes.cpg import CPG
from base_classes.pdg import PDG
from npm_pipeline.classes.api_call import APICallCollection
from npm_pipeline.classes.call_graph_info import CallGraph
from npm_pipeline.classes.file import File


class CodeInfo:
    def __init__(
        self,
        formatted_package_dir: str,
        pdg_dir: str,
        cpg_dir: str,
        pdg_graph_dict: dict,
        cpg_graph,
    ):
        self.formatted_package_dir = formatted_package_dir
        self.pdg_dir = pdg_dir
        self.cpg_dir = cpg_dir
        self.js_file_list = self.__iterate_file()  # get all .js files
        self.files: dict[str, File] = {}  # files
        for js_file, raw_code in self.js_file_list.items():
            self.files[js_file] = File(js_file, raw_code)
        self.js_file_list = list(self.js_file_list.keys())
        self.cpg = CPG(self.cpg_dir, cpg_graph)  # read the cpg dot
        self.__build_static_pdg_dict(pdg_graph_dict)  # read the pdg dot
        self.__build_call_expression_dict()  # build the call expression dict
        self.call_graph = None
        self.api_call_info = None  # the api call info is available in the dynamic analysis
        self.api_call_to_pdg_node_mapping = {}  # record the api call to pdg node mapping
        self.eval_call_info = None  # the eval call info is available in the dynamic analysis

    def __iterate_file(self) -> dict[str, list]:
        """
        iterate all the files in the package
        :return: list containing all the files in the call graph
        """
        js_files = {}
        for root, dirs, files in os.walk(self.formatted_package_dir):
            for file in files:
                file_path = os.path.join(root, file)
                try:
                    with open(file_path, "r", encoding="utf-8") as code_file:
                        raw_code = code_file.readlines()
                except Exception as e:
                    logger.warning(f"UnicodeDecodeError reading file {file_path}: {e}")
                    raw_code = []  # Reset raw_code to an empty list.
                js_files[os.path.relpath(file_path, self.formatted_package_dir)] = raw_code
        return js_files

    def __build_static_pdg_dict(self, pdg_graph_dict=None):
        """
        build the pdg from the pdg dot
        """
        dot_names = os.listdir(self.pdg_dir)

        # key: (first node id, name, full name, file)
        self.pdg_dict: dict[int, PDG] = {}

        # to record whether the pdg is analyzed
        self.pdg_analyzed: dict[int, bool] = {}
        for dot in dot_names:
            dot_path = os.path.join(self.pdg_dir, dot)
            try:
                if pdg_graph_dict is not None and dot in pdg_graph_dict:
                    pdg = PDG(pdg_path=dot_path, cpg=self.cpg, pdg_graph=pdg_graph_dict[dot])
                else:
                    pdg = PDG(pdg_path=dot_path, cpg=self.cpg)
            except Exception as e:
                logger.info(f"Failed to read PDG from {dot_path} of {e}. \nSkipping this PDG.")
                continue
            if pdg.is_empty():
                continue
            name = pdg.get_name()
            filename = pdg.get_file_name()
            if (
                name is None
                or filename is None
                or filename == "<empty>"
                or filename.endswith(".ts")
            ):
                continue

            self.pdg_dict[pdg.get_first_node_id()] = pdg
            self.pdg_analyzed[pdg.get_first_node_id()] = False

    @classmethod
    def for_dynamic(
        cls,
        static_code_info: "CodeInfo",
        formatted_package_dir: str,
        call_graph: CallGraph,
        api_call_info: "APICallCollection | None",
        eval_call_info: dict | None,
    ) -> "CodeInfo":
        """Create an instance for dynamic analysis from a static CodeInfo.

        Rescan files under formatted_package_dir and rebuild call_expression_dict,
        reuse the CPG / PDG from static analysis, and bind the dynamic call_graph / api_call_info / eval_call_info.
        """
        instance = object.__new__(cls)
        instance.formatted_package_dir = formatted_package_dir
        instance.pdg_dir = static_code_info.pdg_dir
        instance.cpg_dir = static_code_info.cpg_dir

        js_file_map = instance.__iterate_file()
        instance.files = {
            js_file: File(js_file, raw_code) for js_file, raw_code in js_file_map.items()
        }
        instance.js_file_list = list(js_file_map.keys())

        instance.cpg = static_code_info.cpg
        instance.pdg_dict = static_code_info.pdg_dict
        instance.pdg_analyzed = {}

        instance.__build_call_expression_dict()

        instance.call_graph = call_graph
        instance.api_call_info = api_call_info
        instance.eval_call_info = eval_call_info
        instance.api_call_to_pdg_node_mapping = {}

        return instance

    def set_call_graph(self, call_graph: CallGraph):
        self.call_graph = call_graph

    def set_api_call_info(self, api_call_info: APICallCollection | None):
        self.api_call_info = api_call_info

    def build_static_call_graph(self, call_graph_path: str):
        """
        read the call graph in cg.json
        """
        with open(call_graph_path, "r") as cg_file:
            json_data = json.load(cg_file)
        self.call_graph = CallGraph.from_json(json_data)

    def __build_call_expression_dict(self):
        """
        record the call expression start from line and column
        """
        self.call_expression_dict: dict[str, dict[tuple, list[tuple]]] = {}
        for file in self.files:
            source_code = "".join(self.files[file].get_raw_code())
            parser = ASTParser(source_code)
            expression_captures = parser.query("(call_expression)@call_expression") + parser.query(
                "(new_expression)@new_expression"
            )
            if not expression_captures:
                continue
            file_dict = self.call_expression_dict.setdefault(file, {})
            for capture in expression_captures:
                node = capture[0]
                start_point = node.start_point
                end_point = node.end_point
                key = (start_point[0], start_point[1])
                value = (end_point[0], end_point[1])
                end_points = file_dict.setdefault(key, [])
                if value not in end_points:
                    end_points.append(value)

    def set_eval_call_info(self, eval_call_info: dict):
        self.eval_call_info = eval_call_info
