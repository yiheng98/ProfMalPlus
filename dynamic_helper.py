import csv
import json
import os
import re
import shutil
import sys
import threading
import traceback
from contextlib import contextmanager

import docker
import yaml
from loguru import logger

from ast_parser import ASTParser
from custom_exception import (
    DynamicRunningException,
)
from npm_pipeline.classes.api_call import APICallCollection
from npm_pipeline.classes.call_graph_info import Call, CallGraph, Function
from npm_pipeline.classes.code_Info import CodeInfo
from util import code_preprocess

csv.field_size_limit(sys.maxsize)

with open("./config.yaml", "r") as file:
    config = yaml.safe_load(file)


# ---------------------------------------------------------------------------
# Dynamic env Docker configuration
# ---------------------------------------------------------------------------
DYNAMIC_IMAGE_VERSION = "2.0"
DYNAMIC_IMAGE_TAG = f"dynamic_env:{DYNAMIC_IMAGE_VERSION}"
# Docker Hub repository; image is pulled from here on first run
DYNAMIC_IMAGE_REPO = "yiheng98/dynamic_env"
DYNAMIC_IMAGE_REPO_TAG = f"{DYNAMIC_IMAGE_REPO}:{DYNAMIC_IMAGE_VERSION}"


def _ensure_dynamic_image(client):
    """
    Ensure a local dynamic image exists. Resolution order:
      1. Use a cached local image
      2. Pull from Docker Hub (yiheng98/dynamic_env)
    """
    # 1. Local cache
    try:
        image = client.images.get(DYNAMIC_IMAGE_TAG)
        logger.info(f"Using cached image with tag: {DYNAMIC_IMAGE_TAG}")
        return image
    except Exception:
        logger.info(f"Local image '{DYNAMIC_IMAGE_TAG}' not found, pulling from Docker Hub")

    # 2. Pull from Docker Hub
    try:
        logger.info(f"Pulling dynamic image from Docker Hub: {DYNAMIC_IMAGE_REPO_TAG}")
        image = client.images.pull(DYNAMIC_IMAGE_REPO, tag=DYNAMIC_IMAGE_VERSION)
        # Tag locally so subsequent lookups hit DYNAMIC_IMAGE_TAG cache
        image.tag(DYNAMIC_IMAGE_TAG)
        logger.info(f"Pulled and tagged dynamic image as: {DYNAMIC_IMAGE_TAG}")
        return image
    except Exception as e:
        raise RuntimeError(
            f"Dynamic image '{DYNAMIC_IMAGE_TAG}' not found locally and pulling "
            f"from '{DYNAMIC_IMAGE_REPO_TAG}' failed: {e}"
        )


@contextmanager
def docker_container_context(volume_mapping: dict):
    """Load Image and create container, and remove after finishing"""
    container_cmd = "bash"
    client = docker.from_env(timeout=300)

    image = _ensure_dynamic_image(client)

    def create_container():
        return client.containers.run(
            image=image.id,
            detach=True,
            tty=True,
            command=container_cmd,
            volumes=volume_mapping,
            network_mode="host",
        )

    # create container
    container = create_container()
    try:
        yield container
    finally:
        try:
            container.stop()
        except Exception as e:
            logger.error(f"Error stopping container: {e}")
        try:
            container.remove()
        except Exception as e:
            logger.error(f"Error removing container: {e}")


def stop_container(container):
    try:
        logger.info("Stopping and removing container due to timeout.")
        container.stop()
    except Exception as e:
        logger.error(f"Error stopping and removing container: {e}")


def docker_execute_command(container, cmd, args, workdir, env, label, timeout=90):
    """
    run command in the docker container
    """
    full_cmd = [cmd] + args
    logger.info(f"[Docker] {label} execution: {' '.join(full_cmd)} (workdir: {workdir})")

    # Start a timer to stop the container on timeout
    timeout_timer = threading.Timer(timeout, stop_container, [container])
    timeout_timer.start()  # Start the timer

    try:
        result = container.exec_run(
            cmd=full_cmd,
            workdir=workdir,
            environment=env,
            stdout=True,
            stderr=True,
            demux=True,
        )
    except Exception as e:
        logger.error(f"{label} command execution failed with error: {str(e)}")
        raise Exception(f"{label} command execution failed with error: {str(e)}")
    finally:
        timeout_timer.cancel()

    stdout, stderr = result.output if result.output else (b"", b"")
    if stdout:
        logger.info(f"{label} - stdout: {stdout.decode('utf-8')}")
    if stderr:
        logger.info(f"{label} - stderr: {stderr.decode('utf-8')}")
    if result.exit_code != 0:
        logger.error(Exception(f"{label} command failed with exit code {result.exit_code}"))
    else:
        logger.info(f"Docker {label} execution finished successfully.")


def generate_dynamic_info(
    package_dir: str,
    formatted_package_dir: str,
    joern_dir: str,
    pdg_dir: str,
    cfg_dir: str,
    cpg_dir: str,
    jelly_cg_dir: str,
    api_info_dir: str,
    dep_tree_dir: str,
    entry_file: str,
    static_code_info: CodeInfo,
):
    move_folder(package_dir, formatted_package_dir)

    # preprocess the code
    code_preprocess(formatted_package_dir)

    # dynamic execution to generate the call graph and `eval` info
    dynamic_call_graph, api_call_info, eval_call_info = dynamic_info_export(
        formatted_package_dir, jelly_cg_dir, api_info_dir, dep_tree_dir, entry_file
    )

    if dynamic_call_graph is None:
        # Failed to generate the dynamic call graph, use the static one
        dynamic_code_info = static_code_info
        dynamic_code_info.set_api_call_info(api_call_info)
        dynamic_code_info.set_eval_call_info(eval_call_info)
        logger.warning("Dynamic Call Graph is None, using the static one")
        return dynamic_code_info

    # merge the call graph from static to dynamic
    merge_call_graph(static_code_info.call_graph, dynamic_call_graph)

    remove_file_not_in_cg(dynamic_call_graph, formatted_package_dir)

    dynamic_code_info = CodeInfo.for_dynamic(
        static_code_info,
        formatted_package_dir,
        dynamic_call_graph,
        api_call_info,
        eval_call_info,
    )
    return dynamic_code_info


def dynamic_info_export(
    package_code_dir: str,
    dynamic_call_graph_dir: str,
    api_locate_dir: str,
    dep_tree_dir: str,
    entry_file: str,
):
    """
    export the dynamic info, including call graph and API call location
    """

    if os.path.exists(dynamic_call_graph_dir):
        shutil.rmtree(dynamic_call_graph_dir)
    if os.path.exists(api_locate_dir):
        shutil.rmtree(api_locate_dir)
    if os.path.exists(dep_tree_dir):
        shutil.rmtree(dep_tree_dir)

    os.makedirs(dynamic_call_graph_dir, exist_ok=True)
    os.makedirs(api_locate_dir, exist_ok=True)
    os.makedirs(dep_tree_dir, exist_ok=True)

    # create a empty csv file
    api_info_csv_file_path = os.path.join(api_locate_dir, "api_info.csv")
    with open(api_info_csv_file_path, mode="w", newline="") as file:
        csv.writer(file)

    source_code_path = os.path.join(package_code_dir, "package")
    custom_dyn_file_path = os.path.abspath(os.path.join(os.getcwd(), "dyn.js"))
    custom_node_file_path = os.path.abspath(os.path.join(os.getcwd(), "node"))

    # path mapping
    CONTAINER_APP_PATH = "/app"
    CONTAINER_JELLY_OUT = "/jelly_out"
    CONTAINER_API_INFO = "/api_info"
    CONTAINER_DEP_TREE = "/dep_tree"
    CONTAINER_DYN_PATH = "/lib/node_modules/@cs-au-dk/jelly/lib/dynamic/dyn.js"
    CONTAINER_CUSTOM_NODE_PATH = "/lib/node_modules/@cs-au-dk/jelly/bin/node"

    volume_mapping = {
        os.path.abspath(source_code_path): {"bind": CONTAINER_APP_PATH, "mode": "rw"},
        os.path.abspath(dynamic_call_graph_dir): {"bind": CONTAINER_JELLY_OUT, "mode": "rw"},
        os.path.abspath(api_locate_dir): {"bind": CONTAINER_API_INFO, "mode": "rw"},
        os.path.abspath(dep_tree_dir): {"bind": CONTAINER_DEP_TREE, "mode": "rw"},
        os.path.abspath(custom_dyn_file_path): {"bind": CONTAINER_DYN_PATH, "mode": "ro"},
        os.path.abspath(custom_node_file_path): {"bind": CONTAINER_CUSTOM_NODE_PATH, "mode": "ro"},
    }

    # execute command in the same container
    with docker_container_context(volume_mapping=volume_mapping) as container:
        # remove the scripts in the package.json
        remove_scripts_in_package_json(source_code_path)

        # STEP 1 install the package
        docker_execute_command(
            container,
            "npm",
            ["install", "--omit=dev", "--registry", "https://registry.npmmirror.com//"],
            workdir=CONTAINER_APP_PATH,
            env={},
            label="npm install",
            timeout=300,
        )

        try:
            docker_execute_command(
                container,
                "sh",
                [
                    "-c",
                    f"npm ls --all --json > {CONTAINER_DEP_TREE}/dep_tree.json 2>/dev/null || true",
                ],
                workdir=CONTAINER_APP_PATH,
                env={},
                label="npm ls",
                timeout=60,
            )
        except Exception as e:
            logger.warning(f"npm ls export failed: {e}")

        # Build Dynamic Call Graph
        custom_node_cmd = "jelly"
        graal_home = "/workspace-nodeprof/graal/sdk/latest_graalvm_home"  # Path inside the image
        env_vars = {"GRAAL_HOME": graal_home, "CALL_FILE": CONTAINER_JELLY_OUT}

        # STEP 2 Dynamic Call Graph Generation
        try:
            docker_execute_command(
                container,
                custom_node_cmd,
                [
                    entry_file,
                    "-d",
                    os.path.join(CONTAINER_JELLY_OUT, "cg.json"),
                    "--basedir",
                    CONTAINER_APP_PATH,
                ],
                workdir=CONTAINER_APP_PATH,
                env=env_vars,
                label="dynamic info",
            )

            cg_path = os.path.join(dynamic_call_graph_dir, "cg.json")
            if not os.path.exists(cg_path):
                dynamic_call_graph = None
            else:
                cg_json_data = json.load(open(cg_path, "r"))
                dynamic_call_graph = build_dynamic_call_graph(cg_json_data)
                # file_in_cg.update(dynamic_call_graph.get_files())
                # the dynamic jelly lacking the `require` call to the source file
                add_call_to_source_file(dynamic_call_graph_dir, dynamic_call_graph)

            # get the eval call info from the dynamic call trace
            eval_call_info = get_eval_info(dynamic_call_graph_dir, package_code_dir)

        except Exception as e:
            logger.error(f"Dynamic Info Execution Failed of {e}")
            dynamic_call_graph = None
            eval_call_info = {}

        # The container runs as root, so files written into the mounted
        # volumes are root-owned on the host. Hand ownership back to the
        # host user here (cheap for in-container root) so the host process
        # can read/write them without sudo afterwards.
        try:
            # A timeout (exit code 137) stops the container, so it may no
            # longer be running here. Restart it (it is not removed until the
            # context manager exits) so the chown exec can succeed.
            container.reload()
            if container.status != "running":
                logger.info(
                    f"Container not running ({container.status}); restarting to fix ownership."
                )
                container.start()

            host_owner = f"{os.getuid()}:{os.getgid()}"
            docker_execute_command(
                container,
                "chown",
                [
                    "-R",
                    host_owner,
                    CONTAINER_APP_PATH,
                    CONTAINER_JELLY_OUT,
                    CONTAINER_API_INFO,
                    CONTAINER_DEP_TREE,
                ],
                workdir="/",
                env={},
                label="fix ownership",
                timeout=120,
            )
        except Exception as e:
            logger.warning(f"Failed to fix ownership inside container: {e}")

    # STEP 3 Get the API Info
    preprocess_api_call_info(api_info_csv_file_path, package_code_dir, CONTAINER_APP_PATH)
    api_call_info_json_path = os.path.join(api_locate_dir, "api_info.json")
    if not os.path.exists(api_call_info_json_path):
        raise DynamicRunningException(
            "Dynamic Call Graph Generation Error: api_info.json not found"
        )
    apI_call_info = APICallCollection(api_call_info_json_path)
    return dynamic_call_graph, apI_call_info, eval_call_info


def remove_scripts_in_package_json(source_code_path: str):
    package_json_path = os.path.join(source_code_path, "package.json")
    if not os.path.exists(package_json_path):
        return
    else:
        with open(package_json_path, "r") as file:
            package_data = json.load(file)

        if "scripts" in package_data:
            del package_data["scripts"]
            with open(package_json_path, "w") as file:
                json.dump(package_data, file, indent=4)


def get_eval_info(eval_trace_dir: str, package_code_dir: str):
    eval_call_info = {}
    call_pattern = re.compile(r"^\(([^:]+):\d+:\d+:\d+:\d+\)$")
    valid_entries = []
    for entry in os.scandir(eval_trace_dir):
        # Process only files whose names start with "eval_trace-"
        if entry.is_file() and entry.name.startswith("eval_trace-"):
            file_path = os.path.abspath(os.path.join(eval_trace_dir, entry.name))
            try:
                with open(file_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    # Ensure data is a list
                    if isinstance(data, list):
                        for item in data:
                            # Ensure each item is a dict with a string "Call" field
                            if (
                                isinstance(item, dict)
                                and "Call" in item
                                and isinstance(item["Call"], str)
                            ):
                                # Keep entries whose Call matches the expected format
                                match = call_pattern.match(item["Call"])
                                if match:
                                    valid_entries.append(item)
            except Exception as e:
                logger.error(f"Error reading JSON from {file_path}: {e}")

    if len(valid_entries) == 0:
        return eval_call_info

    for item in valid_entries:
        call_loc = item.get("Call")
        arg = item.get("Arg")
        loc_str = call_loc.strip("()")
        split_res = loc_str.split(":")
        file_name = split_res[0]
        start_line = int(split_res[1])
        start_column = int(split_res[2])
        end_line = int(split_res[3])
        end_column = int(split_res[4])
        eval_call_info.setdefault(file_name, []).append(
            {
                "start_line": start_line,
                "start_column": start_column,
                "end_line": end_line,
                "end_column": end_column,
                "arg": arg,
                "call_loc": call_loc,
            }
        )

    return eval_call_info


def safe_json_load(value, default=None):
    try:
        return json.loads(value) if value else default
    except json.JSONDecodeError:
        return default


def preprocess_api_call_info(
    api_info_file_path: str, package_code_dir: str, container_app_path: str
):
    def get_string(csv_item):
        if csv_item.startswith('"') and csv_item.endswith('"'):
            csv_item = csv_item[1:-1]
        return csv_item.replace('""', '"')

    columns = [
        "func_type",
        "module_name",
        "func_name",
        "argument",
        "results",
        "file",
        "line",
        "column",
    ]
    csv_data = []

    # Read data from CSV
    with open(api_info_file_path, mode="r", encoding="utf-8") as f:
        csvreader = csv.reader(f)
        for row in csvreader:
            try:
                if len(row) != len(
                    columns
                ):  # Skip rows that don't match the expected number of columns
                    continue

                row_dict = dict(zip(columns, row))

                # Process fields that may have been sanitized (argument, results)
                row_dict["argument"] = get_string(row_dict["argument"])
                row_dict["results"] = get_string(row_dict["results"])

                entry = {
                    "type": row_dict["func_type"],
                    "module": row_dict["module_name"],
                    "function": row_dict["func_name"],
                    "arguments": row_dict["argument"],
                    "result": row_dict["results"],
                    "file": row_dict["file"],
                    "line": safe_json_load(row_dict["line"]),
                    "column": safe_json_load(row_dict["column"]),
                }
                csv_data.append(entry)

            except Exception as row_error:
                logger.warning(f"Error processing row {row}: {row_error}")

    # Separate callback entries
    call_back = [entry for entry in csv_data if entry.get("type") == "callback"]
    non_callback = [entry for entry in csv_data if entry.get("type") != "callback"]

    # Cache file contents for faster AST parsing
    code_cache = {}

    # Process the non callback data
    for entry in non_callback:
        _type = entry.get("type")
        file = entry.get("file")
        line = entry.get("line")
        column = entry.get("column")

        if _type and file and line and column:
            relative_inside = os.path.relpath(file, container_app_path)
            file_host_path = os.path.join(package_code_dir, "package", relative_inside)
            relative_file_path = os.path.relpath(file_host_path, package_code_dir)
            caller = {"file": relative_file_path}

            try:
                if file_host_path not in code_cache:
                    with open(file_host_path, "r", encoding="utf-8") as code_file:
                        code_cache[file_host_path] = code_file.read()

                raw_code = code_cache[file_host_path]
                ast_parser = ASTParser(raw_code)

                if _type == "function":
                    call_loc = ast_parser.get_call_expression_loc(line - 1, column - 1)
                    if call_loc:
                        caller.update(
                            {
                                "start_line": call_loc[0],
                                "start_column": call_loc[1],
                                "end_line": call_loc[2],
                                "end_column": call_loc[3],
                            }
                        )
                elif _type == "property":
                    property_access_loc = ast_parser.get_property_access_loc(line - 1, column - 1)
                    if property_access_loc:
                        caller.update(
                            {
                                "start_line": property_access_loc[0],
                                "start_column": property_access_loc[1],
                                "end_line": property_access_loc[2],
                                "end_column": property_access_loc[3],
                            }
                        )
                entry["caller"] = caller
            except Exception as e:
                logger.warning(f"Failed to get call expression loc for {file}: {e}")
                caller.update(
                    {
                        "start_line": line,
                        "start_column": column,
                        "end_line": None,
                        "end_column": None,
                    }
                )
                entry["caller"] = caller

    # Process callback entries (readFile, readFileSync)
    for entry in call_back:
        arguments = entry.get("arguments", [])
        result = entry.get("result", "")

        if arguments and isinstance(arguments, str):
            for non_callback_entry in reversed(non_callback):
                non_callback_arguments = non_callback_entry.get("arguments", [])
                if (
                    non_callback_arguments
                    and isinstance(non_callback_arguments, str)
                    and non_callback_arguments == arguments
                ):
                    non_callback_entry["result"] = result
                    break

    # Write the filtered and processed data back to a JSON file
    json_file_path = api_info_file_path.replace(".csv", ".json")
    with open(json_file_path, "w", encoding="utf-8") as f:
        json.dump(non_callback, f, indent=2, ensure_ascii=False)
    logger.info("Processed data saved")


def remove_file_not_in_cg(call_graph: CallGraph, format_dir: str):
    files = call_graph.get_files()
    if len(files) == 0:
        return
    package_dir = format_dir
    files_to_keep = set(os.path.normpath(file_path) for file_path in files)

    for root, dirs, files in os.walk(package_dir, topdown=False):
        for file in files:
            file_path = os.path.join(root, file)
            rel_path = os.path.relpath(file_path, package_dir)
            rel_path_normalized = os.path.normpath(rel_path)
            if rel_path_normalized not in files_to_keep:
                try:
                    os.remove(file_path)
                except Exception as e:
                    logger.warning(f"Failed to remove file: {file_path} of {e}")
        for _dir in dirs:
            dir_path = os.path.join(root, _dir)
            try:
                if not os.listdir(dir_path):
                    os.rmdir(dir_path)
            except Exception as e:
                logger.info(f"Error deleting directory '{dir_path}': {e}")


def build_dynamic_call_graph(call_graph_json):
    return CallGraph.from_json(call_graph_json)


def add_call_to_source_file(dynamic_call_graph_dir: str, dynamic_call_graph: CallGraph):
    for entry in os.scandir(dynamic_call_graph_dir):
        if entry.is_file():
            p = os.path.abspath(os.path.join(dynamic_call_graph_dir, entry.name))
            # Check if the file name starts with "cg-"
            if entry.name.startswith("call_file_source-"):
                try:
                    with open(p, "r", encoding="utf-8") as f:
                        data = json.load(f)
                        pairs = extract_call2source(data)
                        for pair in pairs:
                            call_info = pair["call"]
                            caller_split_res = call_info.split(":")
                            if not caller_split_res[1].startswith("/usr/lib"):
                                caller_file = os.path.join("package", caller_split_res[1])
                                caller_call = Call(
                                    caller_file,
                                    int(caller_split_res[2]) - 1,
                                    int(caller_split_res[3]) - 1,
                                    int(caller_split_res[4]) - 1,
                                    int(caller_split_res[5]) - 1,
                                )

                                callee_info = pair["source"]
                                callee_split_res = callee_info.split(":")

                                if not callee_split_res[1].startswith("/usr/lib"):
                                    callee_file = os.path.join("package", callee_split_res[1])
                                    callee_func = dynamic_call_graph.find_function_by_location(
                                        callee_file,
                                        int(callee_split_res[2]) - 1,
                                        int(callee_split_res[3]) - 1,
                                        int(callee_split_res[4]) - 1,
                                        int(callee_split_res[5]) - 1,
                                    )
                                    if callee_func is not None:
                                        dynamic_call_graph.add_call_edge(caller_call, callee_func)
                except Exception as e:
                    logger.error(f"Error decoding JSON from {p}: {e}")
                    logger.error(traceback.format_exc())


def extract_call2source(json_data):
    pairs = []

    for i, item in enumerate(json_data):
        if item.startswith("Source:"):
            # Look backwards for the first "Call:" item
            for j in range(i - 1, -1, -1):
                if json_data[j].startswith("Call:"):
                    new_str = json_data[j].replace("(", "").replace(")", "")
                    pairs.append({"call": new_str, "source": item})
                    break

    return pairs


def move_folder(source, destination):
    """
    move the source code to the destination
    """
    if os.path.exists(destination):
        shutil.rmtree(destination)
    shutil.copytree(source, destination)


def get_dynamic_only_files(static_graph: CallGraph, dynamic_graph: CallGraph) -> list:
    """Return files present in dynamic_graph but absent in static_graph."""
    files_in_static = static_graph.get_files()
    return [f for f in dynamic_graph.get_files() if f not in files_in_static]


def merge_call_graph(static_graph: CallGraph, dynamic_graph: CallGraph):
    for file in static_graph.get_files():
        if file not in dynamic_graph.files:
            dynamic_graph.add_file_from_other_call_graph(file)

    # Map each unique (file, line, col) to the dynamic-graph's own Function
    # instance so merged edges stay consistent with the rest of the graph.
    dyn_func_lookup: dict[Function, Function] = {
        func: func for func in dynamic_graph.functions.values()
    }

    def _resolve(func: Function) -> Function:
        return dyn_func_lookup.get(func, func)

    # Merge call-to-function mappings from static graph into dynamic graph
    for call in static_graph.calls.values():
        for func in call.call_to_functions:
            dynamic_graph.add_call_edge(call, _resolve(func))

    # Merge fun2fun: resolve static Function objects to dynamic equivalents
    for caller_func, callee_list in static_graph.fun2fun_callees.items():
        dyn_caller = _resolve(caller_func)
        existing = set(dynamic_graph.fun2fun_callees.get(dyn_caller, []))
        for callee_func in callee_list:
            dyn_callee = _resolve(callee_func)
            if dyn_callee not in existing:
                dynamic_graph._add_fun2fun_direct(dyn_caller, dyn_callee)
