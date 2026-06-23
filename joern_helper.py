import atexit
import os
import re
import signal
import subprocess
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

import networkx as nx
import psutil
import yaml
from loguru import logger
from tqdm import tqdm

from ast_parser import ASTParser
from custom_exception import GraphReadingException

with open("./config.yaml", "r") as file:
    config = yaml.safe_load(file)

# Global process group management
active_process_groups = set()
process_cleanup_lock = threading.Lock()


def register_process_group(pgid):
    """Register a process group for global cleanup."""
    with process_cleanup_lock:
        active_process_groups.add(pgid)


def unregister_process_group(pgid):
    """Unregister a process group."""
    with process_cleanup_lock:
        active_process_groups.discard(pgid)


def cleanup_all_process_groups():
    """Clean up all registered process groups."""
    with process_cleanup_lock:
        for pgid in active_process_groups.copy():
            try:
                os.killpg(pgid, signal.SIGTERM)
                time.sleep(1)  # Allow processes time to exit gracefully
                os.killpg(pgid, signal.SIGKILL)  # Force kill
            except ProcessLookupError:
                pass
            active_process_groups.discard(pgid)


# Register global cleanup handler
atexit.register(cleanup_all_process_groups)


def kill_process_tree(pid):
    """Recursively terminate a process and all its children."""
    try:
        parent = psutil.Process(pid)
        children = parent.children(recursive=True)
        for child in children:
            try:
                child.terminate()
            except psutil.NoSuchProcess:
                pass
        parent.terminate()

        # Wait for process termination
        gone, still_alive = psutil.wait_procs(children + [parent], timeout=5)
        for p in still_alive:
            try:
                p.kill()
            except psutil.NoSuchProcess:
                pass
    except psutil.NoSuchProcess:
        pass


def run_command_with_timeout(command, cwd, timeout, env=None):
    """Run a command and terminate all related processes on timeout."""
    process = None
    pgid = None

    try:
        # Start process with Popen and assign a process group
        process = subprocess.Popen(
            command,
            cwd=cwd,
            env=env,
            preexec_fn=os.setsid,  # Create a new process group
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

        # Get process group ID and register it
        pgid = os.getpgid(process.pid)
        register_process_group(pgid)

        try:
            # Wait for process completion with timeout
            stdout, stderr = process.communicate(timeout=timeout)
            return process.returncode, stdout, stderr
        except subprocess.TimeoutExpired:
            # On timeout, terminate the entire process group
            logger.warning(f"Command timeout after {timeout}s, killing process group {pgid}")
            os.killpg(pgid, signal.SIGTERM)
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                os.killpg(pgid, signal.SIGKILL)

            # Ensure all related processes are terminated
            kill_process_tree(process.pid)
            raise
    except Exception as e:
        # Clean up processes on any exception (including TimeoutError)
        if pgid is not None:
            logger.warning(f"Exception occurred, killing process group {pgid}: {type(e).__name__}")
            try:
                os.killpg(pgid, signal.SIGKILL)
                # Fallback: clean up again with psutil
                if process and process.pid:
                    kill_process_tree(process.pid)
            except (ProcessLookupError, OSError) as cleanup_error:
                logger.debug(
                    f"Process group {pgid} cleanup error (may already be dead): {cleanup_error}"
                )
        raise e
    finally:
        if pgid is not None:
            unregister_process_group(pgid)


def joern_export(package_code_path: str, joern_workspace_path: str, language: str):
    """
    Export CPG and PDG to joern_workspace_path/package_name/cpg and joern_workspace_path/package_name/pdg.
    :param package_code_path: Path to package source code
    :param joern_workspace_path: Joern workspace path
    :param language: Language (javascript, pythonsrc)
    """
    os.environ["PATH"] = config["joern_path"] + os.pathsep + os.environ["PATH"]
    package_joern_path = os.path.abspath(joern_workspace_path)
    pdg_dir = os.path.join(package_joern_path, "pdg")
    cfg_dir = os.path.join(package_joern_path, "cfg")
    cpg_dir = os.path.join(package_joern_path, "cpg")
    if os.path.exists(package_joern_path):
        subprocess.run(["rm", "-rf", package_joern_path])
    os.makedirs(package_joern_path, exist_ok=True)

    try:
        logger.info("Joern Parse")
        run_command_with_timeout(
            [
                "joern-parse",
                "-J-Xmx40g",
                "--language",
                language,
                os.path.abspath(package_code_path),
            ],
            cwd=package_joern_path,
            timeout=300,
        )
        logger.info("Joern Parse Completed")

        logger.info("Joern Export PDG")
        run_command_with_timeout(
            ["joern-export", "--repr", "pdg", "--out", os.path.abspath(pdg_dir)],
            cwd=package_joern_path,
            timeout=300,
        )
        logger.info("Joern Export PDG Completed")

        logger.info("Joern Export CFG")
        run_command_with_timeout(
            ["joern-export", "--repr", "cfg", "--out", os.path.abspath(cfg_dir)],
            cwd=package_joern_path,
            timeout=300,
        )
        logger.info("Joern Export CFG Completed")

        logger.info("Joern Export CPG")
        run_command_with_timeout(
            [
                "joern-export",
                "--repr",
                "all",
                "--format",
                "graphml",
                "--out",
                os.path.abspath(cpg_dir),
            ],
            cwd=package_joern_path,
            timeout=600,
        )
        logger.info("Joern Export CPG Completed")
    except subprocess.TimeoutExpired as e:
        logger.error(f"Command timed out: {e}")
        raise
    except Exception as e:
        logger.error(f"Error during joern export: {e}")
        raise


def _process_single_pdg(
    pdg_file: str,
    pdg_dir: str,
    cfg_dir: str,
    cpg: nx.MultiDiGraph,
    package_dir: str,
):
    """Process a single PDG file: merge with CFG, enrich CPG node attributes, write back dot file.

    CPG is read-only; threads do not interfere with each other.
    """
    file_id = pdg_file.split("-")[0]
    pdg_path = os.path.join(pdg_dir, pdg_file)
    try:
        pdg: nx.MultiDiGraph = nx.nx_agraph.read_dot(pdg_path)
    except Exception as e:
        logger.info(f"Failed to read PDG from {pdg_path}: {e}. Skipping this PDG.")
        return None

    cfg_file = f"{file_id}-cfg.dot"
    cfg_path = os.path.join(cfg_dir, cfg_file)
    try:
        cfg: nx.MultiDiGraph = nx.nx_agraph.read_dot(cfg_path)
    except Exception as e:
        logger.info(
            f"Failed to read CFG from {cfg_path}: {e}. Skipping CFG integration for this PDG."
        )
        return None

    ddg_null_edges = []
    for u, v, k, d in pdg.edges(data=True, keys=True):
        if d["label"] in ["DDG: ", "CDG: "]:
            ddg_null_edges.append((u, v, k, d))
    pdg.remove_edges_from(ddg_null_edges)

    # Check for key conflicts between PDG and CFG before composing
    # Create a remapped CFG to avoid overwriting PDG edges
    cfg_remapped = nx.MultiDiGraph()
    cfg_remapped.add_nodes_from(cfg.nodes(data=True))

    for u, v, k, d in cfg.edges(data=True, keys=True):
        label = d.get("label", "CFG")
        if label == "":
            label = "CFG"

        if pdg.has_edge(u, v, key=k):
            existing_keys = list(pdg[u][v].keys()) if pdg.has_edge(u, v) else []
            new_key = max(existing_keys) + 1 if existing_keys else 0
            cfg_remapped.add_edge(u, v, key=new_key, label=label)
        else:
            cfg_remapped.add_edge(u, v, key=k, label=label)

    pdg = nx.compose(pdg, cfg_remapped)
    method_node = None
    param_nodes = []
    for node in pdg.nodes:
        for key, value in cpg.nodes[node].items():
            key_in_dot = transform_key(key)
            pdg.nodes[node][key_in_dot] = value
        pdg.nodes[node]["NODE_TYPE"] = pdg.nodes[node]["label"]
        node_type = pdg.nodes[node]["NODE_TYPE"]
        if node_type == "METHOD":
            method_node = node
        if node_type == "METHOD_PARAMETER_IN":
            param_nodes.append(node)
        if "CODE" not in pdg.nodes[node]:
            pdg.nodes[node]["CODE"] = ""
        node_code = pdg.nodes[node]["CODE"].replace("\n", "\\n")
        pdg.nodes[node]["CODE"] = pdg.nodes[node]["CODE"].replace("\n", "\\n")
        node_line = pdg.nodes[node]["LINE_NUMBER"] if "LINE_NUMBER" in pdg.nodes[node] else 0
        node_column = pdg.nodes[node]["COLUMN_NUMBER"] if "COLUMN_NUMBER" in pdg.nodes[node] else 0
        if node_type == "CALL":
            pdg.nodes[node]["label"] = (
                f"[{node}][{node_line}:{node_column}][{node_type}]: {node_code}"
            )
        else:
            pdg.nodes[node]["label"] = f"[{node}][{node_line}:{node_column}][{node_type}]"
        if pdg.nodes[node]["NODE_TYPE"] == "METHOD_RETURN":
            pdg.remove_edges_from(list(pdg.in_edges(node)))

    add_edge(pdg, package_dir, method_node, param_nodes)
    nx.nx_agraph.write_dot(pdg, os.path.join(pdg_dir, pdg_file))
    return pdg_file, pdg


def joern_preprocess(
    package_dir: str,
    pdg_dir: str,
    cfg_dir: str,
    cpg_dir: str,
    max_workers: int | None = None,
):
    logger.info("Joern Preprocess")
    try:
        cpg_path = os.path.join(cpg_dir, "export.xml")
        cpg = nx.read_graphml(cpg_path, force_multigraph=True)
    except Exception:
        raise GraphReadingException("XML Reading Exception of cpg")

    pdg_files = os.listdir(pdg_dir)
    pdg_graph_dict: dict[str, nx.MultiDiGraph] = {}

    if max_workers is None:
        max_workers = min(16, (os.cpu_count() or 4) * 2)

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_file = {
            executor.submit(
                _process_single_pdg, pdg_file, pdg_dir, cfg_dir, cpg, package_dir
            ): pdg_file
            for pdg_file in pdg_files
        }
        for future in tqdm(
            as_completed(future_to_file),
            total=len(future_to_file),
            desc="Processing PDG Files",
            unit="file",
        ):
            pdg_file = future_to_file[future]
            try:
                result = future.result()
            except Exception as e:
                logger.warning(f"Failed to process {pdg_file}: {e}")
                continue
            if result is None:
                continue
            done_file, pdg = result
            pdg_graph_dict[done_file] = pdg

    return pdg_graph_dict, cpg


def transform_key(key):
    if key == "labelV":
        return "label"
    elif key == "labelE":
        return "label"
    else:
        return key


def add_edge(pdg: nx.MultiDiGraph, package_dir, method_node, param_nodes):
    if len(param_nodes) > 0:
        if "NAME" not in pdg.nodes[method_node]:
            return
        method_name = pdg.nodes[method_node]["NAME"]
        if re.search(r"<lambda>\d*", method_name):
            try:
                # This METHOD node is a lambda function
                js_file_path = os.path.join(package_dir, pdg.nodes[method_node]["FILENAME"].strip())
                start_line = int(pdg.nodes[method_node]["LINE_NUMBER"])
                start_column = int(pdg.nodes[method_node]["COLUMN_NUMBER"])
                end_line = int(pdg.nodes[method_node]["LINE_NUMBER_END"])
                end_column = int(pdg.nodes[method_node]["COLUMN_NUMBER_END"])
                code_snippet = ""
                with open(js_file_path, "r") as file:
                    current_line_number = 1
                    for line in file:
                        if current_line_number == start_line:
                            code_snippet += line[start_column - 1 :]  # Adjust for 0-indexing
                        elif start_line < current_line_number < end_line:
                            code_snippet += line
                        elif current_line_number == end_line:
                            code_snippet += line[:end_column]  # Adjust for 0-indexing
                            break
                        current_line_number += 1

                # Parse formal parameters of the lambda function
                ast_parser = ASTParser(code_snippet)
                formal_parameter_query = "(formal_parameters)@formal"
                query_result = ast_parser.query_oneshot(formal_parameter_query)
                formal_parameter_list = []
                if query_result:
                    named_children = query_result.named_children
                    for child in named_children:
                        formal_parameter_list.append(child.text.decode())

                # Parse parameters of the arrow function
                arrow_function_parameters_query = """
                    (arrow_function
                        parameter: (identifier)@identifier
                    )
                """
                query_result = ast_parser.query_oneshot(arrow_function_parameters_query)
                if query_result:
                    formal_parameter_list.append(query_result.text.decode())
                for param_node in param_nodes:
                    param_code = pdg.nodes[param_node]["CODE"]
                    if param_code in formal_parameter_list:
                        pdg.add_edge(method_node, param_node, label="DDG")
            except Exception as e:
                logger.warning(f"Failed to parse lambda function: {e}")
        else:
            for param_node in param_nodes:
                pdg.add_edge(method_node, param_node, label="DDG")


if __name__ == "__main__":
    os.environ["PATH"] = config["joern_path"] + os.pathsep + os.environ["PATH"]
    base_dir = "/home/huangyh/profMalPlus/"
    package_name = "test_package"
    package_code_path = os.path.join(base_dir, "test_package", package_name)
    joern_dir = os.path.join(base_dir, "workspace", package_name)
    language = "javascript"
    joern_export(package_code_path, joern_dir, language)
    pdg_dir = os.path.join(joern_dir, "pdg")
    cfg_dir = os.path.join(joern_dir, "cfg")
    cpg_dir = os.path.join(joern_dir, "cpg")
    joern_preprocess(package_code_path, pdg_dir, cfg_dir, cpg_dir)
