import json
import os
import shutil

from loguru import logger

import jelly_helper
import joern_helper
from custom_exception import JoernGenerationException, NoEntryScriptException
from npm_pipeline.classes.code_Info import CodeInfo
from util import code_preprocess


def generate_static_info(
    cfg_dir,
    cpg_dir,
    format_dir,
    jelly_cg_path,
    joern_dir,
    package_dir,
    pdg_dir,
    entry_script_set,
):
    # move the source code to a new directory, avoid altering the original code
    move_folder(package_dir, format_dir)
    # cwd = os.path.join(format_dir, "package")
    # install_dependencies(cwd)

    if not entry_script_set:
        raise NoEntryScriptException("There is no entry script")
    # preprocess the code
    code_preprocess(format_dir)

    jelly_helper.jelly_export(format_dir, jelly_cg_path, entry_script_set)
    remove_file_not_in_cg(jelly_cg_path, format_dir)
    joern_helper.joern_export(format_dir, joern_dir, "javascript")
    pdg_graph_dict, cpg = joern_helper.joern_preprocess(format_dir, pdg_dir, cfg_dir, cpg_dir, 8)

    if not len(os.listdir(pdg_dir)):
        logger.error("Joern PDG output is missing")
        raise JoernGenerationException("Joern pdg missing")
    if not len(os.listdir(cfg_dir)):
        logger.error("Joern CFG output is missing")
        raise JoernGenerationException("Joern cfg missing")
    if not len(os.listdir(cpg_dir)):
        logger.error("Joern CPG output is missing")
        raise JoernGenerationException("Joern cpg missing")
    static_code_info = CodeInfo(format_dir, pdg_dir, cpg_dir, pdg_graph_dict, cpg)
    static_code_info.build_static_call_graph(jelly_cg_path)
    return static_code_info


def remove_file_not_in_cg(jelly_cg_path, format_dir):
    with open(jelly_cg_path, "r") as cg_file:
        json_data = json.load(cg_file)

    files = json_data["files"]
    if len(files) == 0:
        return
    package_dir = os.path.join(format_dir, "package")
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


def move_folder(source, destination):
    """
    move the source code to the destination, ignoring all `node_modules` directories
    """
    if os.path.exists(destination):
        shutil.rmtree(destination)
    shutil.copytree(source, destination, ignore=shutil.ignore_patterns("node_modules"))


# def install_dependencies(cwd: str, timeout: int = 120):
#     logger.info("Installing Dependencies...")
#     command = [
#         "npm",
#         "install",
#         "--ignore-scripts",
#         "--no-audit",
#         "--production",
#         "--registry",
#         "https://registry.npmmirror.com//",
#     ]
#     try:
#         # Execute the command in the specified working directory
#         _ = subprocess.run(
#             command,
#             cwd=cwd,
#             check=True,
#             stdout=subprocess.PIPE,
#             stderr=subprocess.PIPE,
#             text=True,
#             timeout=timeout,
#         )
#         logger.info("Dependencies installed successfully.")
#     except subprocess.CalledProcessError as error:
#         logger.warning("Error occurred while installing dependencies")
#         logger.warning(error)
#     except subprocess.TimeoutExpired:
#         logger.warning("Dependency installation timed out.")
#         raise TimeoutError(f"Installation timed out after {timeout} seconds.")
