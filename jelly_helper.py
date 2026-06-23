import os
import subprocess

from loguru import logger

from custom_exception import JellyCallGraphGenerationError


def jelly_export(
    package_code_path: str,
    call_graph_path: str,
    entry_script_set: set[str],
):
    """
    export the jelly call graph
    :param package_code_path: package code path
    :param call_graph_path: jelly workspace
    :param entry_script_set: the entry script list
    """
    if os.path.exists(call_graph_path):
        os.remove(call_graph_path)
    parent_dir = os.path.dirname(call_graph_path)
    os.makedirs(parent_dir, exist_ok=True)
    source_code_path = os.path.join(package_code_path, "package")
    logger.info("Start generating call graph")
    result = subprocess.run(
        [
            "jelly",
            "-j",
            call_graph_path,
            "--library",
            "./",
        ],
        cwd=source_code_path,
        timeout=120,
        stdout=subprocess.DEVNULL,
    )
    if result.returncode != 0:
        raise JellyCallGraphGenerationError("Jelly Call Graph Generation Error")
    if not os.path.exists(call_graph_path):
        raise JellyCallGraphGenerationError("Jelly Call Graph Generation Error")
    logger.info("Call Graph Generation Completed")
