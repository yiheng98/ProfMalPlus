import json
import os
import subprocess
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager

import docker
from loguru import logger

from ast_parser import ASTParser

# ---------------------------------------------------------------------------
# Webcrack Docker configuration.
# ---------------------------------------------------------------------------
WEBCRACK_IMAGE_VERSION = "1.0"
WEBCRACK_IMAGE_TAG = f"webcrack_env:{WEBCRACK_IMAGE_VERSION}"
# Docker Hub repository used to pull the image on first run.
WEBCRACK_IMAGE_REPO = "yiheng98/webcrack_env"
WEBCRACK_IMAGE_REPO_TAG = f"{WEBCRACK_IMAGE_REPO}:{WEBCRACK_IMAGE_VERSION}"
WEBCRACK_TIMEOUT_PER_FILE = 120
WEBCRACK_MAX_WORKERS = 8


def remove_dev_dependencies(pkg_dir):
    """
    Read package.json and remove its devDependencies field.
    """
    package_json_path = os.path.join(pkg_dir, "package", "package.json")
    if not os.path.exists(package_json_path):
        logger.warning(f"package.json not found at {package_json_path}")
        return

    try:
        with open(package_json_path, "r", encoding="utf-8") as f:
            package_data = json.load(f)

        if "devDependencies" in package_data:
            del package_data["devDependencies"]
            with open(package_json_path, "w", encoding="utf-8") as f:
                json.dump(package_data, f, indent=4)
            logger.info(f"Removed devDependencies from {package_json_path}")
    except Exception as e:
        logger.error(f"Failed to remove devDependencies from {package_json_path}: {e}")


def code_preprocess(pkg_dir):
    """
    Dynamic-stage code preprocessing: remove devDependencies from package.json, batch-deobfuscate files, then resolve eval calls one by one.
    """
    remove_dev_dependencies(pkg_dir)

    js_files = []
    for root, dirs, files in os.walk(pkg_dir):
        # Remove any directories containing "node_modules" so they won't be traversed.
        dirs[:] = [d for d in dirs if "node_modules" not in d]
        for file in files:
            if file.endswith((".js", ".cjs", ".mjs")):
                file_path = os.path.join(root, file)
                js_files.append(file_path)

    if js_files:
        logger.info(f"Start deobfuscating {len(js_files)} files in docker")
        try:
            deobfuscate_files_in_docker(pkg_dir, js_files)
            logger.info("Deobfuscation completed")
        except Exception as e:
            logger.error(f"Error during deobfuscation: {e}")

        logger.info("Start resolving eval functions")
        for file_path in js_files:
            resolve_eval_in_file(file_path)
        logger.info("Resolving eval functions completed")


def resolve_eval_in_file(file_path):
    """
    Resolve eval functions in a single file.

    :param file_path: File path.
    """
    try:
        with open(file_path, "r") as code_file:
            code = code_file.read()
            after_eval_code = resolve_eval(code)

        with open(file_path, "w") as code_write_file:
            code_write_file.write(after_eval_code)

    except Exception as e:
        logger.warning(f"Resolve eval failed for {file_path}: {e}")


def resolve_eval(code: str):
    parser = ASTParser(code)
    query = """(
          call_expression
            function: (identifier) @func_name
            arguments: (arguments) @args
          (#eq? @func_name "eval")
        ) @eval_call
    """
    query_result = parser.query(query)
    arg_list = [r[0] for r in query_result if r[1] == "args"]
    eval_call_list = [r[0] for r in query_result if r[1] == "eval_call"]
    replacements = []
    eval_wrap_functions = []
    wrap_counter = 1
    code_lines = code.splitlines(keepends=True)  # Keep line breaks to make line-based location easier.
    for eval_node, args_node in zip(eval_call_list, arg_list):
        if not parser.is_isolated_eval(eval_node):
            continue
        fragment_nodes = []

        # Recursively find all nodes of type "string_fragment" under args_node.
        def collect_fragments(node):
            if node.named_children:
                for child in node.named_children:
                    if not collect_fragments(child):
                        return False
                return True
            else:
                if node.type == "string_fragment":
                    fragment_nodes.append(node)
                    return True
                else:
                    return False

        if collect_fragments(args_node):
            eval_code_text = "".join([fragment.text.decode() for fragment in fragment_nodes])
            logger.info("Find eval function with string, extract the code")
            wrap_func_name = f"eval_wrap_{wrap_counter}"
            wrap_counter += 1
            (start_row, start_col) = eval_node.start_point
            (end_row, end_col) = eval_node.end_point
            replacements.append(((start_row, start_col), (end_row, end_col), f"{wrap_func_name}()"))

            wrapped_fn_code = f"""function {wrap_func_name}() {{
                             {eval_code_text};
            }}"""
            eval_wrap_functions.append(wrapped_fn_code)

    for start_pos, end_pos, replacement in sorted(
        replacements, key=lambda x: (x[0][0], x[0][1]), reverse=True
    ):
        start_row, start_col = start_pos
        end_row, end_col = end_pos

        # Replace text in the specified line/column range.
        before = "".join(code_lines[:start_row]) + code_lines[start_row][:start_col]
        after = code_lines[end_row][end_col:] + "".join(code_lines[end_row + 1 :])
        code_lines = list(before + replacement + after)
        code_lines = "".join(code_lines).splitlines(keepends=True)

    new_code = "".join(code_lines)

    if eval_wrap_functions:
        new_code += "\n\n" + "\n\n".join(eval_wrap_functions) + "\n"

    return new_code


# ---------------------------------------------------------------------------
# Run webcrack inside a Docker container.
# ---------------------------------------------------------------------------
def _ensure_webcrack_image(client):
    """
    Ensure the webcrack image exists locally, using this priority:
      1. Existing local cached image.
      2. Pull from Docker Hub (yiheng98/webcrack_env).
    """
    # 1. Local cached image.
    try:
        image = client.images.get(WEBCRACK_IMAGE_TAG)
        logger.info(f"Using cached webcrack image: {WEBCRACK_IMAGE_TAG}")
        return image
    except Exception:
        logger.info(f"Local image '{WEBCRACK_IMAGE_TAG}' not found, pulling from Docker Hub")

    # 2. Pull from Docker Hub.
    try:
        logger.info(f"Pulling webcrack image from Docker Hub: {WEBCRACK_IMAGE_REPO_TAG}")
        image = client.images.pull(WEBCRACK_IMAGE_REPO, tag=WEBCRACK_IMAGE_VERSION)
        # Apply a unified local tag so WEBCRACK_IMAGE_TAG can hit the cache later.
        image.tag(WEBCRACK_IMAGE_TAG)
        logger.info(f"Pulled and tagged webcrack image as: {WEBCRACK_IMAGE_TAG}")
        return image
    except Exception as e:
        raise RuntimeError(
            f"Webcrack image '{WEBCRACK_IMAGE_TAG}' not found locally and pulling "
            f"from '{WEBCRACK_IMAGE_REPO_TAG}' failed: {e}"
        )


@contextmanager
def webcrack_container_context(volume_mapping: dict):
    """Start a long-running webcrack container and automatically stop and remove it after use."""
    client = docker.from_env(timeout=300)

    image = _ensure_webcrack_image(client)

    container = client.containers.run(
        image=image.id,
        detach=True,
        tty=True,
        command="sleep infinity",
        volumes=volume_mapping,
        network_mode="host",
    )
    try:
        yield container
    finally:
        try:
            container.stop(timeout=5)
        except Exception as e:
            logger.error(f"Error stopping webcrack container: {e}")
        try:
            container.remove(force=True)
        except Exception as e:
            logger.error(f"Error removing webcrack container: {e}")


def _run_webcrack_on_file(
    container, host_pkg_dir: str, container_pkg_dir: str, file_path: str
) -> str | None:
    """
    Run webcrack on a single JS file inside the container with `docker exec`, then overwrite the host file in place.

    :param container: Started webcrack container.
    :param host_pkg_dir: Host package directory as an absolute path, mounted to container_pkg_dir.
    :param container_pkg_dir: Matching package directory inside the container as an absolute path.
    :param file_path: JS file on the host to deobfuscate.
    :return: file_path on success; None on failure.
    """
    if not os.path.exists(file_path):
        logger.warning(f"Input file does not exist: {file_path} for deobfuscation")
        return None

    rel_path = os.path.relpath(file_path, host_pkg_dir)
    # Use POSIX separators consistently inside the container.
    container_file = container_pkg_dir + "/" + rel_path.replace(os.sep, "/")

    try:
        # webcrack <file> writes deobfuscated output to stdout so the host file can be overwritten in place.
        result = subprocess.run(
            ["docker", "exec", container.id, "webcrack", container_file],
            capture_output=True,
            text=True,
            timeout=WEBCRACK_TIMEOUT_PER_FILE,
        )
    except subprocess.TimeoutExpired:
        logger.error(f"Deobfuscation timeout for {file_path}")
        return None
    except FileNotFoundError:
        logger.error(
            "`docker` CLI not found. Please install docker engine and ensure the daemon is running."
        )
        return None
    except Exception as e:
        logger.error(f"Error during deobfuscation of {file_path}: {e}")
        return None

    if result.returncode != 0:
        logger.error(f"Deobfuscation failed for {file_path}: {result.stderr}")
        return None

    if not result.stdout:
        logger.warning(f"webcrack produced empty output for {file_path}, skip overwrite")
        return None

    try:
        with open(file_path, "w", encoding="utf-8") as f:
            f.write(result.stdout)
    except Exception as e:
        logger.error(f"Failed to write deobfuscated content to {file_path}: {e}")
        return None

    return file_path


def deobfuscate_files_in_docker(format_dir: str, js_files: list):
    """
    Start a webcrack container, mount format_dir into it,
    and concurrently run webcrack deobfuscation for all files in js_files.

    :param format_dir: Package directory on the host, i.e. format_dir in static/dynamic_helper.
    :param js_files: List of JS file paths to process on the host; each must be under format_dir.
    """
    if not js_files:
        return

    # path mapping
    CONTAINER_FORMAT_PATH = "/format"

    volume_mapping = {
        os.path.abspath(format_dir): {"bind": CONTAINER_FORMAT_PATH, "mode": "rw"},
    }

    abs_format_dir = os.path.abspath(format_dir)

    with webcrack_container_context(volume_mapping) as container:
        max_workers = min(WEBCRACK_MAX_WORKERS, max(1, len(js_files)))
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            list(
                executor.map(
                    lambda f: _run_webcrack_on_file(
                        container, abs_format_dir, CONTAINER_FORMAT_PATH, f
                    ),
                    js_files,
                )
            )
