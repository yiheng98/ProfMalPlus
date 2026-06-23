import os
import sys

from loguru import logger

import npm_pipeline.package_runner as npm_analyser
from status import STATUS_CODE_MALICIOUS, STATUS_PKG_JSON_MALICIOUS


def workflow_logger_config(work_space_dir, package_name, verbose=False):
    logger.remove()
    log_dir = os.path.join(work_space_dir, package_name)
    os.makedirs(log_dir, exist_ok=True)
    main_log_path = os.path.join(log_dir, "work_flow.log")

    def _node_trace_filter(record):
        if record["extra"].get("node_trace") and not verbose:
            return False
        return True

    logger.add(main_log_path, level="DEBUG", mode="w", filter=_node_trace_filter)
    logger.add(sys.stdout, level="DEBUG", filter=_node_trace_filter)


def _is_malicious(status_list) -> bool:
    if not status_list:
        return False
    for status in status_list:
        if status == STATUS_CODE_MALICIOUS or status == STATUS_PKG_JSON_MALICIOUS:
            return True
    return False


def analyse(package_name, package_dir, workspace_dir, dynamic_support, verbose=False):
    workflow_logger_config(workspace_dir, package_name, verbose)
    logger.info(f"🔄Start Analyzing Package: {package_name}")

    status_list = npm_analyser.run(
        package_name=package_name,
        package_dir=package_dir,
        workspace_dir=workspace_dir,
        dynamic_support=dynamic_support,
    )

    logger.info(f"✅Finish Analyzing Package: {package_name}")
    logger.info(f"🔚Status: {status_list}")

    statuses = list(status_list) if status_list else []
    return _is_malicious(statuses), statuses
