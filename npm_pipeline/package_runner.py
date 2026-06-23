import os
import signal
import subprocess
import traceback

from loguru import logger

import joern_helper
from base_classes.report import Report
from custom_exception import (
    GraphReadingException,
    JoernGenerationException,
    NoEntryScriptException,
    PackageJsonNotFoundException,
    PackageJsonReadException,
)
from npm_pipeline.classes.detection_state import AnalysisStep, DetectionState
from npm_pipeline.classes.package import Package
from npm_pipeline.classes.package_json import PackageJson
from status import (
    STATUS_BENIGN,
    STATUS_CODE_NOT_EXIST,
    STATUS_JOERN_ERROR,
    STATUS_LLM_ERROR,
    STATUS_PACKAGE_JSON_NOT_EXIST,
    STATUS_PACKAGE_JSON_READ_ERROR,
    STATUS_PKG_JSON_MALICIOUS,
    STATUS_PROGRAM_ERROR,
    STATUS_TIMEOUT,
)

timeout_limit = 3600


def timeout_handler(signum, frame):
    logger.info("Timeout triggered!")
    joern_helper.cleanup_all_process_groups()
    raise TimeoutError("Time out")


def interrupt_handler(signum, frame):
    logger.warning("User interrupted")
    joern_helper.cleanup_all_process_groups()
    raise KeyboardInterrupt("Interrupted by user")


def timeout(seconds):
    def decorator(func):
        def wrapper(*args, **kwargs):
            signal.signal(signal.SIGALRM, timeout_handler)
            signal.signal(signal.SIGINT, interrupt_handler)
            signal.alarm(seconds)
            try:
                result = func(*args, **kwargs)
            finally:
                signal.alarm(0)
            return result

        return wrapper

    return decorator


def _build_detection_state(package_name: str, script_results: dict[str, dict]) -> DetectionState:
    state = DetectionState(package_name=package_name)

    finding_lines: list[str] = []
    overall = "benign"
    for name, res in script_results.items():
        label = res["label"]
        executed = res.get("executed_js_files", [])
        line = f'• {name}: "{res["content"]}" → {res["label"]}'
        if res.get("explanation"):
            line += f" ({res['explanation']})"
        if executed:
            line += f"\n  ↳ Launches JS: {', '.join(executed)}"
        else:
            line += "\n  ↳ No JS entry files identified"
        finding_lines.append(line)
        if label == "malicious":
            overall = "malicious"
        elif label == "warning" and overall == "benign":
            overall = "warning"

    state.add_step(
        AnalysisStep(
            stage="install_script_analysis",
            entry=None,
            result=overall,
            finding="\n".join(finding_lines),
        )
    )
    return state


@timeout(timeout_limit)
def run(
    package_name: str,
    package_dir: str,
    workspace_dir: str,
    dynamic_support: bool,
):
    statuses: set[str] = set()
    if not os.path.exists(package_dir):
        logger.error(f"{package_name} is not exist")
        statuses.add(STATUS_CODE_NOT_EXIST)
        return statuses
    report = Report()
    report.set_package_name(package_name)
    detection_state: DetectionState | None = None
    try:
        # the default package.json is in the package directory
        package_json_path = os.path.join(package_dir, "package", "package.json")
        if not os.path.exists(package_json_path):
            raise PackageJsonNotFoundException(package_name)

        # Build the package.json object
        package_json = PackageJson(package_json_path)

        # detect the malicious script in the scripts field
        script_results = package_json.classify_all_scripts()
        for name, result in script_results.items():
            report.add_install_time_script(
                name, result["content"], result["label"], result["explanation"]
            )
        if any(r["label"] == "malicious" for r in script_results.values()):
            report.set_maliciousness_in_package_json()

        detection_state = _build_detection_state(package_name, script_results)

        package = Package(
            package_name=package_name,
            original_package_dir=package_dir,
            workspace_dir=workspace_dir,
            package_json=package_json,
            detection_state=detection_state,
        )

        status = package.analyse(dynamic_support)
        statuses.add(status)

    except PackageJsonNotFoundException:
        # the package is not exist
        logger.error("Package.json is not exist")
        statuses.add(STATUS_PACKAGE_JSON_NOT_EXIST)
    except PackageJsonReadException as e:
        # package.json cannot be read or parsed; stop before later stages
        logger.error(f"Package.json read error: {e}")
        statuses.add(STATUS_PACKAGE_JSON_READ_ERROR)
    except GraphReadingException as e:
        logger.error(f"Joern dot reading Error: {e}")
        statuses.add(STATUS_JOERN_ERROR)
    except ConnectionError:
        logger.error("GPT Connection error")
        statuses.add(STATUS_LLM_ERROR)
    except NoEntryScriptException:
        # the package has no entry script
        statuses.add(STATUS_BENIGN)
    except JoernGenerationException as e:
        # the file path of cpg and pdg is wrong
        logger.error(f"Joern parsing Error: {e}")
        statuses.add(STATUS_JOERN_ERROR)
    except subprocess.TimeoutExpired as e:
        # joern time out
        logger.error(f"Subprocess Time Out: {e}")
        statuses.add(STATUS_JOERN_ERROR)
    except TimeoutError:
        # program time out
        logger.error("Time Out")
        statuses.add(STATUS_TIMEOUT)
    except KeyboardInterrupt:
        statuses.add(STATUS_BENIGN)
    except Exception as e:
        traceback_info = traceback.format_exc()
        logger.error("Exception occurred:")
        logger.error(e)
        logger.error(traceback_info)
        statuses.add(STATUS_PROGRAM_ERROR)

    if report.is_maliciousness_in_package_json():
        statuses.add(STATUS_PKG_JSON_MALICIOUS)

    if detection_state is not None:
        latest_by_entry: dict[str, AnalysisStep] = {}
        for step in detection_state.history:
            if step.entry is None:
                continue
            latest_by_entry[step.entry] = step
        for entry, step in latest_by_entry.items():
            report.add_entry_final_verdict(
                entry=entry,
                stage=step.stage,
                result=step.result,
                finding=step.finding,
            )

    status_list = list(statuses)
    report.set_overall_statuses([str(s) for s in status_list])

    try:
        report_path = os.path.join(workspace_dir, package_name, "report.json")
        report.write_json(report_path)
        logger.info(f"[Report] Wrote package report to {report_path}")
    except Exception as e:
        logger.warning(f"[Report] Failed to write report JSON: {e}")

    return status_list
