import json
import os


class Report:
    def __init__(self):
        self.maliciousness_in_package_json = False
        self.install_time_script: list[dict] = []
        self.entry_final_verdicts: list[dict] = []
        self.package_name: str | None = None
        self.overall_statuses: list[str] = []

    def add_install_time_script(self, script_name, script_content, label, explanation):
        self.install_time_script.append(
            {
                "name": script_name,
                "content": script_content,
                "label": label,
                "explanation": explanation,
            }
        )

    def set_maliciousness_in_package_json(self):
        self.maliciousness_in_package_json = True

    def is_maliciousness_in_package_json(self):
        return self.maliciousness_in_package_json

    def add_entry_final_verdict(self, entry: str, stage: str, result: str, finding: str):
        self.entry_final_verdicts.append(
            {
                "entry": entry,
                "stage": stage,
                "result": result,
                "finding": finding,
            }
        )

    def get_entry_final_verdicts(self) -> list[dict]:
        return self.entry_final_verdicts

    def set_package_name(self, package_name: str) -> None:
        self.package_name = package_name

    def set_overall_statuses(self, statuses: list[str]) -> None:
        self.overall_statuses = list(statuses)

    def to_dict(self) -> dict:
        return {
            "package_name": self.package_name,
            "maliciousness_in_package_json": self.maliciousness_in_package_json,
            "install_time_script": self.install_time_script,
            "entry_final_verdicts": self.entry_final_verdicts,
            "overall_statuses": self.overall_statuses,
        }

    def write_json(self, output_path: str) -> None:
        """Dump the report to *output_path* as indented JSON (utf-8)."""
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(self.to_dict(), f, ensure_ascii=False, indent=2)
