"""Stage / StepResult — enumerations of pipeline stages and verdict labels."""

from typing import Literal

Stage = Literal[
    "install_script_analysis",
    "static",
    "static_fallback",
    "static_local_read",
    "third_party_info_enrichment",
    "dynamic",
    "dynamic_local_read",
]

StepResult = Literal["malicious", "benign", "undetermined", "warning"]
