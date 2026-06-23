"""Shared dataclass / Literal type definitions for the npm_pipeline layer."""

from npm_pipeline.types.classification import ClassifiedNodes
from npm_pipeline.types.component import ComponentResult
from npm_pipeline.types.dynamic_context import DynamicContext
from npm_pipeline.types.stage import Stage, StepResult
from npm_pipeline.types.synthesis import SynthesisOutcome

__all__ = [
    "ClassifiedNodes",
    "ComponentResult",
    "DynamicContext",
    "Stage",
    "StepResult",
    "SynthesisOutcome",
]
