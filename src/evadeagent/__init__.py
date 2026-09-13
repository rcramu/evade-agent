"""EVADE-AGENT laboratory: cross-layer runtime assurance for agentic software."""

from evadeagent.detectors import detect
from evadeagent.lab import build_trace, decide
from evadeagent.models import Decision, DetectorMode, ExecutionTrace, Label

__all__ = [
    "Decision",
    "DetectorMode",
    "ExecutionTrace",
    "Label",
    "build_trace",
    "decide",
    "detect",
]
