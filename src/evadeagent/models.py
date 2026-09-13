"""Typed lab objects. No credentials, tokens, or certificate material."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import FrozenSet


class Label(str, Enum):
    BENIGN = "benign"
    BENIGN_VARIANT = "benign_variant"
    MALICIOUS = "malicious"
    ADVERSARIAL = "adversarial"
    CROSS_LAYER = "cross_layer"


class Decision(str, Enum):
    ALLOW = "allow"
    BLOCK = "block"


class DetectorMode(str, Enum):
    B1 = "B1"
    B2 = "B2"
    B3 = "B3"
    B4 = "B4"
    B5 = "B5"
    C1 = "C1"
    C2 = "C2"
    C3 = "C3"
    C4 = "C4"
    C5 = "C5"


@dataclass(frozen=True)
class RuntimeContract:
    agent: str
    allowed_intents: FrozenSet[str]
    allowed_tools: FrozenSet[str]
    allowed_mcp: FrozenSet[str]
    allowed_processes: FrozenSet[str]
    allowed_files: FrozenSet[str]
    allowed_endpoints: FrozenSet[str]
    allow_shell: bool = False
    allow_credential: bool = False
    allow_privilege_change: bool = False


@dataclass
class ExecutionTrace:
    agent: str
    intent: str
    plan: tuple[str, ...]
    tools: tuple[str, ...]
    mcp: tuple[str, ...]
    processes: tuple[str, ...]
    files: tuple[str, ...]
    endpoints: tuple[str, ...]
    timestamps: tuple[int, ...]
    ancestry: tuple[str, ...]
    container: str
    identity: str
    task_completed: bool
    shell: bool = False
    credential: bool = False
    privilege_change: bool = False
    extras: dict[str, str] = field(default_factory=dict)

    def semantic_similarity(self, other: "ExecutionTrace") -> float:
        if self.intent == other.intent and self.task_completed == other.task_completed:
            return 1.0
        a = set(self.intent.lower().split("_"))
        b = set(other.intent.lower().split("_"))
        if not a or not b:
            return 0.0
        return len(a & b) / len(a | b)
