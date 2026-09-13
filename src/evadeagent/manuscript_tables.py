"""Deterministic manuscript Tables 4 and 13. Used by evaluation/run.py."""

from __future__ import annotations

from evadeagent.contracts import AGENTS, contract_for
from evadeagent.detectors import detect
from evadeagent.graph import build_arbg
from evadeagent.lab import build_trace
from evadeagent.models import Decision, DetectorMode
from evadeagent.plans import PLAN_COUNT
from evadeagent.traces import ATTACK_IDS, SCENARIOS

WALK_AGENT = "document-assistant"
WALK_PLAN = 0
WALK_CELLS = ("L1", "M2", "A6", "A9", "A8")


def _scenario_kind(sid: str) -> str:
    for scenario_id, _label, kind in SCENARIOS:
        if scenario_id == sid:
            return kind
    raise KeyError(sid)


def alignment_walk(agent: str = WALK_AGENT, plan_id: int = WALK_PLAN) -> dict:
    """Manuscript Table 4. Does not use latency repeats."""
    rows = []
    contract = contract_for(agent)
    for sid in WALK_CELLS:
        trace = build_trace(agent, _scenario_kind(sid), plan_id=plan_id, scenario_id=sid)
        graph = build_arbg(trace, contract)
        rows.append(
            {
                "cell": sid,
                "unexpected_types": sorted(graph.unexpected_types),
                "alignment": round(graph.alignment, 2),
                "ancestry_ok": graph.ancestry_ok,
                "temporal_ok": graph.temporal_ok,
                "c5": detect(DetectorMode.C5, trace).name,
            }
        )
    return {"agent": agent, "plan_id": plan_id, "source": "build_arbg", "rows": rows}


def per_agent_c5() -> dict:
    """Manuscript Table 13. Does not use latency repeats."""
    agents: dict[str, dict] = {}
    for agent in AGENTS:
        blocked = 0
        residual: dict[str, int] = {}
        for sid in ATTACK_IDS:
            for plan_id in range(PLAN_COUNT):
                trace = build_trace(agent, _scenario_kind(sid), plan_id=plan_id, scenario_id=sid)
                if detect(DetectorMode.C5, trace) is Decision.BLOCK:
                    blocked += 1
                else:
                    residual[sid] = residual.get(sid, 0) + 1
        agents[agent] = {
            "blocked": blocked,
            "n": len(ATTACK_IDS) * PLAN_COUNT,
            "residual_allow": residual,
        }
    return {"attack_cells": list(ATTACK_IDS), "plan_count": PLAN_COUNT, "agents": agents}
