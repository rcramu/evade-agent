"""Five-cell pilots for document-assistant, coding-agent, and devops-agent.

Does not overwrite approach_comparison.json or Section 8.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
if str(_ROOT / "src") not in sys.path:
    sys.path.insert(0, str(_ROOT / "src"))

from evadeagent.kernel_lab.agent_cells import PILOT_AGENTS
from evadeagent.kernel_lab.dumps import write_jsonl
from evadeagent.kernel_lab.execute import write_executed_agent_dumps
from evadeagent.kernel_lab.ingest import load_alerts, select_m1_alerts, select_tetragon_cell
from evadeagent.kernel_lab.pilot import run_pilot

_LIVE_M1 = _ROOT / "kernel-lab" / "dumps" / "live-m1" / "falco.jsonl"
_LIVE_TG = _ROOT / "kernel-lab" / "dumps" / "live-tetragon" / "tetragon.jsonl"


def _join_products(dump_root: Path) -> None:
    tetra = load_alerts(_LIVE_TG) if _LIVE_TG.is_file() else []
    falco = select_m1_alerts(load_alerts(_LIVE_M1)) if _LIVE_M1.is_file() else []
    for agent in PILOT_AGENTS:
        if falco:
            write_jsonl(dump_root / agent / "M1" / "falco.jsonl", falco)
        if tetra:
            l1 = select_tetragon_cell(tetra, "L1", agent)
            a6 = select_tetragon_cell(tetra, "A6", agent)
            if l1:
                write_jsonl(dump_root / agent / "L1" / "tetragon.jsonl", l1)
            if a6:
                write_jsonl(dump_root / agent / "A6" / "tetragon.jsonl", a6)
        manifest = {
            "products_executed": bool(falco and tetra),
            "falco_executed": bool(falco),
            "tetragon_executed": bool(tetra),
            "agent": agent,
            "source": f"executed {agent}; product Falco/Tetragon joined when present",
        }
        (dump_root / agent / "manifest.json").write_text(
            json.dumps(manifest, indent=2) + "\n", encoding="utf-8"
        )


def main() -> int:
    dump_root = _ROOT / "kernel-lab" / "dumps" / "agents"
    write_executed_agent_dumps(dump_root)
    _join_products(dump_root)
    agents: dict = {}
    mismatches: list[str] = []
    for agent in PILOT_AGENTS:
        payload = run_pilot(dump_root / agent, agent=agent)
        agents[agent] = {
            "cells": payload["cells"],
            "mismatches": payload["mismatches"],
            "encoding_disagreements": payload["encoding_disagreements"],
            "products_executed": payload["products_executed"],
        }
        mismatches.extend(f"{agent}.{item}" for item in payload["mismatches"])
    out = {
        "schema": "evadeagent-eval-v4-pilot-agents",
        "agents": agents,
        "mismatches": mismatches,
        "note": "Do not copy these cells into manuscript Section 8.",
    }
    path = _ROOT / "evaluation" / "results" / "kernel_pilot_agents.json"
    path.write_text(json.dumps(out, indent=2) + "\n", encoding="utf-8")
    print(f"wrote {path} agents={list(agents)} mismatches={len(mismatches)}")
    return 0 if not mismatches else 1


if __name__ == "__main__":
    raise SystemExit(main())
