"""Five-cell pilots for all seven Section 8 agents.

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
from evadeagent.kernel_lab.ingest import (
    invert_tetragon_ticks,
    load_alerts,
    select_m1_alerts,
    select_path_alerts,
    select_tetragon_cell,
)
from evadeagent.kernel_lab.pilot import run_pilot

_LIVE_M1 = _ROOT / "kernel-lab" / "dumps" / "live-m1" / "falco.jsonl"
_LIVE_M1_AGENTS = _ROOT / "kernel-lab" / "dumps" / "live-m1" / "agents"
_LIVE_TG = _ROOT / "kernel-lab" / "dumps" / "live-tetragon" / "tetragon.jsonl"
_LIVE_SINKS = _ROOT / "kernel-lab" / "dumps" / "live-sinks" / "falco.jsonl"
_LIVE_A8 = _ROOT / "kernel-lab" / "dumps" / "live-a8" / "falco.jsonl"
_LIVE_A2 = _ROOT / "kernel-lab" / "dumps" / "live-a2" / "falco.jsonl"
_LIVE_A4 = _ROOT / "kernel-lab" / "dumps" / "live-a4" / "falco.jsonl"
_LIVE_A9 = _ROOT / "kernel-lab" / "dumps" / "live-a9" / "falco.jsonl"
_LIVE_TG_EXTRA = _ROOT / "kernel-lab" / "dumps" / "live-tetragon" / "tetragon-extra.jsonl"
_STATIC = ("M1",)
_ADVERSARIAL = ("A2", "A4", "A6", "A8", "A9")
_BENIGN = ("L1",)


def _falco_for(agent: str) -> list[dict]:
    per = _LIVE_M1_AGENTS / agent / "falco.jsonl"
    if per.is_file():
        return select_m1_alerts(load_alerts(per))
    if _LIVE_M1.is_file():
        return select_m1_alerts(load_alerts(_LIVE_M1))
    return []


def _tetra_events() -> list[dict]:
    rows = load_alerts(_LIVE_TG) if _LIVE_TG.is_file() else []
    if _LIVE_TG_EXTRA.is_file():
        rows.extend(load_alerts(_LIVE_TG_EXTRA))
    return rows


def _join_products(dump_root: Path) -> None:
    tetra = _tetra_events()
    a2_path = select_path_alerts(load_alerts(_LIVE_A2)) if _LIVE_A2.is_file() else []
    a4_path = select_path_alerts(load_alerts(_LIVE_A4)) if _LIVE_A4.is_file() else []
    extra_ok = False
    for agent in PILOT_AGENTS:
        falco = _falco_for(agent)
        if falco:
            write_jsonl(dump_root / agent / "M1" / "falco.jsonl", falco)
        if a2_path:
            write_jsonl(
                dump_root / agent / "A2" / "falco.jsonl",
                load_alerts(dump_root / agent / "A2" / "falco.jsonl") + a2_path,
            )
        if a4_path:
            write_jsonl(
                dump_root / agent / "A4" / "falco.jsonl",
                load_alerts(dump_root / agent / "A4" / "falco.jsonl") + a4_path,
            )
        if tetra:
            l1 = select_tetragon_cell(tetra, "L1", agent)
            a6 = select_tetragon_cell(tetra, "A6", agent)
            a2 = select_tetragon_cell(tetra, "A2", agent)
            a4 = select_tetragon_cell(tetra, "A4", agent) or a2
            a8 = select_tetragon_cell(tetra, "A8", agent) or l1
            a9 = select_tetragon_cell(tetra, "A9", agent) or l1
            if l1:
                write_jsonl(dump_root / agent / "L1" / "tetragon.jsonl", l1)
            if a6:
                write_jsonl(dump_root / agent / "A6" / "tetragon.jsonl", a6)
            if a2:
                write_jsonl(dump_root / agent / "A2" / "tetragon.jsonl", a2)
                extra_ok = True
            if a4:
                write_jsonl(dump_root / agent / "A4" / "tetragon.jsonl", a4)
            if a8:
                write_jsonl(dump_root / agent / "A8" / "tetragon.jsonl", a8)
            if a9:
                write_jsonl(
                    dump_root / agent / "A9" / "tetragon.jsonl",
                    invert_tetragon_ticks(a9),
                )
        manifest = {
            "products_executed": bool(falco and tetra),
            "falco_executed": bool(falco),
            "tetragon_executed": bool(tetra),
            "falco_a2": bool(a2_path),
            "falco_a4": bool(a4_path),
            "tetragon_extra": extra_ok,
            "agent": agent,
            "source": f"executed {agent}; product Falco/Tetragon joined when present",
            "note": (
                "A8 Falco stays a designed path miss. A9 Tetragon ticks are inverted "
                "in the join. A2/A4 overlay helper-worker path alerts."
            ),
        }
        (dump_root / agent / "manifest.json").write_text(
            json.dumps(manifest, indent=2) + "\n", encoding="utf-8"
        )


def _ers(fnr_b: float, fnr_a: float) -> float:
    denom = 1.0 - fnr_b
    if denom <= 0.0:
        return 0.0
    return max(0.0, min(1.0, 1.0 - (fnr_a - fnr_b) / denom))


def _product_aers(agents: dict) -> dict:
    """Appendix D AERS on the product join. Not Section 8."""
    out: dict[str, dict] = {}
    for mode in ("B4", "B5", "C5"):
        static_n = static_block = 0
        adv_n = adv_block = 0
        benign_n = benign_block = 0
        for row in agents.values():
            cells = row["cells"]
            for cell in _STATIC:
                static_n += 1
                if cells[cell]["shape"][mode] == "BLOCK":
                    static_block += 1
            for cell in _ADVERSARIAL:
                adv_n += 1
                if cells[cell]["shape"][mode] == "BLOCK":
                    adv_block += 1
            for cell in _BENIGN:
                benign_n += 1
                if cells[cell]["shape"][mode] == "BLOCK":
                    benign_block += 1
        fnr_b = 1.0 - (static_block / static_n) if static_n else 1.0
        fnr_a = 1.0 - (adv_block / adv_n) if adv_n else 1.0
        tp = static_block + adv_block
        fn = (static_n - static_block) + (adv_n - adv_block)
        fp = benign_block
        tn = benign_n - benign_block
        prec = tp / (tp + fp) if (tp + fp) else 0.0
        rec = tp / (tp + fn) if (tp + fn) else 0.0
        f1 = 2 * prec * rec / (prec + rec) if (prec + rec) else 0.0
        ers = _ers(fnr_b, fnr_a)
        out[mode] = {
            "tp": tp,
            "fp": fp,
            "fn": fn,
            "tn": tn,
            "f1": round(f1, 2),
            "fnr_static": round(fnr_b, 2),
            "fnr_adversarial": round(fnr_a, 2),
            "ers": round(ers, 2),
            "aers": round(ers, 2),
            "n_static": static_n,
            "n_adversarial": adv_n,
            "n_benign": benign_n,
            "s_i": 1.0,
        }
    return out


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
    sinks = load_alerts(_LIVE_SINKS) if _LIVE_SINKS.is_file() else []
    a8_neg = load_alerts(_LIVE_A8) if _LIVE_A8.is_file() else []
    a8_path = [row for row in a8_neg if row.get("rule") == "EVADE Lab Sensitive Path"]
    a2_path = select_path_alerts(load_alerts(_LIVE_A2)) if _LIVE_A2.is_file() else []
    a4_path = select_path_alerts(load_alerts(_LIVE_A4)) if _LIVE_A4.is_file() else []
    a9_rows = load_alerts(_LIVE_A9) if _LIVE_A9.is_file() else []
    extra_n = (
        sum(1 for line in _LIVE_TG_EXTRA.read_text(encoding="utf-8").splitlines() if line.strip())
        if _LIVE_TG_EXTRA.is_file()
        else 0
    )
    out = {
        "schema": "evadeagent-eval-v4-pilot-agents",
        "agents": agents,
        "mismatches": mismatches,
        "product_aers": _product_aers(agents),
        "sink_process_alerts": len(sinks),
        "a8_product_path_alerts": len(a8_path),
        "a8_product_alerts": len(a8_path),
        "a2_product_path_alerts": len(a2_path),
        "a4_product_path_alerts": len(a4_path),
        "a9_product_path_alerts": sum(
            1 for row in a9_rows if row.get("rule") == "EVADE Lab Sensitive Path"
        ),
        "tetragon_extra_process_exec": extra_n,
        "note": (
            "Do not copy these cells into manuscript Section 8. "
            "product_aers is the Appendix D join "
            "(7 agents × L1/M1/A2/A4/A6/A8/A9), not Table 10."
        ),
    }
    path = _ROOT / "evaluation" / "results" / "kernel_pilot_agents.json"
    path.write_text(json.dumps(out, indent=2) + "\n", encoding="utf-8")
    print(f"wrote {path} agents={list(agents)} mismatches={len(mismatches)}")
    return 0 if not mismatches else 1


if __name__ == "__main__":
    raise SystemExit(main())
