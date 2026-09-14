"""Lab-side operational metrics. This is not a field SLO.

Writes evaluation/results/lab_slo.json with field_executed=false unless
EVADE_FIELD_LOG points at a production export (never committed).
"""

from __future__ import annotations

import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
if str(_ROOT / "src") not in sys.path:
    sys.path.insert(0, str(_ROOT / "src"))

def main() -> int:
    pilot_path = _ROOT / "evaluation" / "results" / "kernel_pilot.json"
    if not pilot_path.is_file():
        print("kernel_pilot.json missing; run evaluation/run_kernel_pilot.py first", file=sys.stderr)
        return 1
    pilot = json.loads(pilot_path.read_text(encoding="utf-8"))
    cells = list(pilot.get("cells") or {})
    complete = sum(1 for cell in cells if (pilot["cells"][cell].get("capture") or {}).get("complete"))
    field_log = os.environ.get("EVADE_FIELD_LOG", "")
    field_executed = bool(field_log) and Path(field_log).is_file()
    host = dict(pilot.get("host") or {})
    cpu = float(host.get("cpu_seconds") or 0.0)
    payload = {
        "schema": "evadeagent-eval-v5-lab",
        "generated_utc": datetime.now(timezone.utc).isoformat(),
        "field_executed": field_executed,
        "source": "kernel_pilot operational metrics" if not field_executed else field_log,
        "note": (
            "Field SLO needs a production platform and is not claimed. "
            "These numbers are lab-side: five-cell detect + capture completeness."
        ),
        "lab": {
            "cells": len(cells),
            "capture_complete": complete,
            "capture_complete_rate": (complete / len(cells)) if cells else 0.0,
            "cpu_seconds": cpu,
            "peak_rss_mib": host.get("peak_rss_mib"),
            "products_executed": pilot.get("products_executed"),
            "mcp_executed": pilot.get("mcp_executed"),
            "observer_executed": pilot.get("observer_executed"),
            "tls_version": pilot.get("tls_version"),
            "mismatches": pilot.get("mismatches") or [],
        },
    }
    agents_path = _ROOT / "evaluation" / "results" / "kernel_pilot_agents.json"
    if agents_path.is_file():
        agents_src = json.loads(agents_path.read_text(encoding="utf-8"))
        agent_rows: dict = {}
        for name, row in (agents_src.get("agents") or {}).items():
            agent_rows[name] = {
                "products_executed": row.get("products_executed"),
                "mismatches": row.get("mismatches") or [],
                "cells": {
                    cell: {
                        "B4": (item.get("shape") or {}).get("B4"),
                        "B5": (item.get("shape") or {}).get("B5"),
                        "C5": (item.get("shape") or {}).get("C5"),
                        "emitted": (item.get("capture") or {}).get("emitted"),
                        "seen": (item.get("capture") or {}).get("seen"),
                        "complete": (item.get("capture") or {}).get("complete"),
                    }
                    for cell, item in (row.get("cells") or {}).items()
                },
            }
        payload["agents"] = agent_rows
        payload["lab"]["agent_count"] = len(agent_rows)
        payload["lab"]["agent_mismatches"] = agents_src.get("mismatches") or []
    tetra = _ROOT / "kernel-lab" / "dumps" / "live-tetragon" / "tetragon.jsonl"
    falco = _ROOT / "kernel-lab" / "dumps" / "live-m1" / "falco.jsonl"
    falco_agents = _ROOT / "kernel-lab" / "dumps" / "live-m1" / "agents"
    sinks = _ROOT / "kernel-lab" / "dumps" / "live-sinks" / "falco.jsonl"
    a8 = _ROOT / "kernel-lab" / "dumps" / "live-a8" / "falco.jsonl"
    payload["lab"]["tetragon_process_exec"] = (
        sum(1 for line in tetra.read_text(encoding="utf-8").splitlines() if line.strip())
        if tetra.is_file()
        else 0
    )
    per_agent = 0
    if falco_agents.is_dir():
        for path in falco_agents.glob("*/falco.jsonl"):
            per_agent += sum(1 for line in path.read_text(encoding="utf-8").splitlines() if line.strip())
    payload["lab"]["falco_alerts"] = per_agent or (
        sum(1 for line in falco.read_text(encoding="utf-8").splitlines() if line.strip())
        if falco.is_file()
        else 0
    )
    payload["lab"]["falco_agent_files"] = per_agent
    payload["lab"]["sink_process_alerts"] = (
        sum(1 for line in sinks.read_text(encoding="utf-8").splitlines() if line.strip())
        if sinks.is_file()
        else 0
    )
    payload["lab"]["a8_product_path_alerts"] = 0
    if a8.is_file():
        payload["lab"]["a8_product_path_alerts"] = sum(
            1
            for line in a8.read_text(encoding="utf-8").splitlines()
            if line.strip() and json.loads(line).get("rule") == "EVADE Lab Sensitive Path"
        )
    payload["lab"]["falco_executed"] = pilot.get("falco_executed")
    payload["lab"]["tetragon_executed"] = pilot.get("tetragon_executed")
    out = _ROOT / "evaluation" / "results" / "lab_slo.json"
    out.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    print(f"wrote {out} field_executed={field_executed} capture_complete={complete}/{len(cells)}")
    return 0 if not (pilot.get("mismatches")) else 1


if __name__ == "__main__":
    raise SystemExit(main())
