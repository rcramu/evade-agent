"""Lab-side operational metrics. This is not a field SLO.

Writes evaluation/results/lab_slo.json with field_executed=false unless
EVADE_FIELD_LOG points at a production export (never committed).
"""

from __future__ import annotations

import json
import sys
from datetime import datetime, timezone
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
if str(_ROOT / "src") not in sys.path:
    sys.path.insert(0, str(_ROOT / "src"))

from evadeagent.kernel_lab.field import apply_field_slo

def main() -> int:
    pilot_path = _ROOT / "evaluation" / "results" / "kernel_pilot.json"
    if not pilot_path.is_file():
        print("kernel_pilot.json missing; run evaluation/run_kernel_pilot.py first", file=sys.stderr)
        return 1
    pilot = json.loads(pilot_path.read_text(encoding="utf-8"))
    cells = list(pilot.get("cells") or {})
    complete = sum(1 for cell in cells if (pilot["cells"][cell].get("capture") or {}).get("complete"))
    host = dict(pilot.get("host") or {})
    cpu = float(host.get("cpu_seconds") or 0.0)
    payload = {
        "schema": "evadeagent-eval-v5-lab",
        "generated_utc": datetime.now(timezone.utc).isoformat(),
        "field_executed": False,
        "source": "kernel_pilot operational metrics",
        "note": (
            "Field SLO is imported only when EVADE_FIELD_LOG points at a "
            "production export. These numbers are lab-side detect + capture."
        ),
        "lab": {
            "cells": len(cells),
            "capture_complete": complete,
            "capture_complete_rate": (complete / len(cells)) if cells else 0.0,
            "cpu_seconds": cpu,
            "peak_rss_mib": host.get("peak_rss_mib"),
            "products_executed": pilot.get("products_executed"),
            "mcp_executed": bool(pilot.get("mcp_executed"))
            or (_ROOT / "kernel-lab" / "dumps" / "live-mcp" / "mcp-live.jsonl").is_file(),
            "observer_executed": bool(pilot.get("observer_executed"))
            or (_ROOT / "kernel-lab" / "dumps" / "live-mcp" / "observer.jsonl").is_file(),
            "tls_version": pilot.get("tls_version") or "TLSv1.3",
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
    a2 = _ROOT / "kernel-lab" / "dumps" / "live-a2" / "falco.jsonl"
    a4 = _ROOT / "kernel-lab" / "dumps" / "live-a4" / "falco.jsonl"
    a9 = _ROOT / "kernel-lab" / "dumps" / "live-a9" / "falco.jsonl"
    tetra_extra = _ROOT / "kernel-lab" / "dumps" / "live-tetragon" / "tetragon-extra.jsonl"
    payload["lab"]["a2_product_path_alerts"] = (
        sum(1 for line in a2.read_text(encoding="utf-8").splitlines() if line.strip())
        if a2.is_file()
        else 0
    )
    payload["lab"]["a4_product_path_alerts"] = (
        sum(1 for line in a4.read_text(encoding="utf-8").splitlines() if line.strip())
        if a4.is_file()
        else 0
    )
    payload["lab"]["a9_product_alerts"] = (
        sum(1 for line in a9.read_text(encoding="utf-8").splitlines() if line.strip())
        if a9.is_file()
        else 0
    )
    payload["lab"]["tetragon_extra_process_exec"] = (
        sum(1 for line in tetra_extra.read_text(encoding="utf-8").splitlines() if line.strip())
        if tetra_extra.is_file()
        else 0
    )
    payload["lab"]["falco_executed"] = pilot.get("falco_executed")
    payload["lab"]["tetragon_executed"] = pilot.get("tetragon_executed")
    apply_field_slo(payload)
    out = _ROOT / "evaluation" / "results" / "lab_slo.json"
    out.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    print(
        f"wrote {out} field_executed={payload['field_executed']} "
        f"capture_complete={complete}/{len(cells)}"
    )
    return 0 if not (pilot.get("mismatches")) else 1


if __name__ == "__main__":
    raise SystemExit(main())
