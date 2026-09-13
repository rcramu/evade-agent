"""Ingest a Falco JSONL capture into the M1 cell dump.

Keeps only evade-lab alerts from the container that touched /lab/secrets/token.
Does not set products_executed (Tetragon was not run).
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from evadeagent.kernel_lab.dumps import write_jsonl
from evadeagent.kernel_lab.execute import write_executed_dumps
from evadeagent.kernel_lab.pilot import run_pilot


def load_alerts(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.strip():
            rows.append(json.loads(line))
    return rows


def select_m1_alerts(alerts: list[dict[str, Any]]) -> list[dict[str, Any]]:
    path_hits = [
        row
        for row in alerts
        if (row.get("output_fields") or {}).get("fd.name", "").startswith("/lab/secrets")
    ]
    if not path_hits:
        return []
    container = (path_hits[0].get("output_fields") or {}).get("container.id")
    kept: list[dict[str, Any]] = []
    for row in alerts:
        if row.get("rule") not in {"EVADE Lab Shell", "EVADE Lab Sensitive Path"}:
            continue
        fields = dict(row.get("output_fields") or {})
        if container and fields.get("container.id") != container:
            continue
        lab: dict[str, Any] = {"t": _tick(fields.get("evt.time")), "seen": True}
        if row.get("rule") == "EVADE Lab Shell":
            lab["flags"] = ["shell"]
        kept.append({"output_fields": fields, "_lab": lab, "rule": row.get("rule")})
    return kept


def write_hybrid_dumps(dump_dir: Path, falco_jsonl: Path) -> Path:
    """Executed five-cell dumps, with M1 Falco JSONL replaced by a product capture."""
    write_executed_dumps(dump_dir)
    alerts = select_m1_alerts(load_alerts(falco_jsonl))
    write_jsonl(dump_dir / "M1" / "falco.jsonl", alerts)
    manifest = json.loads((dump_dir / "manifest.json").read_text(encoding="utf-8"))
    manifest.update(
        {
            "products_executed": False,
            "falco_executed": True,
            "tetragon_executed": False,
            "falco_version": "0.44.1",
            "falco_cells": ["M1"],
            "source": "executed workloads; M1 Falco 0.44.1 product alerts",
            "note": (
                "Falco modern BPF captured M1 shell + /lab/secrets on LinuxKit. "
                "Tetragon was not run. products_executed stays false."
            ),
        }
    )
    (dump_dir / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    return dump_dir


def _tick(raw: Any) -> int:
    try:
        return int(raw)
    except (TypeError, ValueError):
        return 0


def verify_hybrid(dump_dir: Path) -> dict:
    return run_pilot(dump_dir)
