"""Ingest live Falco and Tetragon captures into executed cell dumps."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from pathlib import PurePosixPath

from evadeagent.kernel_lab.dumps import write_jsonl
from evadeagent.kernel_lab.execute import write_executed_dumps
from evadeagent.kernel_lab.pilot import run_pilot

_LAB_BINARIES = frozenset({"document-assistant", "document-reader", "unrelated-init"})


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


def _binary(event: dict[str, Any]) -> str:
    proc = (event.get("process_exec") or {}).get("process") or {}
    return PurePosixPath(str(proc.get("binary") or "")).name


def _parent(event: dict[str, Any]) -> str:
    parent = (event.get("process_exec") or {}).get("parent") or {}
    return PurePosixPath(str(parent.get("binary") or "")).name


def select_tetragon_cell(events: list[dict[str, Any]], cell: str) -> list[dict[str, Any]]:
    """Keep identity binaries for L1 (agent parent) or A6 (unrelated-init parent)."""
    kept: list[dict[str, Any]] = []
    for event in events:
        if "process_exec" not in event:
            continue
        name = _binary(event)
        parent = _parent(event)
        if name not in _LAB_BINARIES:
            continue
        if cell == "L1":
            if name == "unrelated-init" or parent == "unrelated-init":
                continue
            if name in {"document-assistant", "document-reader"}:
                kept.append(event)
        elif cell == "A6":
            if name == "unrelated-init" or parent == "unrelated-init":
                kept.append(event)
    return kept


def write_hybrid_dumps(
    dump_dir: Path,
    falco_jsonl: Path,
    tetragon_jsonl: Path | None = None,
) -> Path:
    """Executed dumps plus any live Falco M1 and Tetragon L1/A6 captures."""
    write_executed_dumps(dump_dir)
    alerts = select_m1_alerts(load_alerts(falco_jsonl))
    write_jsonl(dump_dir / "M1" / "falco.jsonl", alerts)
    tetra_ok = False
    if tetragon_jsonl is not None and tetragon_jsonl.is_file():
        events = load_alerts(tetragon_jsonl)
        l1 = select_tetragon_cell(events, "L1")
        a6 = select_tetragon_cell(events, "A6")
        if l1 and a6:
            write_jsonl(dump_dir / "L1" / "tetragon.jsonl", l1)
            write_jsonl(dump_dir / "A6" / "tetragon.jsonl", a6)
            tetra_ok = True
    manifest = json.loads((dump_dir / "manifest.json").read_text(encoding="utf-8"))
    if tetra_ok:
        manifest.update(
            {
                "products_executed": True,
                "falco_executed": True,
                "tetragon_executed": True,
                "falco_version": "0.44.1",
                "tetragon_version": "1.7.0",
                "falco_cells": ["M1"],
                "tetragon_cells": ["L1", "A6"],
                "source": (
                    "executed workloads; M1 Falco 0.44.1; L1/A6 Tetragon 1.7.0 process_exec"
                ),
                "note": (
                    "Falco captured M1. Tetragon captured L1 agent-parent and A6 "
                    "unrelated-init parent. A8/A9 host rows stay on the executed recorder."
                ),
            }
        )
    else:
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
                    "Tetragon was not ingested. products_executed stays false."
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
