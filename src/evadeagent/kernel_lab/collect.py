"""Load a cell dump directory into Observation records.

Expected layout (one directory per cell):

    <dump>/manifest.json
    <dump>/L1/falco.jsonl
    <dump>/L1/tetragon.jsonl
    <dump>/L1/mcp.jsonl

`products_executed` is read only from the manifest. Presence of files is not
enough to claim Falco or Tetragon ran.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from evadeagent.kernel_lab.shapes import (
    falco_alerts_to_observations,
    mcp_audit_to_observations,
    tetragon_events_to_observations,
)
from evadeagent.observe import Observation

MANIFEST_NAME = "manifest.json"


def load_jsonl(path: Path) -> list[dict[str, Any]]:
    if not path.is_file():
        return []
    rows: list[dict[str, Any]] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        text = line.strip()
        if not text:
            continue
        rows.append(json.loads(text))
    return rows


def load_manifest(dump_dir: Path) -> dict[str, Any]:
    path = dump_dir / MANIFEST_NAME
    if not path.is_file():
        return {
            "products_executed": False,
            "source": f"dump directory {dump_dir} (no manifest)",
        }
    data = json.loads(path.read_text(encoding="utf-8"))
    data.setdefault("products_executed", False)
    return data


def load_cell_dir(cell_dir: Path, run_id: str) -> list[Observation]:
    falco = load_jsonl(cell_dir / "falco.jsonl")
    tetra = load_jsonl(cell_dir / "tetragon.jsonl")
    mcp = load_jsonl(cell_dir / "mcp.jsonl")
    return (
        falco_alerts_to_observations(falco, run_id=run_id)
        + tetragon_events_to_observations(tetra, run_id=run_id)
        + mcp_audit_to_observations(mcp, run_id=run_id)
    )
