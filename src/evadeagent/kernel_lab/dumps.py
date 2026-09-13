"""Write bundled event-shape dumps. Not a product capture."""

from __future__ import annotations

import json
from pathlib import Path

from evadeagent.kernel_lab.document_assistant import AGENT, records_for
from evadeagent.kernel_lab.pilot import PILOT_CELLS

BUNDLED_SOURCE = "bundled Falco-like / Tetragon-like / MCP-audit fixtures"


def write_jsonl(path: Path, rows: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    body = "".join(json.dumps(row, separators=(",", ":")) + "\n" for row in rows)
    path.write_text(body, encoding="utf-8")


def write_bundled_dumps(dump_dir: Path) -> Path:
    dump_dir.mkdir(parents=True, exist_ok=True)
    for cell in PILOT_CELLS:
        falco, tetra, mcp = records_for(cell)
        cell_dir = dump_dir / cell
        write_jsonl(cell_dir / "falco.jsonl", falco)
        write_jsonl(cell_dir / "tetragon.jsonl", tetra)
        write_jsonl(cell_dir / "mcp.jsonl", mcp)
    manifest = {
        "products_executed": False,
        "agent": AGENT,
        "cells": list(PILOT_CELLS),
        "source": BUNDLED_SOURCE,
        "note": (
            "Replace this directory with a live collector dump and set "
            "products_executed true only after Falco and Tetragon actually ran."
        ),
    }
    (dump_dir / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    return dump_dir
