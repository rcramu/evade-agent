"""document-assistant five-cell pilot. Writes evadeagent-eval-v4-pilot JSON.

Does not overwrite evaluation/results/approach_comparison.json.
Products are not executed.
"""

from __future__ import annotations

import platform
import resource
from datetime import datetime, timezone

from evadeagent.detectors import detect
from pathlib import Path

from evadeagent.kernel_lab.collect import load_cell_dir, load_manifest
from evadeagent.kernel_lab.agent_cells import (
    ENCODING_KIND,
    EXPECTED,
    PILOT_AGENTS,
    context_for,
    observations_for,
)
from evadeagent.kernel_lab.document_assistant import AGENT
from evadeagent.lab import build_trace
from evadeagent.models import DetectorMode
from evadeagent.observe import SCHEMA, assemble_trace

PILOT_CELLS = ("L1", "M1", "A6", "A8", "A9")
MODES = (DetectorMode.B4, DetectorMode.B5, DetectorMode.C5)
PILOT_SCHEMA = "evadeagent-eval-v4-pilot"


def run_pilot(dump_dir: Path | None = None, *, agent: str = AGENT) -> dict:
    started = datetime.now(timezone.utc).isoformat()
    cells: dict[str, dict] = {}
    mismatches: list[str] = []
    encoding_disagreements: list[dict[str, str]] = []
    manifest = load_manifest(dump_dir) if dump_dir is not None else {
        "products_executed": False,
        "source": "in-memory Falco-like and Tetragon-like event-shape fixtures",
    }
    products_executed = bool(manifest.get("products_executed"))
    source = str(manifest.get("source", dump_dir or "in-memory fixtures"))

    for cell in PILOT_CELLS:
        run_id = f"{agent}-{cell}"
        if dump_dir is not None:
            events = load_cell_dir(dump_dir / cell, run_id)
        else:
            events = observations_for(agent, cell, run_id)
        assembled = assemble_trace(context_for(agent, cell, run_id), events)
        shape_decisions = {mode.value: detect(mode, assembled.trace).name for mode in MODES}
        encoding = build_trace(agent, ENCODING_KIND[cell])
        encoding_decisions = {mode.value: detect(mode, encoding).name for mode in MODES}
        expected = EXPECTED[cell]
        row = {
            "shape": shape_decisions,
            "encoding": encoding_decisions,
            "expected": {key: expected[key] for key in ("B4", "B5", "C5")},
            "capture": {
                "emitted": assembled.capture.emitted,
                "seen": assembled.capture.seen,
                "missing": list(assembled.capture.missing),
                "complete": assembled.capture.complete,
            },
            "expected_capture_complete": expected["capture_complete"],
        }
        cells[cell] = row
        for mode in ("B4", "B5", "C5"):
            if shape_decisions[mode] != expected[mode]:
                mismatches.append(f"{cell}.{mode}: {shape_decisions[mode]} != {expected[mode]}")
            if shape_decisions[mode] != encoding_decisions[mode]:
                encoding_disagreements.append(
                    {
                        "cell": cell,
                        "mode": mode,
                        "shape": shape_decisions[mode],
                        "encoding": encoding_decisions[mode],
                    }
                )
        if assembled.capture.complete != expected["capture_complete"]:
            mismatches.append(f"{cell}.capture_complete")

    usage = resource.getrusage(resource.RUSAGE_SELF)
    return {
        "schema": PILOT_SCHEMA,
        "adapter_schema": SCHEMA,
        "generated_utc": started,
        "products_executed": products_executed,
        "falco_executed": bool(manifest.get("falco_executed")),
        "tetragon_executed": bool(manifest.get("tetragon_executed")),
        "mcp_executed": bool(manifest.get("mcp_executed")),
        "observer_executed": bool(manifest.get("observer_executed")),
        "tls_version": manifest.get("tls_version"),
        "source": source,
        "dump_dir": str(dump_dir) if dump_dir is not None else None,
        "agent": agent,
        "cells": cells,
        "mismatches": mismatches,
        "encoding_disagreements": encoding_disagreements,
        "note": (
            "Do not copy these cells into manuscript Section 8. "
            "Do not overwrite approach_comparison.json. "
            "products_executed is true only when both Falco and Tetragon ran."
        ),
        "host": {
            "system": platform.system(),
            "release": platform.release(),
            "machine": platform.machine(),
            "python": platform.python_version(),
            "cpu_seconds": usage.ru_utime + usage.ru_stime,
            "peak_rss_mib": usage.ru_maxrss / (1024 * 1024 if platform.system() == "Darwin" else 1024),
        },
    }
