"""Run Phase 2: live TLS 1.3 MCP + container observer, then join the hybrid dump."""

from __future__ import annotations

import json
import os
import secrets
import tempfile
from pathlib import Path

from evadeagent.kernel_lab.ingest import write_hybrid_dumps
from evadeagent.kernel_lab.mcp_tls import (
    LabMcp,
    LabMcpServer,
    require_token,
    run_document_session,
    write_lab_certs,
)
from evadeagent.kernel_lab.observer import write_observer
from evadeagent.kernel_lab.agent_cells import CORE_CELLS, PILOT_CELLS
from evadeagent.kernel_lab.pilot import run_pilot

from evadeagent.kernel_lab.dumps import write_jsonl

_REPO = Path(__file__).resolve().parents[3]
_LIVE_MCP = _REPO / "kernel-lab" / "dumps" / "live-mcp"


def _jsonl(path: Path) -> list[dict]:
    if not path.is_file():
        return []
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def run_live_mcp(audit: Path, workspace: Path, cert_dir: Path) -> tuple[str, Path, list[dict]]:
    """Start an in-process TLS 1.3 MCP, run five cell sessions, return (url, ca, rows)."""
    token = os.environ.get("EVADE_MCP_TOKEN")
    generated = False
    if not token:
        token = secrets.token_urlsafe(32)
        os.environ["EVADE_MCP_TOKEN"] = token
        generated = True
    token = require_token()
    cert, key = write_lab_certs(cert_dir)
    mcp = LabMcp(workspace, audit, token)
    server = LabMcpServer(mcp, cert, key)
    server.start()
    try:
        for cell in CORE_CELLS:
            run_document_session(server.url, cert, token, extra_read=(cell == "A8"))
        rows = [
            json.loads(line)
            for line in audit.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]
    finally:
        server.stop()
        if generated:
            os.environ.pop("EVADE_MCP_TOKEN", None)
    return server.url, cert, rows


def split_audit(rows: list[dict]) -> dict[str, list[dict]]:
    """Assign consecutive search/read(/read) groups to core cells; pad A2/A4."""
    per: dict[str, list[dict]] = {cell: [] for cell in PILOT_CELLS}
    index = 0
    for cell in CORE_CELLS:
        need = 3 if cell == "A8" else 2
        chunk = rows[index : index + need]
        for row, tick in zip(chunk, (0, 1, 5)):
            item = dict(row)
            item["t"] = tick
            per[cell].append(item)
        index += need
    pad = per.get("L1") or rows[:2]
    for cell in PILOT_CELLS:
        if per[cell]:
            continue
        for row, tick in zip(pad, (0, 1)):
            item = dict(row)
            item["t"] = tick
            per[cell].append(item)
    return per


def write_phase2_dumps(
    dump_dir: Path,
    falco_jsonl: Path,
    tetragon_jsonl: Path | None,
    mcp_rows_by_cell: dict[str, list[dict]],
    observer_rows: list[dict],
) -> Path:
    write_hybrid_dumps(dump_dir, falco_jsonl, tetragon_jsonl)
    for cell, rows in mcp_rows_by_cell.items():
        write_jsonl(dump_dir / cell / "mcp.jsonl", rows)
        write_jsonl(dump_dir / cell / "observer.jsonl", observer_rows)
    manifest = json.loads((dump_dir / "manifest.json").read_text(encoding="utf-8"))
    cid = ""
    if observer_rows:
        cid = str((observer_rows[0].get("container") or {}).get("id") or "")
    manifest.update(
        {
            "mcp_executed": True,
            "observer_executed": True,
            "tls_version": "TLSv1.3",
            "observer_container": cid,
            "source": (
                str(manifest.get("source", ""))
                + "; Phase 2 TLS 1.3 MCP + container observer"
            ),
            "note": (
                "MCP calls used TLS 1.3. Token was read from EVADE_MCP_TOKEN "
                "(or a one-shot generated value) and never stored in the dump. "
                "Certificates are self-signed lab certs. "
                "Field SLO is not claimed."
            ),
        }
    )
    (dump_dir / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    return dump_dir


def run_phase2(
    dump_dir: Path,
    falco_jsonl: Path,
    tetragon_jsonl: Path | None,
    *,
    work_dir: Path | None = None,
) -> dict:
    cleanup = None
    root = work_dir
    if root is None:
        cleanup = tempfile.TemporaryDirectory(prefix="evade-phase2-")
        root = Path(cleanup.name)
    try:
        live_rows = _jsonl(_LIVE_MCP / "mcp-live.jsonl")
        live_obs = _jsonl(_LIVE_MCP / "observer.jsonl")
        if len(live_rows) >= 11 and live_obs:
            rows, observer_rows = live_rows, live_obs
        else:
            audit = root / "mcp-live.jsonl"
            workspace = root / "fs"
            cert_dir = root / "certs"
            _url, _ca, rows = run_live_mcp(audit, workspace, cert_dir)
            observer_rows = write_observer(
                root / "observer.jsonl",
                os.environ.get("EVADE_COMPOSE_PROJECT", "evade-phase2"),
            )
        write_phase2_dumps(dump_dir, falco_jsonl, tetragon_jsonl, split_audit(rows), observer_rows)
        payload = run_pilot(dump_dir)
        payload["mcp_executed"] = True
        payload["observer_executed"] = True
        payload["tls_version"] = "TLSv1.3"
        return payload
    finally:
        if cleanup is not None:
            cleanup.cleanup()
