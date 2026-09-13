"""Call the lab MCP over TLS 1.3 for each pilot cell. Token from the environment."""

from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
if str(_ROOT / "src") not in sys.path:
    sys.path.insert(0, str(_ROOT / "src"))

from evadeagent.kernel_lab.mcp_tls import McpError, run_document_session
from evadeagent.kernel_lab.pilot import PILOT_CELLS


def main() -> int:
    url = os.environ.get("EVADE_MCP_URL", "")
    ca = Path(os.environ.get("EVADE_MCP_CA", "/certs/cert.pem"))
    token = os.environ.get("EVADE_MCP_TOKEN", "")
    if not url or not token:
        print("EVADE_MCP_URL and EVADE_MCP_TOKEN required", file=sys.stderr)
        return 1
    for _ in range(30):
        if ca.is_file():
            break
        time.sleep(0.2)
    if not ca.is_file():
        print(f"CA missing: {ca}", file=sys.stderr)
        return 1
    last = None
    for _ in range(30):
        try:
            for cell in PILOT_CELLS:
                run_document_session(url, ca, token, extra_read=(cell == "A8"))
            last = None
            break
        except McpError as exc:
            last = exc
            time.sleep(0.3)
    if last is not None:
        print(last, file=sys.stderr)
        return 1
    out = Path(os.environ.get("EVADE_AGENT_OK", "/out/agent.ok"))
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps({"cells": list(PILOT_CELLS), "tls": "TLSv1.3"}) + "\n", encoding="utf-8")
    print(f"wrote {out}")
    observed = Path("/out/observer.jsonl")
    for _ in range(60):
        if observed.is_file():
            break
        time.sleep(0.5)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
