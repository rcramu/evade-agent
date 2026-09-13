"""Write observer.jsonl for the Phase 2 compose project."""

from __future__ import annotations

import os
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
if str(_ROOT / "src") not in sys.path:
    sys.path.insert(0, str(_ROOT / "src"))

import time

from evadeagent.kernel_lab.observer import write_observer


def main() -> int:
    out = Path(os.environ.get("EVADE_OBSERVER_OUT", "/out/observer.jsonl"))
    project = os.environ.get("EVADE_COMPOSE_PROJECT", "evade-phase2")
    ready = Path(os.environ.get("EVADE_AGENT_OK", "/out/agent.ok"))
    for _ in range(90):
        if ready.is_file():
            break
        time.sleep(1)
    rows = write_observer(out, project)
    print(f"wrote {out} containers={len(rows)}")
    return 0 if rows else 1


if __name__ == "__main__":
    raise SystemExit(main())
