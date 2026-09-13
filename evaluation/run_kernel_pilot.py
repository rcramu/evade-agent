"""Write evaluation/results/kernel_pilot.json. Does not touch the v3 campaign."""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
if str(_ROOT / "src") not in sys.path:
    sys.path.insert(0, str(_ROOT / "src"))

from evadeagent.kernel_lab.dumps import write_bundled_dumps
from evadeagent.kernel_lab.execute import write_executed_dumps
from evadeagent.kernel_lab.ingest import write_hybrid_dumps
from evadeagent.kernel_lab.pilot import run_pilot

_DUMP_ROOT = Path(os.environ.get("EVADE_DUMP_ROOT", str(_ROOT / "kernel-lab" / "dumps")))
DEFAULT_DUMP = _DUMP_ROOT / "bundled"
EXECUTED_DUMP = _DUMP_ROOT / "executed"
HYBRID_DUMP = _DUMP_ROOT / "hybrid"
LIVE_M1 = _ROOT / "kernel-lab" / "dumps" / "live-m1" / "falco.jsonl"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--from-dir",
        type=Path,
        default=None,
        help="Cell dump directory with manifest.json",
    )
    parser.add_argument(
        "--write-fixtures",
        action="store_true",
        help="Rewrite kernel-lab/dumps/bundled from in-memory fixtures",
    )
    parser.add_argument(
        "--executed",
        action="store_true",
        help="Run real workloads and use kernel-lab/dumps/executed (default when --from-dir is omitted)",
    )
    args = parser.parse_args()
    write_bundled_dumps(DEFAULT_DUMP)
    write_executed_dumps(EXECUTED_DUMP)
    if args.from_dir is not None:
        dump_dir = args.from_dir
    elif args.executed:
        dump_dir = EXECUTED_DUMP
    elif LIVE_M1.is_file():
        dump_dir = write_hybrid_dumps(HYBRID_DUMP, LIVE_M1)
    else:
        dump_dir = EXECUTED_DUMP
    payload = run_pilot(dump_dir)
    out = _ROOT / "evaluation" / "results" / "kernel_pilot.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    print(
        f"wrote {out} schema={payload['schema']} "
        f"products_executed={payload['products_executed']} "
        f"falco_executed={payload.get('falco_executed')}"
    )
    print(f"source={payload['source']}")
    if payload["mismatches"]:
        print("mismatches:", payload["mismatches"])
        return 1
    print("pilot cells matched expected B4/B5/C5 decisions")
    if payload["encoding_disagreements"]:
        print("encoding disagreements:", payload["encoding_disagreements"])
    else:
        print("shape vs encoding decisions agreed on all five cells")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
