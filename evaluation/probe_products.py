"""Record whether Falco/Tetragon can run. Never sets products_executed by itself."""

from __future__ import annotations

import json
import platform
import shutil
import subprocess
from datetime import datetime, timezone
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
OUT = _ROOT / "kernel-lab" / "dumps" / "probe_status.json"


def _which(name: str) -> str | None:
    return shutil.which(name)


def _docker_falco() -> dict:
    docker = _which("docker")
    if not docker:
        return {"attempted": False, "reason": "docker not on PATH"}
    cmd = [
        docker,
        "run",
        "--rm",
        "--network",
        "none",
        "falcosecurity/falco:latest",
        "falco",
        "--version",
    ]
    try:
        completed = subprocess.run(cmd, capture_output=True, text=True, timeout=90, check=False)
    except subprocess.TimeoutExpired:
        return {"attempted": True, "reason": "docker falco --version timed out"}
    except OSError as exc:
        return {"attempted": True, "reason": str(exc)}
    return {
        "attempted": True,
        "returncode": completed.returncode,
        "stdout": (completed.stdout or "")[:400],
        "stderr": (completed.stderr or "")[:400],
        "reason": "version ok" if completed.returncode == 0 else "falco image did not run",
    }


def main() -> int:
    payload = {
        "generated_utc": datetime.now(timezone.utc).isoformat(),
        "host": {
            "system": platform.system(),
            "release": platform.release(),
            "machine": platform.machine(),
        },
        "host_binaries": {
            "falco": _which("falco"),
            "tetragon": _which("tetragon"),
        },
        "docker_falco_version": _docker_falco(),
        "products_executed": False,
        "note": (
            "This probe only checks whether a product binary or image is available. "
            "It does not load BPF and does not write a live dump. "
            "products_executed stays false."
        ),
    }
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    print(f"wrote {OUT}")
    print(f"host falco={payload['host_binaries']['falco']} tetragon={payload['host_binaries']['tetragon']}")
    print(f"docker falco: {payload['docker_falco_version'].get('reason')}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
