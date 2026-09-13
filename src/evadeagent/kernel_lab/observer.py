"""Container observer for the Phase 2 lab.

Records compose/lab container ids. Privileges belong on the observer service
only. Does not load BPF and does not open sockets to the public internet.
"""

from __future__ import annotations

import json
import os
import socket
import subprocess
from pathlib import Path
from typing import Any


def _docker_lab_containers(project: str) -> list[dict[str, Any]]:
    sock_rows = _docker_api_containers(project)
    if sock_rows:
        return sock_rows
    docker = _which("docker")
    if not docker:
        return []
    cmd = [
        docker,
        "ps",
        "--filter",
        f"label=com.docker.compose.project={project}",
        "--format",
        "{{.ID}}\t{{.Names}}\t{{.Label \"com.docker.compose.service\"}}",
    ]
    try:
        completed = subprocess.run(cmd, capture_output=True, text=True, check=False, timeout=15)
    except (OSError, subprocess.TimeoutExpired):
        return []
    if completed.returncode != 0:
        return []
    rows: list[dict[str, Any]] = []
    for line in completed.stdout.splitlines():
        parts = line.split("\t")
        if len(parts) < 2:
            continue
        rows.append(
            {
                "container": {
                    "id": parts[0],
                    "name": parts[1],
                    "service": parts[2] if len(parts) > 2 else "",
                },
                "t": 0,
                "source": "docker-ps",
            }
        )
    return rows


def _docker_api_containers(project: str) -> list[dict[str, Any]]:
    """Read our compose project from the Docker API. Lab containers only."""
    sock = Path("/var/run/docker.sock")
    if not sock.exists():
        return []
    import http.client
    from urllib.parse import urlencode

    class _Unix(http.client.HTTPConnection):
        def connect(self) -> None:
            self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            self.sock.connect(str(sock))

    filters = json.dumps({"label": [f"com.docker.compose.project={project}"]})
    path = "/containers/json?" + urlencode({"all": "true", "filters": filters})
    conn = _Unix("localhost")
    try:
        conn.request("GET", path)
        response = conn.getresponse()
        if response.status != 200:
            return []
        items = json.loads(response.read().decode("utf-8"))
    except OSError:
        return []
    finally:
        conn.close()
    rows: list[dict[str, Any]] = []
    for item in items:
        names = item.get("Names") or []
        labels = item.get("Labels") or {}
        rows.append(
            {
                "container": {
                    "id": str(item.get("Id") or "")[:12],
                    "name": str(names[0]).lstrip("/") if names else "",
                    "service": labels.get("com.docker.compose.service", ""),
                },
                "t": 0,
                "source": "docker-api",
            }
        )
    return rows


def _which(name: str) -> str | None:
    from shutil import which

    return which(name)


def observe(project: str = "evade-phase2") -> list[dict[str, Any]]:
    rows = _docker_lab_containers(project)
    if rows:
        return rows
    hostname = os.environ.get("HOSTNAME") or socket.gethostname()
    cid_path = Path("/proc/1/cgroup")
    container = hostname
    if cid_path.is_file():
        text = cid_path.read_text(encoding="utf-8", errors="replace")
        for token in text.replace("/", " ").split():
            if len(token) >= 12 and token.isalnum():
                container = token[-12:]
                break
    return [
        {
            "container": {"id": container, "name": hostname, "service": "local"},
            "t": 0,
            "source": "hostname",
        }
    ]


def write_observer(path: Path, project: str = "evade-phase2") -> list[dict[str, Any]]:
    rows = observe(project)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")
    return rows
