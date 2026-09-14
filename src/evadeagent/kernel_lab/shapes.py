"""Map Falco-like and Tetragon-like records to Observation.

Field names follow published product JSON *shapes* [12], [32], [33].
This is not Falco or Tetragon. Lab-only extensions live under `_lab`.
Path labels such as /lab/secrets/token are not secrets.
"""

from __future__ import annotations

from pathlib import PurePosixPath
from typing import Any, Iterable

from evadeagent.observe import Layer, Observation


def _basename(value: str | None) -> str | None:
    if not value:
        return None
    name = PurePosixPath(str(value)).name
    return name or str(value)


def falco_alerts_to_observations(
    alerts: Iterable[dict[str, Any]],
    *,
    run_id: str,
) -> list[Observation]:
    out: list[Observation] = []
    for alert in alerts:
        fields = dict(alert.get("output_fields") or {})
        lab = dict(alert.get("_lab") or {})
        seen = bool(lab.get("seen", True))
        t = _tick(fields.get("evt.time"), lab.get("t", 0))
        container = fields.get("container.id") or lab.get("container")
        parent = fields.get("proc.pname")
        flags = _flags(lab.get("flags"))
        proc = fields.get("proc.name")
        if proc:
            out.append(
                Observation(
                    layer=Layer.HOST,
                    kind="process",
                    name=str(proc),
                    t=t,
                    parent=str(parent) if parent else None,
                    container=str(container) if container else None,
                    run_id=run_id,
                    seen=seen,
                    flags=flags,
                )
            )
        path = fields.get("fd.name") or fields.get("fs.path")
        if path and _looks_like_path(str(path)):
            out.append(
                Observation(
                    layer=Layer.HOST,
                    kind="file",
                    name=str(path),
                    t=t,
                    container=str(container) if container else None,
                    run_id=run_id,
                    seen=seen,
                    flags=flags,
                )
            )
        endpoint = fields.get("fd.sip.name") or fields.get("evt.arg.domain") or lab.get("endpoint")
        if endpoint:
            out.append(
                Observation(
                    layer=Layer.HOST,
                    kind="endpoint",
                    name=str(endpoint),
                    t=t,
                    container=str(container) if container else None,
                    run_id=run_id,
                    seen=seen,
                    flags=flags,
                )
            )
        ancestor = fields.get("proc.aname[0]") or lab.get("ancestry0")
        if ancestor:
            out.append(
                Observation(
                    layer=Layer.HOST,
                    kind="ancestry",
                    name=str(ancestor),
                    t=t,
                    run_id=run_id,
                    seen=seen,
                )
            )
        for flag in flags:
            out.append(
                Observation(
                    layer=Layer.HOST,
                    kind="flag",
                    name=flag,
                    t=t,
                    run_id=run_id,
                    seen=seen,
                    flags=frozenset({flag}),
                )
            )
    return out


def tetragon_events_to_observations(
    events: Iterable[dict[str, Any]],
    *,
    run_id: str,
) -> list[Observation]:
    out: list[Observation] = []
    for event in events:
        lab = dict(event.get("_lab") or {})
        seen = bool(lab.get("seen", True))
        exec_ev = event.get("process_exec") or {}
        proc = exec_ev.get("process") or event.get("process") or {}
        parent_obj = exec_ev.get("parent") if isinstance(exec_ev.get("parent"), dict) else {}
        if not parent_obj and isinstance(proc.get("parent"), dict):
            parent_obj = proc["parent"]
        parent = _basename(str(parent_obj.get("binary") or ""))
        binary = _basename(str(proc.get("binary") or proc.get("name") or ""))
        t = _tick(proc.get("start_time"), lab.get("t", 0))
        container = (proc.get("pod") or {}).get("name") or lab.get("container")
        if binary:
            out.append(
                Observation(
                    layer=Layer.HOST,
                    kind="process",
                    name=binary,
                    t=t,
                    parent=parent,
                    container=str(container) if container else None,
                    run_id=run_id,
                    seen=seen,
                )
            )
        ancestry0 = lab.get("ancestry0")
        if ancestry0:
            ancestry_name = _basename(str(ancestry0)) or str(ancestry0)
        elif binary in {
            "document-assistant",
            "coding-agent",
            "devops-agent",
            "database-agent",
            "knowledge-agent",
            "ticket-agent",
            "mail-agent",
            "unrelated-init",
        }:
            ancestry_name = binary
        elif parent in {
            "document-assistant",
            "coding-agent",
            "devops-agent",
            "database-agent",
            "knowledge-agent",
            "ticket-agent",
            "mail-agent",
            "unrelated-init",
        }:
            ancestry_name = parent
        else:
            ancestry_name = None
        if ancestry_name:
            out.append(
                Observation(
                    layer=Layer.HOST,
                    kind="ancestry",
                    name=ancestry_name,
                    t=t,
                    run_id=run_id,
                    seen=seen,
                )
            )
    return out


def mcp_audit_to_observations(
    rows: Iterable[dict[str, Any]],
    *,
    run_id: str,
) -> list[Observation]:
    """Map MCP audit JSON to Observation. File-only; no sockets."""
    out: list[Observation] = []
    for row in rows:
        lab = dict(row.get("_lab") or {})
        seen = bool(lab.get("seen", True))
        t = _tick(row.get("t"), lab.get("t", 0))
        uri = row.get("uri")
        if uri:
            out.append(
                Observation(
                    layer=Layer.MCP,
                    kind="mcp",
                    name=str(uri),
                    t=t,
                    run_id=run_id,
                    seen=seen,
                )
            )
        tool = row.get("tool")
        if tool:
            out.append(
                Observation(
                    layer=Layer.MCP,
                    kind="tool",
                    name=str(tool),
                    t=t,
                    run_id=run_id,
                    seen=seen,
                )
            )
    return out


def _looks_like_path(value: str) -> bool:
    return value.startswith("/") or value.startswith("/lab/") or value.startswith("/workspace/")


def _tick(raw: Any, fallback: int) -> int:
    if raw is None or raw == "":
        return int(fallback)
    try:
        return int(raw)
    except (TypeError, ValueError):
        return int(fallback)


def _flags(raw: Any) -> frozenset[str]:
    if not raw:
        return frozenset()
    if isinstance(raw, str):
        return frozenset({raw})
    return frozenset(str(item) for item in raw)
