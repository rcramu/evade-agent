"""Assemble an ExecutionTrace from normalized observations.

Collectors (Falco, Tetragon, MCP audit) are out of tree. This module does not
load BPF, open sockets, or call those products. It only joins records that a
future kernel-lab collector must already have normalized.

See docs/kernel-lab.md.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Iterable, Sequence

from evadeagent.models import ExecutionTrace

SCHEMA = "evadeagent-eval-v4"


class Layer(str, Enum):
    AGENT = "agent"
    MCP = "mcp"
    HOST = "host"


@dataclass(frozen=True)
class RunContext:
    """Agent / MCP side of one run. Not dropped when the host probe misses an event."""

    agent: str
    intent: str
    plan: tuple[str, ...]
    tools: tuple[str, ...]
    mcp: tuple[str, ...]
    identity: str
    task_completed: bool = True
    run_id: str = "run-0"
    container: str = "ctr:lab"
    extras: dict[str, str] = field(default_factory=dict)


@dataclass(frozen=True)
class Observation:
    """One normalized event. Path labels such as /lab/secrets/token are not secrets."""

    layer: Layer
    kind: str
    name: str
    t: int = 0
    parent: str | None = None
    container: str | None = None
    run_id: str = "run-0"
    seen: bool = True
    flags: frozenset[str] = field(default_factory=frozenset)


@dataclass(frozen=True)
class CaptureRecord:
    emitted: int
    seen: int
    missing: tuple[str, ...]

    @property
    def complete(self) -> bool:
        return self.emitted == self.seen and not self.missing


@dataclass(frozen=True)
class AssembledRun:
    trace: ExecutionTrace
    capture: CaptureRecord
    schema: str = SCHEMA


_HOST_KINDS = frozenset({"process", "file", "endpoint", "ancestry", "flag"})


def assemble_trace(ctx: RunContext, observations: Sequence[Observation]) -> AssembledRun:
    """Join context + observations into the v3 ExecutionTrace schema.

    Tools and MCP URIs come from the context (and seen tool/mcp observations).
    Host fields come only from observations with seen=True. Unseen host events
    increment CaptureRecord.missing and are omitted from the trace (A8 / N*).
    """
    scoped = [obs for obs in observations if obs.run_id == ctx.run_id]
    host_events = [obs for obs in scoped if obs.layer is Layer.HOST and obs.kind in _HOST_KINDS]
    missing = tuple(obs.name for obs in host_events if not obs.seen)
    seen_host = [obs for obs in host_events if obs.seen]
    capture = CaptureRecord(emitted=len(host_events), seen=len(seen_host), missing=missing)

    tools = _unique(ctx.tools + tuple(obs.name for obs in scoped if obs.kind == "tool" and obs.seen))
    mcp = _unique(ctx.mcp + tuple(obs.name for obs in scoped if obs.kind == "mcp" and obs.seen))
    processes = _unique(obs.name for obs in seen_host if obs.kind == "process")
    files = _unique(obs.name for obs in seen_host if obs.kind == "file")
    endpoints = _unique(obs.name for obs in seen_host if obs.kind == "endpoint")
    ancestry = _unique(obs.name for obs in seen_host if obs.kind == "ancestry")
    if not ancestry:
        ancestry = (ctx.agent,)

    # Keep input order so A9 can supply a strictly decreasing tick sequence.
    stamps = tuple(obs.t for obs in seen_host if obs.kind in {"process", "file", "endpoint"})
    if not stamps:
        stamps = tuple(range(max(1, len(tools))))

    container = ctx.container
    for obs in seen_host:
        if obs.container:
            container = obs.container
            break

    flag_names = set()
    for obs in seen_host:
        flag_names.update(obs.flags)
        if obs.kind == "flag":
            flag_names.add(obs.name)

    extras = dict(ctx.extras)
    extras["run_id"] = ctx.run_id
    extras["schema"] = SCHEMA
    if missing:
        extras["capture"] = "loss"
        extras["ground_truth"] = extras.get("ground_truth", "unauthorized")

    trace = ExecutionTrace(
        agent=ctx.agent,
        intent=ctx.intent,
        plan=ctx.plan,
        tools=tools,
        mcp=mcp,
        processes=processes,
        files=files,
        endpoints=endpoints,
        timestamps=stamps,
        ancestry=ancestry,
        container=container,
        identity=ctx.identity,
        task_completed=ctx.task_completed,
        shell="shell" in flag_names,
        credential="credential" in flag_names,
        privilege_change="privilege_change" in flag_names,
        extras=extras,
    )
    return AssembledRun(trace=trace, capture=capture)


def _unique(names: Iterable[str]) -> tuple[str, ...]:
    seen: set[str] = set()
    out: list[str] = []
    for name in names:
        if name and name not in seen:
            seen.add(name)
            out.append(name)
    return tuple(out)
