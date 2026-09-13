"""Agent Runtime Behavioral Graph construction and relational queries."""

from __future__ import annotations

from dataclasses import dataclass

from evadeagent.models import ExecutionTrace, RuntimeContract


@dataclass(frozen=True)
class ARBG:
    nodes: frozenset[tuple[str, str]]
    edges: frozenset[tuple[str, str, str]]
    unexpected_types: frozenset[str]
    alignment: float
    has_credential_exfil_path: bool
    ancestry_ok: bool
    temporal_ok: bool
    intent_runtime_ok: bool


def build_arbg(trace: ExecutionTrace, contract: RuntimeContract) -> ARBG:
    nodes: set[tuple[str, str]] = {
        ("agent", trace.agent),
        ("intent", trace.intent),
        ("identity", trace.identity),
        ("container", trace.container),
    }
    edges: set[tuple[str, str, str]] = {("agent", "generates", "intent")}
    for tool in trace.tools:
        nodes.add(("tool", tool))
        edges.add(("intent", "invokes", tool))
    for mcp in trace.mcp:
        nodes.add(("mcp", mcp))
        edges.add(("tool", "invokes", mcp))
    for proc in trace.processes:
        nodes.add(("process", proc))
        edges.add(("mcp", "executes", proc))
    for path in trace.files:
        nodes.add(("file", path))
        edges.add(("process", "reads", path))
    for endpoint in trace.endpoints:
        nodes.add(("endpoint", endpoint))
        edges.add(("process", "connects", endpoint))
    if trace.credential:
        nodes.add(("resource", "credential"))
        edges.add(("process", "accesses", "credential"))
        for endpoint in trace.endpoints:
            if endpoint not in contract.allowed_endpoints:
                edges.add(("credential", "exfils", endpoint))
    if trace.shell:
        nodes.add(("process", "shell"))
        edges.add(("tool", "executes", "shell"))

    unexpected: set[str] = set()
    if trace.credential:
        unexpected.add("credential")
    if trace.shell:
        unexpected.add("shell")
    for proc in trace.processes:
        if proc not in contract.allowed_processes:
            unexpected.add("unknown_process")
    for endpoint in trace.endpoints:
        if endpoint not in contract.allowed_endpoints:
            unexpected.add("unknown_endpoint")
    for path in trace.files:
        if not any(path == allowed or path.startswith(allowed + "/") for allowed in contract.allowed_files):
            unexpected.add("unknown_file")

    expected_tools = set(contract.allowed_tools)
    observed_tools = set(trace.tools)
    tool_overlap = len(expected_tools & observed_tools) / len(expected_tools | observed_tools) if expected_tools else 0.0
    runtime_penalty = 0.25 * len(unexpected)
    alignment = max(0.0, min(1.0, tool_overlap - runtime_penalty))

    has_exfil = trace.credential and any(ep not in contract.allowed_endpoints for ep in trace.endpoints)
    ancestry_ok = bool(trace.ancestry) and trace.ancestry[0] == trace.agent
    temporal_ok = True
    stamps = trace.timestamps
    if len(stamps) >= 2 and all(stamps[i] > stamps[i + 1] for i in range(len(stamps) - 1)):
        temporal_ok = False
    if trace.extras.get("credential_time") == "before_tools":
        temporal_ok = False
    intent_runtime_ok = trace.intent in contract.allowed_intents and not unexpected

    return ARBG(
        nodes=frozenset(nodes),
        edges=frozenset(edges),
        unexpected_types=frozenset(unexpected),
        alignment=alignment,
        has_credential_exfil_path=has_exfil,
        ancestry_ok=ancestry_ok,
        temporal_ok=temporal_ok,
        intent_runtime_ok=intent_runtime_ok,
    )
