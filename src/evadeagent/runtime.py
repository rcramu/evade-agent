"""In-process agent and MCP-shaped registry. No sockets, no kernel, no LLM."""

from __future__ import annotations

from evadeagent.plans import plan_for
from evadeagent.traces import TEMPLATES
from evadeagent.models import ExecutionTrace


class ObservationLog:
    """Collects typed observations emitted by in-process tool handlers."""

    def __init__(self, agent: str) -> None:
        spec = TEMPLATES[agent]
        self.agent = agent
        self.intent = spec["intent"]
        self.identity = spec["identity"]
        self.tools: list[str] = []
        self.mcp: list[str] = []
        self.processes: list[str] = [agent]
        self.files: list[str] = []
        self.endpoints: list[str] = []
        self.stamps: list[int] = []
        self._t = 0

    def invoke(self, tool: str, mcp: str, process: str, path: str, endpoint: str) -> None:
        self.tools.append(tool)
        self.mcp.append(mcp)
        if process not in self.processes:
            self.processes.append(process)
        if path and path not in self.files:
            self.files.append(path)
        if endpoint and endpoint not in self.endpoints:
            self.endpoints.append(endpoint)
        self.stamps.append(self._t)
        self._t += 1

    def to_trace(self, plan: tuple[str, ...], *, variant_file: bool = False) -> ExecutionTrace:
        files = tuple(self.files)
        if variant_file and files:
            files = files + (files[0] + "/notes",)
        stamps = tuple(self.stamps) if self.stamps else tuple(range(max(3, len(self.tools) + 1)))
        return ExecutionTrace(
            agent=self.agent,
            intent=self.intent,
            plan=plan,
            tools=tuple(self.tools),
            mcp=tuple(self.mcp),
            processes=tuple(self.processes),
            files=files,
            endpoints=tuple(self.endpoints),
            timestamps=stamps,
            ancestry=(self.agent,),
            container=f"ctr:{self.agent}",
            identity=self.identity,
            task_completed=True,
            extras={"source": "executed"},
        )


def _handlers(agent: str) -> list[tuple[str, str, str, str, str]]:
    spec = TEMPLATES[agent]
    tools = spec["tools"]
    mcp = spec["mcp"]
    processes = spec["processes"]
    files = spec["files"]
    endpoints = spec["endpoints"]
    rows = []
    for i, tool in enumerate(tools):
        proc = processes[min(i + 1, len(processes) - 1)]
        path = files[0]
        endpoint = endpoints[min(i, len(endpoints) - 1)]
        rows.append((tool, mcp[i], proc, path, endpoint))
    return rows


def execute_legitimate(agent: str, plan_id: int = 0, *, variant_file: bool = False) -> ExecutionTrace:
    """Run each authorized tool as an in-process MCP handler and record observations."""
    log = ObservationLog(agent)
    for tool, mcp, process, path, endpoint in _handlers(agent):
        log.invoke(tool, mcp, process, path, endpoint)
    return log.to_trace(plan_for(agent, plan_id), variant_file=variant_file)
