"""In-process EVADE-AGENT laboratory. No kernel programs and no network I/O."""

from __future__ import annotations

from random import Random

from evadeagent.contracts import AGENTS
from evadeagent.detectors import detect
from evadeagent.models import Decision, DetectorMode, ExecutionTrace, Label
from evadeagent.traces import NOISE_SEEDS, SCENARIOS
from evadeagent.transforms import apply


def build_trace(agent: str, kind: str, plan_id: int = 0, scenario_id: str | None = None) -> ExecutionTrace:
    seed = NOISE_SEEDS.get(scenario_id) if scenario_id else None
    return apply(kind, agent, plan_id=plan_id, noise_seed=seed)


def vary_trace(trace: ExecutionTrace, rng: Random) -> ExecutionTrace:
    """Seeded timing and wording jitter that must not change detector decisions."""
    offset = rng.randint(0, 40)
    stamps = tuple(ts + offset for ts in trace.timestamps)
    files = trace.files
    workspace_roots = tuple(path for path in trace.files if path.startswith("/workspace"))
    if workspace_roots:
        root = workspace_roots[0]
        files = files + (f"{root}/notes-{rng.randint(1, 9)}",)
    plan = tuple(f"then {step}" if i == 0 else step for i, step in enumerate(trace.plan))
    extras = dict(trace.extras)
    extras["variant"] = str(rng.randint(0, 1_000_000))
    return ExecutionTrace(
        **{
            **trace.__dict__,
            "timestamps": stamps,
            "files": files,
            "plan": plan,
            "extras": extras,
        }
    )


def decide(mode: DetectorMode, agent: str, kind: str) -> tuple[Decision, ExecutionTrace]:
    trace = build_trace(agent, kind)
    return detect(mode, trace), trace


def labeled_universe() -> list[tuple[str, str, str, Label]]:
    """(scenario_id, agent, kind, label) for every agent × scenario."""
    rows: list[tuple[str, str, str, Label]] = []
    for sid, label, kind in SCENARIOS:
        for agent in AGENTS:
            rows.append((sid, agent, kind, label))
    return rows
