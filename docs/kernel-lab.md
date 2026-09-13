# Kernel / MCP / field campaign

This note is the layout and adapter contract for work the JSS manuscript does
**not** claim: product Falco/Tetragon, a lab MCP path, and a later field SLO.

The **kernel-lab pilot** is implemented (`schema: evadeagent-eval-v4-pilot`).
Falco 0.44.1 captured M1; Tetragon 1.7.0 captured L1/A6. A8/A9 host rows still
use the executed recorder. It is not part of `schema: evadeagent-eval-v3`.
Do not copy its cells into Section 8.

LLM-generated plans are out of scope here.
Cisco publication approval is not a gate for this paper.

## Frozen versus new

| Campaign | Object of study | Schema | Status |
|---|---|---|---|
| Compose lab | In-process encodings | `evadeagent-eval-v3` (seed `20260911`) | Section 8 |
| Event-shape / executed / Falco+Tetragon hybrid | Adapter + executed cells + Falco M1 + Tetragon L1/A6 | `evadeagent-eval-v4-pilot` | Achieved |
| Product observers + lab MCP | Falco/Tetragon + TLS 1.3 MCP + observer | `evadeagent-eval-v4-pilot` | Achieved (Phase 1+2) |
| Field SLO | Internal platform | `evadeagent-eval-v5` | Not run (`lab_slo.json` is lab-only) |

`docker-compose.yml` stays offline, non-root, `cap_drop: ALL`, `network_mode: none`.
Do not add BPF capabilities to that file.

C5 (`evadeagent.detectors.detect`) does not change.

```text
agent log + MCP audit + host probe
        │
        ▼
  Falco / Tetragon JSONL               (live M1 + L1/A6; fixtures elsewhere)
        │
        ▼
  shapes.py → Observation
        │
        ▼
  assemble_trace()
        │
        ▼
  detect(B4 / B5 / C5)                 (unchanged)
```

## Layout

```text
github-repo/
  docker-compose.yml                         # v3 only — never privileged
  src/evadeagent/observe.py                  # adapter
  src/evadeagent/kernel_lab/shapes.py        # product JSON shapes → Observation
  src/evadeagent/kernel_lab/collect.py       # load <cell>/{falco,tetragon,mcp}.jsonl
  src/evadeagent/kernel_lab/dumps.py         # write bundled dumps
  src/evadeagent/kernel_lab/document_assistant.py
  src/evadeagent/kernel_lab/pilot.py
  evaluation/run_kernel_pilot.py             # writes kernel_pilot.json
  kernel-lab/dumps/bundled/                  # file source of the pilot
  docs/kernel-lab.md
```

Run the pilot (rewrites bundled dumps, then reads them):

```bash
python evaluation/run_kernel_pilot.py --write-fixtures
```

A later product capture uses the same layout under `kernel-lab/dumps/live/`
with `manifest.json` `"products_executed": true` and pinned product versions.

## Adapter interface

`RunContext` is the agent/MCP side of a run (intent, plan, tools, MCP URIs).
Those fields are not dropped when the host probe misses an event.

`Observation` is one normalized event:

| Field | Meaning |
|---|---|
| `layer` | `agent`, `mcp`, or `host` |
| `kind` | `process`, `file`, `endpoint`, `mcp`, `tool`, `ancestry`, `flag` |
| `name` | Process comm, path label, endpoint label, or MCP URI |
| `t` | Monotonic tick |
| `parent` | Immediate parent comm, if known |
| `container` | cgroup / container id |
| `run_id` | Join key with the agent log |
| `seen` | `False` = ground-truth event the probe missed (A8 / N*) |
| `flags` | `shell`, `credential`, `privilege_change` — labels, not secrets |

Lab-only fields on fixture JSON live under `_lab` (including `seen`).

## Phase 1 — product B4 / B5 (next, after this pilot)

**Host.** A Linux VM you admin. Not the Compose lab.

**Pilot agent.** `document-assistant`. Then `coding-agent`. `devops-agent` last.

**Products.** Pin Falco and Tetragon versions in JSON `host`. Rules implement
**only** manuscript Table C.1 classes. No extra macros unless you add `B4+`.

The five cells and expected decisions are already locked in
`EXPECTED` (`document_assistant.py`) and checked by `tests/test_kernel_pilot.py`.

A product run replaces fixture JSON with collector output, sets
`products_executed: true`, and writes a new file. Do not overwrite
`approach_comparison.json` or treat fixture $F_1$ as a product measurement.

## Phase 2 — lab MCP + container (same host)

Implemented. Internal compose network. TLS 1.3. Token from `EVADE_MCP_TOKEN`.
Privileges only on `kernel-lab/compose` `observer`. In-process TLS is the
default dump join (`run_kernel_pilot.py --phase2`).

## Phase 3 — field SLO

Different paper or *In Practice*. Calendar-time operational metrics. No customer
data in the artifact. `evaluation/run_lab_slo.py` writes lab-side metrics with
`field_executed: false`.

## What this repository will not contain

- Kernel BPF C programs
- Executable Falco/Tetragon rule packs that target real systems
- Live credentials, tokens, or certificates
- Exploit payloads or procedures against real systems

Adversarial cells remain synthetic.
