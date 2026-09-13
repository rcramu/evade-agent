# Kernel-lab goal status

Cisco publication approval is not a gate. LLM-generated plans are out of scope.

| Goal | Status | Evidence |
|---|---|---|
| Five-cell pipeline (L1, M1, A6, A8, A9) → C5 | **Achieved** | pytest + `kernel_pilot.json` |
| Decisions match encodings and EXPECTED | **Achieved** | `evaluation/results/kernel_pilot.json` |
| Real workloads (files + `/bin/sh` child) | **Achieved** | `execute.py`, `dumps/executed/` |
| In-process MCP audit join | **Achieved** | `mcp.jsonl`; A8 keeps MCP while host `seen=false` |
| File-based collector drop-in | **Achieved** | `collect.py` |
| Falco **product** alerts on M1 | **Achieved** | Falco 0.44.1 modern BPF; `dumps/live-m1/falco.jsonl` (`sh` + `/lab/secrets/token`) |
| Tetragon product | **Not achieved** | Not installed; B5 still uses executed ancestry records |
| Full `products_executed: true` | **Not achieved** | Requires Falco **and** Tetragon on all five cells |
| Live networked MCP (TLS 1.3) | **Not achieved** | No sockets in this tree |
| Field SLO | **Not achieved** | Needs a production platform |

The JSS manuscript stays on `evadeagent-eval-v3`. Do not copy kernel-lab cells into Section 8.

On this host the achievable goal is done: **executed five-cell campaign + real Falco M1 alerts**, with `products_executed: false` and `falco_executed: true`.
