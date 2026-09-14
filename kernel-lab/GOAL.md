# Kernel-lab goal status

Cisco publication approval is not a gate. LLM-generated plans are out of scope.

| Goal | Status | Evidence |
|---|---|---|
| Five-cell pipeline (L1, M1, A6, A8, A9) → C5 | **Achieved** | pytest + `kernel_pilot.json` |
| All seven Section 8 agents, five cells | **Achieved** | `kernel_pilot_agents.json`; file-only MCP (no cluster) |
| Decisions match encodings and EXPECTED | **Achieved** | `evaluation/results/kernel_pilot.json` |
| Real workloads (files + `/bin/sh` child) | **Achieved** | `execute.py`, `dumps/executed/` |
| In-process MCP audit join | **Achieved** | `mcp.jsonl`; A8 keeps MCP while host `seen=false` |
| File-based collector drop-in | **Achieved** | `collect.py` |
| Falco **product** alerts on M1 | **Achieved** | Falco 0.44.1 modern BPF; `dumps/live-m1/falco.jsonl` (`sh` + `/lab/secrets/token`) |
| Tetragon product on L1 / A6 | **Achieved** | Tetragon 1.7.0 in Docker; seven-agent `dumps/live-tetragon/tetragon.jsonl` (33 events) |
| Full `products_executed: true` | **Achieved (partial cells)** | Falco M1 + Tetragon L1/A6; A8/A9 still use the executed recorder |
| Live networked MCP (TLS 1.3) | **Achieved** | In-process TLS 1.3 MCP; token from `EVADE_MCP_TOKEN`; `mcp_executed` |
| Container observer | **Achieved** | `observer.jsonl` + `kernel-lab/compose/` (privileges on observer only) |
| Field SLO | **Not achieved** | Lab metrics in `lab_slo.json` with `field_executed: false` |

The JSS manuscript stays on `evadeagent-eval-v3`. Do not copy kernel-lab cells into Section 8.

On this host the achievable goal is done: **Phase 1 products + Phase 2 TLS MCP and observer**. Phase 3 field SLO is not a laboratory measurement.
