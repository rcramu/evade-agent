# Collectors

Parsers live in `src/evadeagent/kernel_lab/shapes.py` and
`src/evadeagent/kernel_lab/collect.py`.

| File | Input |
|---|---|
| `falco.jsonl` | Falco-like `output_fields` records |
| `tetragon.jsonl` | Tetragon-like `process_exec` records |
| `mcp.jsonl` | MCP audit `{uri, tool, t}` |

Lab-only fields stay under `_lab` (`seen`, `flags`, `ancestry0`, `endpoint`).

Live adapters:

| Script | Product | Cells |
|---|---|---|
| `falco_m1_capture.sh` | Falco 0.44.1 (in `falcosecurity/falco`) | one M1 |
| `falco_agents_m1.sh` | Falco 0.44.1 | independent M1 × 7 agents |
| `falco_extra.sh` | Falco 0.44.1 | sink names + A8 negative |
| `falco_extended.sh` | Falco 0.44.1 | A2/A4 helper-path + A9 workspace-only |
| `tetragon_capture.sh` | Tetragon 1.7.0 (`quay.io/cilium/tetragon`) | L1, A6 for seven agents |
| `tetragon_extra.sh` | Tetragon 1.7.0 | A2, A4, A8, A9 for seven agents |

Both run privileged Docker on the LinuxKit VM. They do not open sockets.
