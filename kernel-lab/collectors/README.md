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
| `falco_m1_capture.sh` | Falco 0.44.1 (in `falcosecurity/falco`) | M1 |
| `tetragon_capture.sh` | Tetragon 1.7.0 (`quay.io/cilium/tetragon`) | L1, A6 |

Both run privileged Docker on the LinuxKit VM. They do not open sockets.
