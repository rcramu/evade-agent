# Collectors

Parsers live in `src/evadeagent/kernel_lab/shapes.py` and
`src/evadeagent/kernel_lab/collect.py`.

| File | Input |
|---|---|
| `falco.jsonl` | Falco-like `output_fields` records |
| `tetragon.jsonl` | Tetragon-like `process_exec` records |
| `mcp.jsonl` | MCP audit `{uri, tool, t}` |

Lab-only fields stay under `_lab` (`seen`, `flags`, `ancestry0`, `endpoint`).

This directory is the place for a later **live** adapter (read a product log
file, write JSONL). It does not load BPF and does not open sockets.
