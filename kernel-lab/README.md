# kernel-lab

| Piece | Path |
|---|---|
| Goal status | [`GOAL.md`](GOAL.md) |
| Design | [`../docs/kernel-lab.md`](../docs/kernel-lab.md) |
| Executed workloads | `src/evadeagent/kernel_lab/execute.py` |
| Falco M1 capture | `collectors/falco_m1_capture.sh`, `rules/evade-lab.yaml` |
| Tetragon L1/A6 capture | `collectors/tetragon_capture.sh` |
| Live Falco JSONL | `dumps/live-m1/falco.jsonl` |
| Live Tetragon JSONL | `dumps/live-tetragon/tetragon.jsonl` |
| Runner | `evaluation/run_kernel_pilot.py` |

```bash
python evaluation/run_kernel_pilot.py
```

Default: hybrid dump (executed cells + Falco M1 + Tetragon L1/A6) → `evaluation/results/kernel_pilot.json`.

`products_executed` is true when both products contributed at least one cell.

Do not overwrite `approach_comparison.json`. Do not copy these cells into Section 8.
