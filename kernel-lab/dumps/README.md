# Event dumps

Each dump directory has `manifest.json` plus one folder per cell:

```text
<dump>/
  manifest.json
  L1/falco.jsonl
  L1/tetragon.jsonl
  L1/mcp.jsonl
  M1/ …
  A6/ …
  A8/ …
  A9/ …
```

`bundled/` is generated from in-memory fixtures. `products_executed` is false.

To run a later product capture, copy this layout to `live/`, replace the JSONL
with collector output, set `products_executed` to true, and pin product versions
in the manifest. Then:

```bash
python evaluation/run_kernel_pilot.py --from-dir kernel-lab/dumps/live
```

That writes `evaluation/results/kernel_pilot.json` and does not overwrite
`approach_comparison.json`. Do not set `products_executed` true unless Falco and
Tetragon actually ran.
