# Reproduce the laboratory campaign

All numbers in the JSS manuscript Section 8 / Tables 8–11, plus Table 4 (`tables.alignment_walk`) and Table 13 (`tables.per_agent_c5`), come from this repository. Do not type result cells by hand. JSON keys `tables.table4`–`table7` remain the prevention, authorization, robustness, and latency objects.

The supported way to regenerate them is **Docker Compose**. A local virtualenv is optional.

`docs/kernel-lab.md` describes the product-observer follow-up. Compose also runs `evaluation/run_kernel_pilot.py`, which writes `evaluation/results/kernel_pilot.json` and does not overwrite this JSON. That pilot uses event-shape fixtures; it does not execute Falco or Tetragon.

## What is already captured

| File | Contents |
|---|---|
| `evaluation/results/approach_comparison.json` | Full campaign (`schema: evadeagent-eval-v3`, 616 unique templates, `repeats=200`, `base_seed=20260911`) |
| `figures/figure-11-detection.png` | Detection and benign acceptance (manuscript Figure 11) |
| `figures/figure-12-ablation.png` | Ablation C1–C5 (manuscript Figure 12) |
| `figures/figure-13-residual.png` | Residual heatmap (manuscript Figure 13) |
| `figures/figure-14-latency.png` | In-process `detect()` latency (manuscript Figure 14) |

Detection tables use unique templates. Repeats measure latency and confirm decision invariance. They are not independent security worlds.

## Docker Compose (preferred)

From this directory (`github-repo/`). Requires Docker Compose v2. The container is offline, non-root, read-only root, and writes only into `evaluation/results/` and `figures/`. No ports, credentials, or Docker socket.

```bash
docker compose run --rm --build lab
```

That command:

1. builds `evadeagent-lab:local` (Python 3.12.11)
2. runs the unit tests
3. re-runs the seeded campaign (`repeats=200`, seed `20260911`)
4. rewrites Figures 11–14

Useful overrides (same image, no rebuild after the first time):

```bash
docker compose run --rm lab pytest -q -o cache_dir=/tmp/pytest-cache
docker compose run --rm lab python evaluation/run.py --repeats 200 --seed 20260911
```

A different repeat count is a new campaign, not the paper:

```bash
docker compose run --rm -e EVADEAGENT_REPEATS=20 lab
```

## Local virtualenv (optional)

```bash
python3 -m venv .venv
.venv/bin/pip install -e ".[dev]"
.venv/bin/pytest -q
.venv/bin/python evaluation/run.py --repeats 200 --seed 20260911
.venv/bin/python evaluation/make_figures.py
```
