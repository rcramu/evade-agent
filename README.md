# EVADE-AGENT laboratory

Repository: https://github.com/rcramu/evade-agent


In-process runtime-assurance engine for the JSS manuscript
*EVADE-AGENT: Intent-to-Runtime Assurance for Agentic Software under Semantic-Preserving Behavioral Transformation*.

The prototype correlates agent intent, plans, tool/MCP calls, and typed runtime observations; checks a Runtime Behavioral Contract; and applies relational invariants. **It does not load eBPF programs, call a language model, or open a network socket.** Operating-system observation is modeled as the fields a probe set would emit.

## Reproduce Section 8

Preferred (offline, non-root container). Full instructions: [`REPRODUCE.md`](REPRODUCE.md).

```bash
docker compose run --rm --build lab
```

Optional local venv:

```bash
python3 -m venv .venv
.venv/bin/pip install -e ".[dev]"
.venv/bin/pytest -q
.venv/bin/python evaluation/run.py --repeats 200 --seed 20260911
.venv/bin/python evaluation/make_figures.py
.venv/bin/python evaluation/run_lab_slo.py
```

Dataset: `evaluation/results/approach_comparison.json` (`schema: evadeagent-eval-v3`, 616 unique templates, 7 agents, 4 plan paraphrases, `repeats=200` latency variants, `base_seed=20260911`).
Details: `docs/eval.md`.

A later kernel campaign is specified in [`docs/kernel-lab.md`](docs/kernel-lab.md) and [`kernel-lab/GOAL.md`](kernel-lab/GOAL.md). `evaluation/run_kernel_pilot.py` writes `evaluation/results/kernel_pilot.json` (`schema: evadeagent-eval-v4-pilot`). Falco 0.44.1 captured M1, A2/A4, and A8/A9; Tetragon 1.7.0 captured L1/A6 plus A2/A4/A8/A9; Phase 2 adds TLS 1.3 MCP and a container observer. `evaluation/run_agent_pilots.py` repeats the seven cells for all Section 8 agents. Those files must not overwrite the v3 JSON and must not be copied into Section 8.

## What is not in this repository

- Kernel BPF C programs
- Live credentials, tokens, or certificates
- Exploit payloads or attack procedures against real systems

Adversarial cells rewrite laboratory trace fields (plan text, process labels, timestamps, ancestry, dropped observations). They are defensive robustness fixtures.
