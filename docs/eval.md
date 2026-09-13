# Evaluation

Campaign entry point: `evaluation/run.py`.

| Parameter | Value |
|---|---|
| Schema | `evadeagent-eval-v3` |
| Unique templates | 616 (22 scenarios × 7 agents × 4 plans) |
| Repeats | 200 (latency and invariance only; plan 0) |
| Seed | `20260911` |
| Agents | document-assistant, coding-agent, devops-agent, database-agent, knowledge-agent, ticket-agent, mail-agent |

Detectors: B1 policy, B2 telemetry, B3 event signatures, B4 Falco-style host rules, B5 Tetragon-style lineage, C1–C5 ablation (C5 = full EVADE-AGENT). B4 and B5 are encodings. The lab does not run Falco or Tetragon and does not load kernel BPF.

Kernel / MCP follow-up (not this campaign): `docs/kernel-lab.md`. Event-shape pilot: `evaluation/run_kernel_pilot.py` → `evaluation/results/kernel_pilot.json`. Products are not executed.

Copy numeric tables from `evaluation/results/approach_comparison.json`. Tables 8–11 are `tables.table4`–`table7`. Table 4 is `tables.alignment_walk`. Table 13 is `tables.per_agent_c5`. Do not retype cells. Do not treat JSON Fisher `p` as a sampling inference.

Preferred:

```bash
docker compose run --rm --build lab
```

Optional local venv:

```bash
.venv/bin/python evaluation/run.py --repeats 200 --seed 20260911
.venv/bin/python evaluation/make_figures.py
```
