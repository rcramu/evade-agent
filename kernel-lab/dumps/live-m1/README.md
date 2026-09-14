# Falco 0.44.1 M1 capture

Shared `falco.jsonl` is the original single-run capture. Independent per-agent
runs live under `agents/<agent>/falco.jsonl` (seven files). Recapture:

```bash
./kernel-lab/collectors/falco_agents_m1.sh
```

Rules: `rules/evade-lab.yaml`. Path label `/lab/secrets/token` is not a secret.
