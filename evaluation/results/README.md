# Results

`approach_comparison.json` is the source of truth for manuscript Section 8.

- Schema: `evadeagent-eval-v3`
- Generated: 2026-09-13T23:08:34Z (Compose host)
- Unique templates: 616
- Agents: 7; plan paraphrases: 4; scenarios: 22
- `repeats=200` latency variants, `base_seed=20260911`
- Invariance mismatches: 0 (308000 checks)
- `tables.alignment_walk`: manuscript Table 4 (`build_arbg` on `document-assistant` plan 0)
- `tables.per_agent_c5`: manuscript Table 13 (`detect(C5)` on 19 attack cells × 4 plans)

Those two objects are deterministic. A later `docker compose` run will rewrite them together with Section 8. Latency cells remain host-specific.

Regenerate with `docker compose run --rm --build lab`.

`kernel_pilot.json` is a separate pipeline (`schema: evadeagent-eval-v4-pilot`). It is not a Section 8 source. Falco 0.44.1 captured M1; Tetragon 1.7.0 captured L1/A6; Phase 2 TLS 1.3 MCP and observer are joined. `lab_slo.json` is lab-side operational metrics (`field_executed: false`). `kernel_pilot_agents.json` is the same five cells for `document-assistant`, `coding-agent`, and `devops-agent`.
