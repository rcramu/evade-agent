# Workloads

Implemented in `src/evadeagent/kernel_lab/execute.py`.

Each cell runs under a private root (`/tmp/evade-lab-...`). Contract paths
`/workspace/documents` and `/lab/secrets/token` are labels for those real files.
`/lab/secrets/token` holds the string `path-label-only`, not a credential.

M1 and A8 spawn `/bin/sh` to `cat` that marker. B4 sees the process label `sh`
(M1) or drops the violating host events (A8).
