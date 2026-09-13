# Workloads

Implemented in `src/evadeagent/kernel_lab/execute.py`.

Each cell runs under a private root (`/tmp/evade-lab-...`). Contract paths
`/workspace/documents` and `/lab/secrets/token` are labels for those real files.
`/lab/secrets/token` holds the string `path-label-only`, not a credential.

M1 and A8 spawn `/bin/sh` to `cat` that marker. B4 sees the process label `sh`
(M1) or drops the violating host events (A8).

Tetragon L1/A6 use the named copies in this directory (`l1.sh`, `a6.sh`) so
`process_exec.binary` is `document-assistant`, `document-reader`, or
`unrelated-init`.
