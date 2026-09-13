# Phase 2 compose

Internal network only. Privileges only on `observer`.

`EVADE_MCP_TOKEN` must be in the environment. Do not write it to a file.

Certificates are **self-signed** ECDSA P-256 / SHA-256, valid one day, generated
at process start. Use them only for this laboratory.

```bash
./kernel-lab/compose/run.sh
```

The in-process path (`python evaluation/run_kernel_pilot.py --phase2`) is the
default pilot join and does not need this compose file.
