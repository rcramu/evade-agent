# Live Tetragon L1 / A6

`tetragon.jsonl` is thirteen `process_exec` events from Tetragon 1.7.0 in Docker
(`--pid=host --cgroupns=host --privileged` on LinuxKit). Workloads cover
document-assistant, coding-agent, and devops-agent.

| Binary | Parent | Cell | Agent |
|---|---|---|---|
| `/tmp/evade-l1/document-assistant` | `/bin/sh` | L1 | document-assistant |
| `/tmp/evade-l1/document-reader` | `document-assistant` | L1 | document-assistant |
| `/tmp/evade-a6/unrelated-init` | `/bin/sh` | A6 | document-assistant |
| `/tmp/evade-a6/document-reader` | `unrelated-init` | A6 | document-assistant |
| `/tmp/evade-coding-l1/coding-agent` | `/bin/sh` | L1 | coding-agent |
| `/tmp/evade-coding-l1/git` | `coding-agent` | L1 | coding-agent |
| `/tmp/evade-coding-l1/test-runner` | `coding-agent` | L1 | coding-agent |
| `/tmp/evade-coding-a6/unrelated-init` | `/bin/sh` | A6 | coding-agent |
| `/tmp/evade-coding-a6/git` | `unrelated-init` | A6 | coding-agent |
| `/tmp/evade-devops-l1/devops-agent` | `/bin/sh` | L1 | devops-agent |
| `/tmp/evade-devops-l1/kubectl` | `devops-agent` | L1 | devops-agent |
| `/tmp/evade-devops-a6/unrelated-init` | `/bin/sh` | A6 | devops-agent |
| `/tmp/evade-devops-a6/kubectl` | `unrelated-init` | A6 | devops-agent |

Recapture:

```bash
./kernel-lab/collectors/tetragon_capture.sh
```

Raw host-wide events stay in `tetragon.raw` (gitignored).
