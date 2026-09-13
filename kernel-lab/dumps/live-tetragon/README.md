# Live Tetragon L1 / A6

`tetragon.jsonl` is four `process_exec` events from Tetragon 1.7.0 in Docker
(`--pid=host --cgroupns=host --privileged` on LinuxKit):

| Binary | Parent | Cell |
|---|---|---|
| `/tmp/evade-l1/document-assistant` | `/bin/sh` | L1 |
| `/tmp/evade-l1/document-reader` | `document-assistant` | L1 |
| `/tmp/evade-a6/unrelated-init` | `/bin/sh` | A6 |
| `/tmp/evade-a6/document-reader` | `unrelated-init` | A6 |

Recapture:

```bash
./kernel-lab/collectors/tetragon_capture.sh
```

Raw host-wide events stay in `tetragon.raw` (gitignored).
