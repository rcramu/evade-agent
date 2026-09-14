# Live Tetragon L1 / A6

`tetragon.jsonl` is Tetragon 1.7.0 `process_exec` events (`--pid=host --cgroupns=host --privileged` on LinuxKit) for L1/A6 on all seven Section 8 agents. `tetragon-extra.jsonl` adds A2/A4/A8/A9. Recapture:

```bash
./kernel-lab/collectors/tetragon_capture.sh
./kernel-lab/collectors/tetragon_extra.sh
```

Raw host-wide events stay in `tetragon.raw` (gitignored).
