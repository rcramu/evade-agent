# Live Tetragon L1 / A6

`tetragon.jsonl` is Tetragon 1.7.0 `process_exec` events (`--pid=host --cgroupns=host --privileged` on LinuxKit) for all seven Section 8 agents. Recapture:

```bash
./kernel-lab/collectors/tetragon_capture.sh
```

Raw host-wide events stay in `tetragon.raw` (gitignored).
