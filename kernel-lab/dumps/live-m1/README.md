# Falco 0.44.1 M1 capture

Product alerts from `collectors/falco_m1_capture.sh` on LinuxKit 6.12.54
(modern BPF). Rules: `rules/evade-lab.yaml` (Table C.1 path + shell classes).

`falco.jsonl` is the source. Recapture:

```bash
docker run --rm --privileged --network none --entrypoint /bin/sh \
  -e HOST_ROOT=/host \
  -v /proc:/host/proc:ro \
  -v "$PWD/kernel-lab/rules/evade-lab.yaml:/etc/falco/rules.d/evade-lab.yaml:ro" \
  -v "$PWD/kernel-lab/collectors/falco_m1_capture.sh:/capture.sh:ro" \
  -v "$PWD/kernel-lab/dumps/live-m1:/out" \
  falcosecurity/falco:latest \
  /capture.sh
```
