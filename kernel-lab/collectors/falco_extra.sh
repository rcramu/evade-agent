#!/bin/sh
# Host wrappers for sink-class and A8-negative Falco captures.
set -eu
ROOT=$(CDPATH= cd -- "$(dirname "$0")/../.." && pwd)
RULES="$ROOT/kernel-lab/rules/evade-lab.yaml"
WORK="$ROOT/kernel-lab/workloads"
IMAGE=${FALCO_IMAGE:-falcosecurity/falco:0.44.1}

sinks="$ROOT/kernel-lab/dumps/live-sinks"
a8="$ROOT/kernel-lab/dumps/live-a8"
mkdir -p "$sinks" "$a8"
rm -f "$sinks/falco.jsonl" "$a8/falco.jsonl"

docker run --rm --privileged --network none --entrypoint /bin/sh \
  -e HOST_ROOT=/host \
  -v /proc:/host/proc:ro \
  -v "$RULES:/etc/falco/rules.d/evade-lab.yaml:ro" \
  -v "$WORK:/workloads:ro" \
  -v "$ROOT/kernel-lab/collectors/falco_sinks_capture.sh:/capture.sh:ro" \
  -v "$sinks:/out" \
  "$IMAGE" \
  /capture.sh >/dev/null
echo "sinks $(wc -l <"$sinks/falco.jsonl" | tr -d ' ') lines"

docker run --rm --privileged --network none --entrypoint /bin/sh \
  -e HOST_ROOT=/host \
  -v /proc:/host/proc:ro \
  -v "$RULES:/etc/falco/rules.d/evade-lab.yaml:ro" \
  -v "$ROOT/kernel-lab/collectors/falco_a8_negative.sh:/capture.sh:ro" \
  -v "$a8:/out" \
  "$IMAGE" \
  /capture.sh >/dev/null
echo "a8-negative $(wc -l <"$a8/falco.jsonl" | tr -d ' ') lines"
