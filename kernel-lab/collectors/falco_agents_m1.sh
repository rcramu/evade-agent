#!/bin/sh
# Independent Falco 0.44.1 M1 capture per Section 8 agent.
# Each run is its own container. Path label /lab/secrets/token is not a secret.
set -eu
ROOT=$(CDPATH= cd -- "$(dirname "$0")/../.." && pwd)
OUT="$ROOT/kernel-lab/dumps/live-m1"
RULES="$ROOT/kernel-lab/rules/evade-lab.yaml"
CAPTURE="$ROOT/kernel-lab/collectors/falco_m1_capture.sh"
IMAGE=${FALCO_IMAGE:-falcosecurity/falco:0.44.1}

for agent in document-assistant coding-agent devops-agent database-agent knowledge-agent ticket-agent mail-agent; do
  dest="$OUT/agents/$agent"
  mkdir -p "$dest"
  rm -f "$dest/falco.jsonl" "$dest/falco.raw"
  docker run --rm --privileged --network none --entrypoint /bin/sh \
    -e HOST_ROOT=/host \
    -v /proc:/host/proc:ro \
    -v "$RULES:/etc/falco/rules.d/evade-lab.yaml:ro" \
    -v "$CAPTURE:/capture.sh:ro" \
    -v "$dest:/out" \
    "$IMAGE" \
    /capture.sh >/dev/null
  echo "wrote $dest/falco.jsonl ($(wc -l <"$dest/falco.jsonl" | tr -d ' ') lines) agent=$agent"
done
