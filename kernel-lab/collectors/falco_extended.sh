#!/bin/sh
# Host wrappers for A2/A4 helper-path and A9 workspace-only Falco captures.
set -eu
ROOT=$(CDPATH= cd -- "$(dirname "$0")/../.." && pwd)
RULES="$ROOT/kernel-lab/rules/evade-lab.yaml"
IMAGE=${FALCO_IMAGE:-falcosecurity/falco:0.44.1}

run_one() {
  cell=$1
  script=$2
  dest="$ROOT/kernel-lab/dumps/live-$cell"
  mkdir -p "$dest"
  rm -f "$dest/falco.jsonl"
  docker run --rm --privileged --network none --entrypoint /bin/sh \
    -e HOST_ROOT=/host \
    -v /proc:/host/proc:ro \
    -v "$RULES:/etc/falco/rules.d/evade-lab.yaml:ro" \
    -v "$ROOT/kernel-lab/collectors/$script:/capture.sh:ro" \
    -v "$dest:/out" \
    "$IMAGE" \
    /capture.sh >/dev/null
  touch "$dest/falco.jsonl"
  echo "$cell $(wc -l <"$dest/falco.jsonl" | tr -d ' ') lines"
}

run_one a2 falco_helper_path.sh
run_one a4 falco_helper_path.sh
run_one a9 falco_a9_legit.sh
