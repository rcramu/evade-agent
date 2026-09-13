#!/bin/sh
# Start Tetragon, then stream process_exec while L1 and A6 run.
# Writes kernel-lab/dumps/live-tetragon/tetragon.jsonl (lab binaries only).
set -eu
ROOT=$(CDPATH= cd -- "$(dirname "$0")/../.." && pwd)
OUT="$ROOT/kernel-lab/dumps/live-tetragon"
WORK="$ROOT/kernel-lab/workloads"
IMAGE=${TETRAGON_IMAGE:-quay.io/cilium/tetragon:v1.7.0}
NAME=evade-tetragon

mkdir -p "$OUT"
rm -f "$OUT/tetragon.raw" "$OUT/tetra.err"
docker rm -f "$NAME" >/dev/null 2>&1 || true

docker run -d --name "$NAME" --rm \
  --pid=host --cgroupns=host --privileged \
  "$IMAGE" >/dev/null

i=0
while [ "$i" -lt 40 ]; do
  if docker exec "$NAME" tetra status >/dev/null 2>&1; then
    break
  fi
  i=$((i + 1))
  sleep 1
done

# Stream first, then spawn lab processes so getevents sees them.
docker exec "$NAME" timeout 18 tetra getevents -o json >"$OUT/tetragon.raw" 2>"$OUT/tetra.err" &
stream=$!
sleep 2

docker run --rm --network none --name evade-tg-l1 \
  -v "$WORK:/workloads:ro" \
  alpine:3.20 /bin/sh /workloads/l1.sh >/dev/null

docker run --rm --network none --name evade-tg-a6 \
  -v "$WORK:/workloads:ro" \
  alpine:3.20 /bin/sh /workloads/a6.sh >/dev/null

wait "$stream" || true
docker rm -f "$NAME" >/dev/null 2>&1 || true

python3 - <<'PY' "$OUT/tetragon.raw" "$OUT/tetragon.jsonl"
import json, sys
from pathlib import PurePosixPath
src, dest = sys.argv[1], sys.argv[2]
keep = {"document-assistant", "document-reader", "unrelated-init"}
out = []
for line in open(src, encoding="utf-8"):
    line = line.strip()
    if not line:
        continue
    try:
        row = json.loads(line)
    except json.JSONDecodeError:
        continue
    ev = row.get("process_exec") or {}
    proc = ev.get("process") or {}
    parent = ev.get("parent") or {}
    name = PurePosixPath(str(proc.get("binary") or "")).name
    pname = PurePosixPath(str(parent.get("binary") or "")).name
    if name in keep:
        out.append(row)
open(dest, "w", encoding="utf-8").write("".join(json.dumps(r) + "\n" for r in out))
print(f"kept {len(out)} lab process_exec events of {sum(1 for _ in open(src, encoding='utf-8'))} raw lines")
PY
wc -l "$OUT/tetragon.jsonl"