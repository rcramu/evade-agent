#!/bin/sh
# Start Tetragon, then stream process_exec while L1 and A6 run for seven agents.
# Writes kernel-lab/dumps/live-tetragon/tetragon.jsonl (lab binaries only).
set -eu
ROOT=$(CDPATH= cd -- "$(dirname "$0")/../.." && pwd)
OUT="$ROOT/kernel-lab/dumps/live-tetragon"
WORK="$ROOT/kernel-lab/workloads"
IMAGE=${TETRAGON_IMAGE:-quay.io/cilium/tetragon:v1.7.0}
NAME=evade-tetragon

mkdir -p "$OUT" "$WORK/bin"
rm -f "$OUT/tetragon.raw" "$OUT/tetra.err"
if [ ! -x "$WORK/bin/kubectl" ]; then
  docker create --name evade-kubectl-tmp rancher/kubectl:v1.31.4 >/dev/null 2>&1 || true
  docker cp evade-kubectl-tmp:/bin/kubectl "$WORK/bin/kubectl" 2>/dev/null || true
  docker rm evade-kubectl-tmp >/dev/null 2>&1 || true
fi

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

docker exec "$NAME" timeout 80 tetra getevents -o json >"$OUT/tetragon.raw" 2>"$OUT/tetra.err" &
stream=$!
sleep 2

for agent in document-assistant coding-agent devops-agent database-agent knowledge-agent ticket-agent mail-agent; do
  img=alpine:3.20
  git_img=${GIT_IMAGE:-alpine/git:latest}
  if [ "$agent" = "coding-agent" ] && docker image inspect "$git_img" >/dev/null 2>&1; then
    img=$git_img
  fi
  for cell in L1 A6; do
    docker run --rm --network none --entrypoint /bin/sh \
      --name "evade-tg-${agent}-${cell}" \
      -v "$WORK:/workloads:ro" \
      "$img" /workloads/named_cell.sh "$agent" "$cell" >/dev/null
  done
done

wait "$stream" || true
docker rm -f "$NAME" >/dev/null 2>&1 || true

python3 - <<'PY' "$OUT/tetragon.raw" "$OUT/tetragon.jsonl"
import json, sys
from pathlib import PurePosixPath
src, dest = sys.argv[1], sys.argv[2]
keep = {
    "document-assistant", "document-reader", "unrelated-init",
    "coding-agent", "git", "test-runner",
    "devops-agent", "kubectl",
    "database-agent", "query-engine",
    "knowledge-agent", "vector-client",
    "ticket-agent", "ticket-client",
    "mail-agent", "mail-client",
}
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
    name = PurePosixPath(str(proc.get("binary") or "")).name
    if name in keep:
        out.append(row)
open(dest, "w", encoding="utf-8").write("".join(json.dumps(r) + "\n" for r in out))
print(f"kept {len(out)} lab process_exec events of {sum(1 for _ in open(src, encoding='utf-8'))} raw lines")
PY
wc -l "$OUT/tetragon.jsonl"
