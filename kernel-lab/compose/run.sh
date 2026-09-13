#!/bin/sh
# Start Phase 2 compose. Token stays in the environment only.
set -eu
ROOT=$(CDPATH= cd -- "$(dirname "$0")/../.." && pwd)
COMPOSE="$ROOT/kernel-lab/compose"
LIVE="$ROOT/kernel-lab/dumps/live-mcp"
mkdir -p "$COMPOSE/certs" "$LIVE"
rm -f "$LIVE/agent.ok" "$LIVE/observer.jsonl" "$LIVE/mcp-live.jsonl"
PYTHONPATH="$ROOT/src" python3 - <<'PY' "$COMPOSE/certs"
import sys
from pathlib import Path
from evadeagent.kernel_lab.mcp_tls import write_lab_certs
write_lab_certs(Path(sys.argv[1]))
print("wrote lab certificates (self-signed, one day)")
PY
TOKEN=$(python3 -c 'import secrets; print(secrets.token_urlsafe(32))')
export EVADE_MCP_TOKEN="$TOKEN"
cd "$COMPOSE"
docker compose down >/dev/null 2>&1 || true
docker compose pull
docker compose up -d
i=0
while [ "$i" -lt 90 ]; do
  if [ -f "$LIVE/agent.ok" ] && [ -f "$LIVE/observer.jsonl" ]; then
    break
  fi
  i=$((i + 1))
  sleep 1
done
docker compose logs --no-color agent mcp observer || true
ok=1
if [ -f "$LIVE/agent.ok" ] && [ -f "$LIVE/mcp-live.jsonl" ] && [ -f "$LIVE/observer.jsonl" ]; then
  ok=0
fi
docker compose down
unset EVADE_MCP_TOKEN
ls -l "$LIVE" || true
exit "$ok"
