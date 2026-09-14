#!/bin/sh
# A8 product miss: read only a workspace file. Do not open /lab/secrets.
set -eu
mkdir -p /workspace/documents /out
printf 'architecture note\n' > /workspace/documents/note.md

export HOST_ROOT=/host
falco \
  -o json_output=true \
  -o buffered_outputs=false \
  -o http_output.enabled=false \
  -o webserver.enabled=false \
  -o file_output.enabled=true \
  -o file_output.keep_alive=true \
  -o 'file_output.filename=/out/falco.raw' \
  >/out/falco.stdout 2>/out/falco.stderr &
pid=$!
sleep 3
cat /workspace/documents/note.md >/dev/null
sleep 3
kill "$pid" 2>/dev/null || true
wait "$pid" 2>/dev/null || true
if [ -f /out/falco.raw ]; then
  grep -E 'evade_path|evade_shell|evade_sink|EVADE Lab' /out/falco.raw > /out/falco.jsonl || true
fi
wc -l /out/falco.jsonl /out/falco.raw 2>/dev/null || true
