#!/bin/sh
# Run inside falcosecurity/falco:latest (privileged). Capture M1 lab events.
# Writes /out/falco.jsonl. Does not target third-party systems.
set -eu
mkdir -p /lab/secrets /workspace/documents /out
printf 'path-label-only\n' > /lab/secrets/token
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
/bin/sh -c 'cat /lab/secrets/token >/dev/null'
sleep 3
kill "$pid" 2>/dev/null || true
wait "$pid" 2>/dev/null || true
if [ -f /out/falco.raw ]; then
  grep -E 'evade_path|evade_shell|EVADE Lab' /out/falco.raw > /out/falco.jsonl || true
fi
wc -l /out/falco.jsonl /out/falco.raw 2>/dev/null || true
tail -20 /out/falco.stderr || true
