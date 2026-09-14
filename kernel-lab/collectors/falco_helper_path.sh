#!/bin/sh
# A2/A4 product: helper-worker reads the path-label marker. No sockets.
set -eu
mkdir -p /lab/secrets /out
printf 'path-label-only\n' >/lab/secrets/token
printf '#!/bin/sh\ncat -- "$1" >/dev/null\n' >/tmp/helper-worker
chmod +x /tmp/helper-worker

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
/tmp/helper-worker /lab/secrets/token >/dev/null
sleep 3
kill "$pid" 2>/dev/null || true
wait "$pid" 2>/dev/null || true
if [ -f /out/falco.raw ]; then
  grep -E 'evade_path|EVADE Lab Sensitive Path' /out/falco.raw > /out/falco.jsonl || true
fi
wc -l /out/falco.jsonl /out/falco.raw 2>/dev/null || true
