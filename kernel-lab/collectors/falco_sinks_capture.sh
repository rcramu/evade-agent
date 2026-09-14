#!/bin/sh
# Falco capture of Table C.1 sink process names. No sockets. Lab names only.
set -eu
mkdir -p /tmp/evade-sinks /out
cp /workloads/exfil-sink.sh /tmp/evade-sinks/exfil-sink
cp /workloads/paste-host.sh /tmp/evade-sinks/paste-host
chmod +x /tmp/evade-sinks/exfil-sink /tmp/evade-sinks/paste-host

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
/tmp/evade-sinks/exfil-sink
/tmp/evade-sinks/paste-host
sleep 3
kill "$pid" 2>/dev/null || true
wait "$pid" 2>/dev/null || true
if [ -f /out/falco.raw ]; then
  grep -E 'evade_sink|EVADE Lab Sink' /out/falco.raw > /out/falco.jsonl || true
fi
wc -l /out/falco.jsonl /out/falco.raw 2>/dev/null || true
