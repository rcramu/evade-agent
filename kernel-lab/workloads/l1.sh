#!/bin/sh
# L1: agent is the parent of document-reader.
set -eu
dir=/tmp/evade-l1
mkdir -p "$dir"
cp /workloads/document-reader.sh "$dir/document-reader"
chmod +x "$dir/document-reader"
cp /workloads/l1-agent.sh "$dir/document-assistant"
chmod +x "$dir/document-assistant"
"$dir/document-assistant"
