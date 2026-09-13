#!/bin/sh
# A6: reader parent is unrelated-init, not the agent.
set -eu
dir=/tmp/evade-a6
mkdir -p "$dir"
cp /workloads/document-reader.sh "$dir/document-reader"
chmod +x "$dir/document-reader"
cp /workloads/a6-init.sh "$dir/unrelated-init"
chmod +x "$dir/unrelated-init"
"$dir/unrelated-init"
