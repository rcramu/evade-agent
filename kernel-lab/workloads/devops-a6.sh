#!/bin/sh
set -eu
dir=/tmp/evade-devops-a6
mkdir -p "$dir"
cp /workloads/kubectl.sh "$dir/kubectl"
cp /workloads/devops-a6-init.sh "$dir/unrelated-init"
chmod +x "$dir/kubectl" "$dir/unrelated-init"
"$dir/unrelated-init"
