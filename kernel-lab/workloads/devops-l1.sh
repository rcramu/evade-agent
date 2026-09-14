#!/bin/sh
set -eu
dir=/tmp/evade-devops-l1
mkdir -p "$dir"
cp /workloads/kubectl.sh "$dir/kubectl"
cp /workloads/devops-l1-agent.sh "$dir/devops-agent"
chmod +x "$dir/kubectl" "$dir/devops-agent"
"$dir/devops-agent"
