#!/bin/sh
set -eu
dir=/tmp/evade-coding-l1
mkdir -p "$dir"
cp /workloads/git.sh "$dir/git"
cp /workloads/test-runner.sh "$dir/test-runner"
cp /workloads/coding-l1-agent.sh "$dir/coding-agent"
chmod +x "$dir/git" "$dir/test-runner" "$dir/coding-agent"
"$dir/coding-agent"
