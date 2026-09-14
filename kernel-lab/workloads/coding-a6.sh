#!/bin/sh
set -eu
dir=/tmp/evade-coding-a6
mkdir -p "$dir"
cp /workloads/git.sh "$dir/git"
cp /workloads/coding-a6-init.sh "$dir/unrelated-init"
chmod +x "$dir/git" "$dir/unrelated-init"
"$dir/unrelated-init"
