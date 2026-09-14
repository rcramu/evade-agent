#!/bin/sh
# Spawn named lab binaries for one agent and cell (L1 or A6).
# Usage: named_cell.sh <agent> <L1|A6>
set -eu
agent=${1:?agent}
cell=${2:?cell}
dir=/tmp/evade/${agent}/${cell}
mkdir -p "$dir"

child_for() {
  case $1 in
    document-assistant) echo document-reader ;;
    coding-agent) echo git ;;
    devops-agent) echo kubectl ;;
    database-agent) echo query-engine ;;
    knowledge-agent) echo vector-client ;;
    ticket-agent) echo ticket-client ;;
    mail-agent) echo mail-client ;;
    *) echo child ;;
  esac
}

child=$(child_for "$agent")
cp /workloads/child.sh "$dir/$child"
chmod +x "$dir/$child"
if [ "$agent" = "coding-agent" ]; then
  cp /workloads/test-runner.sh "$dir/test-runner"
  chmod +x "$dir/test-runner"
  if command -v git >/dev/null 2>&1; then
    mkdir -p /tmp/evade-repo
    git -C /tmp/evade-repo init >/dev/null 2>&1 || true
    printf '#!/bin/sh\nexec git -C /tmp/evade-repo status >/dev/null\n' >"$dir/git"
    chmod +x "$dir/git"
  fi
fi
if [ "$agent" = "devops-agent" ] && [ -x /workloads/bin/kubectl ]; then
  cp /workloads/bin/kubectl "$dir/kubectl"
  chmod +x "$dir/kubectl"
  printf '#!/bin/sh\nexec "$(dirname "$0")/kubectl" version --client >/dev/null 2>&1 || true\n' >"$dir/kubectl-run"
fi

if [ "$cell" = "A6" ]; then
  printf '#!/bin/sh\n"$(dirname "$0")/%s"\n' "$child" >"$dir/unrelated-init"
  chmod +x "$dir/unrelated-init"
  "$dir/unrelated-init"
  exit 0
fi

printf '#!/bin/sh\n"$(dirname "$0")/%s"\n' "$child" >"$dir/$agent"
if [ "$agent" = "coding-agent" ]; then
  printf '#!/bin/sh\n"$(dirname "$0")/git"\n"$(dirname "$0")/test-runner"\n' >"$dir/$agent"
fi
chmod +x "$dir/$agent"
"$dir/$agent"
