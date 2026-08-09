#!/usr/bin/env bash
set -euo pipefail

readonly minimum=60
report=${1:-}

if [[ -z "$report" || ! -f "$report" ]]; then
    echo "usage: $0 <llvm-cov-summary.json>" >&2
    exit 2
fi

if ! command -v jq >/dev/null 2>&1; then
    echo "jq is required to enforce D-Bus coverage" >&2
    exit 2
fi

if ! actual=$(jq -er '
    [.data[0].files[]
        | select(.filename | endswith("/src/infrastructure/firewalld/dbus.rs"))
        | .summary.lines.percent]
    | if length == 1 and (.[0] | type) == "number"
      then .[0]
      else error("expected exactly one numeric D-Bus coverage entry")
      end
' "$report"); then
    echo "invalid D-Bus coverage report" >&2
    exit 2
fi

printf 'D-Bus adapter line coverage: %.2f%% (minimum %.2f%%)\n' "$actual" "$minimum"
if ! jq -en \
    --argjson actual "$actual" \
    --argjson minimum "$minimum" \
    '$actual >= $minimum' >/dev/null; then
    echo "D-Bus adapter coverage is below the required minimum" >&2
    exit 1
fi
