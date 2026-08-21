#!/usr/bin/env bash
set -euo pipefail

report=${1:-}
if [[ -z "$report" || ! -f "$report" ]]; then
    echo "usage: $0 <llvm-cov-summary.json>" >&2
    exit 2
fi

if ! command -v jq >/dev/null 2>&1; then
    echo "jq is required to enforce critical-path coverage" >&2
    exit 2
fi

check_file() {
    local suffix=$1
    local minimum=$2
    local label=$3
    local actual

    actual=$(jq -er --arg suffix "$suffix" '
        [.data[0].files[]
            | select(.filename | endswith($suffix))
            | .summary.lines.percent]
        | if length == 1 and .[0] != null
          then .[0]
          else error("expected exactly one coverage entry for " + $suffix)
          end
    ' "$report")

    printf '%s line coverage: %.2f%% (minimum %.2f%%)\n' "$label" "$actual" "$minimum"
    if ! jq -en \
        --argjson actual "$actual" \
        --argjson minimum "$minimum" \
        '$actual >= $minimum' >/dev/null; then
        echo "$label coverage is below the required minimum" >&2
        exit 1
    fi
}

check_file "/src/application/engine.rs" 90 "engine"
check_file "/src/application/refresh_scheduler.rs" 95 "refresh scheduler"
check_file "/src/domain/capability.rs" 95 "traffic capability matrix"
check_file "/src/domain/operation_effect.rs" 95 "operation effect classifier"
check_file "/src/domain/traffic_test.rs" 95 "traffic truth contracts"
check_file "src/infrastructure/firewalld/detail_priority.rs" 95 "detail priority policy"
check_file "/src/infrastructure/rollback.rs" 85 "systemd rollback guard"
check_file "/src/infrastructure/snapshot_store.rs" 80 "snapshot store"
