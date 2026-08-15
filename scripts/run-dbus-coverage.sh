#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
readonly repo_root
readonly report="${repo_root}/target/dbus-coverage-summary.json"
readonly report_dir="${report%/*}"
compose=(docker compose -f "${repo_root}/docker-compose.yml")
run_args=(run --rm)

if [[ -n "${FWDECK_CARGO_REGISTRY:-}" ]]; then
    if [[ ! -d "$FWDECK_CARGO_REGISTRY" ]]; then
        echo "FWDECK_CARGO_REGISTRY must name an existing directory" >&2
        exit 2
    fi
    run_args+=(
        -e CARGO_HOME=/ci-cargo
        -v "${FWDECK_CARGO_REGISTRY}:/ci-cargo/registry:ro"
    )
fi

mkdir -p "$report_dir"
if [[ -f "$report" ]]; then
    rm -- "$report"
fi

cd "$repo_root"
"${compose[@]}" build dev-coverage
"${compose[@]}" "${run_args[@]}" dev-coverage \
    cargo llvm-cov --offline --locked --features dbus \
    --test real_firewalld --json --summary-only \
    --output-path target/dbus-coverage-summary.json -- \
    --ignored --test-threads=1

"${repo_root}/scripts/check-dbus-coverage.sh" "$report"
