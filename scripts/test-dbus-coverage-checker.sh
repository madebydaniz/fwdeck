#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
readonly repo_root
readonly checker="${repo_root}/scripts/check-dbus-coverage.sh"

tmp_dir=$(mktemp -d)
readonly tmp_dir
trap 'rm -rf -- "${tmp_dir}"' EXIT

write_report() {
    local path=$1
    local files=$2
    printf '{"data":[{"files":%s}]}\n' "$files" >"$path"
}

assert_exit() {
    local expected=$1
    local report=$2
    local output
    local actual

    set +e
    output=$("$checker" "$report" 2>&1)
    actual=$?
    set -e

    if [[ "$actual" -ne "$expected" ]]; then
        printf 'expected exit %s, got %s for %s\n%s\n' \
            "$expected" "$actual" "$report" "$output" >&2
        exit 1
    fi
}

readonly suffix='/workspace/src/infrastructure/firewalld/dbus.rs'
write_report "${tmp_dir}/passing.json" \
    "[{\"filename\":\"${suffix}\",\"summary\":{\"lines\":{\"percent\":60}}}]"
write_report "${tmp_dir}/below.json" \
    "[{\"filename\":\"${suffix}\",\"summary\":{\"lines\":{\"percent\":59.99}}}]"
write_report "${tmp_dir}/missing.json" \
    '[{"filename":"/workspace/src/lib.rs","summary":{"lines":{"percent":100}}}]'
write_report "${tmp_dir}/duplicate.json" \
    "[{\"filename\":\"${suffix}\",\"summary\":{\"lines\":{\"percent\":80}}},{\"filename\":\"/other/src/infrastructure/firewalld/dbus.rs\",\"summary\":{\"lines\":{\"percent\":80}}}]"
write_report "${tmp_dir}/non-numeric.json" \
    "[{\"filename\":\"${suffix}\",\"summary\":{\"lines\":{\"percent\":\"sixty\"}}}]"
printf '{not-json\n' >"${tmp_dir}/malformed.json"

assert_exit 0 "${tmp_dir}/passing.json"
assert_exit 1 "${tmp_dir}/below.json"
assert_exit 2 "${tmp_dir}/missing.json"
assert_exit 2 "${tmp_dir}/duplicate.json"
assert_exit 2 "${tmp_dir}/non-numeric.json"
assert_exit 2 "${tmp_dir}/malformed.json"

echo "D-Bus coverage checker contract: pass"
