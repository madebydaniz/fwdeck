#!/usr/bin/env bash
set -euo pipefail

binary=${1:-}
if [[ $# -ne 1 || ! -x "$binary" ]]; then
    echo "usage: $0 <fwdeck binary>" >&2
    exit 2
fi

ldd --version
ldd "$binary"
"$binary" --version
"$binary" --help >/dev/null
tmp_dir=$(mktemp -d)
trap 'rm -rf -- "$tmp_dir"' EXIT
"$binary" doctor >"$tmp_dir/doctor.txt"
grep -q '^fwdeck .*doctor$' "$tmp_dir/doctor.txt"
echo 'Clean EL9 runtime: loader, version, help and doctor entrypoint pass'
