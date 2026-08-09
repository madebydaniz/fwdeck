#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
readonly repo_root

tmp_dir=$(mktemp -d)
readonly tmp_dir
trap 'rm -rf -- "${tmp_dir}"' EXIT

mkdir -p "${tmp_dir}/bin" "${tmp_dir}/scripts"
cp "${repo_root}/docker-compose.yml" "${tmp_dir}/docker-compose.yml"
cp "${repo_root}/scripts/run-dbus-coverage.sh" "${tmp_dir}/scripts/"
cp "${repo_root}/scripts/check-dbus-coverage.sh" "${tmp_dir}/scripts/"

printf '%s\n' \
    '#!/usr/bin/env bash' \
    'set -euo pipefail' \
    "for arg in \"\$@\"; do" \
    "    if [[ \"\$arg\" == \"run\" ]]; then" \
    '        printf '\''{"data":[{"files":[{"filename":"/workspace/src/infrastructure/firewalld/dbus.rs","summary":{"lines":{"percent":81.86}}}]}]}\n'\'' >target/dbus-coverage-summary.json' \
    '        exit 0' \
    '    fi' \
    'done' \
    >"${tmp_dir}/bin/docker"
chmod +x "${tmp_dir}/bin/docker"

PATH="${tmp_dir}/bin:${PATH}" "${tmp_dir}/scripts/run-dbus-coverage.sh"

echo "D-Bus coverage runner clean-checkout contract: pass"
