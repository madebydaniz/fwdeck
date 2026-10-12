#!/usr/bin/env bash
set -euo pipefail
export LC_ALL=C

binary=${1:-}
readonly maximum=2.34
if [[ $# -ne 1 || ! -f "$binary" ]]; then
    echo "usage: $0 <GNU Linux binary>" >&2
    exit 2
fi

if ! info=$(readelf --version-info --wide "$binary"); then
    echo "cannot inspect ELF version requirements: $binary" >&2
    exit 2
fi

# Only imports constrain the runtime; ignore version definitions and symbols.
versions=$(awk '
    /^Version needs section/ { needs = 1; next }
    /^Version (symbols|definition) section/ { needs = 0 }
    needs {
        for (i = 1; i < NF; i++)
            if ($i == "Name:" && $(i + 1) ~ /^GLIBC_/)
                print $(i + 1)
    }
' <<<"$info" | sort -u)

if [[ -z "$versions" ]]; then
    echo "missing GLIBC version requirements: $binary" >&2
    exit 2
fi

while IFS= read -r version; do
    if [[ ! "$version" =~ ^GLIBC_[0-9]+\.[0-9]+(\.[0-9]+)?$ ]]; then
        echo "unsupported GLIBC requirement $version: $binary" >&2
        exit 1
    fi
    required=${version#GLIBC_}
    newest=$(printf '%s\n%s\n' "$maximum" "$required" | sort -V | tail -n 1)
    if [[ "$newest" != "$maximum" ]]; then
        echo "GLIBC requirement $required exceeds $maximum: $binary" >&2
        exit 1
    fi
done <<<"$versions"

printf 'GLIBC requirements <= %s: %s\n' "$maximum" "$binary"
