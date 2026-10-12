#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
readonly checker="${repo_root}/scripts/check-glibc.sh"
tmp_dir=$(mktemp -d)
trap 'rm -rf -- "$tmp_dir"' EXIT

assert_exit() {
    local expected=$1 path=$2 actual=0 output
    output=$(bash "$checker" "$path" 2>&1) || actual=$?
    if [[ "$actual" -ne "$expected" ]]; then
        printf 'expected exit %s, got %s for %s\n%s\n' \
            "$expected" "$actual" "$path" "$output" >&2
        exit 1
    fi
}

printf 'int fixture(void) { return 0; }\n' >"$tmp_dir/library.c"
printf 'extern int fixture(void); int main(void) { return fixture(); }\n' >"$tmp_dir/main.c"

# Real ELF imports catch numeric-ordering mistakes and permissive ABI checks.
for version in 2.9 2.34 2.35 2.39 2.100 PRIVATE; do
    printf 'GLIBC_%s { global: fixture; local: *; };\n' "$version" >"$tmp_dir/versions.map"
    gcc -shared -fPIC "$tmp_dir/library.c" \
        -Wl,--version-script="$tmp_dir/versions.map" -o "$tmp_dir/libfixture.so"
    gcc "$tmp_dir/main.c" -L"$tmp_dir" -lfixture -o "$tmp_dir/fixture-$version"
done

assert_exit 0 "$tmp_dir/fixture-2.9"
assert_exit 0 "$tmp_dir/fixture-2.34"
assert_exit 1 "$tmp_dir/fixture-2.35"
assert_exit 1 "$tmp_dir/fixture-2.39"
assert_exit 1 "$tmp_dir/fixture-2.100"
assert_exit 1 "$tmp_dir/fixture-PRIVATE"
assert_exit 2 "$tmp_dir/missing"
printf 'not an ELF\n' >"$tmp_dir/malformed"
assert_exit 2 "$tmp_dir/malformed"
gcc -c "$tmp_dir/library.c" -o "$tmp_dir/unversioned.o"
assert_exit 2 "$tmp_dir/unversioned.o"
assert_exit 0 "$tmp_dir/libfixture.so"

echo 'GLIBC checker contract: 10 cases pass'
