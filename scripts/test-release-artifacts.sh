#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
readonly checker="$repo_root/scripts/check-release-artifacts.sh"
bash "$checker" "$@"

release_tag=$1
target=$2
dist_dir=$(cd "$3" && pwd)
name="fwdeck-${release_tag}-${target}"
tmp_dir=$(mktemp -d)
trap 'rm -rf -- "$tmp_dir"' EXIT
cp -r "$dist_dir" "$tmp_dir/dist"
mkdir "$tmp_dir/archive" "$tmp_dir/deb"

assert_mismatch() {
    local actual=0 output
    output=$(bash "$checker" "$release_tag" "$target" "$tmp_dir/dist" 2>&1) || actual=$?
    if [[ "$actual" -ne 1 ]]; then
        printf 'expected differing payloads to fail with exit 1, got %s\n%s\n' \
            "$actual" "$output" >&2
        exit 1
    fi
}

# Appending bytes preserves executable behavior while changing the payload.
tar -xzf "$dist_dir/$name.tar.gz" -C "$tmp_dir/archive"
printf '\npayload mismatch\n' >>"$tmp_dir/archive/$name/fwdeck"
tar -czf "$tmp_dir/dist/$name.tar.gz" -C "$tmp_dir/archive" "$name"
assert_mismatch
cp "$dist_dir/$name.tar.gz" "$tmp_dir/dist/$name.tar.gz"

case "$target" in
    x86_64-unknown-linux-gnu) deb_arch=amd64 ;;
    aarch64-unknown-linux-gnu) deb_arch=arm64 ;;
esac
deb_name="fwdeck_${release_tag#v}_${deb_arch}.deb"
data_member=$(ar t "$dist_dir/$deb_name" | grep -E '^data\.tar\.(gz|xz|zst)$')
ar p "$dist_dir/$deb_name" "$data_member" >"$tmp_dir/$data_member"
tar -xf "$tmp_dir/$data_member" -C "$tmp_dir/deb"
printf '\npayload mismatch\n' >>"$tmp_dir/deb/usr/bin/fwdeck"
tar -caf "$tmp_dir/$data_member" -C "$tmp_dir/deb" .
(cd "$tmp_dir" && ar r "dist/$deb_name" "$data_member")
assert_mismatch

echo 'Release artifact contract: matching packages pass; archive/DEB mismatches rejected'
