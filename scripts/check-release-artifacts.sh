#!/usr/bin/env bash
set -euo pipefail

release_tag=${1:-}
target=${2:-}
if [[ $# -ne 3 || ! "$release_tag" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    echo "usage: $0 <vX.Y.Z> <GNU Linux target> <dist directory>" >&2
    exit 2
fi
case "$target" in
    x86_64-unknown-linux-gnu) rpm_arch=x86_64; deb_arch=amd64 ;;
    aarch64-unknown-linux-gnu) rpm_arch=aarch64; deb_arch=arm64 ;;
    *) echo "unsupported GNU release target: $target" >&2; exit 2 ;;
esac

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
dist_dir=$(cd "$3" && pwd)
name="fwdeck-${release_tag}-${target}"
version=${release_tag#v}
tmp_dir=$(mktemp -d)
trap 'rm -rf -- "$tmp_dir"' EXIT
mkdir "$tmp_dir/archive" "$tmp_dir/rpm" "$tmp_dir/deb"

tar -xzf "$dist_dir/$name.tar.gz" -C "$tmp_dir/archive" "$name/fwdeck"
rpm2cpio "$dist_dir/fwdeck-${version}-1.${rpm_arch}.rpm" | \
    (cd "$tmp_dir/rpm" && cpio -idm --quiet --no-absolute-filenames \
        'usr/bin/fwdeck' './usr/bin/fwdeck')

deb="$dist_dir/fwdeck_${version}_${deb_arch}.deb"
data_member=$(ar t "$deb" | grep -E '^data\.tar\.(gz|xz|zst)$')
[[ "$data_member" != *$'\n'* ]]
ar p "$deb" "$data_member" >"$tmp_dir/$data_member"
binary_member=$(tar -tf "$tmp_dir/$data_member" | grep -E '^(\./)?usr/bin/fwdeck$')
[[ "$binary_member" != *$'\n'* ]]
tar -xf "$tmp_dir/$data_member" -C "$tmp_dir/deb" "$binary_member"

archive_binary="$tmp_dir/archive/$name/fwdeck"
cmp "$archive_binary" "$tmp_dir/rpm/usr/bin/fwdeck"
cmp "$archive_binary" "$tmp_dir/deb/usr/bin/fwdeck"

for binary in "$archive_binary" "$tmp_dir/rpm/usr/bin/fwdeck" "$tmp_dir/deb/usr/bin/fwdeck"; do
    bash "$repo_root/scripts/check-glibc.sh" "$binary"
    version_output=$("$binary" --version)
    [[ "$version_output" =~ ^fwdeck\ [0-9]+\.[0-9]+\.[0-9]+ ]]
    "$binary" --help >/dev/null
    "$binary" doctor >"$tmp_dir/doctor.txt"
    grep -q '^fwdeck .*doctor$' "$tmp_dir/doctor.txt"
    "$binary" manpage >"$tmp_dir/fwdeck.1"
    [[ -s "$tmp_dir/fwdeck.1" ]]
    for shell in bash zsh fish; do
        "$binary" completions "$shell" >"$tmp_dir/fwdeck.$shell"
        [[ -s "$tmp_dir/fwdeck.$shell" ]]
    done
done

echo "EL9 release artifacts: identical payloads, GLIBC baseline and startup pass ($target)"
