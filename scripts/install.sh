#!/usr/bin/env bash
set -euo pipefail

OWNER="madebydaniz"
REPO="fwdeck"
BINARY_NAME="fwdeck"
WORKFLOW_IDENTITY_REGEX='^https://github.com/madebydaniz/fwdeck/\.github/workflows/release-binaries\.yml@refs/tags/.+$'
OIDC_ISSUER="https://token.actions.githubusercontent.com"

VERSION=""
INSTALL_DIR=""
VERIFY_SIGNATURE="true"

usage() {
  cat <<USAGE
Usage: install.sh [options]

Options:
  --version <vX.Y.Z|X.Y.Z>   Install a specific release (default: latest)
  --install-dir <path>       Target bin directory (default: ~/.local/bin or /usr/local/bin)
  --no-verify-signature      Skip cosign signature verification (not recommended)
  -h, --help                 Show help

Checksum verification is always enabled. Signature verification uses Cosign
keyless (Sigstore) and needs the \`cosign\` binary on PATH.
USAGE
}

require_tool() {
  local tool="$1"
  if ! command -v "$tool" >/dev/null 2>&1; then
    echo "error: required tool '$tool' was not found" >&2
    exit 1
  fi
}

resolve_latest_tag() {
  local api_url="https://api.github.com/repos/${OWNER}/${REPO}/releases/latest"
  local tag
  tag="$(curl -fsSL "$api_url" | grep -m1 '"tag_name"' | sed -E 's/.*"([^"]+)".*/\1/')"
  if [[ -z "$tag" ]]; then
    echo "error: could not resolve the latest release tag" >&2
    exit 1
  fi
  printf '%s' "$tag"
}

detect_libc() {
  # musl systems (Alpine, postmarketOS, …) have no glibc loader; the static
  # musl build is the one that runs there.
  if [[ -e /lib/ld-musl-x86_64.so.1 || -e /lib/ld-musl-aarch64.so.1 ]]; then
    printf 'musl'
  elif command -v ldd >/dev/null 2>&1 && ldd --version 2>&1 | grep -qi musl; then
    printf 'musl'
  else
    printf 'gnu'
  fi
}

detect_target() {
  local os arch libc
  os="$(uname -s)"
  arch="$(uname -m)"
  libc="$(detect_libc)"
  if [[ "$os" != "Linux" ]]; then
    echo "error: fwdeck manages firewalld and runs on Linux only (detected: $os)" >&2
    exit 1
  fi
  case "$arch" in
    x86_64) printf 'x86_64-unknown-linux-%s' "$libc" ;;
    aarch64 | arm64) printf 'aarch64-unknown-linux-%s' "$libc" ;;
    *)
      echo "error: unsupported architecture '$arch'" >&2
      exit 1
      ;;
  esac
}

resolve_install_dir() {
  if [[ -n "$INSTALL_DIR" ]]; then
    printf '%s' "$INSTALL_DIR"
    return
  fi
  if [[ -d "${HOME}/.local/bin" || ! -w /usr/local/bin ]]; then
    printf '%s' "${HOME}/.local/bin"
  else
    printf '%s' "/usr/local/bin"
  fi
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --version)
      VERSION="$2"
      shift 2
      ;;
    --install-dir)
      INSTALL_DIR="$2"
      shift 2
      ;;
    --no-verify-signature)
      VERIFY_SIGNATURE="false"
      shift
      ;;
    -h | --help)
      usage
      exit 0
      ;;
    *)
      echo "error: unknown option '$1'" >&2
      usage >&2
      exit 1
      ;;
  esac
done

require_tool curl
require_tool tar
require_tool sha256sum
if [[ "$VERIFY_SIGNATURE" == "true" ]]; then
  require_tool cosign
fi

TAG="${VERSION:-$(resolve_latest_tag)}"
# Normalize X.Y.Z to vX.Y.Z.
if [[ "$TAG" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  TAG="v${TAG}"
fi
if [[ ! "$TAG" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  echo "error: unexpected version '$TAG' (expected vX.Y.Z)" >&2
  exit 1
fi

TARGET="$(detect_target)"
ASSET="fwdeck-${TAG}-${TARGET}.tar.gz"
BASE_URL="https://github.com/${OWNER}/${REPO}/releases/download/${TAG}"

WORKDIR="$(mktemp -d)"
trap 'rm -rf "$WORKDIR"' EXIT
cd "$WORKDIR"

echo "downloading ${ASSET} (${TAG})"
curl -fsSLO "${BASE_URL}/${ASSET}"
curl -fsSLO "${BASE_URL}/checksums.txt"

if [[ "$VERIFY_SIGNATURE" == "true" ]]; then
  echo "verifying checksums signature (cosign keyless)"
  curl -fsSLO "${BASE_URL}/checksums.txt.bundle"
  cosign verify-blob \
    --bundle checksums.txt.bundle \
    --certificate-identity-regexp "$WORKFLOW_IDENTITY_REGEX" \
    --certificate-oidc-issuer "$OIDC_ISSUER" \
    checksums.txt
else
  echo "warning: skipping cosign signature verification" >&2
fi

echo "verifying archive checksum"
grep " ${ASSET}\$" checksums.txt | sha256sum -c -

tar -xzf "$ASSET"
EXTRACTED="fwdeck-${TAG}-${TARGET}"

BIN_DIR="$(resolve_install_dir)"
mkdir -p "$BIN_DIR"
install -m 0755 "${EXTRACTED}/${BINARY_NAME}" "${BIN_DIR}/${BINARY_NAME}"

echo "installed ${BINARY_NAME} ${TAG} to ${BIN_DIR}/${BINARY_NAME}"
echo
echo "shell completions and the man page are inside the archive:"
echo "  ${EXTRACTED}/completions/  ${EXTRACTED}/fwdeck.1"
echo "or generate them any time: fwdeck completions <shell> / fwdeck manpage"
if ! command -v "$BINARY_NAME" >/dev/null 2>&1; then
  echo "note: ${BIN_DIR} is not on your PATH"
fi
