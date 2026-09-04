#!/usr/bin/env bash
set -euo pipefail

readonly TEST_NAME="semantic_observation_matches_reviewed_seed_and_daemon_oracle"
readonly SERVICES=(dev dev-debian dev-el9)
readonly HOST_CARGO_REGISTRY="${CARGO_HOME:-${HOME}/.cargo}/registry"

image_for_service() {
    case "$1" in
        dev) echo "fwdeck-dev" ;;
        dev-debian) echo "fwdeck-dev-debian" ;;
        dev-el9) echo "fwdeck-dev-el9" ;;
        *)
            echo "unsupported Docker Compose service: $1" >&2
            return 1
            ;;
    esac
}

if [ ! -d "$HOST_CARGO_REGISTRY" ]; then
    echo "missing host Cargo registry: $HOST_CARGO_REGISTRY" >&2
    echo "run 'cargo fetch --locked' before the offline container matrix" >&2
    exit 1
fi

docker compose build "${SERVICES[@]}"

for service in "${SERVICES[@]}"; do
    image_ref="$(image_for_service "$service")"
    image_id="$(docker image inspect --format '{{.Id}}' "$image_ref")"

    printf '\ntraffic-foundation service=%s image=%s\n' "$service" "$image_ref"
    docker image inspect \
        --format 'image_id={{.Id}} repo_digests={{json .RepoDigests}}' \
        "$image_id"
    docker compose run --rm -T \
        -v "$HOST_CARGO_REGISTRY:/root/.cargo/registry" \
        "$service" \
        cargo test --offline --locked --features dbus \
        --test real_firewalld "$TEST_NAME" -- \
        --ignored --exact --test-threads=1 --nocapture
done
