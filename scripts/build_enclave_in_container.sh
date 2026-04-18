#!/usr/bin/env bash
# build_enclave_in_container.sh — run the entire enclave build inside a pinned
# builder container. PCR0 is determined by the builder image's digest plus the
# source tree, not by the host's nitro-cli / docker / buildx versions.
#
# Usage:
#   NETWORK=mainnet scripts/build_enclave_in_container.sh
#
# Host requirements:
#   - docker daemon (any version) reachable at /var/run/docker.sock
#   - this repo checked out
#
# Everything else (nitro-cli 1.4.2, kernel+init+nsm blobs, docker CLI 25.0.13,
# buildx v0.21.2) is baked into the builder image. To change a pinned tool
# version, edit docker/nitro-builder.Dockerfile and rebuild the builder.

set -euo pipefail

NETWORK="${NETWORK:-mainnet}"
case "$NETWORK" in
    mainnet|testnet|devnet) ;;
    *) echo "NETWORK must be mainnet|testnet|devnet (got '$NETWORK')" >&2; exit 1 ;;
esac

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BUILDER_IMAGE="fluent-nitro-builder:1.4.2"
BUILDER_DOCKERFILE="docker/nitro-builder.Dockerfile"

EIF="rsp-client-enclave-${NETWORK}.eif"
BINARY="rsp-client"

# Always let docker decide: layer cache short-circuits no-op builds, but any
# change to the Dockerfile triggers a rebuild. Avoids stale images when the
# tag stays the same but the Dockerfile was edited.
echo "Ensuring builder image $BUILDER_IMAGE is up to date..."
docker build -f "$REPO_ROOT/$BUILDER_DOCKERFILE" -t "$BUILDER_IMAGE" "$REPO_ROOT"

BUILDER_DIGEST="$(docker image inspect "$BUILDER_IMAGE" --format '{{.Id}}')"
echo "Using builder: $BUILDER_IMAGE ($BUILDER_DIGEST)"

SOURCE_DATE_EPOCH=1776512613

# Run build inside the pinned container. Host docker socket is mounted so
# buildx can drive the daemon; nitro-cli consumes the resulting image via the
# same socket. The kernel/init/nsm blobs come from the container's pinned
# /usr/share/nitro_enclaves/blobs/ — independent of host.
docker run --rm \
    -v "$REPO_ROOT:/src" \
    -v /var/run/docker.sock:/var/run/docker.sock \
    -e NETWORK="$NETWORK" \
    -e SOURCE_DATE_EPOCH="$SOURCE_DATE_EPOCH" \
    -e BINARY="$BINARY" \
    -e EIF="$EIF" \
    -w /src \
    "$BUILDER_IMAGE" \
    -c '
        set -euo pipefail

        docker buildx build \
            --no-cache \
            -f Dockerfile.enclave \
            --build-arg NETWORK="$NETWORK" \
            --output type=docker,rewrite-timestamp=true \
            -t "$BINARY:$NETWORK" .

        nitro-cli build-enclave \
            --docker-uri "$BINARY:$NETWORK" \
            --output-file "$EIF" \
            > "$EIF.pcrs.json"

        cat "$EIF.pcrs.json" | jq -r ".Measurements.PCR0"
    '

echo ""
echo "EIF: $REPO_ROOT/$EIF"
echo "PCRs: $REPO_ROOT/$EIF.pcrs.json"

python3 "$REPO_ROOT/scripts/update_expected_pcr0.py" \
    "$REPO_ROOT/$EIF.pcrs.json" \
    "$REPO_ROOT/bin/aws-nitro-validator/src/lib.rs" \
    "$NETWORK"