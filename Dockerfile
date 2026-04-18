FROM lukemathwalker/cargo-chef:latest-rust-1-bookworm AS chef
WORKDIR /app

# System dependencies. Intentionally no `apt-get upgrade` — it makes builds
# non-reproducible across days (different package versions appear over time).
RUN apt-get update && apt-get install -y --no-install-recommends \
    libclang-dev \
    pkg-config \
    protobuf-compiler \
    libprotobuf-dev \
    jq \
    && rm -rf /var/lib/apt/lists/*

# Builds a cargo-chef plan. Copy only what chef needs to read manifests —
# avoids invalidating recipe.json when unrelated files (ELFs, bin/client,
# bin/aws-nitro-validator) change.
FROM chef AS planner

COPY Cargo.toml Cargo.lock ./
COPY crates/ crates/
COPY bin/proxy/ bin/proxy/
COPY bin/witness-orchestrator/ bin/witness-orchestrator/
RUN cargo chef prepare --recipe-path recipe.json

###############################################################################
#                                                                             #
#                              Combined Builder                               #
#                                                                             #
# Compiles proxy + witness-orchestrator in one cargo invocation so that       #
# shared workspace crates (rsp-host-executor, fluent-stf-primitives, etc)     #
# are compiled once, not per-binary.                                          #
###############################################################################
FROM chef AS builder

ARG NETWORK=mainnet

COPY --from=planner /app/recipe.json recipe.json

# Pre-downloaded genesis cache. crates/primitives/build.rs resolves its cache
# dir via directories::ProjectDirs — on Linux with HOME=/root it lands here.
# Without this COPY, build.rs would HTTPS-pull three genesis.json.gz files
# from GitHub on every cold build.
COPY .docker-cache/genesis /root/.cache/fluent/genesis

# Cook deps with the SAME feature flags as the final cargo build, otherwise
# feature unification forces partial recompilation during the real build.
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    --mount=type=cache,target=/app/target \
    cargo chef cook --profile release --recipe-path recipe.json \
        --no-default-features --features "${NETWORK}" \
        -p proxy -p witness-orchestrator-bin

# Application source. trusted_setup.txt is pulled via include_bytes! in
# bin/proxy/src/main.rs; the file ships with bin/client but is read at
# compile time from here.
COPY Cargo.toml Cargo.lock ./
COPY crates/ crates/
COPY bin/proxy/ bin/proxy/
COPY bin/witness-orchestrator/ bin/witness-orchestrator/
COPY bin/client/trusted_setup.txt bin/client/trusted_setup.txt

# Single cargo build — compiles both binaries against a unified dep graph.
# The `cp` must run inside the same RUN as cargo build because /app/target
# is a cache mount (not a layer-visible directory).
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    --mount=type=cache,target=/app/target \
    cargo build --profile release --locked \
        -p proxy -p witness-orchestrator-bin \
        --no-default-features --features "${NETWORK}" \
    && cp /app/target/release/proxy /app/proxy \
    && cp /app/target/release/witness-orchestrator /app/witness-orchestrator

###############################################################################
#                                                                             #
#                            Proxy Runtime Prep                               #
#                                                                             #
###############################################################################
# Distroless has no shell / mkdir / chown, so we prepare writable directories
# with correct ownership in a throwaway debian stage and COPY --from=prep them.
# nonroot in distroless is UID 65532.
FROM debian:bookworm-slim AS rsp-proxy-prep
RUN mkdir -p /out/var/lib/proxy /out/opt/elfs && \
    chown -R 65532:65532 /out/var/lib/proxy

###############################################################################
#                                                                             #
#                              Proxy Runtime                                  #
#                                                                             #
###############################################################################
FROM gcr.io/distroless/cc-debian12:nonroot AS rsp-proxy

ARG NETWORK=mainnet

# busybox (static) for the TCP healthcheck — distroless has no shell/nc.
# ~1MB overhead, single binary, musl-static.
COPY --from=busybox:1.37.0-musl /bin/busybox /busybox

COPY --from=rsp-proxy-prep --chown=65532:65532 /out/var/lib/proxy /var/lib/proxy
COPY --from=rsp-proxy-prep /out/opt/elfs /opt/elfs

COPY rsp-client-${NETWORK}.elf          /opt/elfs/sp1-client.elf
COPY nitro-validator-${NETWORK}.elf     /opt/elfs/nitro-validator.elf

COPY --from=builder /app/proxy /usr/local/bin/proxy

ENV SP1_ELF_PATH=/opt/elfs/sp1-client.elf \
    NITRO_VALIDATOR_ELF_PATH=/opt/elfs/nitro-validator.elf \
    PROXY_DB_PATH=/var/lib/proxy/proxy.db \
    HOME=/var/lib/proxy

USER nonroot:nonroot
WORKDIR /var/lib/proxy

ENTRYPOINT ["/usr/local/bin/proxy"]

###############################################################################
#                                                                             #
#                      Witness-Orchestrator Runtime Prep                      #
#                                                                             #
###############################################################################
FROM debian:bookworm-slim AS rsp-witness-orchestrator-prep
RUN mkdir -p /out/var/lib/witness && \
    chown -R 65532:65532 /out/var/lib/witness

###############################################################################
#                                                                             #
#                       Witness-Orchestrator Runtime                          #
#                                                                             #
###############################################################################
FROM gcr.io/distroless/cc-debian12:nonroot AS rsp-witness-orchestrator

COPY --from=rsp-witness-orchestrator-prep --chown=65532:65532 /out/var/lib/witness /var/lib/witness

COPY --from=builder /app/witness-orchestrator /usr/local/bin/witness-orchestrator

ENV FLUENT_DB_PATH=/var/lib/witness/witness_courier.db \
    HOME=/var/lib/witness

USER nonroot:nonroot
WORKDIR /var/lib/witness

ENTRYPOINT ["/usr/local/bin/witness-orchestrator"]
