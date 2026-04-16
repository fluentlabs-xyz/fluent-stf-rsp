FROM lukemathwalker/cargo-chef:latest-rust-1-bookworm AS chef
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get -y upgrade && apt-get install -y \
    libclang-dev \
    pkg-config \
    protobuf-compiler \
    && rm -rf /var/lib/apt/lists/*

# Builds a cargo-chef plan
FROM chef AS planner

COPY . .
RUN cargo chef prepare --recipe-path recipe.json

###############################################################################
#                                                                             #
#                                Base Builder                                 #
#                                                                             #
###############################################################################
FROM chef AS builder
COPY --from=planner /app/recipe.json recipe.json

# Install dependencies
RUN apt-get update && apt-get -y upgrade && apt-get install -y jq

# Install Rust Stable
RUN rustup toolchain install stable

# Builds dependencies
RUN cargo chef cook --profile release --recipe-path recipe.json

# Install SP1
RUN curl -L https://sp1.succinct.xyz | bash && \
    ~/.sp1/bin/sp1up -v v6.1.0 && \
    ~/.sp1/bin/cargo-prove prove --version

###############################################################################
#                                                                             #
#                              Proxy Builder                                  #
#                                                                             #
###############################################################################
FROM builder as proxy-builder

ARG NETWORK=mainnet

COPY . .
RUN cargo build --profile release --locked \
    -p proxy \
    --no-default-features \
    --features "${NETWORK}"

RUN cp /app/target/release/proxy /app/proxy

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

COPY --from=proxy-builder /app/proxy /usr/local/bin/proxy

ENV SP1_ELF_PATH=/opt/elfs/sp1-client.elf \
    NITRO_VALIDATOR_ELF_PATH=/opt/elfs/nitro-validator.elf \
    ATTESTATION_STORAGE=/var/lib/proxy/attestation.bin \
    PUBLIC_KEY_STORAGE=/var/lib/proxy/public_key.hex \
    ATTESTATION_REQUEST_ID_STORAGE=/var/lib/proxy/attestation_request_id.hex \
    HOME=/var/lib/proxy

USER nonroot:nonroot
WORKDIR /var/lib/proxy

ENTRYPOINT ["/usr/local/bin/proxy"]
CMD ["--eif_path", "/var/lib/proxy/placeholder.eif"]

###############################################################################
#                                                                             #
#                        Witness-Orchestrator Builder                         #
#                                                                             #
###############################################################################
FROM builder as witness-orchestrator-builder

ARG NETWORK=mainnet

COPY . .
RUN cargo build --profile release --locked \
    -p witness-orchestrator-bin \
    --no-default-features \
    --features "${NETWORK}"

RUN cp /app/target/release/witness-orchestrator /app/witness-orchestrator

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

COPY --from=witness-orchestrator-builder /app/witness-orchestrator /usr/local/bin/witness-orchestrator

ENV FLUENT_DB_PATH=/var/lib/witness/witness_courier.db \
    HOME=/var/lib/witness

USER nonroot:nonroot
WORKDIR /var/lib/witness

ENTRYPOINT ["/usr/local/bin/witness-orchestrator"]