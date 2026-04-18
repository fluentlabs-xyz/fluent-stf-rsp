# Reth Succinct Processor (RSP)

A minimal implementation of generating zero-knowledge proofs of EVM block execution
using [Reth](https://github.com/paradigmxyz/reth). Supports both Ethereum and OP Stack.

> [!CAUTION]
>
> This repository is still an active work-in-progress and is not audited or meant for production usage.

## Build & Test

- `cargo build --all --all-targets` — build all workspace crates
- `cargo test --all -- --skip test_in_zkvm --nocapture` — run tests (skips zkVM tests requiring the SP1 toolchain)
- `cargo clippy --all --all-targets -- -D warnings` — lint
- `cargo fmt --all` — format (use `--check` to verify)
- `make build-client` — build SP1 client ELF (dev, requires `sp1up`)
- `make build-client-docker` — reproducible SP1 ELF build via Docker (prod)
- `make build-enclave` — build AWS Nitro `.eif` image
- `make build-proxy` — build the proxy binary

## Production Docker Compose

The [`docker-compose.yml`](docker-compose.yml) at the repo root runs the `proxy`
and `witness-orchestrator` as two containers on a single EC2 host. The AWS Nitro
Enclave itself runs **outside** Docker — the proxy talks to it over VSOCK via
the host's `/dev/vsock` device.

### Prerequisites

- AWS EC2 instance with Nitro Enclave support, `nitro-cli` installed (any
  version, only needed to *run* the enclave), and the allocator service
  running.
- Host-side Fluent node exposing its gRPC witness server on `127.0.0.1:10000`.
- L2 RPC available (set via `RPC_URL`).
- Build-time: `cargo-prove` (SP1 toolchain) for the SP1 ELF, and
  [Nix](https://determinate.systems/nix/) for the enclave (the flake
  pins every PCR0-relevant input: nixpkgs, rust toolchain, kernel/init/nsm
  blobs via monzo/aws-nitro-util, source tree). Install Nix with:
  `curl -fsSL https://install.determinate.systems/nix | sh -s -- install`.

### One-shot build and run

```bash
cp .env.example .env
chmod 600 .env
# edit .env — fill in API_KEY, L1_SUBMITTER_KEY, RPC_URL, L1_RPC_URL,
# L1_ROLLUP_ADDR, NITRO_VERIFIER_ADDR, etc.

# Build reproducible ELFs + both docker images
make compose-build NETWORK=mainnet

# Start the enclave (outside docker) — the proxy expects CID 10
nitro-cli run-enclave --eif-path rsp-client-enclave-mainnet.eif \
    --cpu-count 2 --memory 512 --enclave-cid 10

# Start proxy + witness-orchestrator
make compose-up

# Tail logs
make compose-logs
```

### Operational notes

- **Secrets**: `.env` holds `API_KEY` and `L1_SUBMITTER_KEY` in plaintext. It is
  gitignored; `chmod 600` so only root/owner can read it. The values are visible
  via `docker inspect fluent-proxy` to anyone with docker socket access — run
  compose as root on a dedicated host.
- **State persistence**: proxy's attestation cache and orchestrator's SQLite DB
  live in named docker volumes (`fluent_proxy_state`, `fluent_witness_state`).
  `compose down` preserves them; use `compose down -v` to wipe.
- **Healthcheck is TCP-only**: the proxy container is considered "healthy"
  when it binds port 8080. This does not verify enclave handshake success.
  Check `docker compose logs proxy` after boot to confirm the vsock handshake.
- **Reproducibility matters**: always use `make compose-build` (chains
  `build-client-docker` + `build-nitro-validator-docker`), never
  `build-client` directly — non-reproducible ELFs change PCR0 and break
  enclave attestation. The enclave PCR0 is pinned entirely by
  [flake.nix](flake.nix) (nixpkgs rev, rust toolchain, kernel/init blobs
  from monzo/aws-nitro-util, source tree) — any machine with Nix produces
  the same PCR0.
- **Updating**: edit `.env` → `make compose-up` (compose recreates changed
  services). For image updates, `make compose-build && make compose-up`.
- **Gotchas**:
  - Hardcoded enclave CID is 10 (proxy side) and 5005 is the VSOCK port;
    `/dev/vsock` is passed through as a device.
  - Docker < 20.10.10 seccomp profile blocks `AF_VSOCK` — host must run a
    recent Docker daemon.
  - `RUSTFLAGS="-C target-cpu=native"` in [Makefile](Makefile) makes the
    `build-proxy` dev target non-portable across CPU generations — the
    compose build uses `build-client-docker` instead, which is reproducible.
