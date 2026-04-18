.PHONY: build-client build-client-docker build-nitro-validator build-nitro-validator-docker \
        build-enclave build-enclave-docker build-proxy run run-sp1-only run-enclave clean help \
        compose-build compose-up compose-down compose-logs download-genesis-cache

# ─── Paths ────────────────────────────────────────────────────────────────────
CLIENT_DIR   := bin/client
PROXY_DIR    := bin/proxy

# ─── Docker Compose (v2 plugin or standalone) ─────────────────────────────────
DOCKER_COMPOSE := $(shell docker compose version >/dev/null 2>&1 && echo "docker compose" || echo "docker-compose")

# ─── Network (mainnet | testnet | devnet) ────────────────────────────────────
NETWORK      ?= mainnet
ifeq ($(filter $(NETWORK),mainnet testnet devnet),)
$(error NETWORK must be one of: mainnet, testnet, devnet (got '$(NETWORK)'))
endif

# ─── Nitro / enclave (network-tagged artifacts) ───────────────────────────────
TARGET       := x86_64-unknown-linux-musl
BINARY       := rsp-client
EIF          := rsp-client-enclave-$(NETWORK).eif
ELF          := rsp-client-$(NETWORK).elf

# ─── Nitro validator (attestation proving) ────────────────────────────────────
NITRO_VALIDATOR_DIR := bin/aws-nitro-validator
NITRO_VALIDATOR_ELF := nitro-validator-$(NETWORK).elf

# ─── Config (override via env or CLI) ─────────────────────────────────────────
EIF_PATH     ?= $(EIF)
ELF_PATH     ?= $(ELF)
API_KEY      ?= secret
LISTEN_ADDR  ?= 0.0.0.0:8080
SP1_PROVER   ?= network          # cpu | network
RUST_LOG 	 ?= info

# ─── SP1 ELF ──────────────────────────────────────────────────────────────────

## Quick ELF build (dev)
build-client:
	cd $(CLIENT_DIR) && cargo prove build \
		--elf-name $(ELF) \
		--locked \
		--output-directory ../../ \
		--no-default-features \
		--features "sp1 $(NETWORK)"

## Reproducible ELF build via Docker (prod)
build-client-docker:
	cd $(CLIENT_DIR) && cargo prove build \
		--elf-name $(ELF) \
		--locked \
		--output-directory ../../ \
		--workspace-directory ../../ \
		--docker \
		--no-default-features \
		--features "sp1 $(NETWORK)"

# ─── Nitro validator ELF (attestation proving) ───────────────────────────────

## Build nitro-validator ELF (dev)
build-nitro-validator:
	cd $(NITRO_VALIDATOR_DIR) && cargo prove build \
		--elf-name $(NITRO_VALIDATOR_ELF) \
		--locked \
		--output-directory ../../ \
		--no-default-features \
		--features $(NETWORK)

## Reproducible nitro-validator ELF build via Docker (prod)
build-nitro-validator-docker:
	cd $(NITRO_VALIDATOR_DIR) && cargo prove build \
		--elf-name $(NITRO_VALIDATOR_ELF) \
		--locked \
		--output-directory ../../ \
		--workspace-directory ../../ \
		--docker \
		--no-default-features \
		--features $(NETWORK)

# ─── Nitro enclave ────────────────────────────────────────────────────────────

## Build .eif for AWS Nitro reproducibly via Nix + monzo/aws-nitro-util.
## PCR0 is determined entirely by the flake (pinned nixpkgs + nitro-util blobs
## + pinned rust toolchain + git-hashed source tree) — any machine with Nix
## produces the same PCR0. `--impure` is needed on first build to let
## builtins.fetchGit pull git dependencies from the Cargo.lock; subsequent
## builds hit the store. Writes EIF + pcr.json into the repo root and rewrites
## EXPECTED_PCR0 in nitro-validator lib.rs.
build-enclave:
	@command -v nix >/dev/null 2>&1 || { echo "error: nix not installed (see https://determinate.systems/nix)"; exit 1; }
	nix --extra-experimental-features 'nix-command flakes' build .#enclave-$(NETWORK) --impure
	install -m 0644 result/image.eif $(EIF)
	install -m 0644 result/pcr.json  $(EIF).pcrs.json
	@echo "EIF: $(EIF)"
	@echo "PCR0: $$(jq -r .PCR0 $(EIF).pcrs.json)"
	python3 scripts/update_expected_pcr0.py \
		$(EIF).pcrs.json \
		bin/aws-nitro-validator/src/lib.rs \
		$(NETWORK)

## Build .eif inside a docker container running nixos/nix, so the host
## machine doesn't need Nix installed. PCR0 is identical to host-built
## because every input is pinned by the flake. A named docker volume
## (`rsp-nix-store`) persists /nix across runs so subsequent builds are
## incremental. Output is chowned back to the invoking user.
build-enclave-docker:
	@command -v docker >/dev/null 2>&1 || { echo "error: docker not installed"; exit 1; }
	docker volume create rsp-nix-store >/dev/null
	docker run --rm \
		-v rsp-nix-store:/nix \
		-v $(PWD):/work \
		-w /work \
		nixos/nix:latest \
		sh -c "git config --global --add safe.directory /work \
			&& nix --extra-experimental-features 'nix-command flakes' build .#enclave-$(NETWORK) --impure --out-link /tmp/result \
			&& install -m 0644 \$$(readlink -f /tmp/result)/image.eif /work/$(EIF) \
			&& install -m 0644 \$$(readlink -f /tmp/result)/pcr.json  /work/$(EIF).pcrs.json \
			&& chown $(shell id -u):$(shell id -g) /work/$(EIF) /work/$(EIF).pcrs.json"
	@echo "EIF: $(EIF)"
	@echo "PCR0: $$(jq -r .PCR0 $(EIF).pcrs.json)"
	python3 scripts/update_expected_pcr0.py \
		$(EIF).pcrs.json \
		bin/aws-nitro-validator/src/lib.rs \
		$(NETWORK)

## Run enclave locally (debug)
run-enclave:
	nitro-cli run-enclave \
		--eif-path $(EIF_PATH) \
		--cpu-count 4 \
		--memory 4096 \
		--enclave-cid 10 \

# ─── Proxy ────────────────────────────────────────────────────────────────────

build-proxy:
	RUSTFLAGS="-C target-cpu=native" cargo build --release -p proxy \
		--no-default-features --features $(NETWORK)

# ─── Run ──────────────────────────────────────────────────────────────────────

## Build and run with both backends (Nitro + SP1)
run: build-client build-enclave build-proxy
	SP1_ELF_PATH=$(ELF_PATH) \
	SP1_PROVER=$(SP1_PROVER) \
	API_KEY=$(API_KEY) \
	LISTEN_ADDR=$(LISTEN_ADDR) \
	RUST_LOG=$(RUST_LOG) \
	./target/release/proxy --eif_path $(EIF_PATH)

## Build and run with SP1 only (no Nitro)
run-sp1-only: build-client build-proxy
	SP1_ELF_PATH=$(ELF_PATH) \
	SP1_PROVER=network \
	API_KEY=$(API_KEY) \
	LISTEN_ADDR=$(LISTEN_ADDR) \
	RUST_LOG=$(RUST_LOG) \
	NETWORK_PRIVATE_KEY=$(NETWORK_PRIVATE_KEY) \
	./target/release/proxy

clean:
	cargo clean
	rm -f rsp-client-enclave-*.eif rsp-client-enclave-*.eif.pcrs.json \
	      rsp-client-*.elf nitro-validator-*.elf

help:
	@echo "Targets:"
	@echo "  build-client                  Build SP1 ELF (dev)"
	@echo "  build-client-docker           Build SP1 ELF reproducible via Docker (prod)"
	@echo "  build-nitro-validator         Build nitro-validator ELF for attestation proving (dev)"
	@echo "  build-nitro-validator-docker  Build nitro-validator ELF reproducible via Docker (prod)"
	@echo "  build-enclave                 Build AWS Nitro .eif via host Nix"
	@echo "  build-enclave-docker          Build AWS Nitro .eif via nixos/nix docker image (no host Nix needed)"
	@echo "  build-proxy                   Build proxy binary"
	@echo "  run                           Build and run with Nitro + SP1"
	@echo "  run-sp1-only                  Build and run with SP1 only (no Nitro)"
	@echo "  run-enclave                   Run enclave in debug mode"
	@echo "  compose-build                 Build ELFs + docker images for compose stack"
	@echo "  compose-up                    Start proxy + witness-orchestrator in background"
	@echo "  compose-down                  Stop the compose stack (volumes preserved)"
	@echo "  compose-logs                  Tail compose logs"
	@echo "  clean                         Remove build artifacts"
	@echo ""
	@echo "Overrides:"
	@echo "  NETWORK=$(NETWORK)            (mainnet | testnet | devnet)"
	@echo "  EIF_PATH=$(EIF_PATH)"
	@echo "  ELF_PATH=$(ELF_PATH)"
	@echo "  API_KEY=$(API_KEY)"
	@echo "  LISTEN_ADDR=$(LISTEN_ADDR)"
	@echo "  SP1_PROVER=$(SP1_PROVER)"
	@echo ""
	@echo "Examples:"
	@echo "  make build-client                      # mainnet (default)"
	@echo "  make build-client NETWORK=testnet      # testnet"
	@echo "  make build-enclave NETWORK=devnet      # devnet"

# ─── Genesis pre-download (for reproducible docker builds) ───────────────────

GENESIS_CACHE_DIR := .docker-cache/genesis

## Pre-download genesis.json.gz for all networks into build context.
## crates/primitives/build.rs iterates all three networks regardless of active
## feature, so we must pre-download all three — otherwise cargo build inside
## docker would pull from GitHub at compile time.
download-genesis-cache:
	@mkdir -p $(GENESIS_CACHE_DIR)
	@set -e; \
	for spec in \
		"v1.0.0:genesis-mainnet-v1.0.0.json.gz" \
		"v0.3.4-dev:genesis-v0.3.4-dev.json.gz" \
		"v0.5.7:genesis-v0.5.7.json.gz"; do \
		tag=$$(echo $$spec | cut -d: -f1); \
		name=$$(echo $$spec | cut -d: -f2); \
		path="$(GENESIS_CACHE_DIR)/$$name"; \
		if [ ! -f "$$path" ]; then \
			echo "Downloading $$name..."; \
			curl -fsSL -o "$$path.tmp" \
				"https://github.com/fluentlabs-xyz/fluentbase/releases/download/$$tag/$$name" \
				&& mv "$$path.tmp" "$$path"; \
		else \
			echo "Cached: $$name"; \
		fi; \
	done

# ─── Docker Compose ───────────────────────────────────────────────────────────

## Build ELFs (reproducibly, via docker) and docker images for the compose
## stack (one-shot). Uses the *-docker targets so ELFs are identical across
## developer machines — critical because the enclave hardcodes EXPECTED_PCR0
## and a non-reproducible build will cause attestation verification to fail.
##
## Exports DOCKER_BUILDKIT=1 COMPOSE_DOCKER_CLI_BUILD=1 so `docker-compose` v1
## routes through BuildKit (needed for --mount=type=cache in Dockerfile).
compose-build: download-genesis-cache build-client-docker build-nitro-validator-docker
	DOCKER_BUILDKIT=1 COMPOSE_DOCKER_CLI_BUILD=1 \
		NETWORK=$(NETWORK) $(DOCKER_COMPOSE) build

## Start the compose stack in the background.
compose-up:
	NETWORK=$(NETWORK) $(DOCKER_COMPOSE) up -d

## Stop and remove the compose stack (volumes preserved).
compose-down:
	$(DOCKER_COMPOSE) down

## Tail compose logs.
compose-logs:
	$(DOCKER_COMPOSE) logs -f --tail=200
