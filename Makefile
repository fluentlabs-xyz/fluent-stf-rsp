.PHONY: build-client build-client-docker build-nitro-validator build-nitro-validator-docker \
        build-enclave build-proxy run run-sp1-only run-enclave clean help \
        compose-build compose-up compose-down compose-logs

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
		--output-directory ../../ \
		--no-default-features \
		--features "sp1 $(NETWORK)"

## Reproducible ELF build via Docker (prod)
build-client-docker:
	cd $(CLIENT_DIR) && cargo prove build \
		--elf-name $(ELF) \
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
		--output-directory ../../ \
		--no-default-features \
		--features $(NETWORK)

## Reproducible nitro-validator ELF build via Docker (prod)
build-nitro-validator-docker:
	cd $(NITRO_VALIDATOR_DIR) && cargo prove build \
		--elf-name $(NITRO_VALIDATOR_ELF) \
		--output-directory ../../ \
		--workspace-directory ../../ \
		--docker \
		--no-default-features \
		--features $(NETWORK)

# ─── Nitro enclave ────────────────────────────────────────────────────────────

## Build .eif for AWS Nitro (reproducible). Rewrites EXPECTED_PCR0 in
## nitro-validator main.rs with the freshly-built enclave's PCR0.
build-enclave:
	SOURCE_DATE_EPOCH=$$(git log -1 --pretty=%ct) \
	docker buildx build \
		-f Dockerfile.enclave \
		--build-arg NETWORK=$(NETWORK) \
		--output type=docker,rewrite-timestamp=true \
		-t $(BINARY):$(NETWORK) .
	nitro-cli build-enclave \
		--docker-uri $(BINARY):$(NETWORK) \
		--output-file $(EIF) \
		> $(EIF).pcrs.json
	python3 scripts/update_expected_pcr0.py \
		$(EIF).pcrs.json \
		$(NITRO_VALIDATOR_DIR)/src/lib.rs \
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
	@echo "  build-enclave                 Build AWS Nitro .eif"
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

# ─── Docker Compose ───────────────────────────────────────────────────────────

## Build ELFs (reproducibly, via docker) and docker images for the compose
## stack (one-shot). Uses the *-docker targets so ELFs are identical across
## developer machines — critical because the enclave hardcodes EXPECTED_PCR0
## and a non-reproducible build will cause attestation verification to fail.
compose-build: build-client-docker build-nitro-validator-docker
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
