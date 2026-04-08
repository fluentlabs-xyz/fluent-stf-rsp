.PHONY: build-client build-client-docker build-nitro-validator build-nitro-validator-docker \
        build-enclave build-proxy run run-sp1-only run-enclave download-genesis clean help

# ─── Paths ────────────────────────────────────────────────────────────────────
CLIENT_DIR   := bin/client
PROXY_DIR    := bin/proxy

# ─── Nitro / enclave ──────────────────────────────────────────────────────────
TARGET       := x86_64-unknown-linux-musl
BINARY       := rsp-client
EIF          := rsp-client-enclave.eif
ELF          := rsp-client.elf

# ─── Nitro validator (attestation proving) ────────────────────────────────────
NITRO_VALIDATOR_DIR := bin/aws-nitro-validator/program
NITRO_VALIDATOR_ELF := nitro-validator.elf

# ─── Config (override via env or CLI) ─────────────────────────────────────────
EIF_PATH     ?= $(EIF)
ELF_PATH     ?= $(ELF)
API_KEY      ?= secret
LISTEN_ADDR  ?= 0.0.0.0:8080
SP1_PROVER   ?= network          # cpu | network
TAG          ?= v0.5.7
RUST_LOG 	 ?= info

# ─── SP1 ELF ──────────────────────────────────────────────────────────────────

## Quick ELF build (dev)
build-client:
	cd $(CLIENT_DIR) && cargo prove build \
		--elf-name $(ELF) \
		--output-directory ../../

## Reproducible ELF build via Docker (prod)
build-client-docker:
	cd $(CLIENT_DIR) && cargo prove build \
		--elf-name $(ELF) \
		--output-directory ../../ \
		--docker

# ─── Nitro validator ELF (attestation proving) ───────────────────────────────

## Build nitro-validator ELF (dev)
build-nitro-validator:
	cd $(NITRO_VALIDATOR_DIR) && cargo prove build \
		--elf-name $(NITRO_VALIDATOR_ELF) \
		--output-directory ../../../

## Reproducible nitro-validator ELF build via Docker (prod)
build-nitro-validator-docker:
	cd $(NITRO_VALIDATOR_DIR) && cargo prove build \
		--elf-name $(NITRO_VALIDATOR_ELF) \
		--output-directory ../../../ \
		--docker

# ─── Nitro enclave ────────────────────────────────────────────────────────────

## Build .eif for AWS Nitro (reproducible)
build-enclave:
	SOURCE_DATE_EPOCH=$$(git log -1 --pretty=%ct) \
	docker buildx build \
		-f Dockerfile.enclave \
		--output type=docker,rewrite-timestamp=true \
		-t $(BINARY):latest .
	nitro-cli build-enclave --docker-uri $(BINARY):latest --output-file $(EIF)

## Run enclave locally (debug)
run-enclave:
	nitro-cli run-enclave \
		--eif-path $(EIF_PATH) \
		--cpu-count 2 \
		--memory 512 \
		--enclave-cid 10 \
		--debug-mode

# ─── Proxy ────────────────────────────────────────────────────────────────────

build-proxy:
	RUSTFLAGS="-C target-cpu=native" cargo build --release -p proxy

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

# ─── Misc ─────────────────────────────────────────────────────────────────────

download-genesis:
	mkdir -p ./bin/host/genesis
	curl -L -o ./bin/host/genesis/genesis-$(TAG).json.gz \
		https://github.com/fluentlabs-xyz/fluentbase/releases/download/$(TAG)/genesis-$(TAG).json.gz
	gunzip -f ./bin/host/genesis/genesis-$(TAG).json.gz

clean:
	cargo clean
	rm -f $(EIF) $(ELF) $(NITRO_VALIDATOR_ELF)

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
	@echo "  download-genesis              Download genesis file (TAG=$(TAG))"
	@echo "  clean                         Remove build artifacts"
	@echo ""
	@echo "Overrides:"
	@echo "  EIF_PATH=$(EIF_PATH)"
	@echo "  ELF_PATH=$(ELF_PATH)"
	@echo "  API_KEY=$(API_KEY)"
	@echo "  LISTEN_ADDR=$(LISTEN_ADDR)"
	@echo "  SP1_PROVER=$(SP1_PROVER)"
	@echo "  TAG=$(TAG)"