.PHONY: build-client build-client-docker build-enclave build-proxy \
        run run-sp1-only run-enclave download-genesis clean help

# ─── Paths ────────────────────────────────────────────────────────────────────
CLIENT_DIR   := bin/client
PROXY_DIR    := bin/proxy
ELF_PATH     := $(CLIENT_DIR)/elf/riscv32im-succinct-zkvm-elf

# ─── Nitro / enclave ──────────────────────────────────────────────────────────
TARGET       := x86_64-unknown-linux-musl
BINARY       := rsp-client
EIF          := rsp-client-enclave.eif

# ─── Config (override via env or CLI) ─────────────────────────────────────────
EIF_PATH     ?= $(EIF)
API_KEY      ?= secret
LISTEN_ADDR  ?= 0.0.0.0:8080
SP1_PROVER   ?= cpu          # cpu | network
TAG          ?= v0.5.3

# ─── SP1 ELF ──────────────────────────────────────────────────────────────────

## Quick ELF build (dev)
build-client:
	cargo build --manifest-path $(CLIENT_DIR)/Cargo.toml

## Reproducible ELF build via Docker (prod)
build-client-docker:
	SP1_DOCKER=1 cargo build --manifest-path $(CLIENT_DIR)/Cargo.toml

# ─── Nitro enclave ────────────────────────────────────────────────────────────

## Build .eif for AWS Nitro
build-enclave:
	cargo build \
		--target $(TARGET) \
		--release \
		--manifest-path $(CLIENT_DIR)/Cargo.toml \
		--features nitro \
		--no-default-features
	tar -C $(CLIENT_DIR)/target/$(TARGET)/release/ -cf - $(BINARY) \
		| docker import - $(BINARY)
	nitro-cli build-enclave --docker-uri $(BINARY) --output-file $(EIF)

## Run enclave locally (debug)
run-enclave:
	nitro-cli run-enclave \
		--eif-path $(EIF_PATH) \
		--cpu-count 2 \
		--memory 256 \
		--enclave-cid 10 \
		--debug-mode

# ─── Proxy ────────────────────────────────────────────────────────────────────

build-proxy:
	cargo build --release -p proxy

# ─── Run ──────────────────────────────────────────────────────────────────────

## Build and run with both backends (Nitro + SP1)
run: build-client build-proxy
	SP1_ELF_PATH=$(ELF_PATH) \
	SP1_PROVER=$(SP1_PROVER) \
	API_KEY=$(API_KEY) \
	LISTEN_ADDR=$(LISTEN_ADDR) \
	./target/release/proxy --eif_path $(EIF_PATH)

## Build and run with SP1 only (no Nitro)
run-sp1-only: build-client build-proxy
	SP1_ELF_PATH=$(ELF_PATH) \
	SP1_PROVER=$(SP1_PROVER) \
	API_KEY=$(API_KEY) \
	LISTEN_ADDR=$(LISTEN_ADDR) \
	./target/release/proxy

# ─── Misc ─────────────────────────────────────────────────────────────────────

download-genesis:
	mkdir -p ./bin/host/genesis
	curl -L -o ./bin/host/genesis/genesis-$(TAG).json.gz \
		https://github.com/fluentlabs-xyz/fluentbase/releases/download/$(TAG)/genesis-$(TAG).json.gz
	gunzip -f ./bin/host/genesis/genesis-$(TAG).json.gz

clean:
	cargo clean
	rm -f $(EIF)

help:
	@echo "Targets:"
	@echo "  build-client         Build SP1 ELF (dev)"
	@echo "  build-client-docker  Build SP1 ELF reproducible via Docker (prod)"
	@echo "  build-enclave        Build AWS Nitro .eif"
	@echo "  build-proxy          Build proxy binary"
	@echo "  run                  Build and run with Nitro + SP1"
	@echo "  run-sp1-only         Build and run with SP1 only (no Nitro)"
	@echo "  run-enclave          Run enclave in debug mode"
	@echo "  download-genesis     Download genesis file (TAG=$(TAG))"
	@echo "  clean                Remove build artifacts"
	@echo ""
	@echo "Overrides:"
	@echo "  EIF_PATH=$(EIF_PATH)"
	@echo "  API_KEY=$(API_KEY)"
	@echo "  LISTEN_ADDR=$(LISTEN_ADDR)"
	@echo "  SP1_PROVER=$(SP1_PROVER)"
	@echo "  TAG=$(TAG)"