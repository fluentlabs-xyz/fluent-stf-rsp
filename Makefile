.PHONY: build-client build-enclave run-enclave clean

TARGET := x86_64-unknown-linux-musl
CLIENT := bin/client
BINARY := rsp-client
EIF := rsp-client-enclave.eif

build-enclave:
	cargo build \
		--target $(TARGET) \
		--release \
		--manifest-path $(CLIENT)/Cargo.toml \
		--features nitro \
		--no-default-features
	tar -C $(CLIENT)/target/$(TARGET)/release/ -cf - $(BINARY) \
		| docker import - $(BINARY)
	nitro-cli build-enclave --docker-uri $(BINARY) --output-file $(EIF)

run-enclave:
	nitro-cli run-enclave \
		--eif-path $(EIF) \
		--cpu-count 2 \
		--memory 256 \
		--enclave-cid 10 \
		--debug-mode

clean:
	rm -f $(EIF)