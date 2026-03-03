# proxy

An HTTP proxy that exposes two Ethereum block execution backends behind a single authenticated API:

| Endpoint | Backend | Output |
|---|---|---|
| `POST /block` | AWS Nitro Enclave | Signed execution result |
| `POST /block/sp1-proof` | SP1 zkVM (local or network) | Groth16 proof for on-chain verification |

---

## How it works
```
Caller ──► proxy ──► host-executor (fetch block + witnesses from RPC)
                      │
                      ├──► Nitro enclave  (VSOCK)  ──► signed EthExecutionResponse
                      │
                      └──► SP1 prover              ──► Groth16 Sp1ProofResponse
```

1. Both endpoints call the same `build_client_input` helper which fetches the block from the provided RPC URL and runs the host-side execution phase.
2. The resulting `ClientExecutorInput` is forwarded to the selected backend.
3. The response is validated (block hash check) before being returned to the caller.

---

## Running
```bash
proxy --eif_path /path/to/enclave.eif
```

### Required environment variables

| Variable | Description |
|---|---|
| `API_KEY` | Value expected in the `x-api-key` request header |
| `AWS_ACCESS_KEY_ID` | AWS credential for KMS operations (must have `kms:GenerateDataKey` / `kms:Decrypt`) |
| `AWS_SECRET_ACCESS_KEY` | AWS credential for KMS operations |

### Optional environment variables

| Variable | Default | Description |
|---|---|---|
| `LISTEN_ADDR` | `0.0.0.0:8080` | TCP address to bind |
| `AWS_SESSION_TOKEN` | *(unset)* | Temporary session token (required when using STS / assumed roles) |
| `DATA_KEY_STORAGE` | `./data_key.enc` | Path to the KMS-encrypted data key |
| `ATTESTATION_STORAGE` | `./attestation.bin` | Path to the NSM attestation document |
| `PUBLIC_KEY_STORAGE` | `./public_key.hex` | Path to the enclave's hex-encoded ECDSA public key |
| `SP1_ELF_PATH` | *(unset — endpoint disabled)* | Path to compiled SP1 zkVM ELF |
| `SP1_PROVER` | `cpu` | `cpu` or `network` |
| `SP1_PRIVATE_KEY` | — | Required when `SP1_PROVER=network` |
| `SP1_PROVER_NETWORK_RPC` | `https://rpc.production.succinct.xyz` | Custom prover network RPC |

---

## API

All requests must include the header:
```
x-api-key: <API_KEY>
```

### Request fields

Exactly one of `block_number` or `block_hash` must be provided. Passing both fields simultaneously is not allowed.

| Field | Type | Description |
|---|---|---|
| `block_number` | `uint64` | Block number. Mutually exclusive with `block_hash` |
| `block_hash` | `bytes32` | Block hash. Mutually exclusive with `block_number` |
| `rpc_url` | `string` | RPC endpoint URL used to fetch block data |

---

### POST /nitro

Executes a block inside the AWS Nitro Enclave and returns a signed result.

**Request**
```json
{
  "block_number": 1234567,
  "rpc_url": "https://your-rpc-endpoint"
}
```
or
```json
{
  "block_hash": "0x…",
  "rpc_url": "https://your-rpc-endpoint"
}
```

**Response**
```json
{
  "parent_hash": "0x…",
  "block_hash":  "0x…",
  "withdrawal_hash": "0x…",
  "deposit_hash": "0x…",
  "result_hash": "0x…",
  "signature":   "0x…"
}
```

`signature` is an ECDSA signature over `result_hash` produced by the enclave's KMS-backed signing key. Verify it against the public key stored in `PUBLIC_KEY_STORAGE` alongside the NSM attestation in `ATTESTATION_STORAGE`.

---

### POST /sp1

Generates a Groth16 SP1 proof for a block. Returns HTTP 500 if `SP1_ELF_PATH` is not set.

**Request**
```json
{
  "block_number": 1234567,
  "rpc_url": "https://your-rpc-endpoint"
}
```
or
```json
{
  "block_hash": "0x…",
  "rpc_url": "https://your-rpc-endpoint"
}
```

**Response**
```json
{
  "block_number": 1234567,
  "block_hash":  "0x…",
  "vk_hash":     "0x…",
  "public_values": "0x…",
  "proof_bytes": "0x…"
}
```

Pass these fields directly to any `ISP1Verifier`-compatible contract:
```solidity
ISP1Verifier(verifier).verifyProof(
    bytes32(response.vk_hash),
    response.public_values,
    response.proof_bytes
);
```

---

### POST /sp1-mock

Returns a hardcoded Groth16 SP1 proof for block **316** on Fluent Devnet. Does not require `SP1_ELF_PATH` to be set. Useful for integration testing without a live prover.

**Request**
```json
{
  "block_number": 316,
  "rpc_url": "https://your-rpc-endpoint"
}
```
> The request body is accepted but ignored — the response is always the same hardcoded proof.

**Response**
```json
{
  "block_number": 316,
  "block_hash":   "0x07d2de84641375cc25710327abfa4ed7a86a7cfeb560619d08ca4842e0cdd3d5",
  "vk_hash":      "0x282233864d7d8e6f6c3a096b5dcc088d76367e553118e432197d3eb215a2023d",
  "public_values": "0x…",
  "proof_bytes":   "0x…"
}
```

The response fields are identical in shape to `POST /block/sp1-proof` and can be passed directly to any `ISP1Verifier`-compatible contract:
```solidity
ISP1Verifier(verifier).verifyProof(
    bytes32(response.vk_hash),
    response.public_values,
    response.proof_bytes
);
```

> ⚠️ **Mock only.** This proof is real and was generated on Fluent Devnet, but it always corresponds to block 316 regardless of the requested `block_number`. Do not use in production.

---

## Enclave lifecycle

On startup the proxy calls `maybe_restart_enclave`, which compares the **PCR0** measurement of any already-running enclave against the PCR0 of the provided EIF file:

| Running enclave | PCR0 match? | Action |
|---|---|---|
| None | — | Start enclave → initialise signing key |
| Yes | ✓ | Skip (no-op) |
| Yes | ✗ | Terminate → start new enclave → re-initialise signing key |

This means you can deploy a new EIF and simply restart the proxy — it will detect the image change and rotate automatically.

### Nitro configuration

The enclave is started with parameters from `NitroConfig`:

| Field | Description |
|---|---|
| `cpu_count` | vCPUs allocated to the enclave |
| `memory_mib` | Memory (MiB) allocated to the enclave |
| `enclave_cid` | VSOCK context ID used to address the enclave |
| `enclave_port` | VSOCK port the enclave listens on for key-management and execution requests |

---

## Enclave key management

The proxy communicates with the enclave over a **VSOCK** connection using length-prefixed bincode frames (max 64 MiB).

### Key initialisation flow
```
proxy                                       enclave (VSOCK)
  │                                              │
  │─── read DATA_KEY_STORAGE ──►                 │
  │    (file exists?)                            │
  │                                              │
  ├─ NO  ─► EnclaveRequest { credentials, encrypted_data_key: None }
  │         ──────────────────────────────────────►
  │         ◄── EncryptedDataKey { encrypted_signing_key, public_key, attestation }
  │                                              │
  │         proxy writes:                        │
  │           DATA_KEY_STORAGE  ← encrypted_signing_key
  │           ATTESTATION_STORAGE ← attestation  │
  │           PUBLIC_KEY_STORAGE ← public_key (hex)
  │                                              │
  ├─ YES ─► EnclaveRequest { credentials, encrypted_data_key: Some(bytes) }
  │         ──────────────────────────────────────►
  │         (enclave decrypts & loads key; no response)
  │                                              │
```

- **First run** — no `data_key.enc` exists. The enclave calls KMS `GenerateDataKey`, derives an ECDSA signing key, and returns the encrypted DEK, the public key, and an NSM attestation document. The proxy persists all three artefacts.
- **Subsequent runs** — `data_key.enc` exists. The proxy sends the encrypted DEK to the enclave, which calls KMS `Decrypt` to recover the signing key. No new artefacts are produced, so the public key and attestation remain stable across restarts.

### Persisted artefacts

| File | Env override | Contents |
|---|---|---|
| `data_key.enc` | `DATA_KEY_STORAGE` | KMS-encrypted data key (re-used across restarts to keep the same signing identity) |
| `attestation.bin` | `ATTESTATION_STORAGE` | NSM attestation document binding the enclave image to the generated key |
| `public_key.hex` | `PUBLIC_KEY_STORAGE` | Hex-encoded ECDSA public key for off-chain signature verification |

The AWS credentials (`AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, and optionally `AWS_SESSION_TOKEN`) must grant `kms:GenerateDataKey` and `kms:Decrypt` on the KMS key configured in the enclave image.

---

## Source layout
```
src/
├── main.rs      # HTTP server, handlers, SP1 and Nitro execution logic
├── types.rs     # Shared request/response structs and configuration types
├── enclave.rs   # Nitro enclave lifecycle (start/stop/restart) and key management
└── vsock.rs     # VSOCK length-prefixed framing helpers (send_framed / recv_framed)
```

---

## SP1 prover backends

### Local (default)

Runs Groth16 proving on the host machine. Suitable for development and testing. Proving time depends on available hardware (minutes on a modern CPU, seconds on a GPU with CUDA support).
```bash
SP1_ELF_PATH=./guest.elf \
SP1_PROVER=cpu \
  proxy --eif_path enclave.eif
```

### Succinct prover network

Delegates proving to the [Succinct prover network](https://docs.succinct.xyz/generating-proofs/prover-network). Proving time depends on network queue depth (typically 5–30 minutes).
```bash
SP1_ELF_PATH=./guest.elf \
SP1_PROVER=network \
SP1_PRIVATE_KEY=0x… \
  proxy --eif_path enclave.eif
```