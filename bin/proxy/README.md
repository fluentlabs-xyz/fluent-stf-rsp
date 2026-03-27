# proxy

An HTTP proxy that sits between callers and execution backends, managing the Multi-Prover execution strategy for Fluent L2.

## Endpoints

### Signing endpoints (Nitro TEE, caller provides `EthClientExecutorInput`)
| Endpoint | Backend | Input | Output |
|---|---|---|---|
| `POST /sign-block-execution` | AWS Nitro Enclave | bincode+zstd | Signed execution result |
| `POST /sign-batch-root` | AWS Nitro Enclave | JSON | Signed batch Merkle root (fetches blobs from L1+Beacon) |
| `POST /sign-batch-root-from-responses` | AWS Nitro Enclave | JSON | Signed batch root from pre-signed responses (fetches blobs from L1+Beacon) |

### Challenge endpoints (proxy builds `ClientInput` from RPC, fetches blobs from Beacon)
| Endpoint | Backend | Output |
|---|---|---|
| `POST /challenge/nitro` | AWS Nitro Enclave | TEE challenge execution with blob verification |
| `POST /challenge/sp1/request` | SP1 zkVM (network) | `request_id` for async Groth16 proof |
| `POST /challenge/sp1/status` | SP1 zkVM (network) | Proof result by `request_id` |

### Mock endpoints (testing, no SP1 network calls)
| Endpoint | Backend | Output |
|---|---|---|
| `POST /mock/sp1/request` | — | Random `request_id` (testing) |
| `POST /mock/sp1/status` | — | Hardcoded proof (testing) |

---

## How it works
```text
Caller ──► proxy ──► host-executor (fetch block + witnesses from RPC)
                      │
                      ├──► Nitro enclave  (VSOCK)  ──► signed EthExecutionResponse
                      │
                      └──► SP1 network prover      ──► async Groth16 Sp1ProofResponse
                           (Host generates KZG
                            witness via Fiat-Shamir)
```

### Signing flow (courier → proxy)

The courier sends block witnesses as **bincode+zstd** payloads to `/sign-block-execution`:

```text
Courier ──► POST /sign-block-execution
            Content-Type: application/octet-stream
            Content-Encoding: zstd
            Body: zstd(bincode(EthClientExecutorInput))
        ◄── 200 OK  JSON(EthExecutionResponse)
```

The proxy decompresses zstd, deserializes bincode, forwards to the enclave, and returns the signed result as JSON.

### Challenge flow

Challenge endpoints build the `ClientInput` from RPC and **fetch blobs from L1 + Beacon API** using the provided `batch_index`:

```text
Challenger ──► POST /challenge/nitro
               { "block_number": 123, "batch_index": 5 }
           ◄── proxy fetches blobs from Beacon
           ◄── proxy builds ClientInput from L2 RPC
           ◄── enclave executes + verifies blob match
           ◄── 200 OK  JSON(EthExecutionResponse)
```

### General notes

1. **Host Execution**: Challenge endpoints call `build_client_input` which fetches the block from the configured `RPC_URL` and runs the host-side execution phase.
2. **KZG Offloading**: For SP1 challenge requests, the proxy performs host-side Fiat-Shamir KZG witness generation, offloading heavy MSM math from the zkVM guest.
3. **Routing**: The resulting execution and verification inputs are forwarded to the selected backend.
4. **Nitro**: The response is validated (block/parent hash check) and returned immediately.
5. **SP1**: Proof generation is **asynchronous**. The caller receives a `request_id` and must poll `/challenge/sp1/status` until the proof is ready.

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
| `RPC_URL` | `http://localhost:8545` | L2 RPC endpoint URL used to fetch block data |
| `LISTEN_ADDR` | `0.0.0.0:8080` | TCP address to bind |
| `L1_RPC_URL` | *(unset)* | L1 RPC endpoint for blob fetching. Required for `/sign-batch-root` and challenge endpoints |
| `L1_CONTRACT_ADDR` | *(unset)* | L1 rollup contract address. Required with `L1_RPC_URL` |
| `L1_BEACON_URL` | *(unset)* | Beacon API endpoint for blob sidecars. Required with `L1_RPC_URL` |
| `BEACON_GENESIS_TIMESTAMP` | `1606824023` | Beacon chain genesis timestamp (mainnet default) |
| `AWS_SESSION_TOKEN` | *(unset)* | Temporary session token (required when using STS / assumed roles) |
| `DATA_KEY_STORAGE` | `./data_key.enc` | Path to the KMS-encrypted data key |
| `ATTESTATION_STORAGE` | `./attestation.bin` | Path to the NSM attestation document |
| `PUBLIC_KEY_STORAGE` | `./public_key.hex` | Path to the enclave's hex-encoded ECDSA public key |
| `SP1_ELF_PATH` | *(unset)* | Path to compiled SP1 zkVM ELF. Disables SP1 endpoints if unset |
| `SP1_PRIVATE_KEY` | — | Required for Succinct network prover authentication |

---

## API

All requests must include the header:
```http
x-api-key: <API_KEY>
```

---

### POST /sign-block-execution

Executes a block inside the AWS Nitro Enclave and returns a signed result. Requires `--eif_path` at startup.

**Input format**: bincode-serialized `EthClientExecutorInput`, optionally compressed with zstd.

```http
POST /sign-block-execution
Content-Type: application/octet-stream
Content-Encoding: zstd
x-api-key: <API_KEY>

<zstd-compressed bincode payload>
```

If `Content-Encoding: zstd` is present, the proxy decompresses first. Otherwise treats the body as raw bincode.

**Response** `200 OK`
```json
{
  "block_number": 1234567,
  "parent_hash": "0x…",
  "block_hash":  "0x…",
  "withdrawal_hash": "0x…",
  "deposit_hash": "0x…",
  "tx_data_hash": "0x…",
  "result_hash": "0x…",
  "signature":   "0x…"
}
```

---

### POST /sign-batch-root

Fetches blobs from L1 + Beacon API using `batch_index`, then sends them to the enclave for batch root signing. Requires `--eif_path` and L1 context (`L1_RPC_URL`, `L1_CONTRACT_ADDR`, `L1_BEACON_URL`).

**Request**
```json
{
  "from_block": 100,
  "to_block": 110,
  "batch_index": 5
}
```

**Response** `200 OK`
```json
{
  "batch_root": "0x…",
  "versioned_hashes": ["0x…"],
  "signature": "0x…"
}
```

---

### POST /sign-batch-root-from-responses

Signs a batch root from pre-signed block execution responses. Fetches blobs from L1 + Beacon API using `batch_index`. Requires `--eif_path` and L1 context (`L1_RPC_URL`, `L1_CONTRACT_ADDR`, `L1_BEACON_URL`).

**Request**
```json
{
  "responses": [
    { "block_number": 100, "parent_hash": "0x…", "block_hash": "0x…", "..." : "..." }
  ],
  "batch_index": 5
}
```

**Response** `200 OK`
```json
{
  "batch_root": "0x…",
  "versioned_hashes": ["0x…"],
  "signature": "0x…"
}
```

---

### POST /challenge/nitro

Executes a block inside the AWS Nitro Enclave with blob verification. The proxy builds `ClientInput` from L2 RPC and fetches blobs from L1 + Beacon API using the provided `batch_index`.

Requires `--eif_path` and L1 context.

**Request**
```json
{
  "block_number": 1234567,
  "batch_index": 5
}
```

Either `block_number` or `block_hash` must be provided (not both).

**Response** `200 OK`
```json
{
  "block_number": 1234567,
  "parent_hash": "0x…",
  "block_hash":  "0x…",
  "withdrawal_hash": "0x…",
  "deposit_hash": "0x…",
  "tx_data_hash": "0x…",
  "result_hash": "0x…",
  "signature":   "0x…"
}
```

`signature` is an ECDSA signature over `result_hash` produced by the enclave's KMS-backed signing key. Verify it against the public key stored in `PUBLIC_KEY_STORAGE` alongside the NSM attestation in `ATTESTATION_STORAGE`.

---

### POST /challenge/sp1/request

Submits a block for asynchronous Groth16 proof generation on the Succinct prover network. Blobs are fetched from L1 + Beacon API using `batch_index`. Returns a `request_id` for polling.

Requires `SP1_ELF_PATH` and L1 context.

**Request**
```json
{
  "block_number": 1234567,
  "batch_index": 5
}
```

**Response** `200 OK`
```json
{
  "request_id": "0x…"
}
```

---

### POST /challenge/sp1/status

Polls the status of a previously submitted proof request.

**Request**
```json
{
  "request_id": "0x…"
}
```

**Response codes**

| Status | Meaning | Body |
|---|---|---|
| `200 OK` | Proof is ready | `Sp1ProofResponse` (see below) |
| `202 Accepted` | Proof is still being generated | *(empty)* |
| `404 Not Found` | `request_id` not found on the SP1 network | `{ "error": "..." }` |

**200 response**
```json
{
  "vk_hash":        "0x…",
  "public_values":  "0x…",
  "proof_bytes":    "0x…"
}
```

The `public_values` byte array encodes:
1. `parent_hash` (B256)
2. `block_hash` (B256)
3. `withdrawal_hash` (B256)
4. `deposit_hash` (B256)
5. `versioned_hashes` (Vec<B256>)

Pass these fields directly to any `ISP1Verifier`-compatible contract:
```solidity
ISP1Verifier(verifier).verifyProof(
    bytes32(response.vk_hash),
    response.public_values,
    response.proof_bytes
);
```

---

### POST /mock/sp1/request

Returns a fake `request_id` without submitting anything to the SP1 network. Takes the same payload as `/challenge/sp1/request`. Does not require `SP1_ELF_PATH`. Useful for integration testing.

**Request**
```json
{
  "block_number": 316,
  "batch_index": 0
}
```

**Response**
```json
{
  "request_id": "0x…"
}
```

---

### POST /mock/sp1/status

Returns a hardcoded `Sp1ProofResponse` regardless of the `request_id` provided. Does not require `SP1_ELF_PATH`.

**Request**
```json
{
  "request_id": "0x…"
}
```

> The `request_id` is accepted but ignored — the response is always the same hardcoded proof.

**Response**
```json
{
  "vk_hash":       "0x282233864d7d8e6f6c3a096b5dcc088d76367e553118e432197d3eb215a2023d",
  "public_values": "0x…",
  "proof_bytes":   "0x…"
}
```

> **Mock only.** This proof was generated on Fluent Devnet for block 316. Do not use in production.

---

## Enclave lifecycle

On startup the proxy calls `ensure_initialized`, which communicates with the enclave over VSOCK to set up the signing key:

| Running enclave | Key exists? | Action |
|---|---|---|
| None | — | Start enclave, initialise signing key |
| Yes | No | Generate new key via KMS, store attestation |
| Yes | Yes | Load existing encrypted key, decrypt via KMS |

### Nitro configuration

The enclave communicates via VSOCK with parameters from `NitroConfig`:

| Field | Description |
|---|---|
| `cpu_count` | vCPUs allocated to the enclave |
| `memory_mib` | Memory (MiB) allocated to the enclave |
| `enclave_cid` | VSOCK context ID used to address the enclave |
| `enclave_port` | VSOCK port the enclave listens on |

---

## Enclave key management

The proxy communicates with the enclave over a **VSOCK** connection using length-prefixed bincode frames (4-byte big-endian length prefix).

### Key initialisation flow
```text
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
- **Subsequent runs** — `data_key.enc` exists. The proxy sends the encrypted DEK to the enclave, which calls KMS `Decrypt` to recover the signing key. No new artefacts are produced.

### Persisted artefacts

| File | Env override | Contents |
|---|---|---|
| `data_key.enc` | `DATA_KEY_STORAGE` | KMS-encrypted data key |
| `attestation.bin` | `ATTESTATION_STORAGE` | NSM attestation document binding the enclave image to the generated key |
| `public_key.hex` | `PUBLIC_KEY_STORAGE` | Hex-encoded ECDSA public key for off-chain signature verification |

The AWS credentials must grant `kms:GenerateDataKey` and `kms:Decrypt` on the KMS key configured in the enclave image.

---

## Source layout
```text
src/
├── main.rs      # HTTP server, handlers, request deserialization (bincode+zstd)
├── types.rs     # Shared request/response structs and configuration types
├── enclave.rs   # Nitro enclave VSOCK communication and key management
└── blob.rs      # EIP-4844 blob fetching from L1 contract + Beacon API
```

---

## SP1 prover network

The SP1 backend uses the [Succinct prover network](https://docs.succinct.xyz/generating-proofs/prover-network) for async Groth16 proof generation. Proving time depends on network queue depth.

```bash
SP1_ELF_PATH=./guest.elf \
SP1_PRIVATE_KEY=0x… \
L1_RPC_URL=https://eth-mainnet.g.alchemy.com/v2/… \
L1_CONTRACT_ADDR=0x… \
L1_BEACON_URL=https://beacon.example.com \
  proxy --eif_path enclave.eif
```

### Typical flow

```text
1. POST /challenge/sp1/request  →  { "request_id": "0xabc..." }
2. POST /challenge/sp1/status   →  202 Accepted        (pending)
3. POST /challenge/sp1/status   →  202 Accepted        (still pending)
4. POST /challenge/sp1/status   →  200 OK + proof      (done)
```
