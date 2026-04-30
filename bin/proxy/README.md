# proxy

An HTTP proxy that sits between callers and execution backends, managing the Multi-Prover execution strategy for Fluent L2.

## Endpoints

### Signing endpoints (Nitro TEE, caller provides `EthClientExecutorInput`)
| Endpoint | Backend | Input | Output |
|---|---|---|---|
| `POST /sign-block-execution` | AWS Nitro Enclave | bincode+zstd | Signed execution result |
| `POST /sign-batch-root` | AWS Nitro Enclave | JSON | Signed batch Merkle root over caller-provided blobs |

### Challenge endpoints (orchestrator supplies pre-built `ClientInput` + blobs in the request body)
| Endpoint | Backend | Output |
|---|---|---|
| `POST /challenge/sp1/request` | SP1 zkVM (network) | `request_id` for async Groth16 proof |
| `POST /challenge/sp1/status` | SP1 zkVM (network) | Proof result by `request_id` |

### Mock endpoints (testing, local SP1 execution)
| Endpoint | Backend | Output |
|---|---|---|
| `POST /mock/sp1/request` | SP1 zkVM (local CPU) | `{ success, error? }` — real execution, no proof |

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

### Signing flow (witness-orchestrator → proxy)

The witness-orchestrator sends block witnesses as **bincode+zstd** payloads to `/sign-block-execution`:

```text
Orchestrator ──► POST /sign-block-execution
                 Content-Type: application/octet-stream
                 Content-Encoding: zstd
                 Body: zstd(bincode(EthClientExecutorInput))
            ◄── 200 OK  JSON(EthExecutionResponse)
```

The proxy decompresses zstd, deserializes bincode, forwards to the enclave, and returns the signed result as JSON.

For `/sign-batch-root` the orchestrator pre-builds the EIP-4844 blobs locally via `rsp_blob_builder::build_blobs_from_l2` and includes them in the JSON body — the proxy does not fetch blobs from L1 or Beacon.

### Challenge flow

The orchestrator owns the witness payload (via its embedded driver's cold-store / MDBX rebuild) and the canonical batch blobs (via `rsp_blob_builder::build_blobs_from_l2`). It packages both into a single bincode-serialized `ChallengeSp1Request { client_input, blobs }` (optionally zstd-compressed) and POSTs to the proxy. The proxy is a thin SP1 forwarder on this path — no L1 / Beacon access, no host-execute:

```text
Orchestrator ──► POST /challenge/sp1/request
                 Content-Type: application/octet-stream
                 [Content-Encoding: zstd]
                 Body: bincode(ChallengeSp1Request { client_input, blobs })
            ◄── proxy submits to SP1 prover network (Groth16)
            ◄── 200 OK  { "request_id": "0x..." }
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
proxy
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
| `RPC_URL` | `http://localhost:8545` | L2 RPC endpoint URL used by `/mock/sp1/request` to build `ClientInput` and reconstruct blobs |
| `LISTEN_ADDR` | `0.0.0.0:8080` | TCP address to bind |
| `L1_RPC_URL` | *(unset)* | L1 RPC endpoint for batch metadata (`BatchCommitted` scans). Required for `/mock/sp1/request` |
| `L1_ROLLUP_ADDR` | *(unset)* | L1 rollup contract address. Required with `L1_RPC_URL` |
| `L1_ROLLUP_DEPLOY_BLOCK` | `0` | Lower bound for `BatchCommitted` event scans |
| `AWS_SESSION_TOKEN` | *(unset)* | Temporary session token (required when using STS / assumed roles) |
| `DATA_KEY_STORAGE` | `./data_key.enc` | Path to the KMS-encrypted data key |
| `ATTESTATION_STORAGE` | `./attestation.bin` | Path to the NSM attestation document |
| `PUBLIC_KEY_STORAGE` | `./public_key.hex` | Path to the enclave's hex-encoded ECDSA public key |
| `SP1_ELF_PATH` | *(unset)* | Path to compiled SP1 zkVM ELF. Disables SP1 endpoints if unset |
| `SP1_PRIVATE_KEY` | — | Required for Succinct network prover authentication |
| `NITRO_VALIDATOR_ELF_PATH` | *(unset)* | Path to nitro validator SP1 ELF. Required for attestation proving |
| `NITRO_VERIFIER_ADDR` | *(unset)* | L1 NitroVerifier contract address. Required for attestation proving |
| `L1_SUBMITTER_KEY` | *(unset)* | Private key for L1 attestation tx submission |
| `PROXY_DB_PATH` | `./proxy.db` | SQLite database for pending attestation rows + in-flight challenge requests |

---

## API

All requests must include the header:
```http
x-api-key: <API_KEY>
```

---

### POST /sign-block-execution

Executes a block inside the AWS Nitro Enclave and returns a signed result.

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
  "result_hash": "0x…",
  "signature":   "0x…"
}
```

---

### POST /sign-batch-root

Signs a batch root over **caller-provided** EIP-4844 blobs. The witness-orchestrator builds these blobs locally via `rsp_blob_builder::build_blobs_from_l2` and includes them in the request body. The proxy does **not** fetch blobs from L1 or any Beacon API.

**Request**
```json
{
  "from_block": 100,
  "to_block": 110,
  "batch_index": 5,
  "responses": [ /* signed EthExecutionResponse per block */ ],
  "blobs": [ /* hex-encoded EIP-4844 blob bytes */ ]
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

### POST /challenge/sp1/request

Submits a fully-built challenge proof to the Succinct prover network for asynchronous Groth16 proof generation. The orchestrator supplies the `EthClientExecutorInput` (witness) and the canonical EIP-4844 blobs in the request body — the proxy does not touch L1 or any L2 RPC on this path.

Requires `SP1_ELF_PATH`.

**Headers**
```http
Content-Type: application/octet-stream
[Content-Encoding: zstd]
```

**Body** — bincode-serialized `nitro_types::ChallengeSp1Request`:
```rust
struct ChallengeSp1Request {
    client_input: Box<EthClientExecutorInput>,
    blobs: Vec<Vec<u8>>,
}
```

Optionally zstd-compressed when `Content-Encoding: zstd` is present.

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
| `404 Not Found` | `request_id` not found | `{ "error": "..." }` |

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

The L1 `Rollup.resolveBlockChallenge` reconstructs these public values from the block header + on-chain blob hashes; orchestrator-side callers do not forward them.

---

### POST /mock/sp1/request

Self-contained dev/testing endpoint: executes the SP1 zkVM program locally on the CPU without submitting to the prover network. Unlike `/challenge/sp1/request`, the proxy builds `ClientInput` from L2 RPC and reconstructs blobs from L2 tx data itself — no orchestrator required.

Requires `SP1_ELF_PATH` and L1 context.

The endpoint performs the full pipeline: reconstructs blobs from L2 tx data via `blob-builder`, builds `ClientInput` from L2 RPC, prepares KZG witnesses, and runs the SP1 guest program via CPU executor. Returns synchronously whether execution succeeded or failed.

**Request**
```json
{
  "block_number": 316,
  "batch_index": 0
}
```

**Response (success)** `200 OK`
```json
{
  "success": true
}
```

**Response (failure)** `200 OK`
```json
{
  "success": false,
  "error": "STF execution failed: ..."
}
```

> **Note:** CPU execution can take several minutes depending on block complexity.

---

## Enclave lifecycle

On startup the proxy calls `ensure_initialized`, which communicates with the enclave over VSOCK to set up the signing key and handle attestation proving:

| Enclave state | Disk state | Action |
|---|---|---|
| New key generated | — | Save artifacts, delete stale `request_id`, submit SP1 proof → L1 |
| Already initialized | `attestation_request_id.hex` exists | Resume pending SP1 proof → L1 |
| Already initialized | No `request_id` | Nothing to do (already attested) |

Attestation proving blocks startup — the HTTP server won't start until attestation completes. If attestation fails, it is logged and the proxy starts anyway. On next restart, a pending `request_id` will be resumed.

In-flight `/challenge/sp1/request` workers are also resumed on startup: any row with `status='pending'` and a stored `sp1_request_id` re-enters `wait_proof(saved_id, ...)` against the SP1 prover network. Rows without a stored `sp1_request_id` are marked `failed` so the orchestrator's existing 5xx → re-issue path generates a fresh request.

### Nitro configuration

The enclave communicates via VSOCK with parameters from `NitroConfig`:

| Field | Description |
|---|---|
| `enclave_cid` | VSOCK context ID used to address the enclave |
| `enclave_port` | VSOCK port the enclave listens on |

---

## Source layout
```text
src/
├── main.rs           # HTTP server, handlers, request deserialization (bincode+zstd)
├── types.rs          # Shared request/response structs and configuration types
├── enclave.rs        # Nitro enclave VSOCK communication and key management
├── challenge.rs      # SP1 challenge proof generation + restart-resume helpers
├── db.rs             # SQLite persistence for pending attestations + challenges
└── attestation/      # Attestation proving via SP1 + L1 submission
    ├── mod.rs        # Tests and root cert embedding
    ├── driver.rs     # Startup serialization + per-key spawn-dedup
    ├── network.rs    # SP1 proof request/wait/submit, request-id persistence, L1 submission
    └── prepare.rs    # Parse attestation document into SP1 guest input
```

---

## SP1 prover network

The SP1 backend uses the [Succinct prover network](https://docs.succinct.xyz/generating-proofs/prover-network) for async Groth16 proof generation. Proving time depends on network queue depth.

```bash
SP1_ELF_PATH=./guest.elf \
SP1_PRIVATE_KEY=0x… \
L1_RPC_URL=https://eth-mainnet.g.alchemy.com/v2/… \
L1_ROLLUP_ADDR=0x… \
  proxy
```

### Typical flow

```text
1. POST /challenge/sp1/request  →  { "request_id": "0xabc..." }
2. POST /challenge/sp1/status   →  202 Accepted        (pending)
3. POST /challenge/sp1/status   →  202 Accepted        (still pending)
4. POST /challenge/sp1/status   →  200 OK + proof      (done)
```
