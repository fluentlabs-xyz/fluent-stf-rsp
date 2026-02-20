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

### Optional environment variables

| Variable | Default | Description |
|---|---|---|
| `LISTEN_ADDR` | `0.0.0.0:8080` | TCP address to bind |
| `GENESIS_PATH` | Built-in devnet genesis (chainId 20993) | Custom chain genesis JSON |
| `SP1_ELF_PATH` | *(unset — endpoint disabled)* | Path to compiled SP1 zkVM ELF |
| `SP1_PROVER` | `local` | `local` or `network` |
| `SP1_PRIVATE_KEY` | — | Required when `SP1_PROVER=network` |
| `SP1_PROVER_NETWORK_RPC` | `https://rpc.production.succinct.xyz` | Custom prover network RPC |

---

## API

All requests must include the header:
```
x-api-key: <API_KEY>
```

### POST /block

Executes a block inside the AWS Nitro Enclave and returns a signed result.

**Request**
```json
{
  "block_number": 1234567,
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

### POST /block/sp1-proof

Generates a Groth16 SP1 proof for a block. Returns HTTP 500 if `SP1_ELF_PATH` is not set.

**Request**
```json
{
  "block_number": 1234567,
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
SP1_PROVER=local \
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

> **Note:** The current implementation uses a local ECDSA signer (`NetworkSigner::local`). For production deployments, replace this with an AWS KMS signer (see the `TODO` comment in `main.rs`).
