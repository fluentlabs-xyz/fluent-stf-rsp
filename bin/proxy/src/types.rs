use revm_primitives::FixedBytes;

// ---------------------------------------------------------------------------
// AWS credentials
// ---------------------------------------------------------------------------

/// AWS credentials forwarded to the enclave so it can call KMS for key
/// wrapping / unwrapping.  Passed as part of every [`EnclaveRequest`].
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub(crate) struct AwsCredentials {
    pub access_key_id: String,
    pub secret_access_key: String,
    /// Present when using temporary STS credentials (e.g. an EC2 instance profile).
    pub session_token: Option<String>,
}

// ---------------------------------------------------------------------------
// Nitro enclave protocol
// ---------------------------------------------------------------------------

/// Request sent to the enclave over VSOCK for key management.
///
/// - `encrypted_data_key = None`  → the enclave generates a fresh signing key, wraps it with KMS,
///   and returns the ciphertext.
/// - `encrypted_data_key = Some`  → the enclave unwraps the existing key with KMS and loads it into
///   memory; no response is sent back.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub(crate) struct EnclaveRequest {
    pub credentials: AwsCredentials,
    pub encrypted_data_key: Option<Vec<u8>>,
}

/// Response returned by the enclave after generating a new signing key.
/// Only sent when `EnclaveRequest::encrypted_data_key` is `None`.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub(crate) enum EnclaveResponse {
    /// The enclave successfully generated and wrapped a signing key.
    EncryptedDataKey {
        /// KMS-wrapped signing key ciphertext.  Persist this to disk.
        encrypted_signing_key: Vec<u8>,
        /// The corresponding secp256k1 public key (uncompressed, 65 bytes).
        public_key: Vec<u8>,
        /// Raw NSM attestation document for the current enclave instance.
        attestation: Vec<u8>,
    },
    /// The enclave encountered an error; the string contains the reason.
    Error(String),
}

// ---------------------------------------------------------------------------
// Nitro block execution result
// ---------------------------------------------------------------------------

/// Result of Ethereum block execution returned by the Nitro enclave.
///
/// The enclave signs `result_hash` with its loaded signing key and returns
/// the signature so callers can verify execution was performed inside a
/// genuine, attested enclave.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub(crate) struct EthExecutionResponse {
    pub parent_hash: FixedBytes<32>,
    pub block_hash: FixedBytes<32>,
    /// Hash of the EIP-4895 withdrawals root (`0x0` pre-Shanghai).
    pub withdrawal_hash: FixedBytes<32>,
    /// Hash of the EIP-6110 deposit receipts root (`0x0` pre-Prague).
    pub deposit_hash: FixedBytes<32>,
    /// Keccak256 of the full execution result committed by the enclave.
    pub result_hash: Vec<u8>,
    /// ECDSA signature over `result_hash` produced by the enclave signing key.
    pub signature: Vec<u8>,
}

// ---------------------------------------------------------------------------
// SP1 proof result
// ---------------------------------------------------------------------------

/// Everything a Solidity contract needs to call `ISP1Verifier.verifyProof()`.
///
/// ```solidity
/// ISP1Verifier(verifier).verifyProof(
///     bytes32(response.vk_hash),  // program verification key hash
///     response.public_values,      // public outputs of the zkVM program
///     response.proof_bytes,        // raw Groth16 proof
/// );
/// ```
///
/// `block_number` and `block_hash` are not required by the verifier contract
/// but are included for indexing and sanity checks on the caller side.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub(crate) struct Sp1ProofResponse {
    // -- Required by ISP1Verifier.verifyProof() ------------------------------
    /// `bytes32` program verification key hash — first argument to `verifyProof`.
    pub vk_hash: FixedBytes<32>,
    /// ABI-encoded public outputs committed by the SP1 program via
    /// `sp1_zkvm::io::commit`.  Layout: `parent_hash (32 B) ++ block_hash (32 B) ++ …`
    pub public_values: Vec<u8>,
    /// Raw Groth16 proof bytes — third argument to `verifyProof`.
    pub proof_bytes: Vec<u8>,
}

// ---------------------------------------------------------------------------
// Nitro enclave configuration
// ---------------------------------------------------------------------------

/// Runtime parameters for the AWS Nitro Enclave process.
///
/// Passed to `nitro-cli run-enclave` on startup and reused when opening
/// VSOCK connections to the running enclave.
#[derive(Debug, Clone, Copy)]
pub(crate) struct NitroConfig {
    /// VSOCK Context ID assigned to the enclave (`--enclave-cid`).
    pub enclave_cid: u32,
    /// VSOCK port the enclave listens on for execution requests.
    pub enclave_port: u32,
    /// Number of vCPUs allocated to the enclave (`--cpu-count`).
    pub cpu_count: u32,
    /// RAM in MiB allocated to the enclave (`--memory`).
    pub memory_mib: u32,
}

impl Default for NitroConfig {
    fn default() -> Self {
        Self { enclave_cid: 10, enclave_port: 5005, cpu_count: 2, memory_mib: 1024 }
    }
}
