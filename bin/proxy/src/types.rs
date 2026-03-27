// ---------------------------------------------------------------------------
// SP1 proof result
// ---------------------------------------------------------------------------

use revm_primitives::FixedBytes;

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
