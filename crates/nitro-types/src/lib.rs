use alloy_primitives::{Address, B256};
use rsp_client_executor::io::EthClientExecutorInput;
use serde::{Deserialize, Serialize};
use serde_big_array::BigArray;

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct AwsCredentials {
    pub access_key_id: String,
    pub secret_access_key: String,
    pub session_token: String,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct EthExecutionResponse {
    pub block_number: u64,
    pub leaf: [u8; 32],
    pub block_hash: B256,
    #[serde(with = "BigArray")]
    pub signature: [u8; 64],
}

/// Host-prepared KZG witness consumed by the SP1 guest. Wire-compat via
/// bincode — proxy serializes, SP1 ELF deserializes.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BlobVerificationInput {
    pub blobs: Vec<Vec<u8>>,
    pub commitments: Vec<Vec<u8>>,
    pub proofs: Vec<Vec<u8>>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct SubmitBatchResponse {
    pub batch_root: Vec<u8>,
    pub versioned_hashes: Vec<B256>,
    pub signature: Vec<u8>,
}

#[derive(Serialize, Deserialize, Debug)]
pub enum EnclaveIncoming {
    Handshake { credentials: AwsCredentials },
    ExecuteBlock { input: Box<EthClientExecutorInput> },
    SubmitBatch { from: u64, to: u64, responses: Vec<EthExecutionResponse>, blobs: Vec<Vec<u8>> },
}

/// Response body when `/sign-batch-root` returns 409: the enclave key was
/// rotated since these responses were signed and they must be re-executed.
///
/// Wire shape exchanged between proxy and orchestrator over HTTP/JSON.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InvalidSignaturesResponse {
    pub invalid_blocks: Vec<u64>,
    pub enclave_address: Address,
}

/// Request body for `POST /sign-batch-root`.
///
/// Blobs are base64-encoded to avoid serde_json's `Vec<u8>`-as-int-array
/// blow-up (~3.5× wire cost per byte). With the serde attribute below,
/// blobs round-trip as short base64 strings over JSON.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignBatchRootRequest {
    pub from_block: u64,
    pub to_block: u64,
    pub batch_index: u64,
    pub responses: Vec<EthExecutionResponse>,
    #[serde(with = "serde_blobs_base64")]
    pub blobs: Vec<Vec<u8>>,
}

mod serde_blobs_base64 {
    use base64::{engine::general_purpose::STANDARD, Engine};
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub(crate) fn serialize<S: Serializer>(blobs: &[Vec<u8>], s: S) -> Result<S::Ok, S::Error> {
        let encoded: Vec<String> = blobs.iter().map(|b| STANDARD.encode(b)).collect();
        encoded.serialize(s)
    }

    pub(crate) fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<Vec<u8>>, D::Error> {
        let encoded: Vec<String> = Vec::deserialize(d)?;
        encoded
            .into_iter()
            .map(|s| STANDARD.decode(s.as_bytes()).map_err(serde::de::Error::custom))
            .collect()
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub enum EnclaveResponse {
    KeyGenerated { public_key: Vec<u8>, attestation: Vec<u8> },
    AlreadyInitialized { public_key: Vec<u8>, attestation: Vec<u8> },
    NotInitialized,
    ExecutionResult(EthExecutionResponse),
    SubmitBatchResult(SubmitBatchResponse),
    InvalidSignatures { invalid_blocks: Vec<u64>, enclave_address: Address },
    Error(String),
}
