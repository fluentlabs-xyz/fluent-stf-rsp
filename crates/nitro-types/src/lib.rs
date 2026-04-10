use alloy_primitives::B256;
use rsp_client_executor::io::EthClientExecutorInput;
use serde::{Deserialize, Serialize};

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
    pub tx_data_hash: B256,
    pub signature: Vec<u8>,
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
    ExecuteBlock { input: EthClientExecutorInput },
    SubmitBatch { from: u64, to: u64, responses: Vec<EthExecutionResponse>, blobs: Vec<Vec<u8>> },
}

#[derive(Serialize, Deserialize, Debug)]
pub enum EnclaveResponse {
    KeyGenerated { public_key: Vec<u8>, attestation: Vec<u8> },
    AlreadyInitialized { public_key: Vec<u8>, attestation: Vec<u8> },
    NotInitialized,
    ExecutionResult(EthExecutionResponse),
    SubmitBatchResult(SubmitBatchResponse),
    InvalidSignatures { invalid_blocks: Vec<u64> },
    Error(String),
}
