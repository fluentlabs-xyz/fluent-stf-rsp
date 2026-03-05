use revm_primitives::FixedBytes;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct AwsCredentials {
    pub access_key_id: String,
    pub secret_access_key: String,
    pub session_token: Option<String>,
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct EnclaveRequest {
    pub credentials: AwsCredentials,
    pub encrypted_data_key: Option<Vec<u8>>,
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub enum EnclaveResponse {
    /// A brand-new signing key was generated, encrypted via KMS, and attested.
    KeyGenerated {
        encrypted_signing_key: Vec<u8>,
        attestation: Vec<u8>,
        public_key: Vec<u8>,
    },
    /// An existing encrypted key was successfully decrypted and loaded.
    KeyRestored {
        public_key: Vec<u8>,
    },
    /// Something went wrong inside the enclave.
    Error(String),
}

/// Structure representing the result of Ethereum block execution.
/// Fields are stored as Vec<u8> for flexible serialization.
#[derive(serde::Serialize, serde::Deserialize, Debug)]
pub struct EthExecutionResponse {
    pub parent_hash: FixedBytes<32>,
    pub block_hash: FixedBytes<32>,
    pub withdrawal_hash: FixedBytes<32>,
    pub deposit_hash: FixedBytes<32>,
    pub result_hash: Vec<u8>,
    pub signature: Vec<u8>,
}