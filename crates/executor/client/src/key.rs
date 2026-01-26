#[cfg(feature = "nitro")]
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct AwsCredentials {
    pub access_key_id: String,
    pub secret_access_key: String,
    pub session_token: Option<String>,
}

#[cfg(feature = "nitro")]
#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct EnclaveKeyRequest {
    pub credentials: AwsCredentials,
    pub encrypted_data_key: Option<Vec<u8>>,
}

#[cfg(feature = "nitro")]
#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub enum EnclaveKeyResponse {
    EncryptedDataKey { encrypted_data_key: Vec<u8> },
    Error(String),
}
