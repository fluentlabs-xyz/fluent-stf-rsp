#[cfg(feature = "nitro")]
#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub enum ExecutorKeyRequest {
    CreateNewKey,
    DecryptKey { encrypted_data_key: Vec<u8> },
}

#[cfg(feature = "nitro")]
#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub enum EnclaveKeyResponse {
    KeyCreated { encrypted_data_key: Vec<u8> },
    KeyDecrypted,
    Error(String),
}
