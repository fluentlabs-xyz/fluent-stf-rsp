#[cfg(feature = "nitro")]
use std::io::{Read, Write};

#[cfg(feature = "nitro")]
use aws_nitro_enclaves_nsm_api::{
    api::{Request, Response},
    driver,
};
#[cfg(feature = "nitro")]
use nix::libc;
#[cfg(feature = "nitro")]
use p256::ecdsa::{signature::Signer, Signature, SigningKey};
#[cfg(feature = "nitro")]
use p256::SecretKey;
#[cfg(feature = "nitro")]
use rsp_client_executor::key::{EnclaveKeyResponse, ExecutorKeyRequest};
use rsp_client_executor::{executor::EthClientExecutor, io::EthClientExecutorInput};
#[cfg(feature = "sp1")]
use rsp_client_executor::{executor::DESERIALZE_INPUTS, utils::profile_report};
use serde::{Deserialize, Serialize};
#[cfg(feature = "nitro")]
use serde_bytes::ByteBuf;
#[cfg(feature = "nitro")]
use sha2::{Digest, Sha256};
use std::sync::Arc;
#[cfg(feature = "nitro")]
use vsock::{SockAddr, VsockListener, VsockStream};

#[cfg(feature = "sp1")]
pub fn main() {
    // Read the input.
    let input = profile_report!(DESERIALZE_INPUTS, {
        let input = sp1_zkvm::io::read_vec();
        bincode::deserialize::<EthClientExecutorInput>(&input).unwrap()
    });

    // Execute the block.
    let executor = EthClientExecutor::eth(
        Arc::new((&input.genesis).try_into().unwrap()),
        input.custom_beneficiary,
    );
    let (header, events_hash) = executor.execute(input).expect("failed to execute client");
    let block_hash = header.hash_slow();
    let parent_hash = header.parent_hash;

    // Commit the block hash.
    sp1_zkvm::io::commit(&parent_hash);
    sp1_zkvm::io::commit(&block_hash);
    sp1_zkvm::io::commit(&events_hash.withdrawal_hash);
    sp1_zkvm::io::commit(&events_hash.deposit_hash);
}

#[cfg(feature = "nitro")]
const VSOCK_PORT: u32 = 5005;
#[cfg(feature = "nitro")]
const KEY_MANAGEMENT_PORT: u32 = 5006;
#[cfg(feature = "nitro")]
const MAX_FRAME_SIZE: usize = 64 * 1024 * 1024;
#[cfg(feature = "nitro")]
const HOST_CID: u32 = 3;
#[cfg(feature = "nitro")]
const KMS_PORT: u32 = 8000;
#[cfg(feature = "nitro")]
const KEY_ID: &str = "alias/enclave-master-key";

#[derive(Serialize, Deserialize)]
struct AttestationUserData {
    pubkey: Vec<u8>,
    signature: Vec<u8>,
    result_hash: Vec<u8>,
}

#[cfg(feature = "nitro")]
#[derive(Serialize)]
#[allow(non_snake_case)]
struct KmsGenerateRequest<'a> {
    Action: &'a str,
    KeyId: &'a str,
    KeySpec: &'a str,
}

#[cfg(feature = "nitro")]
#[derive(Deserialize)]
#[allow(non_snake_case)]
struct KmsGenerateResponse {
    Plaintext: String,
    CiphertextBlob: String,
}

#[cfg(feature = "nitro")]
#[derive(Serialize)]
#[allow(non_snake_case)]
struct KmsDecryptRequest<'a> {
    Action: &'a str,
    CiphertextBlob: &'a str,
}

#[cfg(feature = "nitro")]
#[derive(Deserialize)]
#[allow(non_snake_case)]
struct KmsDecryptResponse {
    Plaintext: String,
}

#[cfg(feature = "nitro")]
fn kms_proxy_call(req: &str) -> anyhow::Result<String> {
    use std::io::{Read, Write};
    let addr = SockAddr::new_vsock(HOST_CID, KMS_PORT);
    let mut stream = VsockStream::connect(&addr)
        .map_err(|e| anyhow::anyhow!("Failed to connect to KMS proxy: {}", e))?;
    stream
        .write_all(req.as_bytes())
        .map_err(|e| anyhow::anyhow!("Failed to write to KMS proxy: {}", e))?;
    stream.flush().map_err(|e| anyhow::anyhow!("Failed to flush KMS proxy stream: {}", e))?;
    let mut resp = String::new();
    stream
        .read_to_string(&mut resp)
        .map_err(|e| anyhow::anyhow!("Failed to read from KMS proxy: {}", e))?;
    Ok(resp)
}

#[cfg(feature = "nitro")]
fn generate_data_key() -> anyhow::Result<(Vec<u8>, Vec<u8>)> {
    use base64::{engine::general_purpose, Engine as _};
    use tracing::info;

    info!("Calling KMS proxy for GenerateDataKey");
    let req = KmsGenerateRequest { Action: "GenerateDataKey", KeyId: KEY_ID, KeySpec: "AES_256" };
    let req_json = serde_json::to_string(&req)
        .map_err(|e| anyhow::anyhow!("Failed to serialize KMS request: {}", e))?;
    let resp = kms_proxy_call(&req_json)?;
    let parsed: KmsGenerateResponse = serde_json::from_str(&resp)
        .map_err(|e| anyhow::anyhow!("Failed to parse KMS response: {}", e))?;
    let plaintext = general_purpose::STANDARD
        .decode(&parsed.Plaintext)
        .map_err(|e| anyhow::anyhow!("Failed to decode plaintext: {}", e))?;
    let ciphertext = general_purpose::STANDARD
        .decode(&parsed.CiphertextBlob)
        .map_err(|e| anyhow::anyhow!("Failed to decode ciphertext: {}", e))?;
    Ok((plaintext, ciphertext))
}

#[cfg(feature = "nitro")]
fn decrypt_data_key(ciphertext: &[u8]) -> anyhow::Result<Vec<u8>> {
    use base64::{engine::general_purpose, Engine as _};
    use tracing::info;

    info!("Calling KMS proxy for Decrypt");
    let ciphertext_b64 = general_purpose::STANDARD.encode(ciphertext);
    let req = KmsDecryptRequest { Action: "Decrypt", CiphertextBlob: &ciphertext_b64 };
    let req_json = serde_json::to_string(&req)
        .map_err(|e| anyhow::anyhow!("Failed to serialize KMS request: {}", e))?;
    let resp = kms_proxy_call(&req_json)?;
    let parsed: KmsDecryptResponse = serde_json::from_str(&resp)
        .map_err(|e| anyhow::anyhow!("Failed to parse KMS response: {}", e))?;
    let plaintext = general_purpose::STANDARD
        .decode(&parsed.Plaintext)
        .map_err(|e| anyhow::anyhow!("Failed to decode plaintext: {}", e))?;
    Ok(plaintext)
}

#[cfg(feature = "nitro")]
fn handle_key_management_request(
    req: ExecutorKeyRequest,
) -> anyhow::Result<(EnclaveKeyResponse, Vec<u8>)> {
    use tracing::info;

    match req {
        ExecutorKeyRequest::CreateNewKey => {
            info!("Handling CreateNewKey request");
            let (data_key, encrypted_data_key) = generate_data_key()?;
            Ok((EnclaveKeyResponse::KeyCreated { encrypted_data_key }, data_key))
        }
        ExecutorKeyRequest::DecryptKey { encrypted_data_key } => {
            info!("Handling DecryptKey request");
            let data_key = decrypt_data_key(&encrypted_data_key)?;
            Ok((EnclaveKeyResponse::KeyDecrypted, data_key))
        }
    }
}

#[cfg(feature = "nitro")]
fn main() -> anyhow::Result<()> {
    println!("Nitro enclave started");

    let key_mgmt_addr = SockAddr::new_vsock(libc::VMADDR_CID_ANY, KEY_MANAGEMENT_PORT);
    let key_mgmt_listener = VsockListener::bind(&key_mgmt_addr)?;
    println!("Key management listener bound to port {}", KEY_MANAGEMENT_PORT);

    let exec_addr = SockAddr::new_vsock(libc::VMADDR_CID_ANY, VSOCK_PORT);
    let exec_listener = VsockListener::bind(&exec_addr)?;
    println!("Execution listener bound to port {}", VSOCK_PORT);

    let data_key = {
        let (mut stream, _) = key_mgmt_listener
            .accept()
            .map_err(|e| anyhow::anyhow!("Key management accept error: {:?}", e))?;
        println!("Accepted key management connection");

        let mut len_buf = [0u8; 4];
        stream.read_exact(&mut len_buf)?;
        let len = u32::from_be_bytes(len_buf) as usize;
        if len > MAX_FRAME_SIZE {
            return Err(anyhow::anyhow!("Key management frame too large: {} bytes", len));
        }

        let mut buf = vec![0u8; len];
        stream.read_exact(&mut buf)?;

        let req: ExecutorKeyRequest = bincode::deserialize(&buf).map_err(|e| {
            let resp = EnclaveKeyResponse::Error(format!("Deserialize error: {}", e));
            let resp_bytes = bincode::serialize(&resp).unwrap_or_default();
            let resp_len = resp_bytes.len() as u32;
            let _ = stream.write_all(&resp_len.to_be_bytes());
            let _ = stream.write_all(&resp_bytes);
            anyhow::anyhow!("Failed to deserialize key request: {}", e)
        })?;

        let (resp, data_key) = handle_key_management_request(req).map_err(|e| {
            eprintln!("Key management error: {}", e);
            anyhow::anyhow!("Key management failed: {}", e)
        })?;

        let resp_bytes = bincode::serialize(&resp)
            .map_err(|e| anyhow::anyhow!("Failed to serialize response: {}", e))?;
        let resp_len = resp_bytes.len() as u32;
        stream
            .write_all(&resp_len.to_be_bytes())
            .map_err(|e| anyhow::anyhow!("Failed to write response length: {}", e))?;
        stream
            .write_all(&resp_bytes)
            .map_err(|e| anyhow::anyhow!("Failed to write response: {}", e))?;
        stream.flush().map_err(|e| anyhow::anyhow!("Failed to flush stream: {}", e))?;
        println!("Sent key management response");

        data_key
    };

    let (mut stream, _) = exec_listener.accept()?;
    println!("Accepted execution connection");

    let secret_key = SecretKey::from_bytes(data_key.as_slice().into())
        .map_err(|e| anyhow::anyhow!("Failed to reconstruct secret key: {}", e))?;
    let signing_key = SigningKey::from(secret_key);

    // Read execution input
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf)?;
    let len = u32::from_be_bytes(len_buf) as usize;
    if len > MAX_FRAME_SIZE {
        return Err(anyhow::anyhow!(
            "Request frame too large: {} bytes (cap {})",
            len,
            MAX_FRAME_SIZE
        ));
    }
    let mut buf = vec![0u8; len];
    stream.read_exact(&mut buf)?;

    println!("Received execution input, size: {} bytes", buf.len());

    let input: EthClientExecutorInput = bincode::deserialize(&buf)
        .map_err(|e| anyhow::anyhow!("Failed to deserialize input: {}", e))?;

    let executor = EthClientExecutor::eth(
        Arc::new((&input.genesis).try_into().unwrap()),
        input.custom_beneficiary,
    );
    let (header, events_hash) = executor
        .execute(input)
        .map_err(|e| anyhow::anyhow!("Failed to execute client: {:?}", e))?;

    let block_hash = header.hash_slow();
    let parent_hash = header.parent_hash;

    let mut hasher = Sha256::new();
    hasher.update(AsRef::<[u8]>::as_ref(&parent_hash));
    hasher.update(AsRef::<[u8]>::as_ref(&block_hash));
    hasher.update(AsRef::<[u8]>::as_ref(&events_hash.withdrawal_hash));
    hasher.update(AsRef::<[u8]>::as_ref(&events_hash.deposit_hash));
    let result_hash = hasher.finalize();

    let pubkey = signing_key.verifying_key();
    let pubkey_bytes = pubkey.to_encoded_point(false).as_bytes().to_vec();

    let signature: Signature = signing_key.sign(&result_hash);

    let user_data = AttestationUserData {
        pubkey: pubkey_bytes,
        signature: signature.to_bytes().to_vec(),
        result_hash: result_hash.to_vec(),
    };

    let user_data_cbor = serde_cbor::to_vec(&user_data)?;

    let nsm_fd = driver::nsm_init();
    let response = driver::nsm_process_request(
        nsm_fd,
        Request::Attestation {
            public_key: None,
            user_data: Some(ByteBuf::from(user_data_cbor)),
            nonce: None,
        },
    );

    let attestation_doc = match response {
        Response::Attestation { document } => document,
        _ => return Err(anyhow::anyhow!("Failed to get attestation document")),
    };
    driver::nsm_exit(nsm_fd);

    let output = serde_json::json!({
        "parent_hash": hex::encode(parent_hash),
        "block_hash": hex::encode(block_hash),
        "withdrawal_hash": hex::encode(events_hash.withdrawal_hash),
        "deposit_hash": hex::encode(events_hash.deposit_hash),
        "result_hash": hex::encode(result_hash),
        "attestation": attestation_doc,
    });

    let serialized = serde_json::to_vec(&output)?;
    let resp_len = serialized.len() as u32;
    stream.write_all(&resp_len.to_be_bytes())?;
    stream.write_all(&serialized)?;
    stream.flush()?;
    println!("Sent response, size: {} bytes", serialized.len());

    Ok(())
}
