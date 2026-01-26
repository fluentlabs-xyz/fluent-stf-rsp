#[cfg(feature = "nitro")]
use std::io::{Read, Write};

#[cfg(feature = "nitro")]
use aws_nitro_enclaves_nsm_api::{
    api::{Request, Response},
    driver,
};
#[cfg(feature = "nitro")]
use hmac::Mac;
#[cfg(feature = "nitro")]
use nix::libc;
#[cfg(feature = "nitro")]
use p256::ecdsa::{signature::Signer, Signature, SigningKey};
#[cfg(feature = "nitro")]
use p256::SecretKey;
#[cfg(feature = "nitro")]
use rsp_client_executor::key::{AwsCredentials, EnclaveKeyRequest, EnclaveKeyResponse};
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
const MAX_FRAME_SIZE: usize = 64 * 1024 * 1024;
#[cfg(feature = "nitro")]
const HOST_CID: u32 = 3;
#[cfg(feature = "nitro")]
const KMS_PORT: u32 = 8000;
#[cfg(feature = "nitro")]
const KEY_ID: &str = "e3e3147b-f94a-4127-a845-a082e6cc8448";
#[cfg(feature = "nitro")]
const REGION: &str = "us-east-1";
#[cfg(feature = "nitro")]
const KMS_HOST: &str = "kms.us-east-1.amazonaws.com";
#[cfg(feature = "nitro")]
const CONTENT_TYPE: &str = "application/x-amz-json-1.1";
#[cfg(feature = "nitro")]
const TARGET_GENERATE_DATA_KEY: &str = "TrentService.GenerateDataKey";
#[cfg(feature = "nitro")]
const TARGET_DECRYPT: &str = "TrentService.Decrypt";

#[derive(Serialize, Deserialize)]
struct AttestationUserData {
    pubkey: Vec<u8>,
    signature: Vec<u8>,
    parent_hash: Vec<u8>,
    block_hash: Vec<u8>,
    withdrawal_hash: Vec<u8>,
    deposit_hash: Vec<u8>,
    result_hash: Vec<u8>,
}

#[cfg(feature = "nitro")]
fn tls_stream_to_kms() -> anyhow::Result<rustls::StreamOwned<rustls::ClientConnection, VsockStream>>
{
    use rustls::{ClientConfig, ClientConnection, RootCertStore};
    use std::sync::Arc;

    let addr = SockAddr::new_vsock(HOST_CID, KMS_PORT);
    let vsock = VsockStream::connect(&addr)
        .map_err(|e| anyhow::anyhow!("Failed to connect to VSOCK proxy: {}", e))?;

    let mut roots = RootCertStore::empty();
    roots.add_server_trust_anchors(webpki_roots::TLS_SERVER_ROOTS.iter().map(|ta| {
        rustls::OwnedTrustAnchor::from_subject_spki_name_constraints(
            ta.subject.as_ref(),
            ta.subject_public_key_info.as_ref(),
            ta.name_constraints.as_ref().map(|nc| nc.as_ref()),
        )
    }));

    let config = ClientConfig::builder()
        .with_safe_defaults()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let server_name = KMS_HOST.try_into().map_err(|e| anyhow::anyhow!("invalid DNS: {}", e))?;
    let conn = ClientConnection::new(Arc::new(config), server_name)
        .map_err(|e| anyhow::anyhow!("rustls client connection: {}", e))?;

    Ok(rustls::StreamOwned::new(conn, vsock))
}

#[cfg(feature = "nitro")]
fn kms_proxy_call(req: &str) -> anyhow::Result<String> {
    let mut tls = tls_stream_to_kms()?;
    tls.write_all(req.as_bytes()).map_err(|e| anyhow::anyhow!("Failed to write request: {}", e))?;
    tls.flush().ok();

    let mut resp = String::new();
    tls.read_to_string(&mut resp).map_err(|e| anyhow::anyhow!("Failed to read response: {}", e))?;
    Ok(resp)
}

#[cfg(feature = "nitro")]
fn split_http(resp: &str) -> (&str, &str) {
    match resp.find("\r\n\r\n") {
        Some(i) => (&resp[..i], &resp[i + 4..]),
        None => (resp, ""),
    }
}

#[cfg(feature = "nitro")]
fn status_line(headers: &str) -> &str {
    headers.lines().next().unwrap_or("<no status line>")
}

#[cfg(feature = "nitro")]
fn sha256_hex(data: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(data);
    hex::encode(h.finalize())
}

#[cfg(feature = "nitro")]
fn hmac_sha256(key: &[u8], msg: &[u8]) -> Vec<u8> {
    let mut mac = hmac::Hmac::<Sha256>::new_from_slice(key).expect("HMAC key");
    mac.update(msg);
    mac.finalize().into_bytes().to_vec()
}

#[cfg(feature = "nitro")]
fn signing_key(secret: &str, date_yyyymmdd: &str, region: &str, service: &str) -> Vec<u8> {
    let k_secret = format!("AWS4{}", secret);
    let k_date = hmac_sha256(k_secret.as_bytes(), date_yyyymmdd.as_bytes());
    let k_region = hmac_sha256(&k_date, region.as_bytes());
    let k_service = hmac_sha256(&k_region, service.as_bytes());
    hmac_sha256(&k_service, b"aws4_request")
}

#[cfg(feature = "nitro")]
fn build_signed_http_request(
    creds: &AwsCredentials,
    target: &str,
    body_json: &str,
    now: chrono::DateTime<chrono::Utc>,
) -> anyhow::Result<String> {
    let amz_date = now.format("%Y%m%dT%H%M%SZ").to_string();
    let date = now.format("%Y%m%d").to_string();

    let mut headers: Vec<(String, String)> = vec![
        ("content-type".into(), CONTENT_TYPE.into()),
        ("host".into(), KMS_HOST.into()),
        ("x-amz-date".into(), amz_date.clone()),
        ("x-amz-target".into(), target.into()),
    ];
    if let Some(token) = &creds.session_token {
        if !token.is_empty() {
            headers.push(("x-amz-security-token".into(), token.clone()));
        }
    }
    headers.sort_by(|a, b| a.0.cmp(&b.0));

    let canonical_headers =
        headers.iter().map(|(k, v)| format!("{}:{}\n", k, v.trim())).collect::<String>();

    let signed_headers = headers.iter().map(|(k, _)| k.clone()).collect::<Vec<_>>().join(";");

    let payload_hash = sha256_hex(body_json.as_bytes());

    let canonical_request =
        format!("POST\n/\n\n{canonical_headers}\n{signed_headers}\n{payload_hash}");
    let canonical_request_hash = sha256_hex(canonical_request.as_bytes());

    let credential_scope = format!("{}/{}/kms/aws4_request", date, REGION);
    let string_to_sign = format!(
        "AWS4-HMAC-SHA256\n{amz_date}\n{scope}\n{cr_hash}",
        amz_date = amz_date,
        scope = credential_scope,
        cr_hash = canonical_request_hash
    );

    let key = signing_key(&creds.secret_access_key, &date, REGION, "kms");
    let signature = hex::encode(hmac_sha256(&key, string_to_sign.as_bytes()));

    let authorization = format!(
        "AWS4-HMAC-SHA256 Credential={}/{}, SignedHeaders={}, Signature={}",
        creds.access_key_id, credential_scope, signed_headers, signature
    );

    let mut req = String::new();
    req.push_str("POST / HTTP/1.1\r\n");
    req.push_str(&format!("Host: {}\r\n", KMS_HOST));
    req.push_str(&format!("Content-Type: {}\r\n", CONTENT_TYPE));
    req.push_str(&format!("X-Amz-Target: {}\r\n", target));
    req.push_str(&format!("X-Amz-Date: {}\r\n", amz_date));
    if let Some(token) = &creds.session_token {
        if !token.is_empty() {
            req.push_str(&format!("X-Amz-Security-Token: {}\r\n", token));
        }
    }
    req.push_str(&format!("Authorization: {}\r\n", authorization));
    req.push_str(&format!("Content-Length: {}\r\n", body_json.as_bytes().len()));
    req.push_str("\r\n");
    req.push_str(body_json);

    Ok(req)
}

#[cfg(feature = "nitro")]
fn generate_data_key(creds: &AwsCredentials) -> anyhow::Result<(Vec<u8>, Vec<u8>)> {
    use base64::{engine::general_purpose, Engine as _};
    use tracing::info;

    info!("Calling KMS proxy for GenerateDataKey");
    let body = serde_json::json!({
        "KeyId": KEY_ID,
        "KeySpec": "AES_256"
    })
    .to_string();

    let req = build_signed_http_request(creds, TARGET_GENERATE_DATA_KEY, &body, chrono::Utc::now())
        .map_err(|e| anyhow::anyhow!("sign GenerateDataKey: {}", e))?;
    let resp = kms_proxy_call(&req)?;
    let (hdr, body) = split_http(&resp);
    if !status_line(hdr).contains("200") {
        return Err(anyhow::anyhow!("GenerateDataKey failed: {}", body));
    }

    let parsed: serde_json::Value =
        serde_json::from_str(body).map_err(|e| anyhow::anyhow!("parse GenerateDataKey: {}", e))?;
    let ciphertext_blob = parsed
        .get("CiphertextBlob")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow::anyhow!("GenerateDataKey missing CiphertextBlob"))?;
    let plaintext = parsed
        .get("Plaintext")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow::anyhow!("GenerateDataKey missing Plaintext"))?;

    let plaintext = general_purpose::STANDARD
        .decode(plaintext)
        .map_err(|e| anyhow::anyhow!("Failed to decode plaintext: {}", e))?;
    let ciphertext = general_purpose::STANDARD
        .decode(ciphertext_blob)
        .map_err(|e| anyhow::anyhow!("Failed to decode ciphertext: {}", e))?;
    Ok((plaintext, ciphertext))
}

#[cfg(feature = "nitro")]
fn decrypt_data_key(creds: &AwsCredentials, ciphertext: &[u8]) -> anyhow::Result<Vec<u8>> {
    use base64::{engine::general_purpose, Engine as _};
    use tracing::info;

    info!("Calling KMS proxy for Decrypt");
    let ciphertext_b64 = general_purpose::STANDARD.encode(ciphertext);
    let body = serde_json::json!({
        "CiphertextBlob": ciphertext_b64
    })
    .to_string();

    let req = build_signed_http_request(creds, TARGET_DECRYPT, &body, chrono::Utc::now())
        .map_err(|e| anyhow::anyhow!("sign Decrypt: {}", e))?;
    let resp = kms_proxy_call(&req)?;
    let (hdr, body) = split_http(&resp);
    if !status_line(hdr).contains("200") {
        return Err(anyhow::anyhow!("Decrypt failed: {}", body));
    }

    let parsed: serde_json::Value =
        serde_json::from_str(body).map_err(|e| anyhow::anyhow!("parse Decrypt: {}", e))?;
    let plaintext = parsed
        .get("Plaintext")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow::anyhow!("Decrypt missing Plaintext"))?;
    let plaintext = general_purpose::STANDARD
        .decode(plaintext)
        .map_err(|e| anyhow::anyhow!("Failed to decode plaintext: {}", e))?;
    Ok(plaintext)
}

#[cfg(feature = "nitro")]
fn handle_key_management_request(req: EnclaveKeyRequest) -> anyhow::Result<(Vec<u8>, Vec<u8>)> {
    use tracing::info;

    match req.encrypted_data_key {
        Some(encrypted_data_key) => {
            info!("Handling decrypt of existing encrypted data key");
            let data_key = decrypt_data_key(&req.credentials, &encrypted_data_key)?;
            Ok((data_key, encrypted_data_key))
        }
        None => {
            info!("Handling GenerateDataKey request");
            let (data_key, encrypted_data_key) = generate_data_key(&req.credentials)?;
            Ok((data_key, encrypted_data_key))
        }
    }
}

#[cfg(feature = "nitro")]
fn main() -> anyhow::Result<()> {
    println!("Nitro enclave started");

    let addr = SockAddr::new_vsock(libc::VMADDR_CID_ANY, VSOCK_PORT);
    let listener = VsockListener::bind(&addr)?;
    println!("Listener bound to port {}", VSOCK_PORT);

    let data_key = {
        let (mut stream, _) = listener
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

        let req: EnclaveKeyRequest = bincode::deserialize(&buf).map_err(|e| {
            let resp = EnclaveKeyResponse::Error(format!("Deserialize error: {}", e));
            let resp_bytes = bincode::serialize(&resp).unwrap_or_default();
            let resp_len = resp_bytes.len() as u32;
            let _ = stream.write_all(&resp_len.to_be_bytes());
            let _ = stream.write_all(&resp_bytes);
            anyhow::anyhow!("Failed to deserialize key request: {}", e)
        })?;

        let (data_key, encrypted_data_key) = handle_key_management_request(req).map_err(|e| {
            eprintln!("Key management error: {}", e);
            anyhow::anyhow!("Key management failed: {}", e)
        })?;

        let resp = EnclaveKeyResponse::EncryptedDataKey { encrypted_data_key };
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

    let (mut stream, _) = listener.accept()?;
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

    let mut signing_hasher = Sha256::new();
    signing_hasher.update(AsRef::<[u8]>::as_ref(&parent_hash));
    signing_hasher.update(AsRef::<[u8]>::as_ref(&block_hash));
    signing_hasher.update(AsRef::<[u8]>::as_ref(&events_hash.withdrawal_hash));
    signing_hasher.update(AsRef::<[u8]>::as_ref(&events_hash.deposit_hash));
    signing_hasher.update(result_hash.as_slice());
    let signing_payload = signing_hasher.finalize();

    let signature: Signature = signing_key.sign(signing_payload.as_slice());

    let user_data = AttestationUserData {
        pubkey: pubkey_bytes,
        signature: signature.to_bytes().to_vec(),
        parent_hash: AsRef::<[u8]>::as_ref(&parent_hash).to_vec(),
        block_hash: AsRef::<[u8]>::as_ref(&block_hash).to_vec(),
        withdrawal_hash: AsRef::<[u8]>::as_ref(&events_hash.withdrawal_hash).to_vec(),
        deposit_hash: AsRef::<[u8]>::as_ref(&events_hash.deposit_hash).to_vec(),
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
