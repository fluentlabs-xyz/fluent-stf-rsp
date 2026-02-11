use base64::{engine::general_purpose, Engine as _};
use hmac::{Hmac, Mac};
use rsp_client_executor::nitro::AwsCredentials;
use rustls::{ClientConfig, ClientConnection, OwnedTrustAnchor, RootCertStore, StreamOwned};
use sha2::{Digest, Sha256};
use std::{
    io::{Read, Write},
    sync::Arc,
};
use vsock::{SockAddr, VsockStream};

use crate::nitro::{
    CONTENT_TYPE, HOST_CID, KEY_ID, KMS_HOST, KMS_PORT, REGION, TARGET_DECRYPT, TARGET_ENCRYPT,
    TARGET_GENERATE_DATA_KEY,
};

/// Client for interacting with AWS KMS via a VSOCK proxy inside a Nitro Enclave.
pub struct KmsClient {
    creds: AwsCredentials,
    region: String,
    host: String,
    key_id: String,
    vsock_addr: SockAddr,
}

impl KmsClient {
    pub fn new(creds: AwsCredentials) -> Self {
        Self {
            creds,
            region: REGION.to_string(),
            host: KMS_HOST.to_string(),
            key_id: KEY_ID.to_string(),
            vsock_addr: SockAddr::new_vsock(HOST_CID, KMS_PORT),
        }
    }

    /// Generates a new 256-bit symmetric Data Key.
    /// Returns a tuple of (Plaintext, CiphertextBlob).
    pub fn generate_data_key(&self) -> anyhow::Result<(Vec<u8>, Vec<u8>)> {
        let body = serde_json::json!({
            "KeyId": self.key_id,
            "KeySpec": "AES_256"
        });

        let resp = self.call_kms(TARGET_GENERATE_DATA_KEY, body)?;
        let plaintext = self.extract_b64(&resp, "Plaintext")?;
        let ciphertext = self.extract_b64(&resp, "CiphertextBlob")?;

        Ok((plaintext, ciphertext))
    }

    /// Encrypts plaintext bytes using the KMS Master Key.
    pub fn encrypt(&self, plaintext: &[u8]) -> anyhow::Result<Vec<u8>> {
        let body = serde_json::json!({
            "KeyId": self.key_id,
            "Plaintext": general_purpose::STANDARD.encode(plaintext)
        });

        let resp = self.call_kms(TARGET_ENCRYPT, body)?;
        self.extract_b64(&resp, "CiphertextBlob")
    }

    /// Decrypts a CiphertextBlob back into Plaintext.
    pub fn decrypt(&self, ciphertext: &[u8]) -> anyhow::Result<Vec<u8>> {
        let body = serde_json::json!({
            "CiphertextBlob": general_purpose::STANDARD.encode(ciphertext)
        });

        let resp = self.call_kms(TARGET_DECRYPT, body)?;
        self.extract_b64(&resp, "Plaintext")
    }

    // --- Private helpers for SigV4 signing and VSOCK communication ---

    fn call_kms(&self, target: &str, body: serde_json::Value) -> anyhow::Result<serde_json::Value> {
        let body_str = body.to_string();
        let http_req = self.build_signed_request(target, &body_str)?;

        let mut tls = self.connect()?;
        tls.write_all(http_req.as_bytes())?;
        tls.flush().ok();

        let mut resp_str = String::new();
        tls.read_to_string(&mut resp_str)?;

        let (_, body_part) = self.split_http(&resp_str);
        let parsed: serde_json::Value = serde_json::from_str(body_part)?;

        if let Some(err) = parsed.get("__type") {
            return Err(anyhow::anyhow!("KMS API Error {}: {}", err, body_part));
        }

        Ok(parsed)
    }

    fn connect(&self) -> anyhow::Result<StreamOwned<ClientConnection, VsockStream>> {
        let vsock = VsockStream::connect(&self.vsock_addr)?;

        let mut roots = RootCertStore::empty();
        roots.add_trust_anchors(webpki_roots::TLS_SERVER_ROOTS.iter().map(|ta| {
            OwnedTrustAnchor::from_subject_spki_name_constraints(
                ta.subject.as_ref(),
                ta.subject_public_key_info.as_ref(),
                ta.name_constraints.as_ref().map(|nc| nc.as_ref()),
            )
        }));

        let config = ClientConfig::builder()
            .with_safe_defaults()
            .with_root_certificates(roots)
            .with_no_client_auth();

        let server_name = self.host.as_str().try_into()?;
        let conn = ClientConnection::new(Arc::new(config), server_name)?;

        Ok(StreamOwned::new(conn, vsock))
    }

    fn build_signed_request(&self, target: &str, body: &str) -> anyhow::Result<String> {
    let now = chrono::Utc::now();
    let amz_date = now.format("%Y%m%dT%H%M%SZ").to_string();
    let date_stamp = now.format("%Y%m%d").to_string();

    let mut headers = vec![
        ("content-type", CONTENT_TYPE),
        ("host", self.host.as_str()),
        ("x-amz-date", amz_date.as_str()),
        ("x-amz-target", target),
    ];
    if let Some(token) = &self.creds.session_token {
        headers.push(("x-amz-security-token", token.as_str()));
    }
    headers.sort_by_key(|a| a.0);

    let canonical_headers: String = headers.iter()
        .map(|(k, v)| format!("{}:{}\n", k, v.trim()))
        .collect();
    let signed_headers = headers.iter()
        .map(|(k, _)| k.to_string())
        .collect::<Vec<_>>().join(";");

    let payload_hash = hex::encode(Sha256::digest(body.as_bytes()));
    let canonical_request = format!("POST\n/\n\n{}\n{}\n{}", canonical_headers, signed_headers, payload_hash);
    
    let credential_scope = format!("{}/{}/kms/aws4_request", date_stamp, self.region);
    let string_to_sign = format!("AWS4-HMAC-SHA256\n{}\n{}\n{}", amz_date, credential_scope, hex::encode(Sha256::digest(canonical_request.as_bytes())));
    let signing_key = self.get_signature_key(&date_stamp);
    let signature = hex::encode(self.hmac_sha256(&signing_key, string_to_sign.as_bytes()));

    let mut req = format!("POST / HTTP/1.1\r\n");
    req.push_str(&format!("Content-Length: {}\r\n", body.len()));
    for (k, v) in &headers {
        req.push_str(&format!("{}: {}\r\n", k, v));
    }
    let auth_header = format!(
        "AWS4-HMAC-SHA256 Credential={}/{}, SignedHeaders={}, Signature={}",
        self.creds.access_key_id, credential_scope, signed_headers, signature
    );
    req.push_str(&format!("Authorization: {}\r\n", auth_header));
    req.push_str("Connection: close\r\n"); // Важно для предотвращения зависаний
    req.push_str("\r\n");
    req.push_str(body);

    Ok(req)
}

    fn get_signature_key(&self, date: &str) -> Vec<u8> {
        let k_date = self.hmac_sha256(
            format!("AWS4{}", self.creds.secret_access_key).as_bytes(),
            date.as_bytes(),
        );
        let k_region = self.hmac_sha256(&k_date, self.region.as_bytes());
        let k_service = self.hmac_sha256(&k_region, b"kms");
        self.hmac_sha256(&k_service, b"aws4_request")
    }

    fn hmac_sha256(&self, key: &[u8], msg: &[u8]) -> Vec<u8> {
        let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("HMAC key length");
        mac.update(msg);
        mac.finalize().into_bytes().to_vec()
    }

    fn extract_b64(&self, json: &serde_json::Value, key: &str) -> anyhow::Result<Vec<u8>> {
        let b64_str = json
            .get(key)
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow::anyhow!("Response missing field: {}", key))?;
        general_purpose::STANDARD.decode(b64_str).map_err(|e| anyhow::anyhow!(e))
    }

    fn split_http<'a>(&self, resp: &'a str) -> (&'a str, &'a str) {
        resp.find("\r\n\r\n").map(|i| (&resp[..i], &resp[i + 4..])).unwrap_or((resp, ""))
    }
}
