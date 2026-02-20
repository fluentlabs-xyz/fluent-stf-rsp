use std::{
    fs,
    io::{Read, Write},
    path::Path,
};

use revm_primitives::hex;
use tokio::{process::Command as TokioCommand, task};
use tracing::info;

use vsock::{VsockAddr, VsockStream};

use crate::types::{AwsCredentials, EnclaveRequest, EnclaveResponse, NitroConfig};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const MAX_FRAME_SIZE: usize = 64 * 1024 * 1024;

// ---------------------------------------------------------------------------
// Enclave lifecycle
// ---------------------------------------------------------------------------

async fn run_enclave(eif_path: &Path, config: NitroConfig) -> eyre::Result<()> {
    let run_output = TokioCommand::new("nitro-cli")
        .args([
            "run-enclave",
            "--eif-path",
            eif_path.to_str().unwrap(),
            "--cpu-count",
            &config.cpu_count.to_string(),
            "--memory",
            &config.memory_mib.to_string(),
            "--enclave-cid",
            &config.enclave_cid.to_string(),
        ])
        .output()
        .await
        .map_err(|e| eyre::eyre!("Failed to execute nitro-cli run-enclave: {}", e))?;

    if !run_output.status.success() {
        let stderr = String::from_utf8_lossy(&run_output.stderr);
        return Err(eyre::eyre!("nitro-cli run-enclave failed: {}", stderr));
    }

    info!("Enclave running successfully");
    Ok(())
}

async fn terminate_enclave() -> eyre::Result<()> {
    let describe_output = TokioCommand::new("nitro-cli")
        .args(["describe-enclaves"])
        .output()
        .await
        .map_err(|e| eyre::eyre!("Failed to describe enclaves: {}", e))?;

    let stdout = String::from_utf8_lossy(&describe_output.stdout);
    let json: serde_json::Value = serde_json::from_str(&stdout)
        .map_err(|e| eyre::eyre!("Failed to parse describe-enclaves output: {}", e))?;

    if let Some(enclaves) = json.as_array() {
        for enclave in enclaves {
            if let Some(enclave_id) = enclave["EnclaveID"].as_str() {
                TokioCommand::new("nitro-cli")
                    .args(["terminate-enclave", "--enclave-id", enclave_id])
                    .output()
                    .await
                    .map_err(|e| {
                        eyre::eyre!("Failed to terminate enclave {}: {}", enclave_id, e)
                    })?;

                info!("Terminated enclave {}", enclave_id);
            }
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// PCR0 helpers
// ---------------------------------------------------------------------------

async fn get_running_enclave_pcr0() -> eyre::Result<Option<String>> {
    let output = TokioCommand::new("nitro-cli")
        .args(["describe-enclaves"])
        .output()
        .await
        .map_err(|e| eyre::eyre!("Failed to describe enclaves: {}", e))?;

    let json: serde_json::Value = serde_json::from_slice(&output.stdout)?;

    Ok(json
        .as_array()
        .and_then(|arr| arr.first())
        .and_then(|e| e["Measurements"]["PCR0"].as_str())
        .map(|s| s.to_string()))
}

async fn get_eif_pcr0(eif_path: &Path) -> eyre::Result<String> {
    let output = TokioCommand::new("nitro-cli")
        .args(["describe-eif", "--eif-path", eif_path.to_str().unwrap()])
        .output()
        .await
        .map_err(|e| eyre::eyre!("Failed to describe eif: {}", e))?;

    let json: serde_json::Value = serde_json::from_slice(&output.stdout)?;

    json["Measurements"]["PCR0"]
        .as_str()
        .map(|s| s.to_string())
        .ok_or_else(|| eyre::eyre!("PCR0 not found in eif description"))
}

// ---------------------------------------------------------------------------
// Public entry-point
// ---------------------------------------------------------------------------

/// Starts or restarts the enclave only when necessary (PCR0 mismatch or not running).
/// On a fresh start the signing key is initialised; on an image-change restart the key
/// is re-initialised so the new enclave can load it.
pub(crate) async fn maybe_restart_enclave(
    eif_path: &Path,
    nitro_config: NitroConfig,
) -> eyre::Result<()> {
    let running_pcr0 = get_running_enclave_pcr0().await?;
    let new_pcr0 = get_eif_pcr0(eif_path).await?;

    match running_pcr0 {
        Some(ref current) if current == &new_pcr0 => {
            info!(
                "Enclave already running with matching image (PCR0: {}), skipping restart",
                current
            );
        }
        Some(_) => {
            info!("Enclave image changed, restarting and re-initialising key…");
            terminate_enclave().await?;
            run_enclave(eif_path, nitro_config).await?;
            // The new enclave process needs the key too.
            initialize_enclave_key(nitro_config).await?;
        }
        None => {
            info!("No enclave running, starting…");
            run_enclave(eif_path, nitro_config).await?;
            initialize_enclave_key(nitro_config).await?;
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Environment helpers
// ---------------------------------------------------------------------------

fn aws_access_key_id() -> String {
    std::env::var("AWS_ACCESS_KEY_ID").expect("AWS_ACCESS_KEY_ID must be set")
}

fn aws_secret_access_key() -> String {
    std::env::var("AWS_SECRET_ACCESS_KEY").expect("AWS_SECRET_ACCESS_KEY must be set")
}

fn aws_session_token() -> Option<String> {
    std::env::var("AWS_SESSION_TOKEN").ok().filter(|s| !s.is_empty())
}

fn data_key_storage() -> String {
    std::env::var("DATA_KEY_STORAGE").unwrap_or_else(|_| "./data_key.enc".to_string())
}

fn attestation_storage() -> String {
    std::env::var("ATTESTATION_STORAGE").unwrap_or_else(|_| "./attestation.bin".to_string())
}

fn public_key_storage() -> String {
    std::env::var("PUBLIC_KEY_STORAGE").unwrap_or_else(|_| "./public_key.hex".to_string())
}

// ---------------------------------------------------------------------------
// Key management
// ---------------------------------------------------------------------------

async fn initialize_enclave_key(nitro_config: NitroConfig) -> eyre::Result<()> {
    let data_key_path = data_key_storage();
    let encrypted_dek = match fs::read(&data_key_path) {
        Ok(data) => {
            info!("Found existing encrypted data key, requesting decryption");
            Some(data)
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            info!("No existing key found, requesting new key creation");
            None
        }
        Err(err) => return Err(eyre::eyre!("Failed to read data key file: {}", err)),
    };

    let request = EnclaveRequest {
        credentials: AwsCredentials {
            access_key_id: aws_access_key_id(),
            secret_access_key: aws_secret_access_key(),
            session_token: aws_session_token(),
        },
        encrypted_data_key: encrypted_dek,
    };

    let resp =
        handle_key_management_request(nitro_config.enclave_cid, nitro_config.enclave_port, request)
            .await?;

    match resp {
        Some(EnclaveResponse::EncryptedDataKey {
            encrypted_signing_key,
            public_key,
            attestation,
        }) => {
            write_file(&data_key_path, &encrypted_signing_key)?;
            info!("Encrypted data key updated");

            write_file(&attestation_storage(), &attestation)?;
            info!("Attestation updated");

            let pk_hex = hex::encode(&public_key);
            write_file(&public_key_storage(), pk_hex.as_bytes())?;
            info!("Public key: {}", pk_hex);
        }
        Some(EnclaveResponse::Error(e)) => return Err(eyre::eyre!("Key management failed: {}", e)),
        _ => {}
    }

    Ok(())
}

/// Creates parent directories as needed then atomically writes `data` to `path`.
fn write_file(path: &str, data: &[u8]) -> eyre::Result<()> {
    if let Some(parent) = Path::new(path).parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(path, data).map_err(|e| eyre::eyre!("Failed to write {}: {}", path, e))
}

/// Sends `req` to the enclave over VSOCK and returns the response.
///
/// The connection and all I/O are offloaded to a blocking thread so that the
/// Tokio runtime is never stalled by synchronous `VsockStream` calls.
async fn handle_key_management_request(
    enclave_cid: u32,
    enclave_port: u32,
    req: EnclaveRequest,
) -> eyre::Result<Option<EnclaveResponse>> {
    info!("Handling key management request (has_key={})", req.encrypted_data_key.is_some());

    let req_bytes = bincode::serialize(&req)
        .map_err(|e| eyre::eyre!("Failed to serialize key request: {}", e))?;

    // Whether we expect a response depends on whether this is a "create key" or
    // "load key" request. Only "create key" (no existing DEK) returns data.
    let expect_response = req.encrypted_data_key.is_none();

    task::spawn_blocking(move || -> eyre::Result<Option<EnclaveResponse>> {
        let addr = VsockAddr::new(enclave_cid, enclave_port);
        let mut stream = VsockStream::connect(&addr)
            .map_err(|e| eyre::eyre!("Failed to connect to enclave: {}", e))?;

        let req_len = req_bytes.len() as u32;
        stream
            .write_all(&req_len.to_be_bytes())
            .map_err(|e| eyre::eyre!("Failed to write request length: {}", e))?;
        stream.write_all(&req_bytes).map_err(|e| eyre::eyre!("Failed to write request: {}", e))?;
        stream.flush().map_err(|e| eyre::eyre!("Failed to flush stream: {}", e))?;

        if !expect_response {
            return Ok(None);
        }

        let mut resp_len_buf = [0u8; 4];
        stream
            .read_exact(&mut resp_len_buf)
            .map_err(|e| eyre::eyre!("Failed to read response length: {}", e))?;
        let resp_len = u32::from_be_bytes(resp_len_buf) as usize;
        if resp_len > MAX_FRAME_SIZE {
            return Err(eyre::eyre!(
                "Response frame too large: {} bytes (max {})",
                resp_len,
                MAX_FRAME_SIZE
            ));
        }

        let mut resp_buf = vec![0u8; resp_len];
        stream
            .read_exact(&mut resp_buf)
            .map_err(|e| eyre::eyre!("Failed to read response body: {}", e))?;

        let response: EnclaveResponse = bincode::deserialize(&resp_buf)
            .map_err(|e| eyre::eyre!("Failed to deserialize response: {}", e))?;

        Ok(Some(response))
    })
    .await
    .map_err(|e| eyre::eyre!("Blocking task panicked: {}", e))?
}
