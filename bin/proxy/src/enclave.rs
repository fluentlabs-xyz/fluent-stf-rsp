use std::{
    fs,
    io::{Read, Write},
    path::Path,
};

use aws_config::BehaviorVersion;
use aws_credential_types::provider::ProvideCredentials;
use eyre::WrapErr;
use reth_ethereum_primitives::EthPrimitives;
use revm_primitives::hex;
use tokio::{process::Command as TokioCommand, task};
use tracing::info;

use vsock::{VsockAddr, VsockStream};

use nitro_types::{AwsCredentials, EnclaveRequest, EnclaveResponse, EthExecutionResponse};
use rsp_client_executor::io::ClientExecutorInput;

use crate::types::NitroConfig;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const MAX_FRAME_SIZE: usize = 64 * 1024 * 1024;

/// Delay before connecting to give the enclave time to bind its listener.
const ENCLAVE_BOOT_DELAY: std::time::Duration = std::time::Duration::from_secs(10);

// ---------------------------------------------------------------------------
// Enclave lifecycle
// ---------------------------------------------------------------------------

async fn run_enclave(eif_path: &Path, config: &NitroConfig) -> eyre::Result<()> {
    let output = TokioCommand::new("nitro-cli")
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
        .wrap_err("Failed to execute nitro-cli run-enclave")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(eyre::eyre!("nitro-cli run-enclave failed: {stderr}"));
    }

    info!("Enclave running successfully");
    Ok(())
}

async fn terminate_enclave() -> eyre::Result<()> {
    let output = TokioCommand::new("nitro-cli")
        .args(["describe-enclaves"])
        .output()
        .await
        .wrap_err("Failed to describe enclaves")?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    let json: serde_json::Value =
        serde_json::from_str(&stdout).wrap_err("Failed to parse describe-enclaves output")?;

    let Some(enclaves) = json.as_array() else { return Ok(()) };

    for enclave in enclaves {
        let Some(id) = enclave["EnclaveID"].as_str() else { continue };

        TokioCommand::new("nitro-cli")
            .args(["terminate-enclave", "--enclave-id", id])
            .output()
            .await
            .wrap_err_with(|| format!("Failed to terminate enclave {id}"))?;

        info!("Terminated enclave {id}");
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
        .wrap_err("Failed to describe enclaves")?;

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
        .wrap_err("Failed to describe eif")?;

    let json: serde_json::Value = serde_json::from_slice(&output.stdout)?;

    json["Measurements"]["PCR0"]
        .as_str()
        .map(|s| s.to_string())
        .ok_or_else(|| eyre::eyre!("PCR0 not found in eif description"))
}

// ---------------------------------------------------------------------------
// Public entry-point
// ---------------------------------------------------------------------------

pub(crate) async fn maybe_restart_enclave(
    eif_path: &Path,
    nitro_config: NitroConfig,
) -> eyre::Result<()> {
    let running_pcr0 = get_running_enclave_pcr0().await?;
    let new_pcr0 = get_eif_pcr0(eif_path).await?;

    match running_pcr0 {
        Some(ref current) if current == &new_pcr0 => {
            info!("Enclave already running with matching image (PCR0: {current}), skipping restart");
        }
        Some(_) => {
            info!("Enclave image changed, restarting and re-initialising key…");
            terminate_enclave().await?;
            run_enclave(eif_path, &nitro_config).await?;
            initialize_enclave_key(&nitro_config).await?;
        }
        None => {
            info!("No enclave running, starting…");
            run_enclave(eif_path, &nitro_config).await?;
            initialize_enclave_key(&nitro_config).await?;
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Block execution — called from axum handlers
// ---------------------------------------------------------------------------

/// Sends a block to the Nitro enclave for execution and verifies the result.
///
/// Each call opens a **new** VSOCK connection, so concurrent calls from
/// multiple axum handlers are safe — the enclave handles them in parallel
/// via `thread::spawn` on its side.
pub(crate) async fn execute_block(
    client_input: ClientExecutorInput<EthPrimitives>,
    config: NitroConfig,
) -> eyre::Result<EthExecutionResponse> {
    let cid = config.enclave_cid;
    let port = config.enclave_port;

    let payload = bincode::serialize(&client_input)
        .map_err(|e| eyre::eyre!("Failed to serialize client input: {e}"))?;

    info!("Sending block request to enclave: {} bytes", payload.len());

    let response: EthExecutionResponse = task::spawn_blocking(move || {
        let mut stream = VsockStream::connect(&VsockAddr::new(cid, port))
            .map_err(|e| eyre::eyre!("VSOCK connect {cid}:{port} failed: {e}"))?;

        write_frame(&mut stream, &payload)?;
        info!("Sent {} bytes to enclave", payload.len());

        let resp_bytes = read_frame(&mut stream)?;
        info!("Received {} bytes from enclave", resp_bytes.len());

        bincode::deserialize(&resp_bytes)
            .map_err(|e| eyre::eyre!("Failed to deserialize enclave response: {e}"))
    })
    .await
    .map_err(|e| eyre::eyre!("Blocking task panicked: {e}"))??;

    // Verify hashes
    let input_block_hash = client_input.current_block.header.hash_slow();
    if input_block_hash != response.block_hash {
        return Err(eyre::eyre!(
            "Block hash mismatch: expected {}, got {}",
            hex::encode(AsRef::<[u8]>::as_ref(&input_block_hash)),
            hex::encode(AsRef::<[u8]>::as_ref(&response.block_hash))
        ));
    }
    if client_input.current_block.header.parent_hash != response.parent_hash {
        return Err(eyre::eyre!(
            "Parent hash mismatch: expected {}, got {}",
            hex::encode(AsRef::<[u8]>::as_ref(
                &client_input.current_block.header.parent_hash
            )),
            hex::encode(AsRef::<[u8]>::as_ref(&response.parent_hash))
        ));
    }

    info!("Nitro enclave execution successful");
    Ok(response)
}

// ---------------------------------------------------------------------------
// AWS credentials (via official SDK default chain)
// ---------------------------------------------------------------------------

/// Resolves AWS credentials using the default provider chain:
/// env vars → ~/.aws/config → Web Identity → ECS task role → EC2 IMDS.
async fn resolve_aws_credentials() -> eyre::Result<AwsCredentials> {
    let config = aws_config::defaults(BehaviorVersion::latest())
        .load()
        .await;

    let provider = config
        .credentials_provider()
        .ok_or_else(|| eyre::eyre!("No AWS credentials provider available"))?;

    let creds = provider
        .provide_credentials()
        .await
        .wrap_err("Failed to resolve AWS credentials")?;

    info!("AWS credentials resolved successfully");

    Ok(AwsCredentials {
        access_key_id: creds.access_key_id().to_string(),
        secret_access_key: creds.secret_access_key().to_string(),
        session_token: creds.session_token().map(|s| s.to_string()),
    })
}

// ---------------------------------------------------------------------------
// Storage paths
// ---------------------------------------------------------------------------

fn storage_path(var: &str, default: &str) -> String {
    std::env::var(var).unwrap_or_else(|_| default.to_string())
}

fn data_key_path() -> String {
    storage_path("DATA_KEY_STORAGE", "./data_key.enc")
}

fn attestation_path() -> String {
    storage_path("ATTESTATION_STORAGE", "./attestation.bin")
}

fn public_key_path() -> String {
    storage_path("PUBLIC_KEY_STORAGE", "./public_key.hex")
}

// ---------------------------------------------------------------------------
// Key management
// ---------------------------------------------------------------------------

async fn initialize_enclave_key(config: &NitroConfig) -> eyre::Result<()> {
    let credentials = resolve_aws_credentials().await?;

    let encrypted_dek = match fs::read(data_key_path()) {
        Ok(data) => {
            info!("Found existing encrypted data key, requesting restore");
            Some(data)
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            info!("No existing key found, requesting generation");
            None
        }
        Err(e) => return Err(e).wrap_err("Failed to read data key file"),
    };

    let request = EnclaveRequest {
        credentials,
        encrypted_data_key: encrypted_dek,
    };

    let resp = send_handshake(config.enclave_cid, config.enclave_port, request)
        .await
        .wrap_err("Handshake with enclave failed")?;

    match resp {
        EnclaveResponse::KeyGenerated {
            encrypted_signing_key,
            attestation,
            public_key,
        } => {
            info!("New signing key generated by enclave");

            write_file(&data_key_path(), &encrypted_signing_key)?;
            info!("Encrypted data key saved");

            write_file(&attestation_path(), &attestation)?;
            info!("Attestation saved");

            save_public_key(&public_key)?;
        }

        EnclaveResponse::KeyRestored { public_key } => {
            info!("Existing signing key restored by enclave");
            save_public_key(&public_key)?;
        }

        EnclaveResponse::Error(e) => {
            return Err(eyre::eyre!("Enclave returned error: {e}"));
        }
    }

    Ok(())
}

fn save_public_key(public_key: &[u8]) -> eyre::Result<()> {
    let pk_hex = hex::encode(public_key);
    write_file(&public_key_path(), pk_hex.as_bytes())?;
    info!("Public key: {pk_hex}");
    Ok(())
}

// ---------------------------------------------------------------------------
// VSOCK communication
// ---------------------------------------------------------------------------

async fn send_handshake(
    cid: u32,
    port: u32,
    req: EnclaveRequest,
) -> eyre::Result<EnclaveResponse> {
    let payload = bincode::serialize(&req).wrap_err("Failed to serialize handshake request")?;

    tokio::time::sleep(ENCLAVE_BOOT_DELAY).await;

    task::spawn_blocking(move || {
        let mut stream = VsockStream::connect(&VsockAddr::new(cid, port))
            .wrap_err("Failed to connect to enclave")?;

        write_frame(&mut stream, &payload)?;
        let resp_bytes = read_frame(&mut stream)?;

        bincode::deserialize(&resp_bytes).wrap_err("Failed to deserialize enclave response")
    })
    .await
    .wrap_err("Blocking task panicked")?
}

fn write_frame(stream: &mut VsockStream, data: &[u8]) -> eyre::Result<()> {
    let len = data.len() as u32;
    stream.write_all(&len.to_be_bytes()).wrap_err("Failed to write length prefix")?;
    stream.write_all(data).wrap_err("Failed to write payload")?;
    stream.flush().wrap_err("Failed to flush stream")?;
    Ok(())
}

fn read_frame(stream: &mut VsockStream) -> eyre::Result<Vec<u8>> {
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf).wrap_err("Failed to read length prefix")?;

    let len = u32::from_be_bytes(len_buf) as usize;
    if len > MAX_FRAME_SIZE {
        return Err(eyre::eyre!(
            "Response frame too large: {len} bytes (max {MAX_FRAME_SIZE})"
        ));
    }

    let mut buf = vec![0u8; len];
    stream.read_exact(&mut buf).wrap_err("Failed to read payload")?;
    Ok(buf)
}

// ---------------------------------------------------------------------------
// File helpers
// ---------------------------------------------------------------------------

fn write_file(path: &str, data: &[u8]) -> eyre::Result<()> {
    if let Some(parent) = Path::new(path).parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(path, data).wrap_err_with(|| format!("Failed to write {path}"))
}