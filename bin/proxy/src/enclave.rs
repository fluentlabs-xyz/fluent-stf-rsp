use std::{
    fs,
    io::{Read, Write},
    path::Path,
};

use aws_config::BehaviorVersion;
use aws_credential_types::provider::ProvideCredentials;
use eyre::WrapErr;
use revm_primitives::hex;
use tokio::task;
use tracing::info;

use vsock::{VsockAddr, VsockStream};

use nitro_types::{
    AwsCredentials, EnclaveIncoming, EnclaveResponse, EthExecutionResponse, SubmitBatchResponse,
};
use rsp_client_executor::io::EthClientExecutorInput;

use alloy_primitives::Address;

use crate::types::NitroConfig;

// ---------------------------------------------------------------------------
// Attestation config
// ---------------------------------------------------------------------------

/// Lazily-initialized attestation config shared by `on_new_attestation` and
/// `/retry-attestation`. First caller (background task or handler) runs
/// `from_env()`; subsequent callers get the cached result.
static ATTESTATION_CONFIG: tokio::sync::OnceCell<crate::attestation::AttestationConfig> =
    tokio::sync::OnceCell::const_new();

/// Guard to ensure only one `prove_and_submit` runs at a time.
#[cfg(feature = "prove-key-attestation")]
static ATTESTATION_PROVING: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// Try to initialize attestation config. Called from background task in main().
/// If `on_new_attestation` already triggered init, this is a no-op.
pub(crate) async fn init_attestation_config() {
    match ATTESTATION_CONFIG.get_or_try_init(crate::attestation::AttestationConfig::from_env).await
    {
        Ok(_) => info!("Attestation config ready"),
        Err(e) => info!("Attestation proving disabled: {e}"),
    }
}

/// Returns the attestation config if initialized.
pub(crate) fn attestation_config() -> Option<&'static crate::attestation::AttestationConfig> {
    ATTESTATION_CONFIG.get()
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const MAX_FRAME_SIZE: usize = 64 * 1024 * 1024;

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Ensures the enclave has a signing key. Call at proxy startup.
/// Only triggers attestation proving when the enclave generates a *new* key.
pub(crate) async fn ensure_initialized(config: &NitroConfig) -> eyre::Result<()> {
    let (public_key, attestation, is_new_key) = handshake_with_enclave(config).await?;
    if is_new_key {
        on_new_attestation(&public_key, &attestation).await?;
    } else {
        info!("Enclave already initialised — skipping attestation proving");
    }
    Ok(())
}

/// Normal block execution — enclave signs with tx_data_hash in the hash.
pub(crate) async fn execute_block(
    input: EthClientExecutorInput,
    config: NitroConfig,
) -> eyre::Result<EthExecutionResponse> {
    let msg = EnclaveIncoming::ExecuteBlock { input: Box::new(input) };
    execute_block_inner(msg, &config).await
}

/// Result of batch submission — either success or invalid signatures requiring re-execution.
pub(crate) enum SubmitBatchOutcome {
    Success(SubmitBatchResponse),
    InvalidSignatures { invalid_blocks: Vec<u64> },
}

/// Batch signing — cache-first with response fallback.
pub(crate) async fn submit_batch(
    from: u64,
    to: u64,
    responses: Vec<EthExecutionResponse>,
    blobs: Vec<Vec<u8>>,
    config: NitroConfig,
) -> eyre::Result<SubmitBatchOutcome> {
    let msg = EnclaveIncoming::SubmitBatch { from, to, responses, blobs };
    submit_batch_inner(msg, &config).await
}

// ---------------------------------------------------------------------------
// Shared dispatch — block execution variants
// ---------------------------------------------------------------------------

async fn execute_block_inner(
    msg: EnclaveIncoming,
    config: &NitroConfig,
) -> eyre::Result<EthExecutionResponse> {
    let resp = send_to_enclave(config.enclave_cid, config.enclave_port, &msg).await?;

    match resp {
        EnclaveResponse::ExecutionResult(r) => Ok(r),

        EnclaveResponse::NotInitialized => {
            info!("Enclave not initialised — triggering key generation");
            ensure_initialized(config).await?;

            let retry = send_to_enclave(config.enclave_cid, config.enclave_port, &msg).await?;
            match retry {
                EnclaveResponse::ExecutionResult(r) => Ok(r),
                EnclaveResponse::Error(e) => Err(eyre::eyre!("Enclave error on retry: {e}")),
                other => Err(eyre::eyre!("Unexpected response on retry: {other:?}")),
            }
        }

        EnclaveResponse::Error(e) => Err(eyre::eyre!("Enclave error: {e}")),
        other => Err(eyre::eyre!("Unexpected response: {other:?}")),
    }
}

// ---------------------------------------------------------------------------
// Shared dispatch — batch variants
// ---------------------------------------------------------------------------

async fn submit_batch_inner(
    msg: EnclaveIncoming,
    config: &NitroConfig,
) -> eyre::Result<SubmitBatchOutcome> {
    let resp = send_to_enclave(config.enclave_cid, config.enclave_port, &msg).await?;

    match resp {
        EnclaveResponse::SubmitBatchResult(r) => Ok(SubmitBatchOutcome::Success(r)),

        EnclaveResponse::InvalidSignatures { invalid_blocks } => {
            Ok(SubmitBatchOutcome::InvalidSignatures { invalid_blocks })
        }

        EnclaveResponse::NotInitialized => {
            info!("Enclave not initialised — triggering key generation");
            ensure_initialized(config).await?;

            let retry = send_to_enclave(config.enclave_cid, config.enclave_port, &msg).await?;
            match retry {
                EnclaveResponse::SubmitBatchResult(r) => Ok(SubmitBatchOutcome::Success(r)),
                EnclaveResponse::InvalidSignatures { invalid_blocks } => {
                    Ok(SubmitBatchOutcome::InvalidSignatures { invalid_blocks })
                }
                EnclaveResponse::Error(e) => Err(eyre::eyre!("Enclave error on retry: {e}")),
                other => Err(eyre::eyre!("Unexpected response on retry: {other:?}")),
            }
        }

        EnclaveResponse::Error(e) => Err(eyre::eyre!("Enclave error: {e}")),
        other => Err(eyre::eyre!("Unexpected response: {other:?}")),
    }
}

// ---------------------------------------------------------------------------
// Initialisation internals
// ---------------------------------------------------------------------------

/// Returns `(public_key, attestation, is_new_key)`.
async fn handshake_with_enclave(config: &NitroConfig) -> eyre::Result<(Vec<u8>, Vec<u8>, bool)> {
    let credentials = resolve_aws_credentials().await?;
    let msg = EnclaveIncoming::Handshake { credentials };

    let resp = send_message(config.enclave_cid, config.enclave_port, &msg)
        .await
        .wrap_err("Handshake with enclave failed")?;

    match resp {
        EnclaveResponse::KeyGenerated { public_key, attestation } => {
            info!("Ephemeral signing key generated by enclave");
            save_artifacts(&public_key, &attestation)?;
            Ok((public_key, attestation, true))
        }

        EnclaveResponse::AlreadyInitialized { public_key, attestation } => {
            info!("Enclave already initialised, received existing key");
            save_artifacts(&public_key, &attestation)?;
            Ok((public_key, attestation, false))
        }

        EnclaveResponse::Error(e) => Err(eyre::eyre!("Enclave returned error: {e}")),
        other => Err(eyre::eyre!("Unexpected handshake response: {other:?}")),
    }
}

async fn on_new_attestation(public_key: &[u8], attestation: &[u8]) -> eyre::Result<()> {
    #[cfg(feature = "prove-key-attestation")]
    {
        let pk = public_key.to_vec();
        let att = attestation.to_vec();

        tokio::spawn(async move {
            // Serialize attestation proving — only one at a time.
            // If a previous proof is in-flight, we wait for it to finish
            // before starting a new one for the latest key.
            let _guard = ATTESTATION_PROVING.lock().await;

            // Delete stale request_id AFTER acquiring the lock, so we don't
            // race with an in-flight prove_and_submit saving its request_id.
            crate::attestation::delete_stale_request_id();

            info!("New key generated — initializing attestation config if needed...");
            match ATTESTATION_CONFIG
                .get_or_try_init(crate::attestation::AttestationConfig::from_env)
                .await
            {
                Ok(config) => {
                    if let Err(e) = crate::attestation::prove_and_submit(config, &pk, &att).await {
                        tracing::error!("Background attestation proving failed: {e}");
                    }
                }
                Err(e) => {
                    tracing::warn!(
                        public_key = %hex::encode(&pk),
                        "Attestation config not available: {e} — skipping proof"
                    );
                }
            }
        });

        return Ok(());
    }

    #[cfg(not(feature = "prove-key-attestation"))]
    {
        info!(
            public_key = %hex::encode(public_key),
            "Attestation received — running local SP1 validation"
        );
        crate::attestation::execute_local(attestation).await;
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// AWS credentials
// ---------------------------------------------------------------------------

async fn resolve_aws_credentials() -> eyre::Result<AwsCredentials> {
    let config = aws_config::defaults(BehaviorVersion::latest()).load().await;

    let provider = config
        .credentials_provider()
        .ok_or_else(|| eyre::eyre!("No AWS credentials provider available"))?;

    let creds =
        provider.provide_credentials().await.wrap_err("Failed to resolve AWS credentials")?;

    info!("AWS credentials resolved successfully");

    Ok(AwsCredentials {
        access_key_id: creds.access_key_id().to_string(),
        secret_access_key: creds.secret_access_key().to_string(),
        session_token: creds.session_token().map(|s| s.to_string()).unwrap_or_default(),
    })
}

// ---------------------------------------------------------------------------
// Storage
// ---------------------------------------------------------------------------

pub(crate) fn storage_path(var: &str, default: &str) -> String {
    std::env::var(var).unwrap_or_else(|_| default.to_string())
}

fn attestation_path() -> String {
    storage_path("ATTESTATION_STORAGE", "./attestation.bin")
}

fn public_key_path() -> String {
    storage_path("PUBLIC_KEY_STORAGE", "./public_key.hex")
}

/// Read saved attestation artifacts from disk (for retry endpoint).
pub(crate) fn load_attestation_artifacts() -> eyre::Result<(Vec<u8>, Vec<u8>)> {
    let pk_hex = fs::read_to_string(public_key_path())
        .wrap_err("Public key file not found — enclave not initialized")?;
    let public_key =
        hex::decode(pk_hex.trim()).map_err(|e| eyre::eyre!("Invalid public key hex: {e}"))?;
    let attestation = fs::read(attestation_path())
        .wrap_err("Attestation file not found — enclave not initialized")?;
    Ok((public_key, attestation))
}

fn save_artifacts(public_key: &[u8], attestation: &[u8]) -> eyre::Result<()> {
    let pk_hex = hex::encode(public_key);
    write_file(&public_key_path(), pk_hex.as_bytes())?;
    info!("Public key: {pk_hex}");

    write_file(&attestation_path(), attestation)?;
    info!("Attestation document saved");

    Ok(())
}

// ---------------------------------------------------------------------------
// VSOCK communication
// ---------------------------------------------------------------------------

async fn send_to_enclave(
    cid: u32,
    port: u32,
    msg: &EnclaveIncoming,
) -> eyre::Result<EnclaveResponse> {
    let payload = bincode::serialize(msg)
        .map_err(|e| eyre::eyre!("Failed to serialize enclave request: {e}"))?;

    info!("Sending {} bytes to enclave", payload.len());

    task::spawn_blocking(move || {
        let mut stream = VsockStream::connect(&VsockAddr::new(cid, port))
            .map_err(|e| eyre::eyre!("VSOCK connect {cid}:{port} failed: {e}"))?;

        write_frame(&mut stream, &payload)?;
        let resp_bytes = read_frame(&mut stream)?;
        info!("Received {} bytes from enclave", resp_bytes.len());

        bincode::deserialize(&resp_bytes)
            .map_err(|e| eyre::eyre!("Failed to deserialize enclave response: {e}"))
    })
    .await
    .map_err(|e| eyre::eyre!("Blocking task panicked: {e}"))?
}

/// Lighter-weight send used only for handshake.
async fn send_message(cid: u32, port: u32, msg: &EnclaveIncoming) -> eyre::Result<EnclaveResponse> {
    let payload = bincode::serialize(msg).wrap_err("Failed to serialize message")?;

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
        return Err(eyre::eyre!("Response frame too large: {len} bytes (max {MAX_FRAME_SIZE})"));
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

// ---------------------------------------------------------------------------
// Enclave address derivation
// ---------------------------------------------------------------------------

/// Returns the current enclave's Ethereum address derived from its public key.
/// Returns None if no key has been generated yet.
pub(crate) fn enclave_address() -> Option<Address> {
    let pk_hex = std::fs::read_to_string(public_key_path()).ok()?;
    let pk_bytes = hex::decode(pk_hex.trim()).ok()?;
    pubkey_to_address(&pk_bytes).ok()
}

/// Derive Ethereum address from 65-byte uncompressed secp256k1 public key.
fn pubkey_to_address(pubkey: &[u8]) -> eyre::Result<Address> {
    if pubkey.len() != 65 || pubkey[0] != 0x04 {
        return Err(eyre::eyre!("Invalid uncompressed pubkey: len={}", pubkey.len()));
    }
    let hash = alloy_primitives::keccak256(&pubkey[1..]);
    Ok(Address::from_slice(&hash[12..]))
}
