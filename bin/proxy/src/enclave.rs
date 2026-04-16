use std::io::{Read, Write};

use aws_config::BehaviorVersion;
use aws_credential_types::provider::ProvideCredentials;
use eyre::WrapErr;
use tokio::task;
use tracing::info;

use vsock::{VsockAddr, VsockStream};

use nitro_types::{AwsCredentials, EnclaveIncoming, EnclaveResponse, EthExecutionResponse};
use rsp_client_executor::io::EthClientExecutorInput;

use crate::types::NitroConfig;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const MAX_FRAME_SIZE: usize = 64 * 1024 * 1024;

// ---------------------------------------------------------------------------
// Initialization (OnceCell for idempotency)
// ---------------------------------------------------------------------------

/// Tracks whether `ensure_initialized` has already run successfully.
/// `execute_block_inner` / `submit_batch_inner` may call `ensure_initialized`
/// again on `NotInitialized` — the `OnceCell` makes repeat calls a no-op.
static INITIALIZED: tokio::sync::OnceCell<()> = tokio::sync::OnceCell::const_new();

/// Ensures the enclave has a signing key and attestation is handled.
///
/// 1. Handshake with enclave (always).
/// 2. New key → save artifacts, delete stale request_id, prove → L1.
/// 3. Existing key + request_id file → resume pending proof → L1.
/// 4. Existing key + no request_id → nothing to do.
///
/// Blocks until attestation proving completes (or is skipped).
/// Idempotent — second call returns immediately.
pub(crate) async fn ensure_initialized(config: &NitroConfig) -> eyre::Result<()> {
    let cfg = *config;
    INITIALIZED.get_or_try_init(|| do_initialize(cfg)).await.map(|_| ())
}

async fn do_initialize(config: NitroConfig) -> eyre::Result<()> {
    let (public_key, attestation, is_new_key) = handshake_with_enclave(&config).await?;

    if is_new_key {
        if let Some(db) = crate::db::db() {
            db.delete_attestation_request_id();
        }

        info!("New enclave key — starting attestation proving");
        match crate::attestation::AttestationConfig::from_env().await {
            Ok(att_config) => {
                if let Err(e) =
                    crate::attestation::prove_and_submit(&att_config, &public_key, &attestation)
                        .await
                {
                    tracing::error!("Attestation proving failed: {e}");
                }
            }
            Err(e) => tracing::error!("Attestation config unavailable: {e}"),
        }
    } else if crate::db::db().and_then(|db| db.load_attestation_request_id()).is_some() {
        info!("Found pending attestation request — resuming");
        match crate::attestation::AttestationConfig::from_env().await {
            Ok(att_config) => {
                if let Err(e) =
                    crate::attestation::prove_and_submit(&att_config, &public_key, &attestation)
                        .await
                {
                    tracing::error!("Failed to resume attestation: {e}");
                }
            }
            Err(e) => tracing::error!("Attestation config unavailable: {e}"),
        }
    } else {
        info!("Enclave already attested — nothing to do");
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Normal block execution — enclave signs with block_hash in the payload.
pub(crate) async fn execute_block(
    input: EthClientExecutorInput,
    config: NitroConfig,
) -> eyre::Result<EthExecutionResponse> {
    let msg = EnclaveIncoming::ExecuteBlock { input: Box::new(input) };
    execute_block_inner(msg, &config).await
}

/// Batch signing.
pub(crate) async fn submit_batch(
    from: u64,
    to: u64,
    responses: Vec<EthExecutionResponse>,
    blobs: Vec<Vec<u8>>,
    config: NitroConfig,
) -> eyre::Result<EnclaveResponse> {
    let msg = EnclaveIncoming::SubmitBatch { from, to, responses, blobs };
    submit_batch_inner(msg, &config).await
}

// ---------------------------------------------------------------------------
// Dispatch — block execution
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
// Dispatch — batch
// ---------------------------------------------------------------------------

async fn submit_batch_inner(
    msg: EnclaveIncoming,
    config: &NitroConfig,
) -> eyre::Result<EnclaveResponse> {
    let resp = send_to_enclave(config.enclave_cid, config.enclave_port, &msg).await?;

    match resp {
        r @ EnclaveResponse::SubmitBatchResult(_) => Ok(r),
        r @ EnclaveResponse::InvalidSignatures { .. } => Ok(r),
        EnclaveResponse::NotInitialized => {
            info!("Enclave not initialised — triggering key generation");
            ensure_initialized(config).await?;
            let retry = send_to_enclave(config.enclave_cid, config.enclave_port, &msg).await?;
            match retry {
                r @ EnclaveResponse::SubmitBatchResult(_) => Ok(r),
                r @ EnclaveResponse::InvalidSignatures { .. } => Ok(r),
                EnclaveResponse::Error(e) => Err(eyre::eyre!("Enclave error on retry: {e}")),
                other => Err(eyre::eyre!("Unexpected response on retry: {other:?}")),
            }
        }
        EnclaveResponse::Error(e) => Err(eyre::eyre!("Enclave error: {e}")),
        other => Err(eyre::eyre!("Unexpected response: {other:?}")),
    }
}

// ---------------------------------------------------------------------------
// Handshake
// ---------------------------------------------------------------------------

/// Returns `(public_key, attestation, is_new_key)`.
async fn handshake_with_enclave(config: &NitroConfig) -> eyre::Result<(Vec<u8>, Vec<u8>, bool)> {
    let credentials = resolve_aws_credentials().await?;
    let msg = EnclaveIncoming::Handshake { credentials };

    let resp = send_to_enclave(config.enclave_cid, config.enclave_port, &msg)
        .await
        .wrap_err("Handshake with enclave failed")?;

    match resp {
        EnclaveResponse::KeyGenerated { public_key, attestation } => {
            info!("Ephemeral signing key generated by enclave");
            Ok((public_key, attestation, true))
        }
        EnclaveResponse::AlreadyInitialized { public_key, attestation } => {
            info!("Enclave already initialised, received existing key");
            Ok((public_key, attestation, false))
        }
        EnclaveResponse::Error(e) => Err(eyre::eyre!("Enclave returned error: {e}")),
        other => Err(eyre::eyre!("Unexpected handshake response: {other:?}")),
    }
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
