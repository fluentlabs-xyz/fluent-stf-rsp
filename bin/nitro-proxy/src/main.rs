mod enclave;

use crate::enclave::maybe_restart_enclave;
use std::{
    io::{Read, Write},
    path::Path,
    sync::Arc,
};

use axum::{
    extract::{Request, State},
    http::{HeaderMap, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Json},
    routing::post,
    Router,
};
use revm_primitives::{hex, FixedBytes};
use rsp_primitives::genesis::{genesis_from_json, Genesis};
use url::Url;

use serde::{Deserialize, Serialize};

use alloy_provider::RootProvider;
use reth_ethereum_primitives::EthPrimitives;
use rsp_client_executor::io::ClientExecutorInput;
use rsp_host_executor::{create_eth_block_execution_strategy_factory, HostExecutor};
use rsp_provider::create_provider;

use reth_chainspec::ChainSpec;
use reth_evm_ethereum::EthEvmConfig;
use rsp_client_executor::custom::CustomEvmFactory;

use tracing::info;

use tokio::task;

use vsock::{VsockAddr, VsockStream};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const MAX_FRAME_SIZE: usize = 64 * 1024 * 1024;

// ---------------------------------------------------------------------------
// Shared types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct AwsCredentials {
    pub access_key_id: String,
    pub secret_access_key: String,
    pub session_token: Option<String>,
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub enum EnclaveResponse {
    EncryptedDataKey {
        encrypted_signing_key: Vec<u8>,
        public_key: Vec<u8>,
        attestation: Vec<u8>,
    },
    Error(String),
}

/// Result of Ethereum block execution returned by the enclave.
#[derive(serde::Serialize, serde::Deserialize, Debug)]
pub struct EthExecutionResponse {
    pub parent_hash: FixedBytes<32>,
    pub block_hash: FixedBytes<32>,
    pub withdrawal_hash: FixedBytes<32>,
    pub deposit_hash: FixedBytes<32>,
    pub result_hash: Vec<u8>,
    pub signature: Vec<u8>,
}

#[derive(Debug, Clone, Copy)]
pub struct NitroConfig {
    pub enclave_cid: u32,
    pub enclave_port: u32,
    /// Number of vCPUs allocated to the enclave.
    pub cpu_count: u32,
    /// RAM in MiB allocated to the enclave.
    pub memory_mib: u32,
}

impl Default for NitroConfig {
    fn default() -> Self {
        Self {
            enclave_cid: 10,
            enclave_port: 5005,
            cpu_count: 2,
            memory_mib: 256,
        }
    }
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct EnclaveRequest {
    pub credentials: AwsCredentials,
    pub encrypted_data_key: Option<Vec<u8>>,
}

// ---------------------------------------------------------------------------
// Application state
// ---------------------------------------------------------------------------

#[derive(Clone)]
struct AppState {
    api_key: String,
    nitro_config: NitroConfig,
    block_execution_strategy_factory: EthEvmConfig<ChainSpec, CustomEvmFactory>,
    genesis: Genesis,
}

// ---------------------------------------------------------------------------
// HTTP layer types
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct BlockRequest {
    block_number: u64,
    rpc_url: String,
}

#[derive(Serialize)]
struct ErrorResponse {
    error: String,
}

// ---------------------------------------------------------------------------
// Middleware
// ---------------------------------------------------------------------------

async fn require_api_key(
    State(state): State<AppState>,
    headers: HeaderMap,
    request: Request,
    next: Next,
) -> impl IntoResponse {
    let provided = headers.get("x-api-key").and_then(|v| v.to_str().ok()).unwrap_or("");

    if provided != state.api_key {
        return (
            StatusCode::UNAUTHORIZED,
            Json(ErrorResponse { error: "Invalid or missing x-api-key".into() }),
        )
            .into_response();
    }

    next.run(request).await
}

// ---------------------------------------------------------------------------
// Enclave execution
// ---------------------------------------------------------------------------

/// Sends `client_input` to the Nitro enclave, reads the response, and verifies
/// that the returned hashes match the input block.
async fn process_nitro_client(
    client_input: ClientExecutorInput<EthPrimitives>,
    config: NitroConfig,
) -> eyre::Result<EthExecutionResponse> {
    info!(
        "Connecting to Nitro enclave at CID={} PORT={}",
        config.enclave_cid, config.enclave_port
    );

    let payload = bincode::serialize(&client_input)
        .map_err(|e| eyre::eyre!("Failed to serialize client input: {}", e))?;
    info!("Serialized input: {} bytes", payload.len());

    // All VSOCK I/O is synchronous; offload to a blocking thread.
    let response = task::spawn_blocking(move || -> eyre::Result<EthExecutionResponse> {
        let addr = VsockAddr::new(config.enclave_cid, config.enclave_port);
        let mut stream = VsockStream::connect(&addr).map_err(|e| {
            eyre::eyre!(
                "Failed to connect to VSOCK {}:{}: {}",
                config.enclave_cid,
                config.enclave_port,
                e
            )
        })?;

        let req_len: u32 = payload
            .len()
            .try_into()
            .map_err(|_| eyre::eyre!("Payload too large: {} bytes", payload.len()))?;
        stream
            .write_all(&req_len.to_be_bytes())
            .map_err(|e| eyre::eyre!("Failed to write request length: {}", e))?;
        stream
            .write_all(&payload)
            .map_err(|e| eyre::eyre!("Failed to write payload: {}", e))?;
        stream.flush().map_err(|e| eyre::eyre!("Failed to flush stream: {}", e))?;
        info!("Sent {} bytes to enclave", payload.len());

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
        info!("Received {} bytes from enclave", resp_buf.len());

        bincode::deserialize(&resp_buf)
            .map_err(|e| eyre::eyre!("Failed to deserialize enclave response: {}", e))
    })
    .await
    .map_err(|e| eyre::eyre!("Blocking task panicked: {}", e))??;

    // Verify the enclave processed the block we asked for.
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
            hex::encode(AsRef::<[u8]>::as_ref(&client_input.current_block.header.parent_hash)),
            hex::encode(AsRef::<[u8]>::as_ref(&response.parent_hash))
        ));
    }

    info!("Nitro enclave execution successful");
    Ok(response)
}

// ---------------------------------------------------------------------------
// HTTP handler
// ---------------------------------------------------------------------------

async fn block(
    State(state): State<AppState>,
    Json(req): Json<BlockRequest>,
) -> Result<Json<EthExecutionResponse>, (StatusCode, Json<ErrorResponse>)> {
    let rpc_url = Url::parse(&req.rpc_url).map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse { error: format!("Invalid rpc_url: {}", e) }),
        )
    })?;

    let provider: RootProvider = create_provider(rpc_url);

    let host_executor = HostExecutor::new(
        state.block_execution_strategy_factory,
        Arc::new((&state.genesis).try_into().map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse { error: format!("Genesis conversion failed: {}", e) }),
            )
        })?),
    );

    let client_input = host_executor
        .execute(req.block_number, &provider, state.genesis.clone(), None, false)
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse { error: format!("Block execution failed: {}", e) }),
            )
        })?;

    let response = process_nitro_client(client_input, state.nitro_config).await.map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse { error: format!("Enclave processing failed: {}", e) }),
        )
    })?;

    Ok(Json(response))
}

// ---------------------------------------------------------------------------
// Genesis
// ---------------------------------------------------------------------------

static DEVNET_GENESIS: &str = r#"{
    "config": {
      "chainId": 20993,
      "homesteadBlock": 0,
      "daoForkBlock": 0,
      "daoForkSupport": true,
      "eip150Block": 0,
      "eip155Block": 0,
      "eip158Block": 0,
      "byzantiumBlock": 0,
      "constantinopleBlock": 0,
      "petersburgBlock": 0,
      "istanbulBlock": 0,
      "muirGlacierBlock": 0,
      "berlinBlock": 0,
      "londonBlock": 0,
      "arrowGlacierBlock": 0,
      "grayGlacierBlock": 0,
      "mergeNetsplitBlock": 0,
      "shanghaiTime": 0,
      "cancunTime": 0,
      "pragueTime": 0,
      "osakaTime": 0,
      "terminalTotalDifficulty": 0,
      "terminalTotalDifficultyPassed": false
    }
}"#;

// ---------------------------------------------------------------------------
// Entry-point
// ---------------------------------------------------------------------------

#[tokio::main]
async fn main() -> eyre::Result<()> {
    tracing_subscriber::fmt::init();

    let eif_path = std::env::args()
        .skip_while(|a| a != "--eif_path")
        .nth(1)
        .ok_or_else(|| eyre::eyre!("Usage: nitro-proxy --eif_path <path-to.eif>"))?;

    let nitro_config = NitroConfig::default();

    maybe_restart_enclave(Path::new(&eif_path), nitro_config).await?;

    let api_key = std::env::var("API_KEY")?;
    let listen_addr = std::env::var("LISTEN_ADDR").unwrap_or_else(|_| "0.0.0.0:8080".into());

    // Allow overriding the genesis via env var so operators don't need to
    // rebuild the binary for different networks.
    let genesis_json = std::env::var("GENESIS_JSON").unwrap_or_else(|_| DEVNET_GENESIS.to_string());
    let alloy_genesis =
        genesis_from_json(&genesis_json).map_err(|e| eyre::eyre!("Invalid genesis: {}", e))?;
    let genesis = Genesis::Custom(alloy_genesis.config);

    let block_execution_strategy_factory =
        create_eth_block_execution_strategy_factory(&genesis, None);

    let state = AppState { api_key, nitro_config, block_execution_strategy_factory, genesis };

    let app = Router::new()
        .route("/block", post(block))
        .route_layer(middleware::from_fn_with_state(state.clone(), require_api_key))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(&listen_addr).await?;
    info!("Listening on {listen_addr}");
    axum::serve(listener, app).await?;

    Ok(())
}