//! # proxy
//!
//! HTTP proxy that sits between callers and two execution backends:
//!
//! 1. **Nitro enclave** (`POST /nitro`) — executes an Ethereum block inside an AWS Nitro Enclave
//!    and returns a signed execution result.
//!
//! 2. **SP1 prover** — executes the same block inside the SP1 zkVM and
//!    returns a Groth16 proof that can be verified on-chain by any `ISP1Verifier`-compatible
//!    contract.
//!    - `POST /sp1/request` — submits a block for async proof generation, returns a `request_id`.
//!    - `POST /sp1/status`  — polls by `request_id`, returns the proof when ready.
//!
//! Both endpoints share the same block-fetching and host-execution pipeline
//! ([`build_client_input`]) and are protected by an API key middleware.
//!
//! ## Optional backends
//!
//! - Nitro enclave is enabled by passing `--eif_path <path>` at startup.
//! - SP1 prover is enabled by setting the `SP1_ELF_PATH` environment variable.

mod enclave;
mod types;

use crate::{
    enclave::maybe_restart_enclave,
    types::{NitroConfig, Sp1ProofResponse},
};
use nitro_types::EthExecutionResponse;

use std::{env, path::Path, sync::Arc};

use axum::{
    extract::{Request, State},
    http::{HeaderMap, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Json},
    routing::post,
    Router,
};
use revm_primitives::{
    hex::{self, FromHex},
    FixedBytes, B256,
};
use rsp_primitives::genesis::Genesis;
use url::Url;

use serde::{Deserialize, Serialize};

use alloy_provider::{Provider, RootProvider};
use reth_chainspec::ChainSpec;
use reth_ethereum_primitives::EthPrimitives;
use reth_evm_ethereum::EthEvmConfig;
use rsp_client_executor::{evm::FluentEvmFactory, io::ClientExecutorInput};
use rsp_host_executor::{create_eth_block_execution_strategy_factory, HostExecutor};
use rsp_provider::create_provider;

use sp1_sdk::{
    network::{prover::NetworkProver, NetworkMode},
    Elf, HashableKey, Prover, ProverClient, ProvingKey, SP1ProvingKey, SP1Stdin,
};

use sp1_sdk::ProveRequest;
use tracing::info;

pub fn rpc_url() -> String {
    // Env var always wins if set
    if let Ok(url) = env::var("RPC_URL") {
        return url;
    }

    #[cfg(feature = "testnet")]
    return "https://rpc.testnet.fluent.xyz".to_string();

    #[cfg(feature = "devnet")]
    return "https://rpc.devnet.fluent.xyz".to_string();

    #[allow(unreachable_code)]
    "http://localhost:8545".to_string()
}


// ---------------------------------------------------------------------------
// Application state
// ---------------------------------------------------------------------------

/// Shared state cloned into every request handler via Axum's `State` extractor.
#[derive(Clone)]
struct AppState {
    api_key: String,
    /// Nitro enclave state. `None` when `--eif_path` is not provided.
    nitro: Option<NitroState>,
    block_execution_strategy_factory: EthEvmConfig<ChainSpec, FluentEvmFactory>,
    genesis: Genesis,
    chain_spec: Arc<ChainSpec>,
    /// SP1 prover state. `None` when `SP1_ELF_PATH` is not set.
    sp1: Option<Sp1State>,
}

/// Nitro-specific state initialised once at startup and shared across requests.
#[derive(Clone)]
struct NitroState {
    config: NitroConfig,
}

/// SP1-specific state initialised once at startup and shared across requests.
#[derive(Clone)]
struct Sp1State {
    client: Arc<NetworkProver>,
    /// Proving key derived from the compiled zkVM ELF.
    pk: Arc<SP1ProvingKey>,
}

// ---------------------------------------------------------------------------
// HTTP request / response types
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct BlockRequest {
    block_number: Option<u64>,
    block_hash: Option<B256>,
}

#[derive(Deserialize)]
struct Sp1StatusRequest {
    request_id: B256,
}

#[derive(Serialize)]
struct Sp1RequestResponse {
    request_id: B256,
}

#[derive(Serialize)]
struct ErrorResponse {
    error: String,
}

type HandlerError = (StatusCode, Json<ErrorResponse>);

fn bad_request(msg: impl ToString) -> HandlerError {
    (StatusCode::BAD_REQUEST, Json(ErrorResponse { error: msg.to_string() }))
}

fn internal(msg: impl ToString) -> HandlerError {
    (StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse { error: msg.to_string() }))
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
// Shared helper: fetch block + build ClientExecutorInput
// ---------------------------------------------------------------------------

/// Fetches `block_number` and runs the host-side execution
/// phase to produce a [`ClientExecutorInput`] ready for either backend.
///
/// This is intentionally shared between [`block`] and [`block_sp1_request`] so
/// the two endpoints always use identical witness data.
async fn build_client_input(
    req: BlockRequest,
    state: &AppState,
) -> Result<ClientExecutorInput<EthPrimitives>, HandlerError> {
    let url = Url::parse(&rpc_url()).map_err(|e| bad_request(format!("Invalid rpc_url: {e}")))?;
    let provider: RootProvider = create_provider(url);

    let block_number = match (req.block_number, req.block_hash) {
        (_, Some(hash)) => {
            provider
                .get_block_by_hash(hash)
                .await
                .map_err(|e| internal(format!("RPC error: {e}")))?
                .ok_or_else(|| bad_request(format!("Block not found for hash: {hash}")))?
                .header
                .number
        }
        (Some(number), _) => number,
        (None, None) => {
            return Err(bad_request(
                "Either block_number or block_hash must be provided".to_string(),
            ))
        }
    };

    let host_executor =
        HostExecutor::new(state.block_execution_strategy_factory.clone(), state.chain_spec.clone());

    host_executor
        .execute(block_number, &provider, state.genesis.clone(), None, false)
        .await
        .map_err(|e| internal(format!("Block execution failed: {e}")))
}

// ---------------------------------------------------------------------------
// Handler: POST /nitro  —  Nitro enclave execution
// ---------------------------------------------------------------------------

/// Executes `block_number` inside the AWS Nitro Enclave and returns a signed
/// [`EthExecutionResponse`].
///
/// Returns HTTP 500 if the server was started without `--eif_path`.
async fn block(
    State(state): State<AppState>,
    Json(req): Json<BlockRequest>,
) -> Result<Json<EthExecutionResponse>, HandlerError> {
    let nitro = state
        .nitro
        .as_ref()
        .ok_or_else(|| internal("Nitro enclave not configured (pass --eif_path at startup)"))?;

    let client_input = build_client_input(req, &state).await?;

    let response = enclave::execute_block(client_input, nitro.config)
        .await
        .map_err(|e| internal(format!("Enclave processing failed: {e}")))?;

    Ok(Json(response))
}

// ---------------------------------------------------------------------------
// Handler: POST /sp1/request  —  submit async SP1 proof request
// ---------------------------------------------------------------------------

/// Builds client input for the given block, submits it to the SP1 prover
/// asynchronously, and returns the `request_id` for later polling.
async fn block_sp1_request(
    State(state): State<AppState>,
    Json(req): Json<BlockRequest>,
) -> Result<Json<Sp1RequestResponse>, HandlerError> {
    let sp1 = state
        .sp1
        .as_ref()
        .ok_or_else(|| internal("SP1 prover not configured (set SP1_ELF_PATH)"))?;

    let client_input = build_client_input(req, &state).await?;
    let block_number = client_input.current_block.number;

    let mut stdin = SP1Stdin::new();
    stdin.write_vec(
        bincode::serialize(&client_input)
            .map_err(|e| internal(format!("Failed to serialize client input: {e}")))?,
    );

    info!(block_number, "Submitting async SP1 Groth16 proof request");

    let request_id: B256 = sp1
        .client
        .prove(sp1.pk.as_ref(), stdin)
        .groth16()
        .request()
        .await
        .map_err(|e| internal(format!("Failed to submit proof request: {e}")))?;

    info!(block_number, request_id = %hex::encode(request_id), "SP1 proof request submitted");

    Ok(Json(Sp1RequestResponse { request_id }))
}

// ---------------------------------------------------------------------------
// Handler: POST /sp1/status  —  poll for SP1 proof result
// ---------------------------------------------------------------------------

/// Checks the status of a previously submitted SP1 proof request.
///
/// - **200** — proof is ready, body contains [`Sp1ProofResponse`].
/// - **202** — proof is still being generated (empty body).
/// - **404** — `request_id` not found on the SP1 network.
async fn block_sp1_status(
    State(state): State<AppState>,
    Json(req): Json<Sp1StatusRequest>,
) -> impl IntoResponse {
    let sp1 = match state.sp1.as_ref() {
        Some(s) => s,
        None => return internal("SP1 prover not configured (set SP1_ELF_PATH)").into_response(),
    };

    let (status, maybe_proof) = match sp1.client.get_proof_status(req.request_id).await {
        Ok(r) => r,
        Err(e) => {
            return (
                StatusCode::NOT_FOUND,
                Json(ErrorResponse {
                    error: format!(
                        "Proof not found for request_id {}: {e}",
                        hex::encode(req.request_id)
                    ),
                }),
            )
                .into_response();
        }
    };

    let proof = match maybe_proof {
        None => {
            info!(request_id = %hex::encode(req.request_id), ?status, "SP1 proof still pending");
            return StatusCode::ACCEPTED.into_response();
        }
        Some(p) => p,
    };

    info!(request_id = %hex::encode(req.request_id), "SP1 proof ready");

    let public_values = proof.public_values.as_slice().to_vec();

    let proof_bytes = match bincode::serialize(&proof.proof) {
        Ok(b) => b,
        Err(e) => return internal(format!("Failed to serialize proof: {e}")).into_response(),
    };

    let vk_hash = FixedBytes::from(sp1.pk.verifying_key().hash_bytes());

    (StatusCode::OK, Json(Sp1ProofResponse { vk_hash, public_values, proof_bytes })).into_response()
}

// ---------------------------------------------------------------------------
// Handler: POST /sp1/mock/request
// ---------------------------------------------------------------------------

/// Generates a random `request_id` and returns it as if an SP1 proof request
/// had been submitted.  Does not require `SP1_ELF_PATH`.
async fn block_sp1_mock_request(
    State(_): State<AppState>,
    Json(_): Json<BlockRequest>,
) -> Result<Json<Sp1RequestResponse>, HandlerError> {
    let request_id = B256::from_hex("0x137").unwrap_or_default();
    
    Ok(Json(Sp1RequestResponse { request_id }))
}

// ---------------------------------------------------------------------------
// Handler: POST /sp1/mock/status  —  hardcoded SP1 proof response
// ---------------------------------------------------------------------------

/// Returns a hardcoded [`Sp1ProofResponse`] for testing purposes, regardless
/// of the `request_id` provided.  Does not require `SP1_ELF_PATH`.
async fn block_sp1_mock_status(
    State(_): State<AppState>,
    Json(_): Json<Sp1StatusRequest>,
) -> Result<Json<Sp1ProofResponse>, HandlerError> {
    let vk_hash = FixedBytes::from([
        0x28, 0x22, 0x33, 0x86, 0x4d, 0x7d, 0x8e, 0x6f, 0x6c, 0x3a, 0x09, 0x6b, 0x5d, 0xcc, 0x08,
        0x8d, 0x76, 0x36, 0x7e, 0x55, 0x31, 0x18, 0xe4, 0x32, 0x19, 0x7d, 0x3e, 0xb2, 0x15, 0xa2,
        0x02, 0x3d,
    ]);

    let public_values: Vec<u8> = vec![
        32, 0, 0, 0, 0, 0, 0, 0, 74, 83, 97, 75, 68, 56, 138, 56, 236, 130, 218, 34, 205, 168, 105,
        43, 161, 13, 12, 56, 226, 32, 46, 197, 47, 217, 77, 19, 70, 83, 63, 54, 32, 0, 0, 0, 0, 0,
        0, 0, 7, 210, 222, 132, 100, 19, 117, 204, 37, 113, 3, 39, 171, 250, 78, 215, 168, 106,
        124, 254, 181, 96, 97, 157, 8, 202, 72, 66, 224, 205, 211, 213, 32, 0, 0, 0, 0, 0, 0, 0,
        197, 210, 70, 1, 134, 247, 35, 60, 146, 126, 125, 178, 220, 199, 3, 192, 229, 0, 182, 83,
        202, 130, 39, 59, 123, 250, 216, 4, 93, 133, 164, 112, 32, 0, 0, 0, 0, 0, 0, 0, 197, 210,
        70, 1, 134, 247, 35, 60, 146, 126, 125, 178, 220, 199, 3, 192, 229, 0, 182, 83, 202, 130,
        39, 59, 123, 250, 216, 4, 93, 133, 164, 112,
    ];

    let proof_bytes: Vec<u8> = vec![
        3, 0, 0, 0, 75, 0, 0, 0, 0, 0, 0, 0, 49, 52, 49, 56, 49, 57, 56, 54, 50, 49, 57, 57, 54,
        49, 55, 54, 49, 55, 53, 52, 50, 50, 49, 57, 51, 48, 57, 50, 51, 49, 48, 49, 57, 49, 50, 48,
        55, 51, 55, 49, 54, 55, 50, 50, 48, 50, 56, 55, 57, 49, 54, 53, 56, 48, 53, 51, 52, 49, 50,
        50, 52, 56, 57, 56, 52, 48, 51, 49, 52, 52, 56, 51, 50, 54, 49, 77, 0, 0, 0, 0, 0, 0, 0,
        49, 48, 56, 52, 52, 56, 57, 49, 53, 54, 48, 55, 56, 55, 53, 57, 56, 55, 54, 48, 54, 49, 51,
        50, 55, 56, 54, 54, 57, 48, 56, 56, 50, 57, 50, 48, 54, 57, 53, 54, 55, 51, 52, 55, 55, 54,
        52, 48, 55, 55, 51, 53, 49, 51, 51, 55, 54, 56, 48, 48, 48, 48, 53, 55, 55, 51, 52, 52, 48,
        54, 48, 53, 57, 48, 53, 53, 52, 1, 0, 0, 0, 0, 0, 0, 0, 48, 75, 0, 0, 0, 0, 0, 0, 0, 50,
        52, 56, 56, 51, 49, 54, 50, 56, 52, 48, 48, 49, 56, 53, 54, 49, 49, 55, 52, 48, 52, 55, 57,
        48, 55, 49, 52, 53, 48, 53, 54, 52, 50, 53, 48, 49, 57, 51, 57, 49, 50, 48, 55, 48, 54, 57,
        51, 57, 50, 53, 48, 49, 51, 49, 56, 50, 50, 52, 51, 49, 50, 55, 50, 56, 50, 51, 52, 50, 50,
        48, 48, 57, 52, 52, 1, 0, 0, 0, 0, 0, 0, 0, 48, 192, 2, 0, 0, 0, 0, 0, 0, 48, 48, 48, 48,
        48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48,
        48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48,
        48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 56, 99, 100, 53, 54, 101,
        49, 48, 99, 50, 102, 101, 50, 52, 55, 57, 53, 99, 102, 102, 49, 101, 49, 100, 49, 102, 52,
        48, 100, 51, 97, 51, 50, 52, 53, 50, 56, 100, 51, 49, 53, 54, 55, 52, 100, 97, 52, 53, 100,
        50, 54, 97, 102, 98, 51, 55, 54, 101, 56, 54, 55, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48,
        48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48,
        48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48,
        48, 48, 48, 48, 48, 48, 48, 48, 48, 49, 102, 97, 55, 99, 48, 52, 98, 54, 52, 52, 51, 51,
        100, 97, 101, 50, 54, 53, 97, 98, 97, 55, 97, 53, 52, 54, 57, 55, 102, 53, 98, 51, 101, 56,
        101, 54, 54, 49, 99, 98, 48, 53, 54, 49, 57, 97, 52, 98, 48, 54, 55, 56, 52, 98, 49, 50,
        55, 49, 98, 57, 53, 49, 51, 50, 54, 48, 99, 54, 48, 101, 53, 49, 49, 56, 51, 50, 54, 100,
        99, 56, 52, 50, 48, 50, 57, 97, 54, 53, 49, 56, 100, 101, 100, 98, 50, 98, 98, 48, 55, 100,
        50, 52, 51, 98, 51, 52, 52, 101, 54, 49, 56, 100, 102, 98, 55, 53, 101, 97, 51, 49, 51, 51,
        54, 100, 55, 50, 53, 48, 97, 52, 98, 52, 99, 52, 51, 102, 100, 55, 102, 57, 50, 53, 51, 52,
        52, 101, 102, 100, 54, 98, 51, 54, 102, 51, 49, 52, 57, 56, 100, 101, 48, 99, 97, 55, 50,
        49, 56, 98, 52, 56, 54, 50, 52, 55, 48, 100, 55, 57, 52, 48, 98, 53, 52, 99, 97, 49, 101,
        101, 53, 98, 102, 50, 54, 55, 98, 51, 50, 99, 102, 52, 52, 49, 52, 100, 53, 49, 48, 53, 53,
        48, 101, 55, 100, 52, 48, 48, 57, 55, 57, 99, 51, 99, 101, 50, 100, 99, 49, 48, 99, 48,
        100, 57, 52, 102, 49, 54, 55, 54, 53, 102, 102, 98, 56, 57, 56, 51, 99, 98, 49, 50, 52, 55,
        51, 100, 99, 49, 52, 97, 53, 50, 100, 102, 97, 52, 50, 51, 53, 99, 53, 48, 98, 48, 98, 99,
        52, 51, 56, 51, 100, 97, 52, 102, 102, 56, 102, 56, 102, 100, 51, 57, 51, 53, 51, 102, 48,
        52, 53, 48, 99, 51, 102, 49, 54, 51, 49, 54, 98, 100, 100, 53, 102, 51, 101, 97, 52, 102,
        100, 50, 51, 49, 102, 54, 54, 55, 50, 49, 102, 97, 53, 48, 57, 98, 99, 98, 102, 100, 52,
        53, 51, 51, 53, 50, 99, 56, 51, 97, 54, 99, 51, 54, 49, 48, 50, 57, 54, 97, 97, 57, 48, 97,
        54, 51, 56, 52, 101, 99, 98, 55, 50, 98, 98, 99, 57, 53, 102, 48, 54, 54, 51, 101, 49, 50,
        99, 50, 100, 101, 48, 100, 55, 52, 53, 48, 49, 100, 53, 56, 101, 54, 56, 100, 53, 56, 102,
        52, 52, 57, 54, 102, 52, 49, 55, 51, 55, 101, 49, 102, 52, 54, 102, 57, 48, 48, 101, 54,
        57, 97, 53, 99, 102, 99, 57, 99, 100, 97, 52, 51, 56, 102, 49, 55, 55, 100, 56, 54, 52, 49,
        48, 49, 100, 101, 101, 49, 50, 101, 57, 97, 101, 55, 49, 49, 53, 102, 98, 55, 53, 55, 56,
        51, 48, 98, 54, 49, 99, 53, 55, 101, 100, 102, 98, 52, 97, 52, 99, 49, 99, 51, 53, 50, 99,
        102, 49, 99, 100, 54, 99, 51, 53, 56, 102, 100, 51, 54, 57, 97, 55, 51, 49, 53, 56, 51, 50,
        136, 2, 0, 0, 0, 0, 0, 0, 49, 102, 97, 55, 99, 48, 52, 98, 54, 52, 52, 51, 51, 100, 97,
        101, 50, 54, 53, 97, 98, 97, 55, 97, 53, 52, 54, 57, 55, 102, 53, 98, 51, 101, 56, 101, 54,
        54, 49, 99, 98, 48, 53, 54, 49, 57, 97, 52, 98, 48, 54, 55, 56, 52, 98, 49, 50, 55, 49, 98,
        57, 53, 49, 51, 50, 54, 48, 99, 54, 48, 101, 53, 49, 49, 56, 51, 50, 54, 100, 99, 56, 52,
        50, 48, 50, 57, 97, 54, 53, 49, 56, 100, 101, 100, 98, 50, 98, 98, 48, 55, 100, 50, 52, 51,
        98, 51, 52, 52, 101, 54, 49, 56, 100, 102, 98, 55, 53, 101, 97, 51, 49, 51, 51, 54, 100,
        55, 50, 53, 48, 97, 52, 98, 52, 99, 52, 51, 102, 100, 55, 102, 57, 50, 53, 51, 52, 52, 101,
        102, 100, 54, 98, 51, 54, 102, 51, 49, 52, 57, 56, 100, 101, 48, 99, 97, 55, 50, 49, 56,
        98, 52, 56, 54, 50, 52, 55, 48, 100, 55, 57, 52, 48, 98, 53, 52, 99, 97, 49, 101, 101, 53,
        98, 102, 50, 54, 55, 98, 51, 50, 99, 102, 52, 52, 49, 52, 100, 53, 49, 48, 53, 53, 48, 101,
        55, 100, 52, 48, 48, 57, 55, 57, 99, 51, 99, 101, 50, 100, 99, 49, 48, 99, 48, 100, 57, 52,
        102, 49, 54, 55, 54, 53, 102, 102, 98, 56, 57, 56, 51, 99, 98, 49, 50, 52, 55, 51, 100, 99,
        49, 52, 97, 53, 50, 100, 102, 97, 52, 50, 51, 53, 99, 53, 48, 98, 48, 98, 99, 52, 51, 56,
        51, 100, 97, 52, 102, 102, 56, 102, 56, 102, 100, 51, 57, 51, 53, 51, 102, 48, 52, 53, 48,
        99, 51, 102, 49, 54, 51, 49, 54, 98, 100, 100, 53, 102, 51, 101, 97, 52, 102, 100, 50, 51,
        49, 102, 54, 54, 55, 50, 49, 102, 97, 53, 48, 57, 98, 99, 98, 102, 100, 52, 53, 51, 51, 53,
        50, 99, 56, 51, 97, 54, 99, 51, 54, 49, 48, 50, 57, 54, 97, 97, 57, 48, 97, 54, 51, 56, 52,
        101, 99, 98, 55, 50, 98, 98, 99, 57, 53, 102, 48, 54, 54, 51, 101, 49, 50, 99, 50, 100,
        101, 48, 100, 55, 52, 53, 48, 49, 100, 53, 56, 101, 54, 56, 100, 53, 56, 102, 52, 52, 57,
        54, 102, 52, 49, 55, 51, 55, 101, 49, 102, 52, 54, 102, 57, 48, 48, 101, 54, 57, 97, 53,
        99, 102, 99, 57, 99, 100, 97, 52, 51, 56, 102, 49, 55, 55, 100, 56, 54, 52, 49, 48, 49,
        100, 101, 101, 49, 50, 101, 57, 97, 101, 55, 49, 49, 53, 102, 98, 55, 53, 55, 56, 51, 48,
        98, 54, 49, 99, 53, 55, 101, 100, 102, 98, 52, 97, 52, 99, 49, 99, 51, 53, 50, 99, 102, 49,
        99, 100, 54, 99, 51, 53, 56, 102, 100, 51, 54, 57, 97, 55, 51, 49, 53, 56, 51, 50, 48, 48,
        48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48,
        48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48,
        48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48,
        48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48,
        48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48,
        48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 14, 120, 244,
        219, 122, 103, 113, 163, 166, 167, 217, 195, 176, 222, 111, 231, 61, 88, 120, 19, 104, 150,
        122, 127, 232, 77, 135, 174, 255, 254, 200, 150,
    ];

    Ok(Json(Sp1ProofResponse {
        vk_hash,
        public_values,
        proof_bytes,
    }))
}

// ---------------------------------------------------------------------------
// Entry-point
// ---------------------------------------------------------------------------

#[tokio::main]
async fn main() -> eyre::Result<()> {
    tracing_subscriber::fmt::init();

    // -----------------------------------------------------------------------
    // Nitro enclave initialisation
    //
    //   --eif_path <path>   path to the compiled EIF (required to enable Nitro)
    // -----------------------------------------------------------------------

    let eif_path = std::env::args().skip_while(|a| a != "--eif_path").nth(1);

    let nitro = match eif_path {
        None => {
            info!("--eif_path not provided — /nitro endpoint disabled");
            None
        }
        Some(ref path) => {
            let nitro_config = NitroConfig::default();
            maybe_restart_enclave(Path::new(path), nitro_config).await?;
            info!("Nitro enclave initialised from {path}");
            Some(NitroState { config: nitro_config })
        }
    };

    let api_key = std::env::var("API_KEY")?;
    let listen_addr = std::env::var("LISTEN_ADDR").unwrap_or_else(|_| "0.0.0.0:8080".into());

    let genesis = Genesis::FluentDevnet;
    let block_execution_strategy_factory =
        create_eth_block_execution_strategy_factory(&genesis, None);

    let chain_spec: Arc<ChainSpec> = Arc::new(
        ChainSpec::try_from(&genesis)
            .map_err(|e| eyre::eyre!("Failed to build chain spec: {e}"))?,
    );

     // -----------------------------------------------------------------------
    // SP1 initialisation
    //
    //   SP1_ELF_PATH            path to the compiled zkVM ELF (required to enable SP1)
    //   SP1_PRIVATE_KEY         required for network prover authentication
    // -----------------------------------------------------------------------

    let sp1 = match std::env::var("SP1_ELF_PATH") {
        Err(_) => {
            info!("SP1_ELF_PATH not set — /sp1 endpoints disabled");
            None
        }
        Ok(elf_path) => {
            let elf = Elf::from(
                std::fs::read(&elf_path)
                    .map_err(|e| eyre::eyre!("Failed to read SP1 ELF {elf_path}: {e}"))?,
            );

            let client = ProverClient::builder()
                .network_for(NetworkMode::Mainnet)
                .build()
                .await;
            let pk = client.setup(elf).await.unwrap();
            let vk = pk.verifying_key();

            info!(vk_hash = %hex::encode(vk.hash_bytes()), "SP1 prover initialised");

            Some(Sp1State { client: Arc::new(client), pk: Arc::new(pk) })
        }
    };

    if nitro.is_none() && sp1.is_none() {
        eyre::bail!("No backends configured: provide --eif_path and/or SP1_ELF_PATH");
    }

    let state = AppState {
        api_key,
        nitro,
        block_execution_strategy_factory,
        genesis,
        chain_spec,
        sp1,
    };

    let app = Router::new()
        .route("/nitro", post(block))
        .route("/sp1/request", post(block_sp1_request))
        .route("/sp1/status", post(block_sp1_status))
        .route("/sp1/mock/request", post(block_sp1_mock_request))
        .route("/sp1/mock/status", post(block_sp1_mock_status))
        .route_layer(middleware::from_fn_with_state(state.clone(), require_api_key))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(&listen_addr).await?;
    info!("Listening on {listen_addr}");
    axum::serve(listener, app).await?;

    Ok(())
}