//! # proxy
//!
//! HTTP proxy that sits between callers and execution backends.
//!
//! ## Signing endpoints (Nitro TEE, caller provides `EthClientExecutorInput`)
//!
//! - `POST /sign-block-execution`           — execute block, return signed result (bincode)
//! - `POST /sign-batch-root`                — sign batch Merkle root from in-memory store
//!
//! ## Challenge endpoints (proxy builds `ClientInput` from RPC)
//!
//! - `POST /challenge/sp1/request`    — submit async SP1 zkVM proof request (blobs from beacon)
//! - `POST /challenge/sp1/status`     — poll for SP1 proof result
//!
//! ## Attestation retry
//!
//! - `POST /retry-attestation`          — retry attestation proof (SP1 + L1)
//!
//! ## Mock endpoints (testing, local SP1 execution)
//!
//! - `POST /mock/sp1/request`         — execute SP1 locally (CPU), return success/failure
//!
//! All endpoints are protected by `x-api-key` header.

mod enclave;
mod types;

mod attestation;

use crate::{
    enclave::ensure_initialized,
    types::{NitroConfig, Sp1ProofResponse},
};
use nitro_types::{EthExecutionResponse, InvalidSignaturesResponse, SignBatchRootRequest};

use std::{env, sync::Arc};
use tokio::sync::OnceCell;

/// Lazily-initialized SP1 prover state.
/// The background init task populates this; handlers await it on first use.
type LazySp1 = Arc<OnceCell<Sp1State>>;

use alloy_primitives::Address;
use axum::{
    body::Bytes,
    extract::{DefaultBodyLimit, Request, State},
    http::{HeaderMap, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Json},
    routing::post,
    Router,
};
use fluent_stf_primitives::fluent_chainspec;
use revm_primitives::{hex, FixedBytes, B256};
use url::Url;

use serde::{Deserialize, Serialize};

use alloy_provider::{Provider, RootProvider};
use reth_chainspec::ChainSpec;
use rsp_client_executor::{evm::FluentEvmConfig, io::EthClientExecutorInput};
use rsp_host_executor::{create_eth_block_execution_strategy_factory, HostExecutor};
use rsp_provider::create_provider;

use sp1_sdk::{
    network::{prover::NetworkProver, NetworkMode},
    Elf, HashableKey, ProveRequest, Prover, ProverClient, ProvingKey, SP1ProvingKey, SP1Stdin,
};

use c_kzg::{Blob as CKzgBlob, KzgSettings};
use tracing::info;

pub fn rpc_url() -> String {
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

#[derive(Clone)]
struct AppState {
    api_key: String,
    nitro: Option<NitroState>,
    sp1: Option<LazySp1>,
    /// Raw SP1 ELF bytes — used by mock endpoint for local CPU execution.
    sp1_elf_bytes: Option<Arc<Vec<u8>>>,
    /// RPC / chain context — used by challenge endpoints to build ClientInput.
    chain: ChainContext,
    /// L1 context — used by `/sign-batch-root` for blob fetching.
    l1: Option<L1State>,
}

#[derive(Clone)]
struct L1State {
    /// L1 RPC provider (rollup contract reads).
    l1_provider: RootProvider,
    /// Rollup contract address on L1.
    contract_addr: Address,
    /// L1 block where the rollup contract was deployed (lower bound for log scans).
    deploy_block: u64,
}

#[derive(Clone)]
struct NitroState {
    config: NitroConfig,
}

#[derive(Clone)]
struct Sp1State {
    client: Arc<NetworkProver>,
    pk: Arc<SP1ProvingKey>,
}

#[derive(Clone)]
struct ChainContext {
    block_execution_strategy_factory: FluentEvmConfig,
    chain_spec: Arc<ChainSpec>,
}

// ---------------------------------------------------------------------------
// Request / response types
// ---------------------------------------------------------------------------

use nitro_types::BlobVerificationInput;

/// `POST /challenge/sp1/request` — block ref + batch index for blob fetching.
#[derive(Deserialize)]
struct ChallengeSp1Request {
    block_number: Option<u64>,
    block_hash: Option<B256>,
    batch_index: u64,
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
struct MockSp1Response {
    success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

#[derive(Deserialize)]
struct RetryAttestationRequest {
    request_id: Option<B256>,
}

#[derive(Serialize)]
struct RetryAttestationResponse {
    request_id: Option<B256>,
    status: String,
    public_key: String,
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
// Helpers
// ---------------------------------------------------------------------------

fn require_nitro(state: &AppState) -> Result<&NitroState, HandlerError> {
    state
        .nitro
        .as_ref()
        .ok_or_else(|| internal("Nitro enclave not configured (pass --eif_path at startup)"))
}

async fn require_sp1(state: &AppState) -> Result<&Sp1State, HandlerError> {
    match &state.sp1 {
        None => Err(internal("SP1 prover not configured (set SP1_ELF_PATH)")),
        Some(cell) => {
            cell.get().ok_or_else(|| internal("SP1 prover still initializing, please retry"))
        }
    }
}

fn require_l1(state: &AppState) -> Result<&L1State, HandlerError> {
    state
        .l1
        .as_ref()
        .ok_or_else(|| internal("L1 not configured (set L1_RPC_URL, L1_ROLLUP_ADDR)"))
}

/// Generates KZG commitments and proofs on the host using Fiat-Shamir.
/// This witness is sent to SP1 to avoid heavy MSMs inside the zkVM.
fn prepare_blob_input(raw_blobs: &[Vec<u8>]) -> Result<BlobVerificationInput, HandlerError> {
    let setup_str = std::str::from_utf8(include_bytes!("../../client/trusted_setup.txt"))
        .map_err(|_| internal("Invalid trusted setup UTF-8"))?;
    let settings = KzgSettings::parse_kzg_trusted_setup(setup_str, 0)
        .map_err(|e| internal(format!("Failed to parse KZG settings: {e}")))?;

    let mut commitments = Vec::with_capacity(raw_blobs.len());
    let mut proofs = Vec::with_capacity(raw_blobs.len());

    for raw in raw_blobs {
        let blob = CKzgBlob::from_bytes(raw)
            .map_err(|e| bad_request(format!("Invalid blob bytes: {e}")))?;

        let commitment = settings
            .blob_to_kzg_commitment(&blob)
            .map_err(|e| internal(format!("KZG commitment failed: {e}")))?;

        let commitment_bytes = commitment.to_bytes();

        let proof = settings
            .compute_blob_kzg_proof(&blob, &commitment_bytes)
            .map_err(|e| internal(format!("KZG proof generation failed: {e}")))?;

        commitments.push(commitment_bytes.to_vec());
        proofs.push(proof.to_bytes().to_vec());
    }

    Ok(BlobVerificationInput { blobs: raw_blobs.to_vec(), commitments, proofs })
}

/// Fetch blobs for a challenge endpoint by reconstructing them from L2 tx data.
///
/// Resolves the batch's L2 block range via an L1 `acceptNextBatch` calldata
/// lookup, then rebuilds the canonical blobs from L2 RPC — no Beacon API.
async fn fetch_challenge_blobs(
    l1: &L1State,
    batch_index: u64,
) -> Result<Vec<Vec<u8>>, HandlerError> {
    let l2_url = Url::parse(&rpc_url()).map_err(|e| internal(format!("Invalid rpc_url: {e}")))?;
    let l2_provider: RootProvider = create_provider(l2_url);

    let (from_block, to_block) = l1_rollup_client::fetch_batch_range(
        &l1.l1_provider,
        l1.contract_addr,
        batch_index,
        l1.deploy_block,
    )
    .await
    .map_err(|e| internal(format!("Batch range lookup failed: {e}")))?;

    rsp_blob_builder::build_blobs_from_l2(&l2_provider, from_block, to_block)
        .await
        .map_err(|e| internal(format!("Blob construction failed: {e}")))
}

/// Resolves a block number from either `block_number` or `block_hash`,
/// fetches the block from RPC and runs host-side execution to produce
/// an `EthClientExecutorInput`.
async fn build_client_input(
    block_number: Option<u64>,
    block_hash: Option<B256>,
    chain: &ChainContext,
) -> Result<EthClientExecutorInput, HandlerError> {
    let url = Url::parse(&rpc_url()).map_err(|e| bad_request(format!("Invalid rpc_url: {e}")))?;
    let provider: RootProvider = create_provider(url);

    let block_number = match (block_number, block_hash) {
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
            return Err(bad_request("Either block_number or block_hash must be provided"))
        }
    };

    let host_executor =
        HostExecutor::new(chain.block_execution_strategy_factory.clone(), chain.chain_spec.clone());

    host_executor
        .execute(block_number, &provider, None, false)
        .await
        .map_err(|e| internal(format!("Block execution failed: {e}")))
}

// ===========================================================================
// Signing endpoints — caller provides EthClientExecutorInput
// ===========================================================================

/// `POST /sign-block-execution`
///
/// Body: bincode-serialized `EthClientExecutorInput`.
/// Headers: `Content-Type: application/octet-stream`.
async fn sign_block_execution(
    State(state): State<AppState>,
    body: Bytes,
) -> Result<Json<EthExecutionResponse>, HandlerError> {
    let nitro = require_nitro(&state)?;

    let input = decode_bincode::<EthClientExecutorInput>(&body)?;

    let response = enclave::execute_block(input, nitro.config)
        .await
        .map_err(|e| internal(format!("Enclave execution failed: {e}")))?;

    Ok(Json(response))
}

/// Decode a bincode payload.
fn decode_bincode<T: serde::de::DeserializeOwned>(body: &[u8]) -> Result<T, HandlerError> {
    bincode::deserialize(body)
        .map_err(|e| bad_request(format!("Bincode deserialization failed: {e}")))
}

/// `POST /sign-batch-root`
///
/// Fetches blobs from L1 + Beacon API using `batch_index`, then sends them
/// to the enclave for batch root signing.
async fn sign_batch_root(
    State(state): State<AppState>,
    Json(req): Json<SignBatchRootRequest>,
) -> Result<impl IntoResponse, HandlerError> {
    let nitro = require_nitro(&state)?;

    if req.from_block > req.to_block {
        return Err(bad_request(format!(
            "invalid range: from_block ({}) > to_block ({})",
            req.from_block, req.to_block
        )));
    }

    if req.blobs.is_empty() {
        return Err(bad_request("blobs field is required and must not be empty"));
    }

    // Blobs are now provided by the courier — no L1/Beacon fetch needed
    let outcome =
        enclave::submit_batch(req.from_block, req.to_block, req.responses, req.blobs, nitro.config)
            .await
            .map_err(|e| internal(format!("Batch submission failed: {e}")))?;

    match outcome {
        enclave::SubmitBatchOutcome::Success(resp) => {
            Ok(Json(serde_json::to_value(resp).unwrap()).into_response())
        }
        enclave::SubmitBatchOutcome::InvalidSignatures { invalid_blocks } => {
            let address = enclave::enclave_address()
                .ok_or_else(|| internal("Enclave address not available"))?;
            Ok((
                StatusCode::CONFLICT,
                Json(InvalidSignaturesResponse { invalid_blocks, enclave_address: address }),
            )
                .into_response())
        }
    }
}

// ===========================================================================
// Challenge endpoints — proxy builds ClientInput from RPC
// ===========================================================================

/// `POST /challenge/sp1/request`
/// Body: `{ block_number?, block_hash?, batch_index }`
///
/// Fetches blobs from L1 + Beacon API using `batch_index`.
async fn challenge_sp1_request(
    State(state): State<AppState>,
    Json(req): Json<ChallengeSp1Request>,
) -> Result<Json<Sp1RequestResponse>, HandlerError> {
    let sp1 = require_sp1(&state).await?;
    let l1 = require_l1(&state)?;

    let raw_blobs = fetch_challenge_blobs(l1, req.batch_index).await?;

    let client_input = build_client_input(req.block_number, req.block_hash, &state.chain).await?;
    let block_number = client_input.current_block.header.number;

    let blob_input = prepare_blob_input(&raw_blobs)?;

    let mut stdin = SP1Stdin::new();
    let serialized_input = bincode::serialize(&client_input)
        .map_err(|e| internal(format!("Failed to serialize client input: {e}")))?;
    stdin.write_slice(&serialized_input);

    let serialized_blobs = bincode::serialize(&blob_input)
        .map_err(|e| internal(format!("Failed to serialize blob input: {e}")))?;
    stdin.write_slice(&serialized_blobs);

    info!(block_number, "Submitting async SP1 Groth16 proof request");

    let request_id: B256 = sp1
        .client
        .prove(sp1.pk.as_ref(), stdin)
        .groth16()
        .max_price_per_pgu(500_000_000u64)
        .request()
        .await
        .map_err(|e| internal(format!("Failed to submit proof request: {e}")))?;

    info!(block_number, request_id = %hex::encode(request_id), "SP1 proof request submitted");

    Ok(Json(Sp1RequestResponse { request_id }))
}

/// `POST /challenge/sp1/status`
/// Body: `{ request_id }`
/// Returns: `Sp1ProofResponse` (200) | 202 Accepted (pending) | 404 (not found)
async fn challenge_sp1_status(
    State(state): State<AppState>,
    Json(req): Json<Sp1StatusRequest>,
) -> impl IntoResponse {
    let sp1 = match require_sp1(&state).await {
        Ok(s) => s,
        Err(e) => return e.into_response(),
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

// ===========================================================================
// Attestation retry endpoint
// ===========================================================================

/// `POST /retry-attestation`
///
/// Without request_id: submit new SP1 proof, return request_id immediately.
/// With request_id: check SP1 proof status, submit to L1 if ready.
async fn retry_attestation(
    State(_state): State<AppState>,
    Json(req): Json<RetryAttestationRequest>,
) -> Result<Json<RetryAttestationResponse>, HandlerError> {
    let (public_key, attestation) = enclave::load_attestation_artifacts()
        .map_err(|e| bad_request(format!("Enclave not initialized: {e}")))?;

    let pk_hex = hex::encode(&public_key);

    let config = enclave::attestation_config()
        .ok_or_else(|| internal("Attestation prover not configured or still initializing"))?;

    let result = attestation::retry(config, &public_key, &attestation, req.request_id)
        .await
        .map_err(|e| internal(format!("Attestation retry failed: {e}")))?;

    Ok(Json(RetryAttestationResponse {
        request_id: result.request_id,
        status: result.status,
        public_key: pk_hex,
    }))
}

// ===========================================================================
// Mock endpoints
// ===========================================================================

/// `POST /mock/sp1/request` — local SP1 zkVM execution, no network call.
/// Same input as `/challenge/sp1/request`, returns `{ success, error? }`.
async fn mock_sp1_request(
    State(state): State<AppState>,
    Json(req): Json<ChallengeSp1Request>,
) -> Result<Json<MockSp1Response>, HandlerError> {
    let elf_bytes = state
        .sp1_elf_bytes
        .as_ref()
        .ok_or_else(|| internal("SP1 ELF not configured (set SP1_ELF_PATH)"))?
        .clone();

    let l1 = require_l1(&state)?;

    tracing::info!(
        block_number = ?req.block_number,
        block_hash = ?req.block_hash,
        batch_index = req.batch_index,
        "Starting mock SP1 local execution"
    );

    let raw_blobs = fetch_challenge_blobs(l1, req.batch_index).await?;
    let client_input = build_client_input(req.block_number, req.block_hash, &state.chain).await?;
    let block_number = client_input.current_block.header.number;
    let blob_input = prepare_blob_input(&raw_blobs)?;

    let mut stdin = SP1Stdin::new();
    let serialized_input = bincode::serialize(&client_input)
        .map_err(|e| internal(format!("Failed to serialize client input: {e}")))?;
    stdin.write_slice(&serialized_input);
    let serialized_blobs = bincode::serialize(&blob_input)
        .map_err(|e| internal(format!("Failed to serialize blob input: {e}")))?;
    stdin.write_slice(&serialized_blobs);

    info!(block_number, "Executing SP1 program locally (CPU)");

    let handle = tokio::runtime::Handle::current();
    let result = tokio::task::spawn_blocking(move || {
        handle.block_on(async {
            let client = sp1_sdk::ProverClient::builder().cpu().build().await;
            client.execute(Elf::from(elf_bytes.as_ref().clone()), stdin).await
        })
    })
    .await
    .map_err(|e| internal(format!("SP1 execution task panicked: {e}")))?;

    match result {
        Ok((_public_values, report)) => {
            info!(
                block_number,
                total_instructions = report.total_instruction_count(),
                "Mock SP1 execution succeeded"
            );
            Ok(Json(MockSp1Response { success: true, error: None }))
        }
        Err(e) => {
            tracing::warn!(block_number, err = %e, "Mock SP1 execution failed");
            Ok(Json(MockSp1Response { success: false, error: Some(format!("{e}")) }))
        }
    }
}

// ---------------------------------------------------------------------------
// Entry-point
// ---------------------------------------------------------------------------

#[tokio::main]
async fn main() -> eyre::Result<()> {
    tracing_subscriber::fmt::init();

    // ── Nitro enclave ────────────────────────────────────────────────────
    let eif_path = std::env::args().skip_while(|a| a != "--eif_path").nth(1);

    // ── SP1 prover (lazy init) ────────────────────────────────────────────
    let mut sp1_elf_bytes: Option<Arc<Vec<u8>>> = None;
    let sp1: Option<LazySp1> = match std::env::var("SP1_ELF_PATH") {
        Err(_) => {
            info!("SP1_ELF_PATH not set — /challenge/sp1 endpoints disabled");
            None
        }
        Ok(elf_path) => {
            let elf_bytes = std::fs::read(&elf_path)
                .map_err(|e| eyre::eyre!("Failed to read SP1 ELF {elf_path}: {e}"))?;

            sp1_elf_bytes = Some(Arc::new(elf_bytes.clone()));

            let cell = Arc::new(OnceCell::new());
            let cell_clone = cell.clone();

            tokio::spawn(async move {
                let elf = Elf::from(elf_bytes);
                let client =
                    ProverClient::builder().network_for(NetworkMode::Mainnet).build().await;
                let pk = client.setup(elf).await.unwrap();
                let vk = pk.verifying_key();
                info!(vk_hash = %hex::encode(vk.hash_bytes()), "SP1 prover initialised (background)");
                let _ = cell_clone.set(Sp1State { client: Arc::new(client), pk: Arc::new(pk) });
            });

            info!("SP1 prover initialization started in background");
            Some(cell)
        }
    };

    // ── Chain context (for challenge endpoints) ──────────────────────────
    let block_execution_strategy_factory = create_eth_block_execution_strategy_factory(None);
    let chain_spec: Arc<ChainSpec> = Arc::new(fluent_chainspec());

    let chain = ChainContext { block_execution_strategy_factory, chain_spec };

    // ── L1 context (for batch metadata lookup in challenge endpoints) ────
    let l1 = match (env::var("L1_RPC_URL"), env::var("L1_ROLLUP_ADDR")) {
        (Ok(l1_rpc), Ok(l1_addr)) => {
            let l1_url = Url::parse(&l1_rpc).map_err(|e| eyre::eyre!("Invalid L1_RPC_URL: {e}"))?;
            let l1_provider: RootProvider = create_provider(l1_url);
            let contract_addr: Address =
                l1_addr.parse().map_err(|e| eyre::eyre!("Invalid L1_ROLLUP_ADDR: {e}"))?;
            let deploy_block: u64 =
                env::var("L1_ROLLUP_DEPLOY_BLOCK").ok().and_then(|s| s.parse().ok()).unwrap_or(0);

            info!(
                l1_rpc = %l1_rpc,
                contract_addr = %l1_addr,
                deploy_block,
                "L1 context initialized for batch metadata lookup"
            );

            Some(L1State { l1_provider, contract_addr, deploy_block })
        }
        _ => {
            info!("L1_RPC_URL/L1_ROLLUP_ADDR not set — challenge endpoints disabled");
            None
        }
    };

    // ── Attestation config (lazy init) ────────────────────────────────
    // Kicked off in background; `on_new_attestation` and `/retry-attestation`
    // will also try to init via the same `OnceCell` if they run first.
    tokio::spawn(enclave::init_attestation_config());
    info!("Attestation config initialization started in background");

    let nitro = match eif_path {
        None => {
            info!("--eif_path not provided — signing endpoints disabled");
            None
        }
        Some(ref path) => {
            let nitro_config = NitroConfig::default();
            ensure_initialized(&nitro_config).await?;
            info!("Nitro enclave initialised from {path}");
            Some(NitroState { config: nitro_config })
        }
    };

    if nitro.is_none() && sp1.is_none() {
        eyre::bail!("No backends configured: provide --eif_path and/or SP1_ELF_PATH");
    }

    let api_key = std::env::var("API_KEY")?;
    let listen_addr = std::env::var("LISTEN_ADDR").unwrap_or_else(|_| "0.0.0.0:8080".into());

    let state = AppState { api_key, nitro, sp1, sp1_elf_bytes, chain, l1 };

    let app = Router::new()
        // ── Signing (TEE, input from caller) ─────────────
        .route("/sign-block-execution", post(sign_block_execution))
        .route("/sign-batch-root", post(sign_batch_root))
        // ── Challenge (proxy builds input from RPC) ──────
        .route("/challenge/sp1/request", post(challenge_sp1_request))
        .route("/challenge/sp1/status", post(challenge_sp1_status))
        // ── Attestation retry ────────────────────────────
        .route("/retry-attestation", post(retry_attestation))
        // ── Mock (testing) ───────────────────────────────
        .route("/mock/sp1/request", post(mock_sp1_request))
        .layer(DefaultBodyLimit::max(usize::MAX))
        // ── Auth ─────────────────────────────────────────
        .route_layer(middleware::from_fn_with_state(state.clone(), require_api_key))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(&listen_addr).await?;
    info!("Listening on {listen_addr}");
    axum::serve(listener, app).await?;

    Ok(())
}
