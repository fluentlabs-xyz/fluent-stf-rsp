//! # proxy
//!
//! HTTP proxy that sits between callers and two execution backends:
//!
//! 1. **Nitro enclave** (`POST /block`) — executes an Ethereum block inside an AWS Nitro Enclave
//!    and returns a signed execution result.
//!
//! 2. **SP1 prover** (`POST /block/sp1-proof`) — executes the same block inside the SP1 zkVM and
//!    returns a Groth16 proof that can be verified on-chain by any `ISP1Verifier`-compatible
//!    contract.
//!
//! Both endpoints share the same block-fetching and host-execution pipeline
//! ([`build_client_input`]) and are protected by an API key middleware.

mod enclave;
mod types;

use crate::{
    enclave::maybe_restart_enclave,
    types::{EthExecutionResponse, NitroConfig, Sp1ProofResponse},
};

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
use reth_chainspec::ChainSpec;
use reth_ethereum_primitives::EthPrimitives;
use reth_evm_ethereum::EthEvmConfig;
use rsp_client_executor::{custom::CustomEvmFactory, io::ClientExecutorInput};
use rsp_host_executor::{create_eth_block_execution_strategy_factory, HostExecutor};
use rsp_provider::create_provider;

use sp1_sdk::{
    network::NetworkMode, CpuProver, HashableKey, NetworkProver, NetworkSigner, Prover,
    SP1ProofWithPublicValues, SP1ProvingKey, SP1Stdin, SP1VerifyingKey,
};

use tokio::task;
use tracing::info;
use vsock::{VsockAddr, VsockStream};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum allowed VSOCK frame size (64 MiB).
/// Applied to both incoming responses and outgoing requests.
const MAX_FRAME_SIZE: usize = 64 * 1024 * 1024;

// ---------------------------------------------------------------------------
// SP1 backend abstraction
// ---------------------------------------------------------------------------

/// Wraps the two concrete SP1 prover implementations behind a single
/// async `prove()` method.
///
/// Both variants produce identical output (`SP1ProofWithPublicValues`) and
/// use `spawn_blocking` because the underlying SDK calls are synchronous —
/// the local prover is CPU-bound and the network prover blocks on HTTP polling.
#[derive(Clone)]
enum ProverBackend {
    /// Runs Groth16 proving on the host machine (CPU or GPU).
    Local(Arc<CpuProver>),
    /// Delegates proving to the Succinct prover network via HTTPS.
    Network(Arc<NetworkProver>),
}

impl ProverBackend {
    /// Generates a Groth16 proof for `stdin` using the given proving key.
    ///
    /// The call is offloaded to a blocking thread pool via `spawn_blocking`
    /// so the Tokio runtime is never stalled.
    async fn prove(
        &self,
        pk: Arc<SP1ProvingKey>,
        stdin: SP1Stdin,
    ) -> eyre::Result<SP1ProofWithPublicValues> {
        match self {
            ProverBackend::Local(client) => {
                let client = client.clone();
                task::spawn_blocking(move || {
                    client
                        .prove(pk.as_ref(), &stdin)
                        .groth16()
                        .run()
                        .map_err(|e| eyre::eyre!("Local proving failed: {e}"))
                })
                .await
                .map_err(|e| eyre::eyre!("Blocking task panicked: {e}"))?
            }
            ProverBackend::Network(client) => {
                let client = client.clone();
                task::spawn_blocking(move || {
                    client
                        .prove(pk.as_ref(), &stdin)
                        .groth16()
                        .run()
                        .map_err(|e| eyre::eyre!("Network proving failed: {e}"))
                })
                .await
                .map_err(|e| eyre::eyre!("Blocking task panicked: {e}"))?
            }
        }
    }

    /// Human-readable backend name used in log messages.
    fn name(&self) -> &'static str {
        match self {
            ProverBackend::Local(_) => "local",
            ProverBackend::Network(_) => "network",
        }
    }
}

// ---------------------------------------------------------------------------
// Application state
// ---------------------------------------------------------------------------

/// Shared state cloned into every request handler via Axum's `State` extractor.
#[derive(Clone)]
struct AppState {
    /// Expected value of the `x-api-key` request header.
    api_key: String,
    nitro_config: NitroConfig,
    block_execution_strategy_factory: EthEvmConfig<ChainSpec, CustomEvmFactory>,
    genesis: Genesis,
    chain_spec: Arc<ChainSpec>,
    /// SP1 prover state.  `None` when `SP1_ELF_PATH` is not set;
    /// the `/block/sp1-proof` endpoint returns HTTP 500 in that case.
    sp1: Option<Sp1State>,
}

/// SP1-specific state initialised once at startup and shared across requests.
#[derive(Clone)]
struct Sp1State {
    backend: ProverBackend,
    /// Proving key derived from the compiled zkVM ELF.
    pk: Arc<SP1ProvingKey>,
    /// Verifying key — its hash is returned to callers as `vk_hash`.
    vk: Arc<SP1VerifyingKey>,
}

// ---------------------------------------------------------------------------
// HTTP request / response types
// ---------------------------------------------------------------------------

/// Request body shared by both `/block` and `/block/sp1-proof`.
#[derive(Deserialize)]
struct BlockRequest {
    block_number: u64,
    /// JSON-RPC endpoint used to fetch the block and its execution witnesses.
    rpc_url: String,
}

/// Generic JSON error body returned on 4xx / 5xx responses.
#[derive(Serialize)]
struct ErrorResponse {
    error: String,
}

// Convenience type alias so handler return types stay readable.
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

/// Rejects requests that do not carry a valid `x-api-key` header.
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

/// Fetches `block_number` from `rpc_url` and runs the host-side execution
/// phase to produce a [`ClientExecutorInput`] ready for either backend.
///
/// This is intentionally shared between [`block`] and [`block_sp1_proof`] so
/// the two endpoints always use identical witness data.
async fn build_client_input(
    block_number: u64,
    rpc_url: &str,
    state: &AppState,
) -> Result<ClientExecutorInput<EthPrimitives>, HandlerError> {
    let url = Url::parse(rpc_url).map_err(|e| bad_request(format!("Invalid rpc_url: {e}")))?;
    let provider: RootProvider = create_provider(url);

    let host_executor =
        HostExecutor::new(state.block_execution_strategy_factory.clone(), state.chain_spec.clone());

    host_executor
        .execute(block_number, &provider, state.genesis.clone(), None, false)
        .await
        .map_err(|e| internal(format!("Block execution failed: {e}")))
}

// ---------------------------------------------------------------------------
// Handler: POST /block  —  Nitro enclave execution
// ---------------------------------------------------------------------------

/// Executes `block_number` inside the AWS Nitro Enclave and returns a signed
/// [`EthExecutionResponse`].
///
/// The enclave signs the result with its KMS-backed key so callers can verify
/// the computation was performed in a genuine, attested environment.
async fn block(
    State(state): State<AppState>,
    Json(req): Json<BlockRequest>,
) -> Result<Json<EthExecutionResponse>, HandlerError> {
    let client_input = build_client_input(req.block_number, &req.rpc_url, &state).await?;

    let response = process_nitro_client(client_input, state.nitro_config)
        .await
        .map_err(|e| internal(format!("Enclave processing failed: {e}")))?;

    Ok(Json(response))
}

// ---------------------------------------------------------------------------
// Handler: POST /block/sp1-proof  —  SP1 Groth16 proof generation
// ---------------------------------------------------------------------------

/// Executes `block_number` inside the SP1 zkVM and returns a Groth16
/// [`Sp1ProofResponse`] that can be verified on-chain.
///
/// Returns HTTP 500 if the server was started without `SP1_ELF_PATH`.
async fn block_sp1_proof(
    State(state): State<AppState>,
    Json(req): Json<BlockRequest>,
) -> Result<Json<Sp1ProofResponse>, HandlerError> {
    let sp1 = state
        .sp1
        .as_ref()
        .ok_or_else(|| internal("SP1 prover not configured (set SP1_ELF_PATH)"))?;

    let client_input = build_client_input(req.block_number, &req.rpc_url, &state).await?;

    // Capture the expected hash before moving client_input into the prover.
    let expected_block_hash = client_input.current_block.header.hash_slow();

    let response = process_sp1_client(client_input, sp1.clone())
        .await
        .map_err(|e| internal(format!("SP1 proof generation failed: {e}")))?;

    // Sanity check: the proof must commit to the block we requested.
    if response.block_hash != expected_block_hash {
        return Err(internal(format!(
            "Block hash mismatch: requested {}, proof contains {}",
            hex::encode(expected_block_hash),
            hex::encode(response.block_hash),
        )));
    }

    Ok(Json(response))
}

// ---------------------------------------------------------------------------
// Nitro enclave execution
// ---------------------------------------------------------------------------

/// Serialises `client_input`, sends it to the Nitro enclave over VSOCK, reads
/// the response, and verifies that the returned hashes match the input block.
///
/// All socket I/O is offloaded to a blocking thread because `VsockStream` does
/// not implement async I/O.
async fn process_nitro_client(
    client_input: ClientExecutorInput<EthPrimitives>,
    config: NitroConfig,
) -> eyre::Result<EthExecutionResponse> {
    info!("Connecting to Nitro enclave CID={} PORT={}", config.enclave_cid, config.enclave_port);

    let payload = bincode::serialize(&client_input)
        .map_err(|e| eyre::eyre!("Failed to serialize client input: {}", e))?;
    info!("Serialized input: {} bytes", payload.len());

    // Offload all blocking VSOCK I/O to the thread pool.
    let response = task::spawn_blocking(move || -> eyre::Result<EthExecutionResponse> {
        let addr = VsockAddr::new(config.enclave_cid, config.enclave_port);
        let mut stream = VsockStream::connect(&addr).map_err(|e| {
            eyre::eyre!(
                "VSOCK connect {}:{} failed: {}",
                config.enclave_cid,
                config.enclave_port,
                e
            )
        })?;

        // Length-prefixed framing: [ u32 big-endian length ][ payload ]
        let req_len: u32 = payload
            .len()
            .try_into()
            .map_err(|_| eyre::eyre!("Payload too large: {} bytes", payload.len()))?;
        stream
            .write_all(&req_len.to_be_bytes())
            .map_err(|e| eyre::eyre!("Failed to write request length: {}", e))?;
        stream.write_all(&payload).map_err(|e| eyre::eyre!("Failed to write payload: {}", e))?;
        stream.flush().map_err(|e| eyre::eyre!("Failed to flush stream: {}", e))?;
        info!("Sent {} bytes to enclave", payload.len());

        // Read the length-prefixed response.
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

    // Verify the enclave processed the exact block we requested.
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
// SP1 proof generation
// ---------------------------------------------------------------------------

/// Serialises `client_input` into SP1 stdin, runs the zkVM program to
/// generate a Groth16 proof, and extracts the three fields required by the
/// on-chain verifier contract.
async fn process_sp1_client(
    client_input: ClientExecutorInput<EthPrimitives>,
    sp1: Sp1State,
) -> eyre::Result<Sp1ProofResponse> {
    let block_number = client_input.current_block.number;

    // Serialise the full block input for the zkVM guest program.
    let mut stdin = SP1Stdin::new();
    stdin.write_vec(
        bincode::serialize(&client_input)
            .map_err(|e| eyre::eyre!("Failed to serialize client input: {e}"))?,
    );

    info!(block_number, backend = sp1.backend.name(), "Starting SP1 Groth16 proof generation");

    let proof = sp1.backend.prove(sp1.pk.clone(), stdin).await?;

    info!(block_number, "SP1 proof generated successfully");

    // --- Extract fields for ISP1Verifier.verifyProof() ---------------------

    // public_values: raw bytes committed by the guest via `sp1_zkvm::io::commit`.
    let public_values = proof.public_values.as_slice().to_vec();

    // Read block_hash back from public values (layout: parent_hash ++ block_hash ++ …).
    let block_hash = {
        let mut pv = proof.public_values.clone();
        let _parent_hash: FixedBytes<32> = pv.read();
        pv.read::<FixedBytes<32>>()
    };

    // proof_bytes: bincode-serialised Groth16 proof, passed verbatim to the contract.
    let proof_bytes = bincode::serialize(&proof.proof)
        .map_err(|e| eyre::eyre!("Failed to serialize proof: {e}"))?;

    // vk_hash: bytes32 commitment to the program, first arg to verifyProof().
    let vk_hash = FixedBytes::from(sp1.vk.hash_bytes());

    Ok(Sp1ProofResponse { block_number, block_hash, vk_hash, public_values, proof_bytes })
}

// ---------------------------------------------------------------------------
// Genesis configuration
// ---------------------------------------------------------------------------

/// Fallback genesis used when `GENESIS_JSON` is not set in the environment.
/// Matches the devnet chain (chainId 20993) with all EIPs active from block 0.
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

    // -----------------------------------------------------------------------
    // CLI
    // -----------------------------------------------------------------------

    let eif_path = std::env::args()
        .skip_while(|a| a != "--eif_path")
        .nth(1)
        .ok_or_else(|| eyre::eyre!("Usage: proxy --eif_path <path-to.eif>"))?;

    // -----------------------------------------------------------------------
    // Nitro enclave — start / restart if needed
    // -----------------------------------------------------------------------

    let nitro_config = NitroConfig::default();
    maybe_restart_enclave(Path::new(&eif_path), nitro_config).await?;

    // -----------------------------------------------------------------------
    // Environment
    // -----------------------------------------------------------------------

    let api_key = std::env::var("API_KEY")?;
    let listen_addr = std::env::var("LISTEN_ADDR").unwrap_or_else(|_| "0.0.0.0:8080".into());

    // -----------------------------------------------------------------------
    // Genesis
    // -----------------------------------------------------------------------

    // Allow operators to point at a different network without recompiling.
    let genesis_json = match std::env::var("GENESIS_PATH") {
        Ok(path) => std::fs::read_to_string(&path)
            .map_err(|e| eyre::eyre!("Failed to read genesis file {path}: {e}"))?,
        Err(_) => {
            info!("GENESIS_PATH not set — using built-in devnet genesis");
            DEVNET_GENESIS.to_string()
        }
    };
    let alloy_genesis =
        genesis_from_json(&genesis_json).map_err(|e| eyre::eyre!("Invalid genesis: {e}"))?;
    let genesis = Genesis::Custom(alloy_genesis.config);
    let block_execution_strategy_factory =
        create_eth_block_execution_strategy_factory(&genesis, None);

    let chain_spec: Arc<ChainSpec> = Arc::new(
        ChainSpec::try_from(&genesis)
            .map_err(|e| eyre::eyre!("Failed to build chain spec: {e}"))?,
    );

    // -----------------------------------------------------------------------
    // SP1 initialisation — optional, controlled by env vars:
    //
    //   SP1_ELF_PATH            path to the compiled zkVM ELF (required to enable SP1)
    //   SP1_PROVER              "local" (default) | "network"
    //   SP1_PRIVATE_KEY         required when SP1_PROVER=network
    //   SP1_PROVER_NETWORK_RPC  optional custom RPC (default: Succinct production network)
    // -----------------------------------------------------------------------

    let sp1 = match std::env::var("SP1_ELF_PATH") {
        Err(_) => {
            info!("SP1_ELF_PATH not set — /block/sp1-proof endpoint disabled");
            None
        }
        Ok(elf_path) => {
            let elf = std::fs::read(&elf_path)
                .map_err(|e| eyre::eyre!("Failed to read SP1 ELF {elf_path}: {e}"))?;

            let backend = match std::env::var("SP1_PROVER").as_deref() {
                Ok("network") => {
                    let private_key = std::env::var("SP1_PRIVATE_KEY").map_err(|_| {
                        eyre::eyre!("SP1_PRIVATE_KEY must be set when SP1_PROVER=network")
                    })?;
                    let rpc_url = std::env::var("SP1_PROVER_NETWORK_RPC")
                        .unwrap_or_else(|_| "https://rpc.production.succinct.xyz".to_string());

                    // TODO: consider AWS KMS signer for production key management.
                    let signer = NetworkSigner::local(&private_key)
                        .map_err(|e| eyre::eyre!("Invalid SP1_PRIVATE_KEY: {e}"))?;

                    info!("SP1 backend: prover network (rpc={})", rpc_url);
                    let client = NetworkProver::new(signer, &rpc_url, NetworkMode::default());
                    ProverBackend::Network(Arc::new(client))
                }
                _ => {
                    info!("SP1 backend: local CPU");
                    ProverBackend::Local(Arc::new(CpuProver::new()))
                }
            };

            // setup() only reads the ELF — identical for both backends.
            let (pk, vk) = match &backend {
                ProverBackend::Local(c) => c.setup(&elf),
                ProverBackend::Network(c) => c.setup(&elf),
            };

            info!(vk_hash = %hex::encode(vk.hash_bytes()), "SP1 prover initialised");
            Some(Sp1State { backend, pk: Arc::new(pk), vk: Arc::new(vk) })
        }
    };

    // -----------------------------------------------------------------------
    // HTTP server
    // -----------------------------------------------------------------------

    let state = AppState {
        api_key,
        nitro_config,
        block_execution_strategy_factory,
        genesis,
        chain_spec,
        sp1,
    };

    let app = Router::new()
        .route("/block", post(block))
        .route("/block/sp1-proof", post(block_sp1_proof))
        .route_layer(middleware::from_fn_with_state(state.clone(), require_api_key))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(&listen_addr).await?;
    info!("Listening on {listen_addr}");
    axum::serve(listener, app).await?;

    Ok(())
}
