//! Witness orchestrator sidecar binary.
//!
//! Runs an embedded forward-sync driver that re-executes Fluent L2 blocks,
//! produces witnesses in-process, and feeds them into the orchestrator loop
//! which dispatches to the Nitro proxy over HTTP and orchestrates L1 batch
//! signing and preconfirmation.
//!
//! ## Data flow
//!
//! ```text
//! L2 RPC ──▶ forward driver ──mpsc──▶ orchestrator ──HTTP POST──▶ proxy ──▶ Nitro
//!                   │
//!                   └──▶ redb cold witness store (for key-rotation replay)
//! ```
//!
//! # Configuration (environment variables)
//!
//! | Variable | Default | Description |
//! |----------|---------|-------------|
//! | `RPC_URL` | — | L2 RPC URL — drives forward sync and blob construction |
//! | `DATADIR` | `./forward-driver` | Driver datadir (MDBX + static_files + RocksDB) |
//! | `WITNESS_COLD_FILE` | `<datadir>/cold.redb` | redb file for cold witness store |
//! | `MAX_COLD_BYTES` | `34359738368` (32 GiB) | Size cap for cold witness store |
//! | `MDBX_MAX_SIZE` | `549755813888` (512 GiB) | MDBX max size |
//! | `PROXY_URL` | `http://127.0.0.1:8080` | Remote proxy base URL |
//! | `DB_PATH` | `./witness_orchestrator.db` | SQLite DB for crash recovery |
//! | `HTTP_TIMEOUT_SECS` | `120` | HTTP POST timeout (seconds) |
//! | `L1_RPC_URL` | — | L1 Ethereum RPC URL |
//! | `L1_ROLLUP_ADDR` | — | Rollup contract address on L1 |
//! | `L1_SUBMITTER_KEY` | — | Private key for signing `preconfirmBatch` txs |
//! | — | — | `NITRO_VERIFIER_ADDR` removed: now compile-time constant from `fluent_stf_primitives` |
//! | `L1_START_BATCH_ID` | — | If set (and no checkpoint in DB), scan L1 to derive L2 start checkpoint |
//! | `L1_ROLLUP_DEPLOY_BLOCK` | `0` | L1 block where Rollup contract was deployed (lower bound for event scans) |
//! | `API_KEY` | — | API key forwarded to the proxy |
//! | `PRUNE_FULL` | `false` | If `true`, prune MDBX/static-files using the same defaults as `reth --full` (sender_recovery=Full, receipts/account_history/storage_history distance=10064 blocks, bodies_history=Before(Paris)) |

mod accumulator;
mod db;
mod driver;
mod hub;
mod l1_listener;
mod orchestrator;
mod types;

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use crate::hub::WitnessHub;
use crate::types::ProveRequest;
use alloy_network::{Ethereum, EthereumWallet};
use alloy_primitives::Address;
use alloy_provider::{ProviderBuilder, RootProvider};
use alloy_signer_local::PrivateKeySigner;
use fluent_stf_primitives::fluent_chainspec;
use reth_chainspec::{ChainSpec, EthereumHardfork, EthereumHardforks};
use reth_config::PruneConfig;
use reth_prune::PrunerBuilder;
use reth_prune_types::{PruneMode, PruneModes, MINIMUM_UNWIND_SAFE_DISTANCE};
use reth_tasks::Runtime;
use rsp_host_executor::EthHostExecutor;
use tokio::runtime::Handle;
use tokio_util::sync::CancellationToken;
use tracing::info;

use driver::DriverConfig;
use orchestrator::OrchestratorConfig;

const DEFAULT_PROXY_URL: &str = "http://127.0.0.1:8080";
const DEFAULT_DB_PATH: &str = "./witness_orchestrator.db";
const DEFAULT_HTTP_TIMEOUT_SECS: u64 = 120;
const DEFAULT_DATADIR: &str = "./forward-driver";
/// 32 GiB default cap for cold witness storage.
const DEFAULT_MAX_COLD_BYTES: u64 = 32 * 1024 * 1024 * 1024;
/// 512 GiB default MDBX geometry max size.
const DEFAULT_MDBX_MAX_SIZE: u64 = 512 * 1024 * 1024 * 1024;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let rpc_url = std::env::var("RPC_URL").expect("RPC_URL is required");
    let datadir =
        PathBuf::from(std::env::var("DATADIR").unwrap_or_else(|_| DEFAULT_DATADIR.into()));
    let cold_file = std::env::var("WITNESS_COLD_FILE")
        .map(PathBuf::from)
        .unwrap_or_else(|_| datadir.join("cold.redb"));
    let max_cold_bytes: u64 = std::env::var("MAX_COLD_BYTES")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(DEFAULT_MAX_COLD_BYTES);
    let mdbx_max_size: u64 = std::env::var("MDBX_MAX_SIZE")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(DEFAULT_MDBX_MAX_SIZE);

    let proxy_url = std::env::var("PROXY_URL").unwrap_or_else(|_| DEFAULT_PROXY_URL.into());
    let db_path =
        PathBuf::from(std::env::var("DB_PATH").unwrap_or_else(|_| DEFAULT_DB_PATH.into()));
    let http_timeout_secs: u64 = std::env::var("HTTP_TIMEOUT_SECS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(DEFAULT_HTTP_TIMEOUT_SECS);

    // L1 configuration
    let l1_rpc_url = std::env::var("L1_RPC_URL").expect("L1_RPC_URL is required");
    let l1_rollup_addr: Address = std::env::var("L1_ROLLUP_ADDR")
        .expect("L1_ROLLUP_ADDR is required")
        .parse()
        .expect("Invalid L1_ROLLUP_ADDR");
    let l1_submitter_key = std::env::var("L1_SUBMITTER_KEY").expect("L1_SUBMITTER_KEY is required");
    let nitro_verifier_addr: Address = fluent_stf_primitives::NITRO_VERIFIER_ADDR;
    let start_batch_id: Option<u64> =
        std::env::var("L1_START_BATCH_ID").ok().and_then(|s| s.parse().ok());
    let l1_deploy_block: u64 =
        std::env::var("L1_ROLLUP_DEPLOY_BLOCK").ok().and_then(|s| s.parse().ok()).unwrap_or(0);
    let api_key = std::env::var("API_KEY").expect("API_KEY is required");

    let http_client = reqwest::Client::builder()
        .timeout(Duration::from_secs(http_timeout_secs))
        .pool_max_idle_per_host(2)
        .build()
        .expect("failed to build HTTP client");

    // Build L1 provider for reading (events) — with retry layer for 429/5xx
    let l1_rpc_url_parsed: url::Url = l1_rpc_url.parse().expect("Invalid L1_RPC_URL");
    let l1_read_provider: RootProvider = rsp_provider::create_provider(l1_rpc_url_parsed.clone());

    // L2 provider — used by the startup resolver (for `lastBlockHash` lookup)
    // AND later by the embedded driver + blob builder.
    let l2_rpc_parsed: url::Url = rpc_url.parse().expect("Invalid RPC_URL");
    let l2_provider: RootProvider = rsp_provider::create_provider(l2_rpc_parsed);

    // ── Startup: resolve L2 checkpoint from START_BATCH_ID ───────────────────────
    let (listener_from_block, witness_from_block, orchestrator_checkpoint): (u64, u64, u64) = {
        let db_startup = crate::db::Db::open(&db_path).expect("Failed to open DB for startup");

        if let Some(batch_id) = start_batch_id {
            if db_startup.get_checkpoint() == 0 {
                info!(batch_id, "L1_START_BATCH_ID set — resolving L2 start checkpoint from L1");
                let (l2_from_block, l1_event_block, _num_blocks) =
                    l1_rollup_client::resolve_l2_start_checkpoint(
                        &l1_read_provider,
                        &l2_provider,
                        l1_rollup_addr,
                        batch_id,
                        l1_deploy_block,
                    )
                    .await
                    .expect("Fatal: failed to resolve L2 start checkpoint from L1");

                let l2_checkpoint = l2_from_block.saturating_sub(1);
                db_startup.save_checkpoint(l2_checkpoint);
                db_startup.save_l1_checkpoint(l1_event_block.saturating_sub(1));

                if db_startup.get_last_batch_end().is_none() {
                    db_startup.save_last_batch_end(l2_checkpoint);
                }

                info!(
                    batch_id,
                    l2_from_block,
                    l2_checkpoint,
                    l1_event_block,
                    "L2 start checkpoint resolved and saved to DB"
                );
            } else {
                info!(
                    batch_id,
                    checkpoint = db_startup.get_checkpoint(),
                    "L2 checkpoint already in DB — skipping startup scan"
                );
            }
        }

        let checkpoint = db_startup.get_checkpoint();
        let witness_from = if checkpoint > 0 { checkpoint + 1 } else { 0 };

        let lfb = if let Some(ckpt) = db_startup.get_l1_checkpoint() {
            (ckpt + 1).max(l1_deploy_block)
        } else {
            l1_deploy_block
        };

        drop(db_startup);
        (lfb, witness_from, checkpoint)
    };

    info!(
        %rpc_url,
        ?datadir,
        ?cold_file,
        max_cold_bytes,
        %proxy_url,
        ?db_path,
        http_timeout_secs,
        %l1_rollup_addr,
        %nitro_verifier_addr,
        listener_from_block,
        start_batch_id,
        l1_deploy_block,
        witness_from_block,
        "Starting witness orchestrator"
    );

    // Build L1 provider for writing (preconfirmBatch)
    let signer: PrivateKeySigner = l1_submitter_key.parse().expect("Invalid L1_SUBMITTER_KEY");
    let wallet = EthereumWallet::from(signer);
    let l1_write_provider: orchestrator::L1WriteProvider =
        ProviderBuilder::new().wallet(wallet).connect_http(l1_rpc_url_parsed);

    // Root shutdown token — cancelled on SIGTERM/SIGINT or on any
    // background task exit. Propagated into every spawned task so in-flight
    // work can drain cleanly instead of being abruptly dropped by runtime
    // teardown.
    let shutdown = CancellationToken::new();
    let mut tasks: tokio::task::JoinSet<(&'static str, eyre::Result<()>)> =
        tokio::task::JoinSet::new();

    // Signal handler
    {
        let shutdown = shutdown.clone();
        tasks.spawn(async move {
            let r = async {
                let mut sigterm =
                    tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                        .map_err(|e| eyre::eyre!("install SIGTERM: {e}"))?;
                tokio::select! {
                    _ = sigterm.recv() => info!("SIGTERM received — graceful shutdown"),
                    _ = tokio::signal::ctrl_c() => info!("SIGINT received — graceful shutdown"),
                }
                shutdown.cancel();
                Ok::<(), eyre::Report>(())
            }
            .await;
            ("signal", r)
        });
    }

    // Start L1 event listener
    let (l1_tx, l1_rx) = tokio::sync::mpsc::channel(64);
    {
        let shutdown = shutdown.clone();
        tasks.spawn(async move {
            let r = l1_listener::run(
                l1_read_provider,
                l1_rollup_addr,
                listener_from_block,
                l1_tx,
                shutdown,
            )
            .await;
            ("l1_listener", r)
        });
    }

    // Cold witness store + in-process witness channel.
    let hub = Arc::new(WitnessHub::new(cold_file, max_cold_bytes));
    let (prove_tx, prove_rx) = tokio::sync::mpsc::channel::<ProveRequest>(64);

    // ── Embedded forward-sync driver ─────────────────────────────────────────────
    let chain_spec: Arc<ChainSpec> = Arc::new(fluent_chainspec());
    let driver_rpc: RootProvider<Ethereum> = l2_provider.clone();
    let runtime = Runtime::with_existing_handle(Handle::current())
        .expect("failed to build reth_tasks::Runtime from current handle");
    let factory = driver::open_writable_factory::<driver::FluentMdbxNode>(
        &datadir,
        chain_spec.clone(),
        mdbx_max_size,
        runtime,
    )
    .expect("failed to open writable ProviderFactory");
    let host_executor = Arc::new(EthHostExecutor::eth(chain_spec.clone(), None));

    // Optional pruner: mirror `reth --full` semantics exactly.
    let prune_full: bool = std::env::var("PRUNE_FULL")
        .ok()
        .map(|s| matches!(s.to_ascii_lowercase().as_str(), "1" | "true" | "yes" | "on"))
        .unwrap_or(false);
    let pruner = if prune_full {
        let segments = PruneModes {
            sender_recovery: Some(PruneMode::Full),
            transaction_lookup: None,
            receipts: Some(PruneMode::Distance(MINIMUM_UNWIND_SAFE_DISTANCE)),
            account_history: Some(PruneMode::Distance(MINIMUM_UNWIND_SAFE_DISTANCE)),
            storage_history: Some(PruneMode::Distance(MINIMUM_UNWIND_SAFE_DISTANCE)),
            bodies_history: chain_spec
                .ethereum_fork_activation(EthereumHardfork::Paris)
                .block_number()
                .map(PruneMode::Before),
            receipts_log_filter: Default::default(),
        };
        let prune_config =
            PruneConfig { block_interval: PruneConfig::default().block_interval, segments };
        info!(?prune_config, "Pruning enabled (reth --full equivalent)");
        Some(PrunerBuilder::new(prune_config).build_with_provider_factory(factory.clone()))
    } else {
        info!("Pruning disabled — archive mode");
        None
    };

    {
        let hub = Arc::clone(&hub);
        let shutdown = shutdown.clone();
        tasks.spawn(async move {
            let r = driver::run(
                DriverConfig {
                    factory,
                    rpc: driver_rpc,
                    host_executor,
                    hub,
                    prove_tx,
                    chain_spec,
                    pruner,
                    witness_from_block,
                    orchestrator_checkpoint,
                },
                shutdown,
            )
            .await;
            ("driver", r)
        });
    }

    let config = OrchestratorConfig {
        proxy_url,
        db_path,
        http_client,
        l1_rollup_addr,
        nitro_verifier_addr,
        l1_provider: l1_write_provider,
        api_key,
        l2_provider,
    };

    // Orchestrator runs in the foreground. Race it against `tasks.join_next()`
    // so that ANY background task exiting first (driver failure, listener
    // error, signal handler) immediately cancels the root token. Without
    // this race, a driver failure closes prove_tx — the orchestrator's
    // `Some(req) = prove_rx.recv()` arm would simply disable, and the loop
    // would keep running forever on l1_events / sign_done / ticker.
    let mut exit_code = 0;
    let mut orchestrator_fut =
        std::pin::pin!(orchestrator::run(config, hub, prove_rx, l1_rx, shutdown.clone()));

    tokio::select! {
        () = orchestrator_fut.as_mut() => {
            shutdown.cancel();
        }
        Some(join) = tasks.join_next() => {
            match join {
                Ok((name, Ok(()))) => info!(task = name, "background task exited cleanly"),
                Ok((name, Err(e))) => {
                    tracing::error!(task = name, err = %e, "background task exited with error");
                    exit_code = 1;
                }
                Err(e) => {
                    tracing::error!(err = %e, "background task join failed");
                    exit_code = 1;
                }
            }
            shutdown.cancel();
            orchestrator_fut.await;
        }
    }

    // Drain any remaining background tasks.
    while let Some(join) = tasks.join_next().await {
        match join {
            Ok((name, Ok(()))) => info!(task = name, "background task exited cleanly"),
            Ok((name, Err(e))) => {
                tracing::error!(task = name, err = %e, "background task exited with error");
                exit_code = 1;
            }
            Err(e) => {
                tracing::error!(err = %e, "background task join failed");
                exit_code = 1;
            }
        }
    }

    if exit_code != 0 {
        std::process::exit(exit_code);
    }
}
