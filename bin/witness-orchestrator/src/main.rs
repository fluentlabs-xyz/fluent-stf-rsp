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
//! L2 RPC ──▶ Driver (struct) ◀──pull── feeder ──▶ normal_tx ──▶ workers ──HTTP──▶ proxy
//!                   │                                                         │
//!                   └──▶ redb cold witness store             result_rx ◀──────┘
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
//! | `WITNESS_RETENTION_BLOCKS` | `172800` | Cold store retention window in L2 blocks — blocks older than `tip - retention` are pruned on push. `0` disables retention (archive mode). |
//! | `WITNESS_HUB_LISTEN_ADDR` | `127.0.0.1:8090` | HTTP listen address of the witness-server that serves cold witnesses to external consumers (proxy). |
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
//! | `FLUENT_METRICS_ADDR` | `0.0.0.0:9090` | HTTP listen address for the Prometheus `/metrics` endpoint. |
//!
//! # Metrics
//!
//! Mirrors the Go sequencer metric shape (see
//! `rollup-bridge-services/internal/services/sequencer/metrics.go`).
//! Scraped from `FLUENT_METRICS_ADDR` on `/metrics`.
//!
//! | Metric | Type | Description |
//! |--------|------|-------------|
//! | `orchestrator_last_block_witness_built` | gauge | Latest L2 block with a witness available (fresh or cold-store reuse). |
//! | `orchestrator_last_block_executed` | gauge | Latest L2 block executed by the proxy/enclave. |
//! | `orchestrator_last_block_signed` | gauge | Latest L2 block with a signed `/sign-block-execution` response. |
//! | `orchestrator_last_batch_signed` | gauge | Index of the most recently signed L1 batch. |
//! | `orchestrator_last_batch_signed_from_block` | gauge | `from_block` of the most recently signed batch. |
//! | `orchestrator_last_batch_signed_to_block` | gauge | `to_block` of the most recently signed batch. |
//! | `orchestrator_last_batch_dispatched` | gauge | Index of the most recently L1-included `preconfirmBatch` (status=1). |
//! | `orchestrator_last_batch_dispatched_from_block` | gauge | `from_block` of the most recently L1-included batch. |
//! | `orchestrator_last_batch_dispatched_to_block` | gauge | `to_block` of the most recently L1-included batch. |
//! | `orchestrator_sign_block_execution_duration_seconds` | histogram | Per-attempt duration of `/sign-block-execution`. |
//! | `orchestrator_sign_batch_root_duration_seconds` | histogram | Per-attempt duration of `/sign-batch-root`. |
//! | `orchestrator_sign_failures_total{stage,kind}` | counter | Sign-endpoint failures. `stage=block\|batch`, `kind=enclave_busy\|other`. |
//! | `orchestrator_l1_dispatch_rejected_total` | counter | `preconfirmBatch` txs mined with status=0 (on-chain revert). |
//! | `orchestrator_l1_dispatch_cost_eth_total` | counter | Cumulative ETH spent on L1 `preconfirmBatch` gas. |
//! | `orchestrator_l1_dispatch_cost_eth` | histogram | Per-tx ETH cost (`gas_used × effective_gas_price / 1e18`). |

mod accumulator;
mod db;
mod driver;
mod hub;
mod l1_listener;
mod metrics;
mod orchestrator;
mod types;
mod witness_server;

use std::{
    collections::HashSet,
    path::PathBuf,
    sync::{Arc, RwLock},
    time::Duration,
};

use crate::hub::{WitnessHub, DEFAULT_COLD_BATCH_SIZE};
use alloy_network::{Ethereum, EthereumWallet};
use alloy_primitives::Address;
use alloy_provider::{ProviderBuilder, RootProvider};
use alloy_signer_local::PrivateKeySigner;
use fluent_stf_primitives::fluent_chainspec;
use reth_chainspec::ChainSpec;
use reth_tasks::Runtime;
use rsp_host_executor::EthHostExecutor;
use tokio::runtime::Handle;
use tokio_util::sync::CancellationToken;
use tracing::info;

use driver::{Driver, DriverConfig};
use orchestrator::OrchestratorConfig;

const DEFAULT_PROXY_URL: &str = "http://127.0.0.1:8080";
const DEFAULT_DB_PATH: &str = "./witness_orchestrator.db";
const DEFAULT_HTTP_TIMEOUT_SECS: u64 = 120;
const DEFAULT_DATADIR: &str = "./forward-driver";
/// 32 GiB default cap for cold witness storage.
const DEFAULT_MAX_COLD_BYTES: u64 = 32 * 1024 * 1024 * 1024;
/// 512 GiB default MDBX geometry max size.
const DEFAULT_MDBX_MAX_SIZE: u64 = 512 * 1024 * 1024 * 1024;
/// Default cold-store retention window: 172 800 L2 blocks (~2 days at 1 s/block).
const DEFAULT_WITNESS_RETENTION_BLOCKS: u64 = 172_800;
/// Default listen address for the witness HTTP server.
const DEFAULT_WITNESS_HUB_LISTEN_ADDR: &str = "127.0.0.1:8090";
/// Default listen address for the Prometheus `/metrics` HTTP server.
const DEFAULT_METRICS_LISTEN_ADDR: &str = "0.0.0.0:9090";

#[tokio::main]
async fn main() -> eyre::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    // Install Prometheus recorder before any spawn so early metric writes are
    // not lost to the noop recorder.
    let metrics_handle = Arc::new(metrics::install()?);
    let metrics_listen_addr =
        std::env::var("FLUENT_METRICS_ADDR").unwrap_or_else(|_| DEFAULT_METRICS_LISTEN_ADDR.into());

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
    let witness_retention_blocks: u64 = std::env::var("WITNESS_RETENTION_BLOCKS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(DEFAULT_WITNESS_RETENTION_BLOCKS);
    let witness_hub_listen_addr = std::env::var("WITNESS_HUB_LISTEN_ADDR")
        .unwrap_or_else(|_| DEFAULT_WITNESS_HUB_LISTEN_ADDR.into());
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
    let env_start_batch_id: Option<u64> =
        std::env::var("L1_START_BATCH_ID").ok().and_then(|s| s.parse().ok());
    let l1_deploy_block: u64 =
        std::env::var("L1_ROLLUP_DEPLOY_BLOCK").ok().and_then(|s| s.parse().ok()).unwrap_or(0);
    let api_key = std::env::var("API_KEY").expect("API_KEY is required");

    // RBF dispatch tuning: 15s cycle, +20% bump (safely above EIP-1559's
    // +12.5% minimum), 500 gwei cap.
    let rbf_bump_interval = Duration::from_secs(
        std::env::var("RBF_BUMP_INTERVAL_SECS").ok().and_then(|s| s.parse().ok()).unwrap_or(15),
    );
    let rbf_bump_percent: u32 =
        std::env::var("RBF_BUMP_PERCENT").ok().and_then(|s| s.parse().ok()).unwrap_or(20);
    let rbf_max_fee_per_gas_wei: u128 = std::env::var("RBF_MAX_FEE_PER_GAS_WEI")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(500_000_000_000u128);

    let l1_poll_interval_secs: u64 =
        std::env::var("L1_POLL_INTERVAL_SECS").ok().and_then(|s| s.parse().ok()).unwrap_or(60);
    let l1_safe_blocks: u64 =
        std::env::var("L1_SAFE_BLOCKS").ok().and_then(|s| s.parse().ok()).unwrap_or(7);

    let http_client = reqwest::Client::builder()
        .timeout(Duration::from_secs(http_timeout_secs))
        .pool_max_idle_per_host(2)
        .build()
        .expect("failed to build HTTP client");

    // Build L1 provider for reading (events) — with retry layer for 429/5xx
    let l1_rpc_url_parsed: url::Url = l1_rpc_url.parse().expect("Invalid L1_RPC_URL");
    let l1_read_provider: RootProvider = rsp_provider::create_provider(l1_rpc_url_parsed.clone())
        .expect("failed to build L1 read provider");

    // L2 provider — used by the startup resolver (for `lastBlockHash` lookup)
    // AND later by the embedded driver + blob builder.
    let l2_rpc_parsed: url::Url = rpc_url.parse().expect("Invalid RPC_URL");
    let l2_provider =
        rsp_provider::create_provider(l2_rpc_parsed).expect("failed to build L2 provider");

    // ── Startup: resolve L2 checkpoint from START_BATCH_ID ───────────────────────
    let (listener_from_block, witness_from_block, orchestrator_checkpoint): (u64, u64, u64) = {
        let db_startup = crate::db::Db::open(&db_path).expect("Failed to open DB for startup");

        // DB-persisted start batch id takes precedence over the env var.
        // It is written by the BatchReverted handler after wiping all state,
        // so a restart re-resolves the L2 checkpoint from the reverted batch
        // instead of the stale env value that bootstrapped the deployment.
        let db_start_batch_id = db_startup.get_start_batch_id();
        let start_batch_id: Option<u64> = db_start_batch_id.or(env_start_batch_id);

        if let Some(batch_id) = start_batch_id {
            if db_startup.get_checkpoint() == 0 {
                info!(
                    batch_id,
                    from_db = db_start_batch_id.is_some(),
                    "Resolving L2 start checkpoint from L1"
                );
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
                // For env-var bootstrap we rewind l1_checkpoint one block
                // behind the committing event so the listener re-observes it.
                // For BatchReverted recovery the DB already holds the event
                // block — keep whichever is later.
                if db_start_batch_id.is_none() {
                    db_startup.save_l1_checkpoint(l1_event_block.saturating_sub(1));
                }

                if db_startup.get_last_batch_end().is_none() {
                    db_startup.save_last_batch_end(l2_checkpoint);
                }

                // Clear the one-shot revert anchor so a manual env-var
                // restart later is not shadowed by a stale DB entry.
                if db_start_batch_id.is_some() {
                    db_startup.clear_start_batch_id();
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

        // ── Startup checkpoint normalisation ───────────────────────────────────
        {
            let pending = db_startup.load_batches();
            let dispatched_ranges = db_startup.load_dispatched_block_ranges();
            let response_blocks: HashSet<u64> =
                db_startup.get_all_response_block_numbers().into_iter().collect();
            let signed_batch_indexes: HashSet<u64> =
                db_startup.load_batch_signature_indexes().into_iter().collect();
            let current_ckpt = db_startup.get_checkpoint();

            let result = normalize_startup_checkpoint(
                current_ckpt,
                &pending,
                &dispatched_ranges,
                &response_blocks,
                &signed_batch_indexes,
            );

            if let Some(gap) = result.earliest_gap {
                if !result.stale_signature_indexes.is_empty() {
                    info!(
                        current_ckpt,
                        earliest_gap = gap,
                        new_ckpt = result.new_ckpt,
                        gapped_batches = ?result.stale_signature_indexes,
                        "Startup gap recovery: rolling back checkpoint"
                    );
                    for idx in &result.stale_signature_indexes {
                        db_startup.delete_batch_signature(*idx);
                    }
                } else {
                    info!(
                        current_ckpt,
                        earliest_gap = gap,
                        "Startup gap detected but checkpoint already at or below rollback target"
                    );
                }
            } else {
                info!("Startup gap scan: no gaps detected");
            }

            if result.new_ckpt != current_ckpt {
                info!(current_ckpt, new_ckpt = result.new_ckpt, "Startup checkpoint normalised");
                db_startup.save_checkpoint(result.new_ckpt);
            } else {
                info!(current_ckpt, "Startup checkpoint unchanged");
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
        witness_retention_blocks,
        %witness_hub_listen_addr,
        %proxy_url,
        ?db_path,
        http_timeout_secs,
        %l1_rollup_addr,
        %nitro_verifier_addr,
        listener_from_block,
        env_start_batch_id,
        l1_deploy_block,
        witness_from_block,
        "Starting witness orchestrator"
    );

    // Build L1 provider for writing (preconfirmBatch). Keep the signer as a
    // separate Arc'd handle so the RBF worker can sign bumped txs with an
    // explicit nonce + fees, bypassing alloy's NonceFiller / GasFiller.
    let signer: PrivateKeySigner = l1_submitter_key.parse().expect("Invalid L1_SUBMITTER_KEY");
    let l1_signer_address = signer.address();
    let l1_signer: Arc<dyn alloy_network::TxSigner<alloy_primitives::Signature> + Send + Sync> =
        Arc::new(signer.clone());
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

    // Metrics HTTP server — exposes `/metrics` on `FLUENT_METRICS_ADDR`.
    {
        let shutdown = shutdown.clone();
        let addr = metrics_listen_addr.clone();
        let handle = Arc::clone(&metrics_handle);
        tasks.spawn(async move {
            let r = metrics::run_server(addr, handle, shutdown).await;
            ("metrics_server", r)
        });
    }

    let l1_listened_l2_provider = l2_provider.clone();

    // Start L1 event listener
    let (l1_tx, l1_rx) = tokio::sync::mpsc::channel(64);
    {
        let shutdown = shutdown.clone();
        tasks.spawn(async move {
            let r = l1_listener::run(
                l1_read_provider,
                l1_listened_l2_provider,
                l1_rollup_addr,
                listener_from_block,
                l1_poll_interval_secs,
                l1_safe_blocks,
                l1_tx,
                shutdown,
            )
            .await;
            ("l1_listener", r)
        });
    }

    // Cold witness store. Owned by `Driver`; external consumers reach it
    // indirectly through `Driver::get_or_build_witness`, which also provides
    // the MDBX rebuild fallback on cold miss. Tip-following writes are
    // buffered in batches of `DEFAULT_COLD_BATCH_SIZE` to amortize redb fsync.
    let hub = Arc::new(WitnessHub::new(
        cold_file,
        max_cold_bytes,
        witness_retention_blocks,
        DEFAULT_COLD_BATCH_SIZE,
    )?);

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

    // TODO: re-enable pruner after adding runtime coupling between MDBX
    // prune floor and WITNESS_RETENTION_BLOCKS. The risk scenario: driver
    // runs far ahead while L1 is stalled (low ETH on submitter, rollup
    // contract frozen, etc.); pruner drops state for blocks that still
    // need re-witnessing on key rotation; re-exec fails with silent None
    // from `get_or_build_witness` and retries forever. Re-enabling needs:
    // (a) a runtime guard that stops the pruner when dispatch is lagging,
    // (b) an explicit StateAtBlockNotAvailable error instead of Ok(None)
    // from the driver's witness rebuild path. Until then — archive mode.
    let _ = std::env::var("PRUNE_FULL"); // swallow env so misconfig doesn't silently fail
    info!("Pruning disabled — archive mode");
    let pruner: Option<driver::DriverPruner> = None;

    let hub_for_shutdown = Arc::clone(&hub);
    let driver = Arc::new(
        Driver::new(DriverConfig {
            factory,
            rpc: driver_rpc,
            host_executor,
            hub,
            chain_spec,
            pruner,
            witness_from_block,
            orchestrator_checkpoint,
        })
        .expect("Driver::new failed"),
    );

    // Witness HTTP server — serves witnesses to the proxy (challenge/mock
    // endpoints). Cold-store hit is verbatim; cold miss falls through to an
    // MDBX-backed rebuild inside `Driver::get_or_build_witness`. Opens its
    // own read path into the cold `redb` file via the Arc it shares with the
    // driver — no cross-process lock conflict.
    {
        let driver = Arc::clone(&driver);
        let shutdown = shutdown.clone();
        let addr = witness_hub_listen_addr.clone();
        tasks.spawn(async move {
            let r = witness_server::run(addr, driver, shutdown).await;
            ("witness_server", r)
        });
    }

    // Catch-up runs as its own task so the orchestrator (L1 listener, signing,
    // dispatch) stays responsive while MDBX fast-forwards to witness_from_block.
    //
    // NOT added to `tasks` on purpose: this is a one-shot catch-up — successful
    // completion is expected (and happens instantly when MDBX is already past
    // `witness_from_block`). The JoinSet race below cancels the root token on
    // ANY task exit, so routing this through `tasks` would tear the whole
    // process down as soon as catch-up finished. On failure, we cancel the
    // root token here ourselves.
    let catchup_handle = {
        let driver = Arc::clone(&driver);
        let shutdown = shutdown.clone();
        tokio::spawn(async move {
            match driver.advance_to_witness_from_block(&shutdown).await {
                Ok(()) => info!("driver_catchup: completed"),
                Err(e) => {
                    tracing::error!(err = %e, "driver_catchup: fatal — cancelling shutdown");
                    shutdown.cancel();
                }
            }
        })
    };

    let config = OrchestratorConfig {
        proxy_url,
        db_path,
        http_client,
        l1_rollup_addr,
        nitro_verifier_addr,
        l1_provider: l1_write_provider,
        api_key,
        l2_provider,
        l1_signer,
        l1_signer_address,
        rbf_bump_interval,
        rbf_bump_percent,
        rbf_max_fee_per_gas_wei,
    };

    // Shared channel + dedup set between the feeder (driver pull) and the
    // orchestrator (worker pool consumer). Owned at the top level so the
    // feeder can be supervised via `tasks`.
    let (normal_tx, normal_rx) =
        async_channel::bounded::<orchestrator::ExecutionTask>(orchestrator::EXECUTION_WORKERS * 2);
    let known_responses: orchestrator::KnownResponses = Arc::new(RwLock::new(HashSet::new()));

    // Spawn the feeder into the top-level JoinSet so a feeder crash (driver
    // fatal, panic) cancels the root token via the `tasks.join_next()` race
    // below and shuts down the whole process cleanly.
    {
        let driver = Arc::clone(&driver);
        let normal_tx = normal_tx.clone();
        let known_responses = Arc::clone(&known_responses);
        let shutdown = shutdown.clone();
        tasks.spawn(async move {
            let r = orchestrator::feeder_loop(driver, normal_tx, known_responses, shutdown).await;
            ("feeder", r)
        });
    }

    // Orchestrator runs in the foreground. Race it against `tasks.join_next()`
    // so that ANY background task exiting first (signal handler, L1 listener,
    // witness server, feeder) immediately cancels the root token. Catch-up is
    // tracked separately via `catchup_handle` because its successful completion
    // is expected and must not trigger shutdown.
    let mut exit_code = 0;
    let mut orchestrator_fut = std::pin::pin!(orchestrator::run(
        config,
        driver,
        l1_rx,
        shutdown.clone(),
        normal_rx,
        Arc::clone(&known_responses),
    ));
    drop(normal_tx);

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

    // Wait for catch-up to observe shutdown and exit. Aborts only if it's still
    // running — on normal exit it has already completed long ago.
    if let Err(e) = catchup_handle.await {
        if !e.is_cancelled() {
            tracing::error!(err = %e, "driver_catchup join failed");
            exit_code = 1;
        }
    }

    // Flush any buffered cold-witness entries before exit. On a clean shutdown
    // this makes `cold_last == mdbx_tip` so the next start needs no re-witness
    // gap-fill. A failure here is logged but does not change the exit code —
    // the re-witness fallback still handles any unflushed blocks on restart.
    if let Err(e) = hub_for_shutdown.flush_pending().await {
        tracing::error!(err = %e, "cold witness flush_pending failed at shutdown");
    }

    if exit_code != 0 {
        std::process::exit(exit_code);
    }
    Ok(())
}

/// Pure result of the startup checkpoint walk.
///
/// Two invariants the caller must preserve after applying it:
///   1. Checkpoint is never above a block with a missing response/dispatch (so the driver does not
///      skip re-execution).
///   2. Checkpoint is walked forward across every contiguous present block (so the driver does not
///      re-walk already-computed blocks).
///
/// "Present" = response stored OR dispatched batch covers the block OR the
/// block belongs to a pending batch whose signature is already cached
/// (signing early-purges responses, so a signed-but-not-dispatched batch has
/// no response rows yet its work is complete). A single forward walk that
/// stops at the first gap preserves both invariants, which rules out the
/// gap-vs-`last_batch_end` race between those two conditions.
pub(crate) struct StartupCheckpointResult {
    pub(crate) new_ckpt: u64,
    pub(crate) stale_signature_indexes: Vec<u64>,
    pub(crate) earliest_gap: Option<u64>,
}

pub(crate) fn normalize_startup_checkpoint(
    current_ckpt: u64,
    pending: &[accumulator::PendingBatch],
    dispatched_ranges: &[(u64, u64)],
    response_blocks: &HashSet<u64>,
    signed_batch_indexes: &HashSet<u64>,
) -> StartupCheckpointResult {
    let mut present_set: HashSet<u64> =
        dispatched_ranges.iter().flat_map(|&(f, t)| f..=t).collect();
    // Signed pending batches have their responses early-purged right after
    // signing (see `on_sign_done`), so treat their full block range as
    // present — the work is complete even though no response rows remain.
    for batch in pending {
        if signed_batch_indexes.contains(&batch.batch_index) {
            present_set.extend(batch.from_block..=batch.to_block);
        }
    }
    let present = |b: u64| response_blocks.contains(&b) || present_set.contains(&b);

    let mut earliest_gap: Option<u64> = None;
    let mut gapped_batches: Vec<u64> = Vec::new();
    for batch in pending {
        // Signed batches are complete by construction — skip the gap scan so
        // their signatures are never marked stale.
        if signed_batch_indexes.contains(&batch.batch_index) {
            continue;
        }
        let mut batch_has_gap = false;
        for b in batch.from_block..=batch.to_block {
            if present(b) {
                continue;
            }
            batch_has_gap = true;
            earliest_gap = Some(match earliest_gap {
                Some(cur) => cur.min(b),
                None => b,
            });
        }
        if batch_has_gap {
            gapped_batches.push(batch.batch_index);
        }
    }

    let mut new_ckpt = current_ckpt;
    let mut stale_signature_indexes = Vec::new();
    if let Some(gap) = earliest_gap {
        let rollback = gap.saturating_sub(1);
        if rollback < new_ckpt {
            new_ckpt = rollback;
            stale_signature_indexes = gapped_batches;
        }
    }
    while present(new_ckpt + 1) {
        new_ckpt += 1;
    }

    StartupCheckpointResult { new_ckpt, stale_signature_indexes, earliest_gap }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::accumulator::PendingBatch;

    fn batch(batch_index: u64, from: u64, to: u64) -> PendingBatch {
        PendingBatch { batch_index, from_block: from, to_block: to, blobs_accepted: true }
    }

    #[test]
    fn gap_below_lbe_rolls_back_not_forward() {
        // Pathological ordering: gap at block 50 inside a pending batch,
        // but checkpoint is already at 100 (as if a prior run advanced past
        // blocks for which responses were later lost).
        // The fix must pull the checkpoint DOWN to 49, not leave it at 100.
        let pending = [batch(5, 40, 60)];
        let dispatched: Vec<(u64, u64)> = vec![];
        let mut response_blocks = HashSet::new();
        for b in 40..=49 {
            response_blocks.insert(b);
        }
        // blocks 50..=60 missing — pretend the response store lost them.
        let signed = HashSet::new();

        let r = normalize_startup_checkpoint(100, &pending, &dispatched, &response_blocks, &signed);

        assert_eq!(r.earliest_gap, Some(50));
        assert_eq!(r.new_ckpt, 49, "must roll back to gap-1, not stay at current_ckpt");
        assert_eq!(r.stale_signature_indexes, vec![5]);
    }

    #[test]
    fn walk_forward_stops_at_first_missing_block() {
        let pending: Vec<PendingBatch> = vec![];
        let dispatched = vec![(11u64, 15u64)];
        let mut response_blocks = HashSet::new();
        for b in 16..=20 {
            response_blocks.insert(b);
        }
        // contiguous: 11..=20 present; 21 missing.
        let signed = HashSet::new();

        let r = normalize_startup_checkpoint(10, &pending, &dispatched, &response_blocks, &signed);

        assert_eq!(r.new_ckpt, 20);
        assert!(r.earliest_gap.is_none());
        assert!(r.stale_signature_indexes.is_empty());
    }

    #[test]
    fn no_gap_no_rollback_keeps_current_ckpt() {
        let pending = [batch(1, 5, 10)];
        let dispatched: Vec<(u64, u64)> = vec![];
        let mut response_blocks = HashSet::new();
        for b in 5..=10 {
            response_blocks.insert(b);
        }
        let signed = HashSet::new();

        let r = normalize_startup_checkpoint(10, &pending, &dispatched, &response_blocks, &signed);

        assert_eq!(r.new_ckpt, 10);
        assert!(r.earliest_gap.is_none());
    }

    #[test]
    fn gap_above_current_ckpt_does_not_rollback() {
        // Gap at block 50, but current_ckpt is already 30 (below the gap).
        // No rollback needed — the driver will naturally re-execute 31..50.
        let pending = [batch(3, 40, 60)];
        let dispatched: Vec<(u64, u64)> = vec![];
        let mut response_blocks = HashSet::new();
        for b in 40..=49 {
            response_blocks.insert(b);
        }
        let signed = HashSet::new();

        let r = normalize_startup_checkpoint(30, &pending, &dispatched, &response_blocks, &signed);

        assert_eq!(r.earliest_gap, Some(50));
        assert_eq!(r.new_ckpt, 30, "should not lower below current_ckpt");
        assert!(r.stale_signature_indexes.is_empty(), "no rollback → no stale sigs");
    }

    #[test]
    fn walk_forward_after_rollback_does_not_jump_past_gap() {
        // Two pending batches, gap in the first. Walk-forward from the
        // rolled-back checkpoint must NOT advance past the gap.
        let pending = [batch(1, 10, 20), batch(2, 21, 30)];
        let dispatched: Vec<(u64, u64)> = vec![];
        let mut response_blocks = HashSet::new();
        for b in 10..=14 {
            response_blocks.insert(b);
        }
        // gap at 15..20; 21..30 also missing.
        let signed = HashSet::new();

        let r = normalize_startup_checkpoint(25, &pending, &dispatched, &response_blocks, &signed);

        assert_eq!(r.earliest_gap, Some(15));
        assert_eq!(r.new_ckpt, 14, "must stop at gap-1, not re-advance to 25");
        // Only batch 1 contains the earliest gap; batch 2 also has a gap and
        // is reported as well (all batches containing any gap).
        assert!(r.stale_signature_indexes.contains(&1));
        assert!(r.stale_signature_indexes.contains(&2));
    }

    #[test]
    fn signed_pending_batch_is_not_treated_as_gap() {
        // Regression: on `on_sign_done`, responses for a signed batch are
        // early-purged while the batch row stays in `pending_batches` until
        // dispatched. At startup the gap scan must NOT flag the signed batch
        // as stale, its signature must NOT be deleted, and the checkpoint
        // must walk forward over the signed range.
        let pending = [batch(7, 100, 110)];
        let dispatched: Vec<(u64, u64)> = vec![];
        let response_blocks = HashSet::new(); // all responses purged post-signing
        let signed: HashSet<u64> = [7].into_iter().collect();

        let r = normalize_startup_checkpoint(99, &pending, &dispatched, &response_blocks, &signed);

        assert!(r.earliest_gap.is_none(), "signed batch must not register as a gap");
        assert!(r.stale_signature_indexes.is_empty(), "signed batch signature must be preserved");
        assert_eq!(r.new_ckpt, 110, "checkpoint must walk forward across the signed range");
    }

    #[test]
    fn signed_batch_before_unsigned_gap_still_detects_gap() {
        // Signed batch 7 (100..=110) is complete (responses purged).
        // Unsigned batch 8 (111..=120) has no responses — real gap at 111.
        let pending = [batch(7, 100, 110), batch(8, 111, 120)];
        let dispatched: Vec<(u64, u64)> = vec![];
        let response_blocks = HashSet::new();
        let signed: HashSet<u64> = [7].into_iter().collect();

        let r = normalize_startup_checkpoint(115, &pending, &dispatched, &response_blocks, &signed);

        assert_eq!(r.earliest_gap, Some(111));
        assert_eq!(r.new_ckpt, 110, "walk must stop at the signed batch's last block");
        assert_eq!(r.stale_signature_indexes, vec![8], "only the unsigned gap batch is stale");
    }
}
