//! Orchestrator: pulls witnesses from the embedded forward driver, dispatches
//! them to the Nitro proxy, and drives L1 batch signing + submission.
//!
//! # Architecture
//!
//! A persistent pool of `EXECUTION_WORKERS` tasks reads from a priority channel
//! pair (`high_rx` / `normal_rx`) via `biased` select, ensuring re-execution
//! after enclave key rotation takes precedence over fresh witnesses.
//!
//! Witnesses are **pulled** by a single feeder task that calls
//! [`Driver::try_take_new_block`] and forwards the result into `normal_tx`.
//! Back-pressure is natural: when workers are saturated, the feeder blocks on
//! `normal_tx.send().await`, which stops calling the driver, which idles.
//! The main select loop is drain-only — no branch performs an awaited send,
//! so the bounded channels cannot deadlock against it.
//!
//! On key rotation, blocks that need re-execution are fetched via
//! [`Driver::get_or_build_witness`] — cold-store hit is verbatim, cold miss
//! falls through to an MDBX-backed rebuild — and pushed onto the high-priority
//! queue independent of the feeder.

use std::{
    collections::HashSet,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc, Mutex, RwLock,
    },
    time::Duration,
};

use async_channel::{Receiver as AsyncReceiver, Sender as AsyncSender};
use bytes::Bytes;
use tokio::{sync::mpsc, task::JoinSet, time::MissedTickBehavior};
use tokio_util::sync::CancellationToken;
use tracing::{error, info, warn};

use crate::{
    accumulator::{self, BatchAccumulator, RbfResumeState},
    db::{db_send_sync, AsyncOp, BatchStatus, Db, DbCommand, SyncOp},
    driver::Driver,
    l1_listener::L1Event,
    types::{EthExecutionResponse, SignBatchRootRequest, SubmitBatchResponse},
};
use l1_rollup_client::{nitro_verifier::is_key_registered, NonceAllocator};

use alloy_eips::BlockNumberOrTag;
use alloy_network::{Ethereum, EthereumWallet, TxSigner};
use alloy_primitives::{Address, Signature, B256};
use alloy_provider::{
    fillers::{
        BlobGasFiller, ChainIdFiller, FillProvider, GasFiller, JoinFill, NonceFiller, WalletFiller,
    },
    Identity, Provider, RootProvider,
};

/// Shared set of block numbers whose execution response is already present in
/// the accumulator. Read by the feeder (to skip blocks with a response),
/// written on every response insert / purge / finalization. Kept as a narrow
/// projection of `BatchAccumulator.responses` so the feeder does not need to
/// lock the full accumulator.
pub(crate) type KnownResponses = Arc<RwLock<HashSet<u64>>>;

/// Concrete type of the L1 write provider built in `main`. Pinned to the
/// current alloy filler stack; a future alloy upgrade that changes the filler
/// chain will cause a compile error here and require updating the alias.
pub(crate) type L1WriteProvider = FillProvider<
    JoinFill<
        JoinFill<
            Identity,
            JoinFill<GasFiller, JoinFill<BlobGasFiller, JoinFill<NonceFiller, ChainIdFiller>>>,
        >,
        WalletFiller<EthereumWallet>,
    >,
    RootProvider,
    Ethereum,
>;

/// Maximum wall-clock time the RBF worker will keep rebroadcasting at the
/// fee cap after the cap is first reached. Once this elapses with no
/// receipt, the worker returns `Failed` so the main loop can undispatch,
/// apply global backoff, and retry from scratch (including re-running
/// pre-flight reconciliation). Prevents a stuck-at-cap worker from running
/// forever against a mempool that refuses to mine it.
pub(crate) const STUCK_AT_CAP_TIMEOUT: Duration = Duration::from_secs(300);

/// Number of persistent execution workers sending blocks to the Nitro proxy.
pub(crate) const EXECUTION_WORKERS: usize = 8;

/// Bounded wait for workers to finish their in-flight HTTP calls on
/// shutdown. Longer than a typical request, shorter than a systemd
/// `TimeoutStopSec`.
const SHUTDOWN_DRAIN_TIMEOUT: Duration = Duration::from_secs(30);

/// Return true at attempts 1, 2, 4, 8, 16, ... — exponential log thinning
/// so a prolonged L1 outage does not flood Loki while the orchestrator
/// polls forever waiting for the enclave key to be registered.
fn is_log_worthy(attempts: u64) -> bool {
    attempts > 0 && attempts.is_power_of_two()
}

/// zstd level for `/sign-block-execution` payload compression. Level 3 is the
/// default and a good size/CPU trade-off for online use (~3–10× on bincode
/// witness data; sub-100ms on multi-MB inputs).
#[cfg(feature = "zstd-block-payload")]
const ZSTD_COMPRESSION_LEVEL: i32 = 3;

/// Configuration for the orchestrator.
#[derive(Clone)]
pub(crate) struct OrchestratorConfig {
    pub proxy_url: String,
    pub http_client: reqwest::Client,
    pub l1_rollup_addr: Address,
    /// L1 block where the Rollup contract was deployed. Lower bound for
    /// `fetch_batch_range` event scans on the challenge-resolve path.
    pub l1_deploy_block: u64,
    pub nitro_verifier_addr: Address,
    pub l1_provider: L1WriteProvider,
    /// Separate L1 read provider for `fetch_batch_range` (which expects
    /// the concrete `RootProvider`, not the wallet-filler stack). Built
    /// once at startup; same RPC URL as `l1_provider`.
    pub l1_read_provider: RootProvider,
    pub api_key: String,
    pub l2_provider: alloy_provider::RootProvider,
    /// Held alongside `l1_provider` so the RBF worker can sign with an
    /// explicit nonce and fees, bypassing alloy's `NonceFiller` /
    /// `GasFiller`.
    pub l1_signer: Arc<dyn TxSigner<Signature> + Send + Sync>,
    pub l1_signer_address: Address,
    pub rbf_bump_interval: Duration,
    /// Must be `>= 13` to satisfy the EIP-1559 +12.5% replacement-tx
    /// minimum (20 by default).
    pub rbf_bump_percent: u32,
    /// Hitting this cap is a loud operator-attention event; the worker
    /// continues rebroadcasting at the cap.
    pub rbf_max_fee_per_gas_wei: u128,
}

/// `accumulator` uses `std::sync::Mutex` deliberately: holding the guard
/// across `.await` is a compile error, which forces every site to drop the
/// lock before any async work and prevents deadlocks at runtime.
pub(crate) struct OrchestratorShared {
    pub(crate) config: OrchestratorConfig,
    /// Direct DB read access for the challenge active worker (status
    /// queries every tick) and for L1-event handlers that need to look up
    /// existing challenge rows. Writes still flow through `db_tx`.
    pub(crate) db: Arc<std::sync::Mutex<Db>>,
    pub(crate) db_tx: mpsc::UnboundedSender<DbCommand>,
    pub(crate) accumulator: Arc<std::sync::Mutex<BatchAccumulator>>,
    pub(crate) known_responses: KnownResponses,
    pub(crate) nonce_allocator: Arc<NonceAllocator>,
    pub(crate) orchestrator_tip: Arc<AtomicU64>,
    /// Set by the signer on `InvalidSignatures` (key rotation detected),
    /// cleared by the spawned key-check task once the new key is on L1.
    /// The dispatcher skips broadcasting while this is `Some(_)`.
    pub(crate) pending_key_check: Arc<std::sync::Mutex<Option<Address>>>,
    pub(crate) high_tx: AsyncSender<ExecutionTask>,
    pub(crate) driver: Arc<Driver>,
    pub(crate) shutdown: CancellationToken,
}

/// Task for the execution worker pool. Produced by the feeder (from the
/// driver) and by the re-execution path (enclave key rotation recovery).
pub(crate) struct ExecutionTask {
    pub(crate) block_number: u64,
    pub(crate) payload: Vec<u8>,
}

/// Response from a `/sign-block-execution` request.
struct BlockResult {
    block_number: u64,
    response: EthExecutionResponse,
}

enum SignOutcome {
    Signed {
        response: SubmitBatchResponse,
    },
    /// Enclave key rotated; the listed blocks need re-execution against
    /// the new key.
    InvalidSignatures {
        invalid_blocks: Vec<u64>,
        enclave_address: Address,
    },
    TaskFailed,
}

/// Cheap classification of a reverted preconfirmBatch tx based on the
/// gasUsed/gasLimit ratio. A deepest-CALL out-of-gas burns ~all forwarded
/// gas and leaves only the EIP-150 1/64 reserve at the outer frame, so
/// `gasUsed` lands within ~5% of `gasLimit`. Anything well below that ratio
/// is a logic-revert (require failure with custom error data).
///
/// Used to decide retry policy: `Oog` → re-dispatch with inflated gas buffer
/// (estimate was too tight); `Logic` → undispatch + backoff (contract state
/// is in an unexpected shape, operator should inspect).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RevertKind {
    Oog,
    Logic,
}

/// `gas_used / gas_limit >= 0.95` → Oog. Pulled out for unit testing.
pub(crate) fn classify_revert(gas_used: u64, gas_limit: u64) -> RevertKind {
    if gas_limit == 0 {
        return RevertKind::Logic;
    }
    if gas_used.saturating_mul(100) >= gas_limit.saturating_mul(95) {
        RevertKind::Oog
    } else {
        RevertKind::Logic
    }
}

enum ReceiptCheck {
    /// Receipt found with status=1. `finalized` reflects whether
    /// `l1_block <= finalized_block_number` at observation time —
    /// finality decisions are deferred to `apply_finalization_changes`.
    Found {
        finalized: bool,
    },
    Reverted {
        kind: RevertKind,
    },
    /// Receipt absent — implies the tx is no longer in the canonical
    /// chain (reorg) or the RPC is briefly inconsistent. Caller drives
    /// recovery by rolling status back to `Sent` so the dispatcher
    /// resumes RBF.
    Missing,
    CheckFailed,
}

enum FinalizationDone {
    Observed { observations: Vec<(u64, B256, ReceiptCheck)> },
    NoOp,
}

/// Error from `/sign-batch-root` call.
enum SignBatchError {
    InvalidSignatures { invalid_blocks: Vec<u64>, enclave_address: Address },
    Other(eyre::Report),
}

// ============================================================================
// Persistent execution worker pool
// ============================================================================

/// Reads tasks from the priority channel pair (high before normal) and sends
/// `/sign-block-execution` requests with aggressive retry.
#[allow(clippy::too_many_arguments)]
async fn execution_worker(
    worker_id: usize,
    high_rx: AsyncReceiver<ExecutionTask>,
    normal_rx: AsyncReceiver<ExecutionTask>,
    result_tx: mpsc::Sender<BlockResult>,
    http_client: reqwest::Client,
    proxy_url: String,
    api_key: String,
    shutdown: CancellationToken,
) {
    info!(worker_id, "Execution worker started");
    loop {
        // biased: always drain high-priority (re-execution) before normal.
        // Cancel is checked ONLY between tasks — never mid-HTTP-call —
        // so an in-flight payload is either fully sent and answered, or
        // not started at all.
        let task = tokio::select! {
            biased;
            _ = shutdown.cancelled() => break,
            Ok(t) = high_rx.recv() => t,
            Ok(t) = normal_rx.recv() => t,
            else => break,
        };

        #[cfg(feature = "zstd-block-payload")]
        let payload = {
            let uncompressed_len = task.payload.len();
            match zstd::encode_all(task.payload.as_slice(), ZSTD_COMPRESSION_LEVEL) {
                Ok(compressed) => {
                    tracing::debug!(
                        block = task.block_number,
                        uncompressed_len,
                        compressed_len = compressed.len(),
                        "Compressed block payload for /sign-block-execution"
                    );
                    Bytes::from(compressed)
                }
                Err(e) => {
                    error!(
                        worker_id,
                        block = task.block_number,
                        err = %e,
                        "zstd compression failed — dropping task"
                    );
                    continue;
                }
            }
        };
        #[cfg(not(feature = "zstd-block-payload"))]
        let payload = Bytes::from(task.payload);
        let mut backoff = Duration::from_millis(50);
        let mut attempts: u32 = 0;
        loop {
            attempts += 1;
            let t_start = std::time::Instant::now();
            match send_block_request(
                &http_client,
                &proxy_url,
                &api_key,
                task.block_number,
                payload.clone(),
            )
            .await
            {
                Ok(response) => {
                    metrics::histogram!(crate::metrics::SIGN_BLOCK_EXECUTION_DURATION)
                        .record(t_start.elapsed().as_secs_f64());
                    if attempts > 1 {
                        info!(
                            worker_id,
                            block = task.block_number,
                            attempts,
                            "Block succeeded after retries"
                        );
                    }
                    if result_tx
                        .send(BlockResult { block_number: task.block_number, response })
                        .await
                        .is_err()
                    {
                        warn!(worker_id, block = task.block_number, "Result channel closed");
                    }
                    break;
                }
                Err(e) => {
                    metrics::histogram!(crate::metrics::SIGN_BLOCK_EXECUTION_DURATION)
                        .record(t_start.elapsed().as_secs_f64());
                    metrics::counter!(
                        crate::metrics::SIGN_FAILURES_TOTAL,
                        "stage" => "block",
                        "kind" => crate::metrics::sign_failure_kind(&e),
                    )
                    .increment(1);
                    warn!(
                        worker_id,
                        block = task.block_number,
                        attempt = attempts,
                        err = %e,
                        "Execution failed, retrying"
                    );
                    tokio::select! {
                        _ = shutdown.cancelled() => return,
                        _ = tokio::time::sleep(backoff) => {}
                    }
                    backoff = (backoff * 2).min(Duration::from_secs(2));
                }
            }
        }
    }
    info!(worker_id, "Execution worker exiting");
}

// ============================================================================
// Feeder
// ============================================================================

/// Consume ready witnesses from the cold witness store in strict block
/// order and forward them to the execution worker pool via `normal_tx`.
///
/// **Invariant.** This is the ONLY producer for `normal_tx`; the key-rotation
/// replay path writes directly to the high-priority channel owned inside
/// `run`. Back-pressure propagates naturally: when workers saturate,
/// `normal_tx.send().await` blocks the feeder — the driver's background
/// loop continues filling the hub up to the orchestrator_tip lookahead cap.
///
/// Spawned by `main.rs` into the top-level `JoinSet`; feeder exit (clean or
/// error) is observed by the main-loop race and triggers clean process exit.
pub(crate) async fn feeder_loop(
    hub: Arc<crate::hub::WitnessHub>,
    normal_tx: AsyncSender<ExecutionTask>,
    known_responses: KnownResponses,
    starting_block: u64,
    shutdown: CancellationToken,
) -> eyre::Result<()> {
    const FEEDER_IDLE: Duration = Duration::from_millis(100);
    let mut next_block = starting_block;
    loop {
        if shutdown.is_cancelled() {
            info!("Feeder: shutdown — exiting");
            break;
        }

        // Dedup: if the main loop already has a response for this block
        // (startup checkpoint rollback path), skip the proxy round-trip and
        // advance. `on_block_result` enforces the gate if a dup slips through;
        // this is an efficiency layer.
        if known_responses.read().unwrap_or_else(|e| e.into_inner()).contains(&next_block) {
            next_block += 1;
            continue;
        }

        match hub.get_witness(next_block).await {
            Some(req) => {
                let task = ExecutionTask { block_number: req.block_number, payload: req.payload };
                if normal_tx.send(task).await.is_err() {
                    warn!("Feeder: normal_tx closed — exiting");
                    break;
                }
                next_block += 1;
            }
            None => {
                // Driver has not yet committed block `next_block` — sleep and retry.
                tokio::select! {
                    _ = shutdown.cancelled() => break,
                    _ = tokio::time::sleep(FEEDER_IDLE) => continue,
                }
            }
        }
    }
    info!("Feeder exited");
    Ok(())
}

// ============================================================================
// Main orchestrator loop
// ============================================================================

/// Run the orchestrator loop until `shutdown` fires.
///
/// Creates the persistent execution worker pool once. The feeder task that
/// pulls witnesses from the embedded driver and forwards them into `normal_tx`
/// is owned by `main.rs` and supervised via the top-level `JoinSet`, so a
/// feeder crash triggers clean process exit alongside the orchestrator.
///
/// `known_responses` is shared with the feeder and is seeded here from the
/// persistent accumulator before entering the main select loop.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn run(
    config: OrchestratorConfig,
    db: Arc<Mutex<Db>>,
    db_tx: mpsc::UnboundedSender<DbCommand>,
    driver: Arc<Driver>,
    orchestrator_tip: Arc<AtomicU64>,
    l1_events: mpsc::Receiver<L1Event>,
    shutdown: CancellationToken,
    normal_rx: AsyncReceiver<ExecutionTask>,
    known_responses: KnownResponses,
) {
    let accumulator = {
        let db = Arc::clone(&db);
        let db_tx = db_tx.clone();
        tokio::task::spawn_blocking(move || BatchAccumulator::with_db(db, db_tx))
            .await
            .expect("startup accumulator load panicked")
    };

    // Single-writer window — runs before any background task that could emit.
    {
        let checkpoint = accumulator.highest_dispatched_to_block().unwrap_or(0);
        let dispatched_max: Option<(u64, u64, u64)> = accumulator
            .batches
            .values()
            .rev()
            .find(|b| b.status >= BatchStatus::Sent)
            .map(|b| (b.batch_index, b.from_block, b.to_block));
        let signed_max: Option<(u64, u64, u64)> = accumulator
            .batches
            .values()
            .rev()
            .find(|b| b.enclave_signed)
            .map(|b| (b.batch_index, b.from_block, b.to_block));
        crate::metrics::seed_gauges_on_startup(checkpoint, dispatched_max, signed_max);
    }

    let mut initial_last_batch_end: Option<u64> = accumulator.highest_finalized_to_block();

    // Sweep preconfirmed rows from the prior process before spawning workers,
    // so finalization gets a chance to drive any already-finalized rows to
    // terminal status, and the dispatcher does not try to resume one whose
    // tx is already mined.
    run_startup_sweep(
        &accumulator,
        &db_tx,
        &mut initial_last_batch_end,
        &orchestrator_tip,
        &config.l1_provider,
    )
    .await;

    // Capacity tied to `EXECUTION_WORKERS`: each queued `ExecutionTask`
    // can hold a 30-80 MB payload, so larger buffers risk OOM.
    let (high_tx, high_rx) = async_channel::bounded::<ExecutionTask>(EXECUTION_WORKERS);
    let (result_tx, result_rx) = mpsc::channel::<BlockResult>(EXECUTION_WORKERS * 2);

    let mut workers: JoinSet<()> = JoinSet::new();
    for i in 0..EXECUTION_WORKERS {
        workers.spawn(execution_worker(
            i,
            high_rx.clone(),
            normal_rx.clone(),
            result_tx.clone(),
            config.http_client.clone(),
            config.proxy_url.clone(),
            config.api_key.clone(),
            shutdown.clone(),
        ));
    }

    let initial_checkpoint = accumulator.highest_dispatched_to_block().unwrap_or(0);
    let from_block = initial_checkpoint + 1;

    let stored_nonce_floor: Option<u64> = accumulator.stored_nonce_floor();
    let nonce_allocator = Arc::new(
        NonceAllocator::bootstrap(
            &config.l1_provider,
            config.l1_signer_address,
            stored_nonce_floor,
        )
        .await
        .expect("NonceAllocator bootstrap failed — L1 RPC unreachable at startup"),
    );

    let target_tip = initial_checkpoint.max(initial_last_batch_end.unwrap_or(0));
    let current_tip = orchestrator_tip.load(Ordering::Relaxed);
    if target_tip > current_tip {
        orchestrator_tip.store(target_tip, Ordering::Relaxed);
    }
    let _ = initial_last_batch_end;

    let shared = Arc::new(OrchestratorShared {
        config,
        db: Arc::clone(&db),
        db_tx: db_tx.clone(),
        accumulator: Arc::new(std::sync::Mutex::new(accumulator)),
        known_responses: Arc::clone(&known_responses),
        nonce_allocator,
        orchestrator_tip: Arc::clone(&orchestrator_tip),
        pending_key_check: Arc::new(std::sync::Mutex::new(None)),
        high_tx: high_tx.clone(),
        driver: Arc::clone(&driver),
        shutdown: shutdown.clone(),
    });

    info!(from_block, "Orchestrator ready — awaiting witnesses");

    let mut tasks: JoinSet<&'static str> = JoinSet::new();
    {
        let shared = Arc::clone(&shared);
        tasks.spawn(async move {
            signer_worker(shared).await;
            "signer_worker"
        });
    }
    {
        let shared = Arc::clone(&shared);
        tasks.spawn(async move {
            dispatcher_worker(shared).await;
            "dispatcher_worker"
        });
    }
    {
        let shared = Arc::clone(&shared);
        tasks.spawn(async move {
            finalization_worker(shared).await;
            "finalization_worker"
        });
    }
    {
        let shared = Arc::clone(&shared);
        tasks.spawn(async move {
            router(shared, l1_events, result_rx, initial_checkpoint).await;
            "router"
        });
    }
    {
        let shared = Arc::clone(&shared);
        tasks.spawn(async move {
            crate::challenge_resolver::run(shared).await;
            "challenge_resolver"
        });
    }

    // Any worker exit — clean or fatal — cancels the root token so the
    // rest drain together.
    tokio::select! {
        _ = shutdown.cancelled() => {
            info!("Shutdown requested — draining orchestrator workers");
        }
        Some(join) = tasks.join_next() => {
            match join {
                Ok(name) => info!(task = name, "orchestrator worker exited"),
                Err(e) => warn!(err = %e, "orchestrator worker join failed"),
            }
            shutdown.cancel();
        }
    }

    while let Some(join) = tasks.join_next().await {
        match join {
            Ok(name) => info!(task = name, "orchestrator worker drained"),
            Err(e) => warn!(err = %e, "orchestrator worker join failed during drain"),
        }
    }

    // The feeder owns `normal_tx` and drops it on cancel; here we only
    // drop the channels the orchestrator itself owns.
    info!("Closing worker task channels — draining execution workers");
    drop(high_tx);
    drop(result_tx);

    let drain = async {
        while let Some(res) = workers.join_next().await {
            if let Err(e) = res {
                warn!(err = %e, "Worker panicked or was cancelled");
            }
        }
    };
    match tokio::time::timeout(SHUTDOWN_DRAIN_TIMEOUT, drain).await {
        Ok(()) => info!("All workers drained cleanly"),
        Err(_) => {
            warn!(
                timeout_secs = SHUTDOWN_DRAIN_TIMEOUT.as_secs(),
                "Shutdown drain deadline exceeded — aborting remaining workers"
            );
            workers.shutdown().await;
        }
    }
    info!("client::run exited");
}

// ============================================================================
// L1 finality helpers
// ============================================================================

/// Narrow RPC surface for the finalization check. Blanket-impl'd for any
/// `alloy` `Provider` so production passes `&l1_provider`; tests stub it.
#[async_trait::async_trait]
pub(crate) trait FinalityRpc: Send + Sync {
    async fn finalized_block_number(&self) -> Option<u64>;
    async fn receipt_status(&self, tx_hash: B256) -> Result<Option<(bool, u64)>, String>;
    async fn tx_gas_limit(&self, tx_hash: B256) -> Result<Option<u64>, String>;
}

#[async_trait::async_trait]
impl<P: Provider + Send + Sync> FinalityRpc for P {
    async fn finalized_block_number(&self) -> Option<u64> {
        match self.get_block_by_number(BlockNumberOrTag::Finalized).await {
            Ok(Some(block)) => Some(block.header.number),
            Ok(None) => {
                warn!("Finalized block not available from RPC");
                None
            }
            Err(e) => {
                warn!(err = %e, "Failed to fetch finalized block");
                None
            }
        }
    }

    async fn receipt_status(&self, tx_hash: B256) -> Result<Option<(bool, u64)>, String> {
        match self.get_transaction_receipt(tx_hash).await {
            Ok(Some(r)) => Ok(Some((r.status(), r.gas_used))),
            Ok(None) => Ok(None),
            Err(e) => Err(e.to_string()),
        }
    }

    async fn tx_gas_limit(&self, tx_hash: B256) -> Result<Option<u64>, String> {
        use alloy_consensus::Transaction as TransactionTrait;
        match self.get_transaction_by_hash(tx_hash).await {
            Ok(Some(tx)) => Ok(Some(tx.gas_limit())),
            Ok(None) => Ok(None),
            Err(e) => Err(e.to_string()),
        }
    }
}

/// Pure-RPC half of the finalization + reorg check: takes a `dispatched`
/// snapshot and returns receipt observations without touching the
/// accumulator or DB. Skips rows whose `l1_block == 0` (in-flight
/// initial broadcast — the dispatcher remains the sole observer until
/// its first broadcast lands).
async fn check_finalized_batches_query(
    provider: &dyn FinalityRpc,
    dispatched_snapshot: Vec<(u64, B256, u64)>,
) -> FinalizationDone {
    let Some(finalized_block) = provider.finalized_block_number().await else {
        return FinalizationDone::NoOp;
    };
    let candidates: Vec<(u64, B256, u64)> =
        dispatched_snapshot.into_iter().filter(|(_, _, l1_block)| *l1_block > 0).collect();
    if candidates.is_empty() {
        return FinalizationDone::NoOp;
    }
    let mut observations = Vec::with_capacity(candidates.len());
    for (batch_index, tx_hash, l1_block) in candidates {
        let check = match provider.receipt_status(tx_hash).await {
            Ok(Some((true, _))) => ReceiptCheck::Found { finalized: l1_block <= finalized_block },
            Ok(Some((false, gas_used))) => {
                let gas_limit = match provider.tx_gas_limit(tx_hash).await {
                    Ok(Some(g)) => g,
                    Ok(None) | Err(_) => 0,
                };
                let kind = classify_revert(gas_used, gas_limit);
                warn!(
                    batch_index,
                    %tx_hash,
                    ?kind,
                    gas_used,
                    gas_limit,
                    "Finalization-ticker observed REVERTED preconfirmBatch"
                );
                ReceiptCheck::Reverted { kind }
            }
            Ok(None) => ReceiptCheck::Missing,
            Err(e) => {
                warn!(batch_index, %tx_hash, err = %e, "Receipt check failed — will retry");
                ReceiptCheck::CheckFailed
            }
        };
        observations.push((batch_index, tx_hash, check));
    }
    FinalizationDone::Observed { observations }
}

// ============================================================================
// Batch signing I/O
// ============================================================================

/// Sign a batch root via the proxy with retry until definitive result.
#[allow(clippy::too_many_arguments)]
async fn sign_batch_io(
    http_client: &reqwest::Client,
    proxy_url: &str,
    api_key: &str,
    batch_index: u64,
    from_block: u64,
    to_block: u64,
    responses: Vec<EthExecutionResponse>,
    l2_provider: &alloy_provider::RootProvider,
    shutdown: &CancellationToken,
) -> SignOutcome {
    info!(batch_index, from_block, to_block, "Signing batch root");

    let blobs = {
        let mut backoff = Duration::from_secs(1);
        loop {
            match rsp_blob_builder::build_blobs_from_l2(l2_provider, from_block, to_block).await {
                Ok(blobs) => break blobs,
                Err(e) => {
                    warn!(batch_index, err = %e, ?backoff, "Blob construction failed — retrying");
                    tokio::select! {
                        _ = tokio::time::sleep(backoff) => {}
                        _ = shutdown.cancelled() => return SignOutcome::TaskFailed,
                    }
                    backoff = (backoff * 2).min(Duration::from_secs(30));
                }
            }
        }
    };

    info!(batch_index, num_blobs = blobs.len(), "Blobs built from L2 tx data");

    let mut backoff = Duration::from_secs(1);
    loop {
        let t_start = std::time::Instant::now();
        match call_sign_batch_root(
            http_client,
            proxy_url,
            api_key,
            from_block,
            to_block,
            batch_index,
            &responses,
            &blobs,
        )
        .await
        {
            Ok(resp) => {
                metrics::histogram!(crate::metrics::SIGN_BATCH_ROOT_DURATION)
                    .record(t_start.elapsed().as_secs_f64());
                info!(batch_index, "Batch root signed");
                return SignOutcome::Signed { response: resp };
            }
            Err(SignBatchError::InvalidSignatures { invalid_blocks, enclave_address }) => {
                metrics::histogram!(crate::metrics::SIGN_BATCH_ROOT_DURATION)
                    .record(t_start.elapsed().as_secs_f64());
                warn!(
                    batch_index,
                    ?invalid_blocks,
                    %enclave_address,
                    "Batch has stale signatures — key rotation detected"
                );
                return SignOutcome::InvalidSignatures { invalid_blocks, enclave_address };
            }
            Err(SignBatchError::Other(e)) => {
                metrics::histogram!(crate::metrics::SIGN_BATCH_ROOT_DURATION)
                    .record(t_start.elapsed().as_secs_f64());
                metrics::counter!(
                    crate::metrics::SIGN_FAILURES_TOTAL,
                    "stage" => "batch",
                    "kind" => crate::metrics::sign_failure_kind(&e),
                )
                .increment(1);
                warn!(batch_index, err = %e, ?backoff, "sign-batch-root failed — retrying");
                tokio::select! {
                    _ = tokio::time::sleep(backoff) => {}
                    _ = shutdown.cancelled() => return SignOutcome::TaskFailed,
                }
                backoff = (backoff * 2).min(Duration::from_secs(30));
            }
        }
    }
}

/// Call the proxy's `/sign-batch-root` endpoint.
#[allow(clippy::too_many_arguments)]
async fn call_sign_batch_root(
    http_client: &reqwest::Client,
    proxy_url: &str,
    api_key: &str,
    from_block: u64,
    to_block: u64,
    batch_index: u64,
    responses: &[EthExecutionResponse],
    blobs: &[Vec<u8>],
) -> Result<SubmitBatchResponse, SignBatchError> {
    let url = format!("{proxy_url}/sign-batch-root");

    let body = SignBatchRootRequest {
        from_block,
        to_block,
        batch_index,
        responses: responses.to_vec(),
        blobs: blobs.to_vec(),
    };

    let resp = http_client
        .post(&url)
        .timeout(Duration::from_secs(300))
        .header("x-api-key", api_key)
        .json(&body)
        .send()
        .await
        .map_err(|e| {
            use std::error::Error;
            let kind = if e.is_connect() {
                "connect"
            } else if e.is_timeout() {
                "timeout"
            } else if e.is_request() {
                "request"
            } else {
                "unknown"
            };
            let mut chain = format!("{e}");
            let mut source = e.source();
            while let Some(cause) = source {
                chain.push_str(&format!(" → {cause}"));
                source = cause.source();
            }
            SignBatchError::Other(eyre::eyre!("sign-batch-root failed ({kind}): {chain}"))
        })?;

    let status = resp.status();

    if status == reqwest::StatusCode::CONFLICT {
        let parsed: crate::types::InvalidSignaturesResponse = resp
            .json()
            .await
            .map_err(|e| SignBatchError::Other(eyre::eyre!("Failed to parse 409: {e}")))?;
        return Err(SignBatchError::InvalidSignatures {
            invalid_blocks: parsed.invalid_blocks,
            enclave_address: parsed.enclave_address,
        });
    }

    if !status.is_success() {
        let text = resp.text().await.unwrap_or_default();
        return Err(SignBatchError::Other(eyre::eyre!("sign-batch-root returned {status}: {text}")));
    }

    resp.json::<SubmitBatchResponse>()
        .await
        .map_err(|e| SignBatchError::Other(eyre::eyre!("Failed to parse SubmitBatchResponse: {e}")))
}

// ============================================================================
// Block execution request
// ============================================================================

/// Send a single `/sign-block-execution` request.
async fn send_block_request(
    http_client: &reqwest::Client,
    proxy_url: &str,
    api_key: &str,
    block_number: u64,
    payload: Bytes,
) -> eyre::Result<EthExecutionResponse> {
    let url = format!("{proxy_url}/sign-block-execution");
    let req = http_client
        .post(&url)
        .timeout(Duration::from_secs(30))
        .header("content-type", "application/octet-stream")
        .header("x-block-number", block_number.to_string())
        .header("x-api-key", api_key)
        .body(payload);
    #[cfg(feature = "zstd-block-payload")]
    let req = req.header("content-encoding", "zstd");
    let resp = req.send().await.map_err(|e| eyre::eyre!("HTTP POST failed: {e}"))?;

    let status = resp.status();
    if !status.is_success() {
        let body = resp.text().await.unwrap_or_else(|_| "<unreadable>".into());
        return Err(eyre::eyre!("proxy returned {status}: {body}"));
    }

    resp.json::<EthExecutionResponse>()
        .await
        .map_err(|e| eyre::eyre!("Failed to parse response: {e}"))
}

// ============================================================================
// Long-lived workers
// ============================================================================

const WORKER_TICK: Duration = Duration::from_secs(1);
const FINALIZATION_TICK: Duration = Duration::from_secs(30);

/// Capped at 5 minutes so a transient L1 outage cannot freeze dispatch
/// indefinitely.
#[derive(Default)]
pub(crate) struct DispatchBackoff {
    attempts: u32,
    next_allowed: Option<tokio::time::Instant>,
}

impl DispatchBackoff {
    pub(crate) fn apply(&mut self, reason: &'static str) {
        self.attempts += 1;
        let delay_secs = (10u64 * self.attempts as u64).min(300);
        self.next_allowed = Some(tokio::time::Instant::now() + Duration::from_secs(delay_secs));
        warn!(attempts = self.attempts, delay_secs, reason, "Dispatch backoff applied");
    }

    pub(crate) fn reset(&mut self) {
        self.attempts = 0;
        self.next_allowed = None;
    }

    fn is_blocking(&self) -> bool {
        match self.next_allowed {
            Some(deadline) => tokio::time::Instant::now() < deadline,
            None => false,
        }
    }
}

fn spawn_re_execution(shared: Arc<OrchestratorShared>, block_number: u64) {
    tokio::spawn(async move {
        let mut backoff = Duration::from_secs(1);
        let mut attempts: u64 = 0;
        loop {
            if shared.shutdown.is_cancelled() {
                return;
            }
            match shared.driver.get_or_build_witness(block_number).await {
                Ok(Some(payload)) => {
                    if shared.high_tx.send(ExecutionTask { block_number, payload }).await.is_err() {
                        warn!(block_number, "High-priority channel closed during re-execution");
                    }
                    return;
                }
                Ok(None) => {
                    attempts += 1;
                    if is_log_worthy(attempts) {
                        warn!(
                            block_number,
                            attempts,
                            "Re-execution: block not yet in MDBX and not cached — \
                             retrying with backoff"
                        );
                    }
                }
                Err(e) => {
                    attempts += 1;
                    if is_log_worthy(attempts) {
                        warn!(
                            block_number,
                            attempts,
                            err = %e,
                            "Re-execution: witness rebuild failed — retrying with backoff"
                        );
                    }
                }
            }
            tokio::select! {
                _ = shared.shutdown.cancelled() => return,
                _ = tokio::time::sleep(backoff) => {}
            }
            backoff = (backoff * 2).min(Duration::from_secs(60));
        }
    });
}

/// Polls L1 for the rotated key's registration; clears
/// `pending_key_check` on success so the dispatcher can resume.
fn spawn_key_check(shared: Arc<OrchestratorShared>, addr: Address) {
    tokio::spawn(async move {
        let mut attempts: u64 = 0;
        loop {
            if shared.shutdown.is_cancelled() {
                return;
            }
            let registered = is_key_registered(
                &shared.config.l1_provider,
                shared.config.nitro_verifier_addr,
                addr,
            )
            .await
            .unwrap_or(false);
            if registered {
                info!(%addr, attempts, "Enclave key confirmed on L1");
                let mut g = shared.pending_key_check.lock().unwrap_or_else(|e| e.into_inner());
                if *g == Some(addr) {
                    *g = None;
                }
                return;
            }
            attempts += 1;
            if is_log_worthy(attempts) {
                warn!(
                    %addr,
                    attempts,
                    "Enclave key still not registered — continuing to poll every 10s"
                );
            }
            tokio::select! {
                _ = shared.shutdown.cancelled() => return,
                _ = tokio::time::sleep(Duration::from_secs(10)) => {}
            }
        }
    });
}

#[cfg_attr(test, derive(Debug))]
enum DispatchTarget {
    /// A previous-lifetime broadcast left an `l1_block == 0` row with
    /// full RBF state — resume its bump loop with the persisted nonce.
    ResumeInFlight {
        batch_index: u64,
        signature: Vec<u8>,
        resume: RbfResumeState,
    },
    Fresh {
        batch_index: u64,
        signature: Vec<u8>,
    },
    None,
}

fn pick_next_dispatch_target(acc: &BatchAccumulator) -> DispatchTarget {
    if let Some((batch_index, signature, resume)) = acc.first_inflight_resume() {
        return DispatchTarget::ResumeInFlight { batch_index, signature, resume };
    }
    if let Some(batch_index) = acc.first_dispatchable() {
        if let Some(row) = acc.get(batch_index) {
            if let Some(sig) = &row.signature {
                return DispatchTarget::Fresh { batch_index, signature: sig.signature.clone() };
            }
        }
    }
    DispatchTarget::None
}

/// One in-flight RBF lifecycle at a time. The "at most one fresh dispatch"
/// gate is what lets the resume scope return a single row.
async fn dispatcher_worker(shared: Arc<OrchestratorShared>) {
    let mut tick = tokio::time::interval(WORKER_TICK);
    tick.set_missed_tick_behavior(MissedTickBehavior::Skip);
    let mut backoff = DispatchBackoff::default();

    loop {
        tokio::select! {
            biased;
            _ = shared.shutdown.cancelled() => break,
            _ = tick.tick() => {}
        }

        if backoff.is_blocking() {
            continue;
        }
        if shared.pending_key_check.lock().unwrap_or_else(|e| e.into_inner()).is_some() {
            continue;
        }

        let target = {
            let acc = shared.accumulator.lock().unwrap_or_else(|e| e.into_inner());
            pick_next_dispatch_target(&acc)
        };

        match target {
            DispatchTarget::ResumeInFlight { batch_index, signature, resume } => {
                info!(
                    batch_index,
                    nonce = resume.nonce,
                    stored_tx_hash = %resume.tx_hash,
                    stored_max_fee_per_gas = resume.max_fee_per_gas,
                    stored_max_priority_fee_per_gas = resume.max_priority_fee_per_gas,
                    "RBF: resuming dispatched batch from persisted state"
                );
                crate::rbf::run(&shared, batch_index, signature, Some(resume), &mut backoff).await;
            }
            DispatchTarget::Fresh { batch_index, signature } => {
                crate::rbf::run(&shared, batch_index, signature, None, &mut backoff).await;
            }
            DispatchTarget::None => {}
        }
    }
    info!("dispatcher_worker exiting");
}

async fn signer_worker(shared: Arc<OrchestratorShared>) {
    let mut tick = tokio::time::interval(WORKER_TICK);
    tick.set_missed_tick_behavior(MissedTickBehavior::Skip);

    loop {
        tokio::select! {
            biased;
            _ = shared.shutdown.cancelled() => break,
            _ = tick.tick() => {}
        }

        // Snapshot current state under one lock acquisition: pick the next
        // batch eligible to sign (status=Accepted, !enclave_signed, all
        // responses present) and copy out its responses. Drop the lock
        // before the HTTP call.
        let pick: Option<(u64, u64, u64, Vec<EthExecutionResponse>)> = {
            let acc = shared.accumulator.lock().unwrap_or_else(|e| e.into_inner());
            acc.first_accepted_unsigned().and_then(|batch_index| {
                let batch = acc.get(batch_index)?;
                let from_block = batch.from_block;
                let to_block = batch.to_block;
                let responses = acc.get_responses(from_block, to_block);
                Some((batch_index, from_block, to_block, responses))
            })
        };

        let Some((batch_index, from_block, to_block, responses)) = pick else { continue };

        let outcome = sign_batch_io(
            &shared.config.http_client,
            &shared.config.proxy_url,
            &shared.config.api_key,
            batch_index,
            from_block,
            to_block,
            responses,
            &shared.config.l2_provider,
            &shared.shutdown,
        )
        .await;

        match outcome {
            SignOutcome::Signed { response } => {
                info!(batch_index, "Batch signed — available for dispatch");
                if let Err(e) =
                    accumulator::record_enclave_signed(&shared.accumulator, batch_index, response)
                        .await
                {
                    error!(batch_index, err = %e, "record_enclave_signed failed");
                    continue;
                }
                // Update gauges + purge per-block responses (memory + queued
                // SQL DELETE). known_responses stays populated to dedupe any
                // stale in-flight worker result for this range.
                let blocks: Option<Vec<u64>> = {
                    let mut acc = shared.accumulator.lock().unwrap_or_else(|e| e.into_inner());
                    let blocks = acc.get(batch_index).map(|batch| {
                        metrics::gauge!(crate::metrics::LAST_BATCH_SIGNED).set(batch_index as f64);
                        metrics::gauge!(crate::metrics::LAST_BATCH_SIGNED_FROM_BLOCK)
                            .set(batch.from_block as f64);
                        metrics::gauge!(crate::metrics::LAST_BATCH_SIGNED_TO_BLOCK)
                            .set(batch.to_block as f64);
                        metrics::gauge!(crate::metrics::LAST_BLOCK_SIGNED)
                            .set(batch.to_block as f64);
                        (batch.from_block..=batch.to_block).collect::<Vec<u64>>()
                    });
                    if let Some(ref b) = blocks {
                        acc.purge_responses(b);
                    }
                    blocks
                };
                let _ = blocks;
            }
            SignOutcome::InvalidSignatures { invalid_blocks, enclave_address } => {
                warn!(
                    batch_index,
                    invalid_count = invalid_blocks.len(),
                    %enclave_address,
                    "Key rotation detected — invalidating signature and re-executing"
                );

                if let Err(e) =
                    accumulator::invalidate_signature(&shared.accumulator, batch_index).await
                {
                    error!(batch_index, err = %e, "invalidate_signature failed");
                }

                {
                    let mut acc = shared.accumulator.lock().unwrap_or_else(|e| e.into_inner());
                    acc.purge_responses(&invalid_blocks);
                }

                {
                    let mut w = shared.known_responses.write().unwrap_or_else(|e| e.into_inner());
                    for b in &invalid_blocks {
                        w.remove(b);
                    }
                }

                for &block_number in &invalid_blocks {
                    spawn_re_execution(Arc::clone(&shared), block_number);
                }

                {
                    let mut g = shared.pending_key_check.lock().unwrap_or_else(|e| e.into_inner());
                    *g = Some(enclave_address);
                }
                spawn_key_check(Arc::clone(&shared), enclave_address);
            }
            SignOutcome::TaskFailed => {
                error!(batch_index, "Sign task crashed — batch will be retried on next tick");
            }
        }
    }
    info!("signer_worker exiting");
}

async fn finalization_worker(shared: Arc<OrchestratorShared>) {
    let mut tick = tokio::time::interval(FINALIZATION_TICK);
    tick.set_missed_tick_behavior(MissedTickBehavior::Skip);

    loop {
        tokio::select! {
            biased;
            _ = shared.shutdown.cancelled() => break,
            _ = tick.tick() => {}
        }

        let batch_snapshot = {
            let acc = shared.accumulator.lock().unwrap_or_else(|e| e.into_inner());
            acc.dispatched_for_finalization_check()
        };
        if !batch_snapshot.is_empty() {
            let done =
                check_finalized_batches_query(&shared.config.l1_provider, batch_snapshot).await;
            apply_finalization_changes(
                &shared.accumulator,
                &shared.known_responses,
                &shared.orchestrator_tip,
                done,
            )
            .await;
        }

        // Reorg detection for dispatched challenge rows. The active worker
        // owns the in-flight RBF lifecycle (dispatched + l1_block IS NULL);
        // here we only watch rows that have already observed a receipt.
        let challenge_snapshot: Vec<(i64, B256, u64)> = {
            let guard = shared.db.lock().unwrap_or_else(|e| e.into_inner());
            guard.dispatched_challenges_with_l1_block()
        };
        if !challenge_snapshot.is_empty() {
            apply_challenge_reorg_check(
                &shared.config.l1_provider,
                &shared.db_tx,
                challenge_snapshot,
            )
            .await;
        }
    }
    info!("finalization_worker exiting");
}

/// For each dispatched challenge row that has previously observed a
/// receipt: re-check the receipt against L1. A missing receipt indicates
/// reorg — clear `l1_block` so the active worker re-broadcasts (using
/// the persisted `sp1_proof_bytes`, no re-prove). A revert indicates the
/// receipt-watcher missed the failure earlier — clear RBF state and
/// alert.
async fn apply_challenge_reorg_check(
    provider: &dyn FinalityRpc,
    db_tx: &mpsc::UnboundedSender<crate::db::DbCommand>,
    snapshot: Vec<(i64, B256, u64)>,
) {
    use crate::db::{db_send_sync, ChallengePatch, SyncOp};

    for (challenge_id, tx_hash, recorded_l1_block) in snapshot {
        match provider.receipt_status(tx_hash).await {
            Ok(Some((true, _gas_used))) => {}
            Ok(Some((false, _))) => {
                metrics::counter!("orchestrator_challenge_reverted_post_mine_total").increment(1);
                warn!(
                    challenge_id,
                    %tx_hash,
                    recorded_l1_block,
                    "challenge tx receipt status=0 post-mine — clearing RBF state for retry"
                );
                let patch = ChallengePatch {
                    tx_hash: Some(None),
                    nonce: Some(None),
                    max_fee_per_gas: Some(None),
                    max_priority_fee_per_gas: Some(None),
                    l1_block: Some(None),
                    ..Default::default()
                };
                if let Err(e) =
                    db_send_sync(db_tx, SyncOp::PatchChallenge { challenge_id, patch }).await
                {
                    error!(challenge_id, err = %e, "patch_challenge (reverted post-mine) failed");
                }
            }
            Ok(None) => {
                metrics::counter!("orchestrator_challenge_reorg_detected_total").increment(1);
                warn!(
                    challenge_id,
                    %tx_hash,
                    recorded_l1_block,
                    "challenge tx receipt missing — suspecting reorg, clearing l1_block"
                );
                let patch = ChallengePatch { l1_block: Some(None), ..Default::default() };
                if let Err(e) =
                    db_send_sync(db_tx, SyncOp::PatchChallenge { challenge_id, patch }).await
                {
                    error!(challenge_id, err = %e, "patch_challenge (reorg) failed");
                }
            }
            Err(e) => warn!(challenge_id, %tx_hash, err = %e, "challenge receipt check failed"),
        }
    }
}

/// Startup-only sweep: drives each `Preconfirmed` row through one
/// finalization-check pass before workers spawn. `Sent` rows are left for
/// the dispatcher's resume path (`first_inflight_resume`).
async fn run_startup_sweep(
    accumulator: &BatchAccumulator,
    _db_tx: &mpsc::UnboundedSender<DbCommand>,
    last_batch_end: &mut Option<u64>,
    orchestrator_tip: &Arc<AtomicU64>,
    provider: &dyn FinalityRpc,
) {
    let snapshot = accumulator.dispatched_for_finalization_check();
    if snapshot.is_empty() {
        return;
    }
    info!(rows = snapshot.len(), "Startup: sweeping preconfirmed rows for finality");
    // We can't call `record_finalized` here because the accumulator is not
    // yet wrapped in the shared Mutex. Instead, after the sweep completes,
    // the steady-state finalization_worker will pick these up on its first
    // tick. We DO advance orchestrator_tip and last_batch_end so the driver
    // bootstrap reflects the post-sweep watermark immediately.
    let done = check_finalized_batches_query(provider, snapshot).await;
    let FinalizationDone::Observed { observations } = done else { return };
    for (batch_index, tx_hash, check) in observations {
        if !matches!(check, ReceiptCheck::Found { finalized: true }) {
            continue;
        }
        let Some(row) = accumulator.get(batch_index) else { continue };
        let block = row.to_block;
        *last_batch_end = Some(match *last_batch_end {
            Some(prev) => prev.max(block),
            None => block,
        });
        let current = orchestrator_tip.load(Ordering::Relaxed);
        if block > current {
            orchestrator_tip.store(block, Ordering::Relaxed);
        }
        info!(
            batch_index,
            %tx_hash,
            to_block = block,
            "Startup: batch already finalized on L1"
        );
    }
}

async fn apply_finalization_changes(
    accumulator: &Arc<std::sync::Mutex<BatchAccumulator>>,
    known_responses: &KnownResponses,
    orchestrator_tip: &Arc<AtomicU64>,
    done: FinalizationDone,
) {
    let FinalizationDone::Observed { observations } = done else {
        return;
    };
    for (batch_index, tx_hash, check) in observations {
        match check {
            ReceiptCheck::Found { finalized: true } => {
                let range = {
                    let acc = accumulator.lock().unwrap_or_else(|e| e.into_inner());
                    acc.get(batch_index).map(|b| (b.from_block, b.to_block))
                };
                if let Err(e) = accumulator::record_finalized(accumulator, batch_index).await {
                    error!(batch_index, err = %e, "record_finalized failed");
                    continue;
                }
                let Some((from_block, to_block)) = range else { continue };
                {
                    let mut w = known_responses.write().unwrap_or_else(|e| e.into_inner());
                    for b in from_block..=to_block {
                        w.remove(&b);
                    }
                }
                let current = orchestrator_tip.load(Ordering::Relaxed);
                if to_block > current {
                    orchestrator_tip.store(to_block, Ordering::Relaxed);
                }
                info!(batch_index, %tx_hash, to_block, "Batch finalized on L1");
            }
            ReceiptCheck::Found { finalized: false } => {
                // Receipt is observable but the L1 block is still in the
                // unfinalized window. No-op — wait for the next tick to
                // re-check finality.
            }
            ReceiptCheck::Reverted { kind } => {
                let still_ours = {
                    let acc = accumulator.lock().unwrap_or_else(|e| e.into_inner());
                    acc.dispatched_tx_hash(batch_index) == Some(tx_hash)
                };
                if !still_ours {
                    info!(
                        batch_index,
                        observed = %tx_hash,
                        "Stale ticker observation: dispatched tx_hash changed — skip"
                    );
                } else {
                    metrics::counter!(
                        crate::metrics::L1_DISPATCH_REJECTED_TOTAL,
                        "kind" => crate::metrics::revert_kind_label(kind),
                    )
                    .increment(1);
                    error!(
                        batch_index,
                        %tx_hash,
                        ?kind,
                        "Finalization-ticker rolling back reverted batch"
                    );
                    if let Err(e) =
                        accumulator::rollback_to_accepted(accumulator, batch_index).await
                    {
                        error!(batch_index, err = %e, "rollback_to_accepted failed");
                    }
                }
            }
            ReceiptCheck::Missing => {
                // Reorg recovery: the L1 event was observed
                // (status=Preconfirmed + l1_block set) but the receipt is
                // gone. Roll status back to `Sent` + clear l1_block so
                // the dispatcher's `first_inflight_resume` resumes RBF
                // against the persisted nonce.
                let still_ours = {
                    let acc = accumulator.lock().unwrap_or_else(|e| e.into_inner());
                    acc.dispatched_tx_hash(batch_index) == Some(tx_hash)
                };
                if !still_ours {
                    info!(
                        batch_index,
                        observed = %tx_hash,
                        "Stale Missing observation: dispatched tx_hash changed — skip"
                    );
                    continue;
                }
                metrics::counter!("orchestrator_batch_reorg_detected_total").increment(1);
                warn!(
                    batch_index,
                    %tx_hash,
                    "Batch tx receipt missing — suspecting reorg, rolling back to Sent"
                );
                if let Err(e) = accumulator::record_reorg_to_sent(accumulator, batch_index).await {
                    error!(batch_index, err = %e, "record_reorg_to_sent failed");
                }
            }
            ReceiptCheck::CheckFailed => {}
        }
    }
}

/// Owns the per-process `checkpoint` + `confirmed` state used to advance
/// the L2 watermark monotonically and triggers shutdown on `BatchReverted`.
async fn router(
    shared: Arc<OrchestratorShared>,
    mut l1_events: mpsc::Receiver<L1Event>,
    mut block_results: mpsc::Receiver<BlockResult>,
    initial_checkpoint: u64,
) {
    let mut checkpoint = initial_checkpoint;
    let mut confirmed: HashSet<u64> = HashSet::new();

    loop {
        tokio::select! {
            biased;
            _ = shared.shutdown.cancelled() => break,
            Some(event) = l1_events.recv() => {
                handle_l1_event(&shared, event).await;
            }
            Some(result) = block_results.recv() => {
                handle_block_result(&shared, result, &mut checkpoint, &mut confirmed).await;
            }
        }
    }
    info!("router exiting");
}

async fn handle_l1_event(shared: &OrchestratorShared, event: L1Event) {
    match event {
        L1Event::BatchCommitted { batch_index, from, to } => {
            if let Err(e) =
                accumulator::observe_committed(&shared.accumulator, batch_index, from, to).await
            {
                error!(batch_index, err = %e, "observe_committed failed");
            }
        }
        L1Event::BatchSubmitted { batch_index } => {
            if let Err(e) = accumulator::observe_submitted(&shared.accumulator, batch_index).await {
                error!(batch_index, err = %e, "observe_submitted failed");
            }
        }
        L1Event::BatchPreconfirmed { batch_index, tx_hash, l1_block } => {
            // The accumulator decides "external" vs "ours" by the row's
            // current status. If we owned the broadcast (status=Sent),
            // status flips to Preconfirmed and l1_block is overwritten with
            // the event-authoritative value. If we never broadcast
            // (status<=Accepted), the row is marked as external takeover
            // (nonce/fees cleared, tx_hash from the event).
            if let Err(e) = accumulator::observe_preconfirmed(
                &shared.accumulator,
                batch_index,
                tx_hash,
                l1_block,
            )
            .await
            {
                error!(batch_index, err = %e, "observe_preconfirmed failed");
                return;
            }
            {
                let acc = shared.accumulator.lock().unwrap_or_else(|e| e.into_inner());
                if let Some(batch) = acc.get(batch_index) {
                    crate::metrics::set_last_batch_dispatched(
                        batch_index,
                        batch.from_block,
                        batch.to_block,
                    );
                }
            }
        }
        L1Event::Checkpoint(l1_block) => {
            if shared.db_tx.send(DbCommand::Async(AsyncOp::SaveL1Checkpoint(l1_block))).is_err() {
                warn!(l1_block, "save_l1_checkpoint: db writer channel closed");
            }
        }
        L1Event::BatchReverted { from_batch_index, l1_block } => {
            // Wipe persists the recovery anchors before shutdown so the
            // supervisor's restart can re-resolve the L2 checkpoint from
            // the reverted batch via `resolve_l2_start_checkpoint`.
            info!(from_batch_index, l1_block, "BatchReverted — wiping DB and scheduling restart");
            if let Err(e) = db_send_sync(
                &shared.db_tx,
                SyncOp::WipeForRevert { start_batch_id: from_batch_index, l1_block },
            )
            .await
            {
                error!(from_batch_index, l1_block, err = %e, "wipe_for_revert failed");
            }
            shared.shutdown.cancel();
        }
        L1Event::BlockChallenged { batch_index, commitment } => {
            if let Err(e) = crate::challenge_db::observe_block_challenged(
                &shared.db_tx,
                &shared.config.l1_provider,
                shared.config.l1_rollup_addr,
                batch_index,
                commitment,
            )
            .await
            {
                warn!(batch_index, %commitment, err = %e, "observe_block_challenged failed");
            }
        }
        L1Event::BatchRootChallenged { batch_index } => {
            if let Err(e) =
                crate::challenge_db::observe_batch_root_challenged(&shared.db_tx, batch_index).await
            {
                warn!(batch_index, err = %e, "observe_batch_root_challenged failed");
            }
        }
        L1Event::ChallengeResolved { batch_index, commitment } => {
            if let Err(e) = crate::challenge_db::observe_resolved(
                &shared.db,
                &shared.db_tx,
                crate::db::ChallengeKind::Block,
                batch_index,
                Some(commitment),
            )
            .await
            {
                warn!(batch_index, %commitment, err = %e, "observe_resolved (block) failed");
            }
        }
        L1Event::BatchRootChallengeResolved { batch_index } => {
            if let Err(e) = crate::challenge_db::observe_resolved(
                &shared.db,
                &shared.db_tx,
                crate::db::ChallengeKind::BatchRoot,
                batch_index,
                None,
            )
            .await
            {
                warn!(batch_index, err = %e, "observe_resolved (batch_root) failed");
            }
        }
    }
}

async fn handle_block_result(
    shared: &OrchestratorShared,
    result: BlockResult,
    checkpoint: &mut u64,
    confirmed: &mut HashSet<u64>,
) {
    let block_number = result.block_number;

    if shared.known_responses.read().unwrap_or_else(|e| e.into_inner()).contains(&block_number) {
        return;
    }

    // Drop late results that fall at or below the highest finalized batch's
    // to_block. Derived from the accumulator (no separate scalar).
    {
        let acc = shared.accumulator.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(lbe) = acc.highest_finalized_to_block() {
            if block_number <= lbe {
                warn!(
                    block_number,
                    last_batch_end = lbe,
                    "Ignoring block result: already finalized"
                );
                return;
            }
        }
    }

    info!(block_number, "Block execution response received");
    {
        let mut acc = shared.accumulator.lock().unwrap_or_else(|e| e.into_inner());
        acc.insert_response(result.response);
    }

    metrics::gauge!(crate::metrics::LAST_BLOCK_EXECUTED).set(block_number as f64);

    shared.known_responses.write().unwrap_or_else(|e| e.into_inner()).insert(block_number);

    confirmed.insert(block_number);
    while confirmed.contains(&(*checkpoint + 1)) {
        *checkpoint += 1;
        confirmed.remove(checkpoint);
    }
    let cp = *checkpoint;
    shared.orchestrator_tip.store(cp, Ordering::Relaxed);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rbf::bump_fees;

    #[test]
    fn classify_revert_above_95pct_is_oog() {
        assert_eq!(classify_revert(95_000, 100_000), RevertKind::Oog);
        assert_eq!(classify_revert(85_591, 86_476), RevertKind::Oog);
    }

    #[test]
    fn classify_revert_below_95pct_is_logic() {
        assert_eq!(classify_revert(50_000, 100_000), RevertKind::Logic);
        assert_eq!(classify_revert(30_000, 100_000), RevertKind::Logic);
        assert_eq!(classify_revert(94_999, 100_000), RevertKind::Logic);
    }

    #[test]
    fn classify_revert_zero_limit_is_logic() {
        assert_eq!(classify_revert(0, 0), RevertKind::Logic);
    }

    #[test]
    fn bump_fees_20_percent_both_fields() {
        let (fee, tip, clamped) = bump_fees(1_000_000_000, 100_000_000, 20, 500_000_000_000);
        assert_eq!(fee, 1_200_000_000);
        assert_eq!(tip, 120_000_000);
        assert!(!clamped);
    }

    #[test]
    fn bump_fees_clamps_at_cap() {
        let cap = 500_000_000_000u128;
        let (fee, tip, clamped) = bump_fees(500_000_000_000, 100_000_000, 20, cap);
        assert_eq!(fee, cap);
        assert!(tip <= fee);
        assert!(clamped);
    }

    #[test]
    fn bump_fees_tip_never_exceeds_fee() {
        let cap = 1_000_000_000u128;
        let (fee, tip, _) = bump_fees(900_000_000, 900_000_000, 20, cap);
        assert_eq!(fee, cap);
        assert!(tip <= fee);
    }

    #[test]
    fn bump_fees_eip1559_minimum_always_met() {
        let max_fee: u128 = 100_000_000_000;
        let tip: u128 = 10_000_000_000;
        let (fee_out, tip_out, _) = bump_fees(max_fee, tip, 20, u128::MAX);
        assert!(fee_out >= max_fee * 1125 / 1000);
        assert!(tip_out >= tip * 1125 / 1000);
    }
}
