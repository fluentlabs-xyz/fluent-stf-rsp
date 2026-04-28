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
    collections::{HashMap, HashSet},
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
    accumulator::{BatchAccumulator, RbfResumeState},
    db::{Db, DbCommand},
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

/// Time window after which a still-missing receipt triggers a single warn-level
/// log per batch (then resets). With RBF in place the worker owns the broadcast
/// lifecycle, so this is purely a visibility aid — no action is taken. The
/// value is chosen to be meaningfully larger than a normal fee-bump climb to
/// the configured cap, so the log fires only on genuinely stuck dispatches
/// rather than on every in-flight bump cycle.
const RECEIPT_MISSING_WINDOW: Duration = Duration::from_secs(600);

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
    pub nitro_verifier_addr: Address,
    pub l1_provider: L1WriteProvider,
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
    /// Synchronous SQLite handle, used for the startup load and the
    /// `get_batch_signature` cache check inside `sign_batch_io`. All
    /// writes go through `db_tx` instead.
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
    /// `to_block` of the last L1-finalized dispatched batch. Read by the
    /// router to drop already-finalized block results, written by the
    /// finalization worker.
    pub(crate) last_batch_end: Arc<std::sync::Mutex<Option<u64>>>,
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
    Found,
    Reverted { kind: RevertKind },
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
    let mut accumulator = {
        let db = Arc::clone(&db);
        let db_tx = db_tx.clone();
        tokio::task::spawn_blocking(move || BatchAccumulator::with_db(db, db_tx))
            .await
            .expect("startup accumulator load panicked")
    };

    // Single-writer window — runs before any background task that could emit.
    {
        let checkpoint = db.lock().unwrap_or_else(|e| e.into_inner()).get_checkpoint();
        let dispatched_max: Option<(u64, u64, u64)> =
            accumulator.dispatched.iter().next_back().map(|(&i, d)| (i, d.from_block, d.to_block));
        let pending_signed = accumulator
            .batches
            .iter()
            .rev()
            .find(|(i, _)| accumulator.signatures.contains_key(i))
            .map(|(&i, b)| (i, b.from_block, b.to_block));
        let signed_max = match (pending_signed, dispatched_max) {
            (Some(s), Some(d)) if d.0 > s.0 => Some(d),
            (None, d) => d,
            (s, _) => s,
        };
        crate::metrics::seed_gauges_on_startup(checkpoint, dispatched_max, signed_max);
    }

    let mut initial_last_batch_end: Option<u64> =
        db.lock().unwrap_or_else(|e| e.into_inner()).get_last_batch_end();

    // Sweep dispatched rows from the prior process before spawning workers,
    // so the dispatcher does not try to resume one already finalized on L1.
    let mut missing_receipt_first_seen: HashMap<u64, tokio::time::Instant> = HashMap::new();
    run_startup_sweep(
        &mut accumulator,
        &db_tx,
        &mut initial_last_batch_end,
        &known_responses,
        &orchestrator_tip,
        &config.l1_provider,
        &mut missing_receipt_first_seen,
    )
    .await;
    drop(missing_receipt_first_seen);

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

    let from_block = {
        let db_guard = db.lock().unwrap_or_else(|e| e.into_inner());
        db_guard.get_checkpoint() + 1
    };

    let stored_nonce_floor: Option<u64> =
        accumulator.dispatched.values().filter_map(|d| d.nonce).max().map(|n| n + 1);
    let nonce_allocator = Arc::new(
        NonceAllocator::bootstrap(
            &config.l1_provider,
            config.l1_signer_address,
            stored_nonce_floor,
        )
        .await
        .expect("NonceAllocator bootstrap failed — L1 RPC unreachable at startup"),
    );

    let initial_checkpoint = from_block.saturating_sub(1);
    let target_tip = initial_checkpoint.max(initial_last_batch_end.unwrap_or(0));
    let current_tip = orchestrator_tip.load(Ordering::Relaxed);
    if target_tip > current_tip {
        orchestrator_tip.store(target_tip, Ordering::Relaxed);
    }

    let shared = Arc::new(OrchestratorShared {
        config,
        db: Arc::clone(&db),
        db_tx: db_tx.clone(),
        accumulator: Arc::new(std::sync::Mutex::new(accumulator)),
        known_responses: Arc::clone(&known_responses),
        nonce_allocator,
        orchestrator_tip: Arc::clone(&orchestrator_tip),
        pending_key_check: Arc::new(std::sync::Mutex::new(None)),
        last_batch_end: Arc::new(std::sync::Mutex::new(initial_last_batch_end)),
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

/// Pure-RPC half of the finalization check: takes a `dispatched` snapshot
/// and returns receipt observations without touching accumulator or DB.
async fn check_finalized_batches_query(
    provider: &dyn FinalityRpc,
    dispatched_snapshot: Vec<(u64, B256, u64)>,
) -> FinalizationDone {
    let Some(finalized_block) = provider.finalized_block_number().await else {
        return FinalizationDone::NoOp;
    };
    // Skip the `l1_block == 0` placeholder so the in-flight dispatcher
    // remains the sole receipt observer until its initial broadcast lands;
    // otherwise this loop and `finalize_dispatched` would race on the
    // same row.
    let candidates: Vec<(u64, B256)> = dispatched_snapshot
        .into_iter()
        .filter(|(_, _, l1_block)| *l1_block > 0 && *l1_block <= finalized_block)
        .map(|(bi, tx_hash, _)| (bi, tx_hash))
        .collect();
    if candidates.is_empty() {
        return FinalizationDone::NoOp;
    }
    let mut observations = Vec::with_capacity(candidates.len());
    for (batch_index, tx_hash) in candidates {
        let check = match provider.receipt_status(tx_hash).await {
            Ok(Some((true, _))) => ReceiptCheck::Found,
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
    db: Arc<Mutex<Db>>,
    db_tx: mpsc::UnboundedSender<DbCommand>,
    l2_provider: &alloy_provider::RootProvider,
    shutdown: &CancellationToken,
) -> SignOutcome {
    // Check for a cached signature from a previous attempt (survived crash).
    {
        let db_check = Arc::clone(&db);
        let sig = tokio::task::spawn_blocking(move || {
            db_check.lock().unwrap_or_else(|e| e.into_inner()).get_batch_signature(batch_index)
        })
        .await
        .unwrap_or(None);
        if let Some(resp) = sig {
            info!(batch_index, "Batch already signed (cached) — skipping /sign-batch-root");
            return SignOutcome::Signed { response: resp };
        }
    }

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
                // Skip persistence if shutdown is in flight: a concurrent
                // BatchReverted wipe may have queued WipeForRevert before us,
                // and persisting after the wipe would leak an orphan
                // batch_signatures row. On restart we re-sign anyway.
                if shutdown.is_cancelled() {
                    warn!(
                        batch_index,
                        "Sign succeeded during shutdown — dropping persistence to avoid wipe race"
                    );
                    return SignOutcome::TaskFailed;
                }
                if db_tx
                    .send(DbCommand::SaveBatchSignature { batch_index, resp: resp.clone() })
                    .is_err()
                {
                    warn!(batch_index, "save_batch_signature: db writer channel closed");
                }
                info!(batch_index, "Batch root signed and persisted");
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

/// `tip <= max_fee` is the EIP-1559 invariant; the third return value is
/// the `clamped` flag indicating the post-bump fee reached `cap`.
pub(crate) fn bump_fees(
    max_fee: u128,
    tip: u128,
    bump_percent: u32,
    cap: u128,
) -> (u128, u128, bool) {
    let factor = 100u128 + bump_percent as u128;
    let new_fee = max_fee.saturating_mul(factor) / 100;
    let new_tip = tip.saturating_mul(factor) / 100;
    let clamped = new_fee >= cap;
    let new_fee = new_fee.min(cap);
    let new_tip = new_tip.min(new_fee);
    (new_fee, new_tip, clamped)
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
    if let Some((batch_index, signature)) = acc.first_sequential_signed() {
        return DispatchTarget::Fresh { batch_index, signature };
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

        let pick: Option<(u64, u64, u64, Vec<EthExecutionResponse>)> = {
            let acc = shared.accumulator.lock().unwrap_or_else(|e| e.into_inner());
            acc.first_ready_unsigned().and_then(|batch_index| {
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
            Arc::clone(&shared.db),
            shared.db_tx.clone(),
            &shared.config.l2_provider,
            &shared.shutdown,
        )
        .await;

        match outcome {
            SignOutcome::Signed { response } => {
                info!(batch_index, "Batch signed — available for dispatch");

                // After `cache_signature`, future sign attempts for this
                // batch short-circuit to the cached signature, so the
                // per-block responses are unreachable — purge them now to
                // reclaim memory and SQLite rows. `known_responses` stays
                // populated to dedupe any stale in-flight result.
                {
                    let mut acc = shared.accumulator.lock().unwrap_or_else(|e| e.into_inner());
                    acc.cache_signature(batch_index, response);
                    let blocks: Option<Vec<u64>> = acc.get(batch_index).map(|batch| {
                        metrics::gauge!(crate::metrics::LAST_BATCH_SIGNED).set(batch_index as f64);
                        metrics::gauge!(crate::metrics::LAST_BATCH_SIGNED_FROM_BLOCK)
                            .set(batch.from_block as f64);
                        metrics::gauge!(crate::metrics::LAST_BATCH_SIGNED_TO_BLOCK)
                            .set(batch.to_block as f64);
                        metrics::gauge!(crate::metrics::LAST_BLOCK_SIGNED)
                            .set(batch.to_block as f64);
                        (batch.from_block..=batch.to_block).collect()
                    });
                    if let Some(b) = blocks {
                        acc.purge_responses(&b);
                    }
                }
            }
            SignOutcome::InvalidSignatures { invalid_blocks, enclave_address } => {
                warn!(
                    batch_index,
                    invalid_count = invalid_blocks.len(),
                    %enclave_address,
                    "Key rotation detected — purging stale responses and re-executing"
                );

                {
                    let mut acc = shared.accumulator.lock().unwrap_or_else(|e| e.into_inner());
                    acc.purge_responses(&invalid_blocks);
                    acc.delete_batch_signature(batch_index);
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
    let mut missing_receipt_first_seen: HashMap<u64, tokio::time::Instant> = HashMap::new();

    loop {
        tokio::select! {
            biased;
            _ = shared.shutdown.cancelled() => break,
            _ = tick.tick() => {}
        }

        let snapshot = {
            let acc = shared.accumulator.lock().unwrap_or_else(|e| e.into_inner());
            if !acc.has_dispatched() {
                continue;
            }
            acc.dispatched_snapshot()
        };

        let done = check_finalized_batches_query(&shared.config.l1_provider, snapshot).await;
        apply_finalization_changes_v2(
            &shared.accumulator,
            &shared.db_tx,
            &shared.last_batch_end,
            &shared.known_responses,
            &shared.orchestrator_tip,
            done,
            &mut missing_receipt_first_seen,
        )
        .await;
    }
    info!("finalization_worker exiting");
}

/// Startup-only sweep: drives each previously-dispatched batch through one
/// finalization-check pass, applying receipt observations directly to the
/// passed-in references. Mirrors the steady-state finalization loop but
/// runs before `OrchestratorShared` is constructed, so it operates on
/// pre-shared values (`&mut Option<u64>` for `last_batch_end`, etc.). The
/// `&mut` on `last_batch_end` is what lets the post-sweep `orchestrator_tip`
/// seed in `run()` reflect the highest `to_block` finalized here.
#[allow(clippy::too_many_arguments)]
async fn run_startup_sweep(
    accumulator: &mut BatchAccumulator,
    db_tx: &mpsc::UnboundedSender<DbCommand>,
    last_batch_end: &mut Option<u64>,
    known_responses: &KnownResponses,
    orchestrator_tip: &Arc<AtomicU64>,
    provider: &dyn FinalityRpc,
    missing_receipt_first_seen: &mut HashMap<u64, tokio::time::Instant>,
) {
    if !accumulator.has_dispatched() {
        return;
    }
    info!("Checking dispatched batches from previous run...");
    let snapshot = accumulator.dispatched_snapshot();
    let done = check_finalized_batches_query(provider, snapshot).await;
    let FinalizationDone::Observed { observations } = done else {
        return;
    };
    for (batch_index, tx_hash, check) in observations {
        match check {
            ReceiptCheck::Found => {
                let Some(dispatched) = accumulator.finalize_dispatched(batch_index) else {
                    continue;
                };
                {
                    let mut w = known_responses.write().unwrap_or_else(|e| e.into_inner());
                    for b in dispatched.from_block..=dispatched.to_block {
                        w.remove(&b);
                    }
                }
                let block = dispatched.to_block;
                if db_tx.send(DbCommand::SaveLastBatchEnd(block)).is_err() {
                    warn!(block, "save_last_batch_end: db writer channel closed");
                }
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
                    to_block = dispatched.to_block,
                    "Startup: batch finalized on L1 — cleaned up"
                );
            }
            ReceiptCheck::Reverted { kind } => {
                if accumulator.dispatched_tx_hash(batch_index) == Some(tx_hash) {
                    metrics::counter!(
                        crate::metrics::L1_DISPATCH_REJECTED_TOTAL,
                        "kind" => crate::metrics::revert_kind_label(kind),
                    )
                    .increment(1);
                    error!(
                        batch_index,
                        %tx_hash,
                        ?kind,
                        "Startup: undispatching reverted batch"
                    );
                    accumulator.undispatch(batch_index);
                }
            }
            ReceiptCheck::Missing => {
                missing_receipt_first_seen
                    .entry(batch_index)
                    .or_insert(tokio::time::Instant::now());
            }
            ReceiptCheck::CheckFailed => {}
        }
    }
}

/// Takes shared fields by reference rather than `&OrchestratorShared` so
/// the unit tests can drive it without building a full shared state.
#[allow(clippy::too_many_arguments)]
async fn apply_finalization_changes_v2(
    accumulator: &std::sync::Mutex<BatchAccumulator>,
    db_tx: &mpsc::UnboundedSender<DbCommand>,
    last_batch_end: &std::sync::Mutex<Option<u64>>,
    known_responses: &KnownResponses,
    orchestrator_tip: &Arc<AtomicU64>,
    done: FinalizationDone,
    missing_receipt_first_seen: &mut HashMap<u64, tokio::time::Instant>,
) {
    let FinalizationDone::Observed { observations } = done else {
        return;
    };
    for (batch_index, tx_hash, check) in observations {
        match check {
            ReceiptCheck::Found => {
                missing_receipt_first_seen.remove(&batch_index);
                let finalized = {
                    let mut acc = accumulator.lock().unwrap_or_else(|e| e.into_inner());
                    acc.finalize_dispatched(batch_index)
                };
                let Some(dispatched) = finalized else {
                    continue;
                };
                {
                    let mut w = known_responses.write().unwrap_or_else(|e| e.into_inner());
                    for b in dispatched.from_block..=dispatched.to_block {
                        w.remove(&b);
                    }
                }
                {
                    let block = dispatched.to_block;
                    if db_tx.send(DbCommand::SaveLastBatchEnd(block)).is_err() {
                        warn!(block, "save_last_batch_end: db writer channel closed");
                    }
                    let mut lbe = last_batch_end.lock().unwrap_or_else(|e| e.into_inner());
                    *lbe = Some(match *lbe {
                        Some(prev) => prev.max(block),
                        None => block,
                    });
                    // Monotonic to keep a late checkpoint update from
                    // rolling the tip backwards.
                    let current = orchestrator_tip.load(Ordering::Relaxed);
                    if block > current {
                        orchestrator_tip.store(block, Ordering::Relaxed);
                    }
                }
                info!(
                    batch_index,
                    %tx_hash,
                    to_block = dispatched.to_block,
                    "Batch finalized on L1 — cleaned up"
                );
            }
            ReceiptCheck::Reverted { kind } => {
                missing_receipt_first_seen.remove(&batch_index);
                // Skip if the snapshot's `tx_hash` is no longer current —
                // the dispatcher worker has already started a fresh
                // dispatch which will be observed on its own merits.
                let mut acc = accumulator.lock().unwrap_or_else(|e| e.into_inner());
                if acc.dispatched_tx_hash(batch_index) != Some(tx_hash) {
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
                        "Finalization-ticker undispatching reverted batch"
                    );
                    acc.undispatch(batch_index);
                }
            }
            ReceiptCheck::Missing => {
                let now = tokio::time::Instant::now();
                let first = *missing_receipt_first_seen.entry(batch_index).or_insert(now);
                let elapsed = now.duration_since(first);
                warn!(
                    batch_index,
                    %tx_hash,
                    elapsed_secs = elapsed.as_secs(),
                    "Receipt missing after finalization"
                );
                // The dispatcher owns the broadcast lifecycle. Forcing
                // an undispatch here would collide on the nonce it is
                // still bumping against; the dispatcher will either land
                // the tx or bail via STUCK_AT_CAP_TIMEOUT.
                if elapsed >= RECEIPT_MISSING_WINDOW {
                    warn!(
                        batch_index,
                        %tx_hash,
                        elapsed_secs = elapsed.as_secs(),
                        "Receipt still missing beyond window — dispatcher owns recovery; \
                         inspect dispatcher logs for batch"
                    );
                    // Reset the window so this logs at most once per cycle.
                    missing_receipt_first_seen.insert(batch_index, now);
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
            let mut acc = shared.accumulator.lock().unwrap_or_else(|e| e.into_inner());
            acc.set_batch(batch_index, from, to);
        }
        L1Event::BatchSubmitted { batch_index } => {
            let mut acc = shared.accumulator.lock().unwrap_or_else(|e| e.into_inner());
            acc.mark_batch_submitted(batch_index);
        }
        L1Event::BatchPreconfirmed { batch_index, tx_hash, l1_block } => {
            // External `BatchPreconfirmed`: if the batch is still in
            // `batches` (we hadn't dispatched yet), `mark_dispatched_external`
            // moves it to `dispatched` with `nonce = None`, which
            // `pick_next_dispatch_target` will skip. If we ARE mid-dispatch
            // (the row is already in `dispatched`), the call returns early
            // and the bump loop observes its own receipt via
            // `poll_for_terminal` — cancelling here would race that
            // observation and leak the loop's allocated nonce.
            {
                let mut acc = shared.accumulator.lock().unwrap_or_else(|e| e.into_inner());
                acc.mark_dispatched_external(batch_index, tx_hash, l1_block);
                if let Some(batch) = acc.dispatched.get(&batch_index) {
                    crate::metrics::set_last_batch_dispatched(
                        batch_index,
                        batch.from_block,
                        batch.to_block,
                    );
                }
            }
            info!(
                batch_index,
                %tx_hash,
                l1_block,
                "BatchPreconfirmed — marked dispatched via L1 event"
            );
        }
        L1Event::Checkpoint(l1_block) => {
            if shared.db_tx.send(DbCommand::SaveL1Checkpoint(l1_block)).is_err() {
                warn!(l1_block, "save_l1_checkpoint: db writer channel closed");
            }
        }
        L1Event::BatchReverted { from_batch_index, l1_block } => {
            // Wipe persists the recovery anchors before shutdown so the
            // supervisor's restart can re-resolve the L2 checkpoint from
            // the reverted batch via `resolve_l2_start_checkpoint`.
            info!(from_batch_index, l1_block, "BatchReverted — wiping DB and scheduling restart");
            if shared
                .db_tx
                .send(DbCommand::WipeForRevert { start_batch_id: from_batch_index, l1_block })
                .is_err()
            {
                error!(from_batch_index, l1_block, "wipe_for_revert: db writer channel closed");
            }
            shared.shutdown.cancel();
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

    {
        let lbe = *shared.last_batch_end.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(lbe) = lbe {
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
    if shared.db_tx.send(DbCommand::SaveCheckpoint(cp)).is_err() {
        warn!(cp, "save_checkpoint: db writer channel closed");
    }
    shared.orchestrator_tip.store(cp, Ordering::Relaxed);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{accumulator::BatchAccumulator, db::Db};
    use std::{
        collections::HashMap,
        sync::{
            atomic::{AtomicU64, Ordering},
            Mutex as StdMutex,
        },
    };

    fn temp_db() -> Arc<StdMutex<Db>> {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let id = COUNTER.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!("client_test_{id}_{}.db", std::process::id()));
        let db = Db::open(&path).unwrap();
        Arc::new(StdMutex::new(db))
    }

    /// Hand-rolled stub implementing the RPC methods
    /// [`check_finalized_batches_query`] actually touches.
    struct StubFinality {
        finalized: Option<u64>,
        receipt_statuses: HashMap<B256, Result<Option<(bool, u64)>, String>>,
        tx_gas_limits: HashMap<B256, Result<Option<u64>, String>>,
    }

    #[async_trait::async_trait]
    impl FinalityRpc for StubFinality {
        async fn finalized_block_number(&self) -> Option<u64> {
            self.finalized
        }
        async fn receipt_status(&self, tx_hash: B256) -> Result<Option<(bool, u64)>, String> {
            self.receipt_statuses.get(&tx_hash).cloned().unwrap_or(Ok(None))
        }
        async fn tx_gas_limit(&self, tx_hash: B256) -> Result<Option<u64>, String> {
            self.tx_gas_limits.get(&tx_hash).cloned().unwrap_or(Ok(None))
        }
    }

    fn register_dispatched(
        acc: &mut BatchAccumulator,
        batch_index: u64,
        from_block: u64,
        to_block: u64,
        tx_hash: B256,
        l1_block: u64,
    ) {
        acc.set_batch(batch_index, from_block, to_block);
        acc.mark_dispatched(batch_index, tx_hash, l1_block, 0, 0, 0);
    }

    struct FinalizationFixture {
        accumulator: Arc<std::sync::Mutex<BatchAccumulator>>,
        db_tx: mpsc::UnboundedSender<DbCommand>,
        last_batch_end: Arc<std::sync::Mutex<Option<u64>>>,
        known_responses: KnownResponses,
        tip: Arc<AtomicU64>,
        first_seen: HashMap<u64, tokio::time::Instant>,
    }

    impl FinalizationFixture {
        fn new() -> (Self, mpsc::UnboundedReceiver<DbCommand>) {
            let db = temp_db();
            let (db_tx, db_rx) = mpsc::unbounded_channel();
            let acc = BatchAccumulator::with_db(Arc::clone(&db), db_tx.clone());
            (
                Self {
                    accumulator: Arc::new(std::sync::Mutex::new(acc)),
                    db_tx,
                    last_batch_end: Arc::new(std::sync::Mutex::new(None)),
                    known_responses: Arc::new(RwLock::new(HashSet::new())),
                    tip: Arc::new(AtomicU64::new(0)),
                    first_seen: HashMap::new(),
                },
                db_rx,
            )
        }

        async fn run_once(&mut self, provider: &dyn FinalityRpc) {
            let snapshot = {
                let acc = self.accumulator.lock().unwrap();
                if !acc.has_dispatched() {
                    return;
                }
                acc.dispatched_snapshot()
            };
            let done = check_finalized_batches_query(provider, snapshot).await;
            apply_finalization_changes_v2(
                &self.accumulator,
                &self.db_tx,
                &self.last_batch_end,
                &self.known_responses,
                &self.tip,
                done,
                &mut self.first_seen,
            )
            .await;
        }
    }

    /// The finalization path must not undispatch from the missing-receipt
    /// window — that would collide with the dispatcher on the same nonce.
    #[tokio::test(start_paused = true)]
    async fn receipt_missing_window_logs_only() {
        let (mut fx, _db_rx) = FinalizationFixture::new();
        let tx_hash = B256::repeat_byte(0xAA);
        register_dispatched(&mut fx.accumulator.lock().unwrap(), 1, 100, 110, tx_hash, 500);

        let provider = StubFinality {
            finalized: Some(1000),
            receipt_statuses: HashMap::new(),
            tx_gas_limits: HashMap::new(),
        };

        fx.run_once(&provider).await;
        assert!(fx.accumulator.lock().unwrap().has_dispatched(), "batch must remain dispatched");
        assert!(fx.first_seen.contains_key(&1));

        tokio::time::advance(RECEIPT_MISSING_WINDOW + Duration::from_secs(1)).await;
        fx.run_once(&provider).await;
        assert!(
            fx.accumulator.lock().unwrap().has_dispatched(),
            "batch must remain dispatched after window"
        );
        assert!(fx.first_seen.contains_key(&1), "timer is reset but entry stays");
    }

    /// One `Ok(None)` on an early candidate must not abort the tick —
    /// later candidates with real receipts must still be finalized.
    #[tokio::test(start_paused = true)]
    async fn finalization_no_break_after_transient_none() {
        let (mut fx, _db_rx) = FinalizationFixture::new();
        let tx_a = B256::repeat_byte(0x01);
        let tx_b = B256::repeat_byte(0x02);
        {
            let mut acc = fx.accumulator.lock().unwrap();
            register_dispatched(&mut acc, 1, 100, 110, tx_a, 500);
            register_dispatched(&mut acc, 2, 111, 120, tx_b, 501);
        }

        let mut receipt_statuses = HashMap::new();
        receipt_statuses.insert(tx_a, Ok(None));
        receipt_statuses.insert(tx_b, Ok(Some((true, 50_000u64))));

        let provider =
            StubFinality { finalized: Some(1000), receipt_statuses, tx_gas_limits: HashMap::new() };

        fx.run_once(&provider).await;

        assert!(fx.first_seen.contains_key(&1), "batch 1 first_seen recorded");
        let acc = fx.accumulator.lock().unwrap();
        assert!(acc.has_dispatched(), "batch 1 remains dispatched (transient None)");
        assert!(
            !acc.dispatched.contains_key(&2),
            "batch 2 must be removed from dispatched after finalization"
        );
    }

    #[test]
    fn classify_revert_above_95pct_is_oog() {
        assert_eq!(classify_revert(95_000, 100_000), RevertKind::Oog);
        // Real on-chain numbers from batch 553 failed tx 0xc09798…cbbd.
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

    #[tokio::test(start_paused = true)]
    async fn finalization_ticker_oog_revert_undispatches() {
        let (mut fx, _db_rx) = FinalizationFixture::new();
        let tx_hash = B256::repeat_byte(0xCC);
        register_dispatched(&mut fx.accumulator.lock().unwrap(), 1, 100, 110, tx_hash, 500);

        let mut receipt_statuses = HashMap::new();
        receipt_statuses.insert(tx_hash, Ok(Some((false, 95_000u64))));
        let mut tx_gas_limits = HashMap::new();
        tx_gas_limits.insert(tx_hash, Ok(Some(100_000u64)));
        let provider = StubFinality { finalized: Some(1000), receipt_statuses, tx_gas_limits };

        fx.run_once(&provider).await;

        let acc = fx.accumulator.lock().unwrap();
        assert!(!acc.has_dispatched(), "batch must be undispatched");
        assert!(acc.get(1).is_some(), "batch must be back in pending after undispatch");
    }

    #[tokio::test(start_paused = true)]
    async fn finalization_ticker_logic_revert_undispatches() {
        let (mut fx, _db_rx) = FinalizationFixture::new();
        let tx_hash = B256::repeat_byte(0xDD);
        register_dispatched(&mut fx.accumulator.lock().unwrap(), 1, 100, 110, tx_hash, 500);

        let mut receipt_statuses = HashMap::new();
        receipt_statuses.insert(tx_hash, Ok(Some((false, 50_000u64))));
        let mut tx_gas_limits = HashMap::new();
        tx_gas_limits.insert(tx_hash, Ok(Some(100_000u64)));
        let provider = StubFinality { finalized: Some(1000), receipt_statuses, tx_gas_limits };

        fx.run_once(&provider).await;

        assert!(!fx.accumulator.lock().unwrap().has_dispatched(), "batch must be undispatched");
    }

    /// Stale ticker observation (snapshot tx_hash differs from current
    /// dispatched tx_hash) MUST NOT undispatch the live dispatch.
    #[tokio::test(start_paused = true)]
    async fn finalization_ticker_skips_stale_tx_hash() {
        let (mut fx, _db_rx) = FinalizationFixture::new();
        let stale_hash = B256::repeat_byte(0xAA);
        let live_hash = B256::repeat_byte(0xBB);

        // Register dispatch with stale_hash, then re-mark with live_hash via
        // record_rbf_bump so accumulator's dispatched.tx_hash = live_hash.
        {
            let mut acc = fx.accumulator.lock().unwrap();
            register_dispatched(&mut acc, 1, 100, 110, stale_hash, 500);
            acc.record_rbf_bump(1, live_hash, 0, 0);
        }

        // Provider returns reverted for stale_hash (the snapshot value).
        let mut receipt_statuses = HashMap::new();
        receipt_statuses.insert(stale_hash, Ok(Some((false, 95_000u64))));
        let mut tx_gas_limits = HashMap::new();
        tx_gas_limits.insert(stale_hash, Ok(Some(100_000u64)));
        let provider = StubFinality { finalized: Some(1000), receipt_statuses, tx_gas_limits };

        // Build the stale snapshot directly so the test can assert the
        // skip path that production hits when the snapshot's `tx_hash`
        // diverges from the live dispatched row.
        let stale_snapshot = vec![(1u64, stale_hash, 500u64)];
        let done = check_finalized_batches_query(&provider, stale_snapshot).await;
        apply_finalization_changes_v2(
            &fx.accumulator,
            &fx.db_tx,
            &fx.last_batch_end,
            &fx.known_responses,
            &fx.tip,
            done,
            &mut fx.first_seen,
        )
        .await;

        assert!(
            fx.accumulator.lock().unwrap().has_dispatched(),
            "live dispatch must remain untouched"
        );
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

    /// Sweep finalizes a row whose `to_block` is ahead of the pre-sweep
    /// `last_batch_end`. Both `last_batch_end` and `orchestrator_tip` must
    /// reflect the post-sweep value — otherwise downstream block-result
    /// gating uses a stale watermark and the driver's lookahead is wrong.
    #[tokio::test(start_paused = true)]
    async fn startup_sweep_advances_last_batch_end_and_tip() {
        let db = temp_db();
        let (db_tx, _db_rx) = mpsc::unbounded_channel();
        let mut acc = BatchAccumulator::with_db(Arc::clone(&db), db_tx.clone());

        let tx_hash = B256::repeat_byte(0xAA);
        register_dispatched(&mut acc, 1, 100, 200, tx_hash, 500);

        let mut receipt_statuses = HashMap::new();
        receipt_statuses.insert(tx_hash, Ok(Some((true, 50_000u64))));
        let provider =
            StubFinality { finalized: Some(1000), receipt_statuses, tx_gas_limits: HashMap::new() };

        let mut last_batch_end: Option<u64> = Some(50);
        let known_responses: KnownResponses = Arc::new(RwLock::new(HashSet::new()));
        let tip = Arc::new(AtomicU64::new(0));
        let mut first_seen: HashMap<u64, tokio::time::Instant> = HashMap::new();

        run_startup_sweep(
            &mut acc,
            &db_tx,
            &mut last_batch_end,
            &known_responses,
            &tip,
            &provider,
            &mut first_seen,
        )
        .await;

        assert_eq!(last_batch_end, Some(200), "last_batch_end advances to finalized to_block");
        assert_eq!(
            tip.load(Ordering::Relaxed),
            200,
            "orchestrator_tip advances to finalized to_block"
        );
        assert!(!acc.has_dispatched(), "row removed after finalize");
    }

    #[tokio::test(start_paused = true)]
    async fn startup_sweep_takes_max_when_multiple_finalize() {
        let db = temp_db();
        let (db_tx, _db_rx) = mpsc::unbounded_channel();
        let mut acc = BatchAccumulator::with_db(Arc::clone(&db), db_tx.clone());

        let tx_a = B256::repeat_byte(0x01);
        let tx_b = B256::repeat_byte(0x02);
        register_dispatched(&mut acc, 1, 100, 150, tx_a, 500);
        register_dispatched(&mut acc, 2, 151, 250, tx_b, 600);

        let mut receipt_statuses = HashMap::new();
        receipt_statuses.insert(tx_a, Ok(Some((true, 50_000u64))));
        receipt_statuses.insert(tx_b, Ok(Some((true, 50_000u64))));
        let provider =
            StubFinality { finalized: Some(1000), receipt_statuses, tx_gas_limits: HashMap::new() };

        let mut last_batch_end: Option<u64> = None;
        let known_responses: KnownResponses = Arc::new(RwLock::new(HashSet::new()));
        let tip = Arc::new(AtomicU64::new(0));
        let mut first_seen = HashMap::new();

        run_startup_sweep(
            &mut acc,
            &db_tx,
            &mut last_batch_end,
            &known_responses,
            &tip,
            &provider,
            &mut first_seen,
        )
        .await;

        assert_eq!(
            last_batch_end,
            Some(250),
            "last_batch_end is the max to_block across finalized rows"
        );
        assert_eq!(tip.load(Ordering::Relaxed), 250);
    }

    #[tokio::test(start_paused = true)]
    async fn startup_sweep_no_op_when_no_dispatched() {
        let db = temp_db();
        let (db_tx, _db_rx) = mpsc::unbounded_channel();
        let mut acc = BatchAccumulator::with_db(Arc::clone(&db), db_tx.clone());

        let provider = StubFinality {
            finalized: Some(1000),
            receipt_statuses: HashMap::new(),
            tx_gas_limits: HashMap::new(),
        };

        let mut last_batch_end: Option<u64> = Some(42);
        let known_responses: KnownResponses = Arc::new(RwLock::new(HashSet::new()));
        let tip = Arc::new(AtomicU64::new(7));
        let mut first_seen = HashMap::new();

        run_startup_sweep(
            &mut acc,
            &db_tx,
            &mut last_batch_end,
            &known_responses,
            &tip,
            &provider,
            &mut first_seen,
        )
        .await;

        assert_eq!(last_batch_end, Some(42), "untouched");
        assert_eq!(tip.load(Ordering::Relaxed), 7, "untouched");
    }

    fn make_response(block_number: u64) -> crate::types::EthExecutionResponse {
        crate::types::EthExecutionResponse {
            block_number,
            leaf: [0u8; 32],
            block_hash: B256::ZERO,
            signature: [0u8; 64],
        }
    }

    fn make_signature(byte: u8) -> crate::types::SubmitBatchResponse {
        crate::types::SubmitBatchResponse {
            batch_root: vec![0u8; 32],
            versioned_hashes: vec![],
            signature: vec![byte],
        }
    }

    /// A mid-RBF row (`l1_block == 0`) must be picked as resume even when
    /// a fresh signed batch is also ready.
    #[test]
    fn pick_next_dispatch_target_prefers_inflight_resume() {
        let mut acc = BatchAccumulator::new();

        // Batch 1: mid-RBF row from a prior lifetime.
        acc.set_batch(1, 10, 11);
        acc.insert_response(make_response(10));
        acc.insert_response(make_response(11));
        acc.mark_batch_submitted(1);
        acc.cache_signature(1, make_signature(0xAA));
        acc.mark_dispatched(1, B256::from([0xAA; 32]), 0, 5, 1_000, 100);

        // Batch 2: signed and ready, but resume must win.
        acc.set_batch(2, 12, 13);
        acc.insert_response(make_response(12));
        acc.insert_response(make_response(13));
        acc.mark_batch_submitted(2);
        acc.cache_signature(2, make_signature(0xBB));

        match pick_next_dispatch_target(&acc) {
            DispatchTarget::ResumeInFlight { batch_index, .. } => assert_eq!(batch_index, 1),
            other => panic!("expected ResumeInFlight, got {other:?}"),
        }
    }

    /// With no mid-RBF row, the picker falls through to the next fresh
    /// signed batch.
    #[test]
    fn pick_next_dispatch_target_falls_through_to_fresh() {
        let mut acc = BatchAccumulator::new();

        // Batch 1: already preconfirmed (real l1_block) — finalization
        // worker's territory, not a resume candidate.
        acc.set_batch(1, 10, 11);
        acc.insert_response(make_response(10));
        acc.insert_response(make_response(11));
        acc.mark_batch_submitted(1);
        acc.cache_signature(1, make_signature(0xAA));
        acc.mark_dispatched(1, B256::from([0xAA; 32]), 100, 5, 1_000, 100);

        // Batch 2: ready and signed; should be picked as Fresh.
        acc.set_batch(2, 12, 13);
        acc.insert_response(make_response(12));
        acc.insert_response(make_response(13));
        acc.mark_batch_submitted(2);
        acc.cache_signature(2, make_signature(0xBB));

        match pick_next_dispatch_target(&acc) {
            DispatchTarget::Fresh { batch_index, .. } => assert_eq!(batch_index, 2),
            other => panic!("expected Fresh, got {other:?}"),
        }
    }

    #[test]
    fn pick_next_dispatch_target_none_when_idle() {
        let acc = BatchAccumulator::new();
        match pick_next_dispatch_target(&acc) {
            DispatchTarget::None => {}
            other => panic!("expected None, got {other:?}"),
        }
    }
}
