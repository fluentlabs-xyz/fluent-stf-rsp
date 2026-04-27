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
    accumulator::{BatchAccumulator, DispatchedBatch},
    db::{Db, DbCommand},
    driver::Driver,
    l1_listener::L1Event,
    types::{EthExecutionResponse, SignBatchRootRequest, SubmitBatchResponse},
};
use l1_rollup_client::{
    batch_status, broadcast_preconfirm, build_preconfirm_tx, find_batch_preconfirm_event,
    get_batch_on_chain, is_nonce_too_low_error, nitro_verifier::is_key_registered, NonceAllocator,
};

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
const STUCK_AT_CAP_TIMEOUT: Duration = Duration::from_secs(300);

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

/// Ensures that if a spawned task's body panics or is dropped without sending
/// its normal result on a `mpsc::Sender`, a fallback payload is still sent so
/// the main-loop gate that guards the spawn is never silently latched.
///
/// `Drop` runs synchronously, so the failure send uses `try_send`. A full or
/// closed channel is ignored — under shutdown the main loop is being torn
/// down anyway, and the guard's single signing-at-a-time invariant means the
/// sign-done channel always has capacity in steady state.
struct DoneGuard<T: Send + 'static> {
    tx: mpsc::Sender<T>,
    failure: Option<T>,
}

impl<T: Send + 'static> DoneGuard<T> {
    fn arm(tx: mpsc::Sender<T>, failure: T) -> Self {
        Self { tx, failure: Some(failure) }
    }
    fn disarm(mut self) {
        self.failure = None;
    }
}

impl<T: Send + 'static> Drop for DoneGuard<T> {
    fn drop(&mut self) {
        if let Some(failure) = self.failure.take() {
            let _ = self.tx.try_send(failure);
        }
    }
}

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
    /// Private-key signer for `preconfirmBatch` transactions. Kept as a
    /// separate handle (alongside the wallet-bound `l1_provider`) so the RBF
    /// worker can sign bumped txs with an explicit nonce + fees, bypassing
    /// alloy's `NonceFiller` / `GasFiller`.
    pub l1_signer: Arc<dyn TxSigner<Signature> + Send + Sync>,
    /// Address derived from `l1_signer` — used for `get_transaction_count`
    /// and `estimate_gas(from: ...)` calls.
    pub l1_signer_address: Address,
    /// How often the RBF worker wakes up to poll the latest tx hash's
    /// receipt and rebroadcast with bumped fees when the receipt is
    /// missing.
    pub rbf_bump_interval: Duration,
    /// Per-bump percentage applied to both `max_fee_per_gas` and
    /// `max_priority_fee_per_gas`. Must be `>= 13` to satisfy the
    /// EIP-1559 +12.5 % replacement-tx minimum (20 by default).
    pub rbf_bump_percent: u32,
    /// Upper bound on `max_fee_per_gas`. Once reached, the worker keeps
    /// rebroadcasting at the cap and emits `CapReached` to main for
    /// loud operator logging.
    pub rbf_max_fee_per_gas_wei: u128,
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

/// Result of a batch signing attempt.
enum SignOutcome {
    /// Batch signed and persisted to DB.
    Signed { response: SubmitBatchResponse },
    /// Enclave key rotated — these blocks need re-execution.
    InvalidSignatures { invalid_blocks: Vec<u64>, enclave_address: Address },
    /// Task panicked or was dropped mid-flight. Main loop clears
    /// `signing_batch` and lets the next natural trigger retry signing.
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

/// Result of an L1 dispatch attempt.
#[derive(Debug)]
enum DispatchOutcome {
    /// TX included in L1 block — awaiting finalization.
    Submitted { tx_hash: B256, l1_block: u64 },
    /// L1 transaction failed — will retry with backoff.
    Failed,
    /// TX mined but reverted on-chain. `kind` decides retry policy:
    /// `Oog` → re-dispatch with inflated gas buffer; `Logic` → undispatch +
    /// backoff (give operators time to inspect before retrying).
    Reverted { tx_hash: B256, kind: RevertKind },
    /// Pre-flight L1 view-call revealed the batch is already `Preconfirmed`
    /// (or `Finalized`) — almost certainly by a previous instance of this
    /// orchestrator that crashed between broadcast and the `mark_dispatched`
    /// DB write. `l1_checkpoint` may have already advanced past the original
    /// `BatchPreconfirmed` event, so the live listener will not replay it;
    /// the main loop seeds `dispatched_batches` with the discovered on-chain
    /// coordinates and advances past this batch without sending a tx.
    AlreadyPreconfirmed { tx_hash: B256, l1_block: u64 },
    /// Task panicked or was dropped mid-flight. Treated identically to
    /// `Failed` by the main loop (clears gate, applies backoff).
    TaskFailed,
}

/// Progress signal emitted by the RBF worker back to the main loop. Drives
/// the accumulator's `mark_dispatched` (on initial broadcast) and
/// `record_rbf_bump` (on subsequent fee bumps) without giving the worker
/// direct DB access — main stays the single writer.
#[derive(Debug)]
enum RbfBumpEvent {
    /// First successful broadcast — main loop calls `mark_dispatched` with
    /// nonce + initial fees. Emitted exactly once per dispatch before any
    /// `Bumped` events.
    InitialBroadcast {
        tx_hash: B256,
        nonce: u64,
        max_fee_per_gas: u128,
        max_priority_fee_per_gas: u128,
    },
    /// Subsequent bump after a missed-receipt tick — main loop calls
    /// `record_rbf_bump` to persist the new tx hash + fees.
    Bumped { tx_hash: B256, max_fee_per_gas: u128, max_priority_fee_per_gas: u128 },
    /// Fee cap reached — worker continues rebroadcasting at the cap.
    /// Logged at WARN/ERROR level by main so operators are paged.
    CapReached { max_fee_per_gas: u128 },
}

/// Receipt observation for one dispatched batch, as seen by the finalization
/// query task. The main loop turns these into `finalize_dispatched` /
/// `undispatch` mutations once it has access to `missing_receipt_first_seen`.
enum ReceiptCheck {
    /// `get_transaction_receipt` returned `Some(..)` with `status = true` —
    /// batch is finalized.
    Found,
    /// `get_transaction_receipt` returned `Some(..)` with `status = false` —
    /// classified by [`classify_revert`] using `gas_used / gas_limit`.
    Reverted { kind: RevertKind },
    /// `get_transaction_receipt` returned `None` — receipt absent.
    Missing,
    /// The RPC itself errored — main loop leaves state untouched and lets
    /// the next tick retry.
    CheckFailed,
}

/// Result of a background finalization-check task.
enum FinalizationDone {
    /// Raw RPC observations for each candidate dispatched batch. The main
    /// loop merges these with `missing_receipt_first_seen` and applies
    /// accumulator mutations (`finalize_dispatched`, `undispatch`).
    Observed { observations: Vec<(u64, B256, ReceiptCheck)> },
    /// Finalized block unavailable or no candidates in this tick — nothing
    /// to apply. Produced by the query function itself.
    NoOp,
    /// Task panicked or was dropped mid-flight. Main loop clears
    /// `finalization_in_flight` and waits for the next tick.
    TaskFailed,
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
    db_tx: mpsc::Sender<DbCommand>,
    driver: Arc<Driver>,
    orchestrator_tip: Arc<AtomicU64>,
    mut l1_events: mpsc::Receiver<L1Event>,
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
        // A dispatched batch was signed before dispatch, so it counts toward
        // `signed_max`. Take the higher batch_index across pending-signed and
        // dispatched.
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

    let mut last_batch_end: Option<u64> =
        db.lock().unwrap_or_else(|e| e.into_inner()).get_last_batch_end();

    // Persists across finalization ticks: a batch still dispatched but with a
    // transiently missing receipt should not reset its observation window.
    let mut missing_receipt_first_seen: HashMap<u64, tokio::time::Instant> = HashMap::new();

    if accumulator.has_dispatched() {
        info!("Checking dispatched batches from previous run...");
        let snapshot = accumulator.dispatched_snapshot();
        let done = check_finalized_batches_query(&config.l1_provider, snapshot).await;
        let _outcome = apply_finalization_changes(
            done,
            &mut accumulator,
            &db_tx,
            &orchestrator_tip,
            &known_responses,
            &mut missing_receipt_first_seen,
            &mut last_batch_end,
        )
        .await;
    }

    // High-priority channel lives for the entire process. Capacity is tied
    // to EXECUTION_WORKERS to bound memory: each queued ExecutionTask may
    // hold a 30-80 MB payload, so large buffers cause OOM. `normal_rx` is
    // provided by `main.rs` so the feeder is supervised via the top-level
    // JoinSet.
    let (high_tx, high_rx) = async_channel::bounded::<ExecutionTask>(EXECUTION_WORKERS);
    let (result_tx, mut result_rx) = mpsc::channel::<BlockResult>(EXECUTION_WORKERS * 2);

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

    let (sign_done_tx, mut sign_done_rx) = mpsc::channel::<(u64, SignOutcome)>(8);
    let (dispatch_done_tx, mut dispatch_done_rx) = mpsc::channel::<(u64, DispatchOutcome)>(8);
    let (rbf_bump_tx, mut rbf_bump_rx) = mpsc::channel::<(u64, RbfBumpEvent)>(32);
    let (key_check_tx, mut key_check_rx) = mpsc::channel::<(Address, bool)>(4);
    let (finalization_done_tx, mut finalization_done_rx) = mpsc::channel::<FinalizationDone>(1);
    let mut finalization_ticker = tokio::time::interval(Duration::from_secs(30));
    finalization_ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);

    // Seed the nonce allocator from the max of (RPC pending, persisted
    // dispatched nonces + 1). Runs BEFORE the resume-worker spawn loop so
    // the first fresh dispatch after restart never collides with a resume
    // worker's in-mempool tx.
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
    // Seed the shared driver watermark with the higher of checkpoint or
    // last_batch_end so the driver's lookahead starts with an accurate view
    // of orchestrator progress (finalized batches imply the checkpoint has
    // already passed that block).
    orchestrator_tip.store(initial_checkpoint.max(last_batch_end.unwrap_or(0)), Ordering::Relaxed);

    let mut state = OrchestratorState {
        config: config.clone(),
        db: Arc::clone(&db),
        db_tx: db_tx.clone(),
        orchestrator_tip: Arc::clone(&orchestrator_tip),
        driver: Arc::clone(&driver),
        high_tx: high_tx.clone(),
        sign_done_tx,
        dispatch_done_tx,
        rbf_bump_tx,
        dispatch_cancel: HashMap::new(),
        key_check_tx,
        finalization_done_tx,
        checkpoint: initial_checkpoint,
        confirmed: HashSet::new(),
        signing_batch: None,
        dispatching_batch: None,
        finalization_in_flight: false,
        global_dispatch_attempts: 0,
        global_next_dispatch_allowed: None,
        pending_key_check: None,
        key_check_attempts: 0,
        known_responses: Arc::clone(&known_responses),
        last_batch_end,
        shutdown: shutdown.clone(),
        nonce_allocator,
    };

    // Startup resume: for every still-dispatched batch with persisted RBF
    // state, spawn a resume worker that reloads the signature from DB, picks
    // up the stored (nonce, tx_hash, fees), and either finds a receipt or
    // keeps bumping. Batches without RBF state (legacy rows pre-migration)
    // are handled by the finalization ticker only.
    let dispatched_resume: Vec<DispatchedBatch> =
        accumulator.dispatched.values().cloned().collect();
    for d in dispatched_resume {
        match (d.nonce, d.max_fee_per_gas, d.max_priority_fee_per_gas) {
            (Some(nonce), Some(max_fee_per_gas), Some(max_priority_fee_per_gas)) => {
                let db = Arc::clone(&db);
                let bi = d.batch_index;
                let sig_opt = tokio::task::spawn_blocking(move || {
                    db.lock().unwrap_or_else(|e| e.into_inner()).get_batch_signature(bi)
                })
                .await
                .unwrap_or(None);
                let Some(sig) = sig_opt else {
                    error!(
                        batch_index = d.batch_index,
                        "RBF resume: signature missing from DB — cannot rebroadcast; \
                         batch will be cleaned up by finalization ticker if tx lands"
                    );
                    continue;
                };
                state.spawn_rbf_resume(
                    d.batch_index,
                    sig.signature,
                    RbfResumeState {
                        nonce,
                        tx_hash: d.tx_hash,
                        max_fee_per_gas,
                        max_priority_fee_per_gas,
                    },
                );
            }
            _ => {
                warn!(
                    batch_index = d.batch_index,
                    tx_hash = %d.tx_hash,
                    "Dispatched batch has no RBF state (legacy row) — finalization \
                     ticker will poll receipt only; no bump worker spawned"
                );
            }
        }
    }

    info!(from_block, "Orchestrator ready — awaiting witnesses");

    loop {
        tokio::select! {
            biased;
            _ = shutdown.cancelled() => {
                info!("Shutdown requested — exiting orchestrator loop");
                break;
            }
            _ = finalization_ticker.tick() =>
                state.try_start_finalization(&accumulator),

            Some(done) = finalization_done_rx.recv() =>
                state.on_finalization_done(done, &mut accumulator, &mut missing_receipt_first_seen).await,

            // ── Block execution results ────────────────────────────────
            Some(result) = result_rx.recv() =>
                state.on_block_result(result, &mut accumulator).await,

            // ── L1 events ──────────────────────────────────────────────
            Some(event) = l1_events.recv() =>
                state.on_l1_event(event, &mut accumulator).await,

            // ── Batch signing completions ──────────────────────────────
            Some((batch_index, outcome)) = sign_done_rx.recv() =>
                state.on_sign_done(batch_index, outcome, &mut accumulator).await,

            // ── Batch dispatch completions ─────────────────────────────
            Some((batch_index, outcome)) = dispatch_done_rx.recv() =>
                state.on_dispatch_done(batch_index, outcome, &mut accumulator).await,

            // ── RBF worker progress events (per-bump) ──────────────────
            Some((batch_index, event)) = rbf_bump_rx.recv() =>
                state.on_rbf_bump(batch_index, event, &mut accumulator).await,

            // ── Key registration check results ─────────────────────────
            Some((addr, registered)) = key_check_rx.recv() => {
                if registered {
                    info!(
                        %addr,
                        attempts = state.key_check_attempts,
                        "Enclave key confirmed on L1"
                    );
                    state.pending_key_check = None;
                    state.key_check_attempts = 0;
                    state.try_sign_next_batch(&accumulator);
                    state.try_dispatch_next_batch(&accumulator);
                } else {
                    state.key_check_attempts += 1;
                    state.spawn_key_check(addr, Some(Duration::from_secs(10)));
                }
            }
        }
    }

    // ── Graceful drain ────────────────────────────────────────────────
    // The feeder owns `normal_tx` and drops it when shutdown cancels —
    // orchestrator only drops the pool channels it owns directly.
    info!("Closing worker task channels — draining workers");
    drop(high_tx);
    drop(result_tx);
    drop(result_rx);

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
// Orchestrator state
// ============================================================================

struct OrchestratorState {
    config: OrchestratorConfig,
    /// Kept for synchronous startup reads + the mid-flight
    /// `get_batch_signature` cache-check in `sign_batch_io`. All writes go
    /// through `db_tx` so this handle is never used for mutations at runtime.
    db: Arc<Mutex<Db>>,
    /// Sender into the DB writer actor. Every mutating SQL operation in the
    /// orchestrator routes through this channel.
    db_tx: mpsc::Sender<DbCommand>,
    /// Shared watermark read by the driver's lookahead gate. Advanced to
    /// `self.checkpoint` on every block-result update and to `last_batch_end`
    /// on finalization.
    orchestrator_tip: Arc<AtomicU64>,
    driver: Arc<Driver>,
    high_tx: AsyncSender<ExecutionTask>,
    sign_done_tx: mpsc::Sender<(u64, SignOutcome)>,
    dispatch_done_tx: mpsc::Sender<(u64, DispatchOutcome)>,
    /// Out-band channel on which the RBF worker reports per-bump progress
    /// (initial broadcast, each rebroadcast, fee cap). Main loop applies
    /// these to the accumulator — the worker never touches the DB directly.
    rbf_bump_tx: mpsc::Sender<(u64, RbfBumpEvent)>,
    /// One cancel token per in-flight dispatch. Fired by the main loop
    /// before any `undispatch` call so the RBF worker exits promptly and
    /// does not double-submit against a stale batch. Entries are removed
    /// either by `on_dispatch_done` (worker finished on its own) or by the
    /// undispatch-callsite (worker was cancelled).
    dispatch_cancel: HashMap<u64, CancellationToken>,
    key_check_tx: mpsc::Sender<(Address, bool)>,
    finalization_done_tx: mpsc::Sender<FinalizationDone>,
    checkpoint: u64,
    confirmed: HashSet<u64>,
    signing_batch: Option<u64>,
    dispatching_batch: Option<u64>,
    /// True while a finalization-check task is in flight. Cleared by
    /// `on_finalization_done` (including on `TaskFailed`). Prevents
    /// overlapping ticks from stacking RPC calls if one tick is slow.
    finalization_in_flight: bool,
    global_dispatch_attempts: u32,
    global_next_dispatch_allowed: Option<tokio::time::Instant>,
    pending_key_check: Option<Address>,
    /// Number of consecutive failed L1 reads for the currently pending
    /// key rotation. Reset on successful confirmation and whenever a fresh
    /// `InvalidSignatures` rotation starts. Used by `spawn_key_check` to
    /// thin logs at 1, 2, 4, 8, ... attempts during long outages.
    key_check_attempts: u64,
    known_responses: KnownResponses,
    /// `to_block` of the last L1-finalized dispatched batch. Used in
    /// `on_block_result` to drop results for already-finalized blocks
    /// (their rows were purged by `finalize_dispatched_batch`).
    last_batch_end: Option<u64>,
    /// Top-level process shutdown token. Fired by `BatchReverted` handling
    /// after DB wipe — the supervisor restarts the process, and the startup
    /// path picks up the persisted `start_batch_id` + `l1_checkpoint`.
    shutdown: CancellationToken,
    /// Single writer for L1 signer nonces across all dispatch paths. Fresh
    /// dispatches pull their nonce via [`NonceAllocator::allocate`]; resume
    /// dispatches carry the persisted nonce verbatim. Avoids the RPC
    /// `get_transaction_count(pending)` race that historically surfaced as
    /// "nonce too low" errors when resume workers and a fresh worker shared
    /// the same signer against a load-balanced RPC endpoint.
    nonce_allocator: Arc<NonceAllocator>,
}

impl OrchestratorState {
    /// Handle a completed block execution response: advance watermark, persist, try dispatch.
    async fn on_block_result(&mut self, result: BlockResult, accumulator: &mut BatchAccumulator) {
        let block_number = result.block_number;

        // Dedup: a response for this block is already persisted (races between
        // the feeder and re-execution can produce duplicates).
        if self.known_responses.read().unwrap_or_else(|e| e.into_inner()).contains(&block_number) {
            return;
        }

        if let Some(lbe) = self.last_batch_end {
            if block_number <= lbe {
                warn!(
                    block_number,
                    last_batch_end = lbe,
                    "Ignoring block result: already finalized"
                );
                return;
            }
        }

        info!(block_number, "Block execution response received");
        accumulator.insert_response(result.response).await;

        // `LAST_BLOCK_SIGNED` advances in `on_sign_done` (batch-level), not here.
        // The resulting `executed − signed` gap surfaces blocks already executed
        // but not yet included in a signed batch.
        metrics::gauge!(crate::metrics::LAST_BLOCK_EXECUTED).set(block_number as f64);

        self.known_responses.write().unwrap_or_else(|e| e.into_inner()).insert(block_number);

        self.confirmed.insert(block_number);
        while self.confirmed.contains(&(self.checkpoint + 1)) {
            self.checkpoint += 1;
            self.confirmed.remove(&self.checkpoint);
        }
        let cp = self.checkpoint;
        if self.db_tx.send(DbCommand::SaveCheckpoint(cp)).await.is_err() {
            warn!(cp, "save_checkpoint: db writer channel closed");
        }
        // Publish the new watermark so the driver's lookahead gate can observe it.
        self.orchestrator_tip.store(cp, Ordering::Relaxed);

        self.try_sign_next_batch(accumulator);
        self.try_dispatch_next_batch(accumulator);
    }

    /// Handle an L1 event: register a new batch or mark blobs accepted.
    async fn on_l1_event(&mut self, event: L1Event, accumulator: &mut BatchAccumulator) {
        match event {
            L1Event::BatchCommitted { batch_index, from, to } => {
                accumulator.set_batch(batch_index, from, to).await;
            }
            L1Event::BatchSubmitted { batch_index } => {
                accumulator.mark_batch_submitted(batch_index).await;
            }
            L1Event::BatchPreconfirmed { batch_index, tx_hash, l1_block } => {
                // Do NOT cancel the RBF worker here: cancel maps to
                // DispatchOutcome::Failed in run_rbf_dispatch, and
                // on_dispatch_done's Failed arm calls undispatch — which would
                // wipe the external dispatch we just recorded. The worker will
                // detect the on-chain confirmation naturally on its next 15s
                // poll cycle (receipt → Submitted → on_dispatch_done just
                // patches l1_block via record_dispatched_l1_block).
                accumulator.mark_dispatched_external(batch_index, tx_hash, l1_block).await;
                if let Some(batch) = accumulator.dispatched.get(&batch_index) {
                    crate::metrics::set_last_batch_dispatched(
                        batch_index,
                        batch.from_block,
                        batch.to_block,
                    );
                }
                self.global_dispatch_attempts = 0;
                self.global_next_dispatch_allowed = None;
                info!(
                    batch_index,
                    %tx_hash,
                    l1_block,
                    "BatchPreconfirmed — marked dispatched via L1 event"
                );
                self.try_dispatch_next_batch(accumulator);
            }
            L1Event::Checkpoint(l1_block) => {
                if self.db_tx.send(DbCommand::SaveL1Checkpoint(l1_block)).await.is_err() {
                    warn!(l1_block, "save_l1_checkpoint: db writer channel closed");
                }
            }
            L1Event::BatchReverted { from_batch_index, l1_block } => {
                // Admin force-reverted batches from `from_batch_index` onward.
                // Wipe the entire orchestrator DB and persist the recovery
                // anchors for the next startup, then trigger graceful
                // shutdown — the supervisor restarts the process, and the
                // startup path re-resolves the L2 checkpoint from the
                // reverted batch via `resolve_l2_start_checkpoint`.
                info!(
                    from_batch_index,
                    l1_block, "BatchReverted — wiping DB and scheduling restart"
                );
                if self
                    .db_tx
                    .send(DbCommand::WipeForRevert {
                        start_batch_id: from_batch_index,
                        // Persist the revert event's exact L1 block. Startup
                        // resumes the listener at `saved + 1`, so the
                        // BatchReverted event itself is not replayed but other
                        // events emitted in `l1_block + 1` are not skipped.
                        l1_block,
                    })
                    .await
                    .is_err()
                {
                    error!(from_batch_index, l1_block, "wipe_for_revert: db writer channel closed");
                }
                self.shutdown.cancel();
            }
        }
    }

    /// Queue a block for re-execution after key rotation.
    ///
    /// Resolves the witness via [`Driver::get_or_build_witness`] — cold-store
    /// hit is verbatim, cold miss rebuilds from MDBX — and pushes an eager
    /// task onto the high-priority execution queue.
    fn spawn_re_execution(&self, block_number: u64) {
        let h_tx = self.high_tx.clone();
        let driver = Arc::clone(&self.driver);
        let shutdown = self.shutdown.clone();
        tokio::spawn(async move {
            let mut backoff = Duration::from_secs(1);
            let mut attempts: u64 = 0;
            loop {
                if shutdown.is_cancelled() {
                    return;
                }
                match driver.get_or_build_witness(block_number).await {
                    Ok(Some(payload)) => {
                        if h_tx.send(ExecutionTask { block_number, payload }).await.is_err() {
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
                    _ = shutdown.cancelled() => return,
                    _ = tokio::time::sleep(backoff) => {}
                }
                backoff = (backoff * 2).min(Duration::from_secs(60));
            }
        });
    }

    /// Pick the next ready-but-unsigned batch and spawn a signing task.
    fn try_sign_next_batch(&mut self, accumulator: &BatchAccumulator) {
        if self.signing_batch.is_some() {
            return;
        }

        let Some(batch_index) = accumulator.first_ready_unsigned() else { return };
        let Some(batch) = accumulator.get(batch_index) else { return };

        let responses = accumulator.get_responses(batch.from_block, batch.to_block);
        self.signing_batch = Some(batch_index);

        let cfg = self.config.clone();
        let tx = self.sign_done_tx.clone();
        let db = Arc::clone(&self.db);
        let db_tx = self.db_tx.clone();
        let from_block = batch.from_block;
        let to_block = batch.to_block;
        let l2_provider = cfg.l2_provider.clone();
        let shutdown = self.shutdown.clone();

        tokio::spawn(async move {
            let guard = DoneGuard::arm(tx.clone(), (batch_index, SignOutcome::TaskFailed));
            let outcome = sign_batch_io(
                &cfg.http_client,
                &cfg.proxy_url,
                &cfg.api_key,
                batch_index,
                from_block,
                to_block,
                responses,
                db,
                db_tx,
                &l2_provider,
                &shutdown,
            )
            .await;
            if tx.send((batch_index, outcome)).await.is_ok() {
                guard.disarm();
            } else {
                warn!(batch_index, "Sign done channel closed");
            }
        });
    }

    /// Handle the result of a background batch signing task.
    async fn on_sign_done(
        &mut self,
        batch_index: u64,
        outcome: SignOutcome,
        accumulator: &mut BatchAccumulator,
    ) {
        self.signing_batch = None;

        match outcome {
            SignOutcome::Signed { response } => {
                info!(batch_index, "Batch signed — available for dispatch");
                accumulator.cache_signature(batch_index, response);

                // Early-purge responses: once the batch signature is cached,
                // those block responses are unreachable — `sign_batch_io` for
                // this batch would short-circuit to the cached signature
                // without touching the proxy, so a 409 re-execution path is
                // impossible. Dropping them now frees memory + SQLite rows
                // across the signed-but-not-yet-finalized window (which can
                // be long when L1 finalization is slow). `known_responses`
                // stays populated so any stale in-flight result is deduped.
                if let Some(batch) = accumulator.get(batch_index) {
                    metrics::gauge!(crate::metrics::LAST_BATCH_SIGNED).set(batch_index as f64);
                    metrics::gauge!(crate::metrics::LAST_BATCH_SIGNED_FROM_BLOCK)
                        .set(batch.from_block as f64);
                    metrics::gauge!(crate::metrics::LAST_BATCH_SIGNED_TO_BLOCK)
                        .set(batch.to_block as f64);
                    metrics::gauge!(crate::metrics::LAST_BLOCK_SIGNED).set(batch.to_block as f64);

                    let blocks: Vec<u64> = (batch.from_block..=batch.to_block).collect();
                    accumulator.purge_responses(&blocks).await;
                }

                self.try_sign_next_batch(accumulator);
                self.try_dispatch_next_batch(accumulator);
            }
            SignOutcome::InvalidSignatures { invalid_blocks, enclave_address } => {
                warn!(
                    batch_index,
                    invalid_count = invalid_blocks.len(),
                    %enclave_address,
                    "Key rotation detected — purging stale responses and re-executing"
                );

                accumulator.purge_responses(&invalid_blocks).await;
                accumulator.delete_batch_signature(batch_index).await;

                {
                    let mut w = self.known_responses.write().unwrap_or_else(|e| e.into_inner());
                    for b in &invalid_blocks {
                        w.remove(b);
                    }
                }

                for &block_number in &invalid_blocks {
                    self.spawn_re_execution(block_number);
                }

                self.pending_key_check = Some(enclave_address);
                // Fresh rotation — reset the counter so log thinning works
                // correctly across consecutive rotations.
                self.key_check_attempts = 0;
                self.spawn_key_check(enclave_address, None);
            }
            SignOutcome::TaskFailed => {
                error!(batch_index, "Sign task crashed — batch will be retried on next trigger");
            }
        }
    }

    /// Spawn an async task that checks whether `addr` is registered on L1.
    fn spawn_key_check(&self, addr: Address, delay: Option<Duration>) {
        let tx = self.key_check_tx.clone();
        let provider = self.config.l1_provider.clone();
        let verifier = self.config.nitro_verifier_addr;
        let attempts = self.key_check_attempts;
        tokio::spawn(async move {
            let guard = DoneGuard::arm(tx.clone(), (addr, false));
            if let Some(d) = delay {
                tokio::time::sleep(d).await;
            }
            let ok = is_key_registered(&provider, verifier, addr).await.unwrap_or(false);
            if !ok && is_log_worthy(attempts) {
                warn!(
                    %addr,
                    attempts,
                    "Enclave key still not registered — continuing to poll every 10s"
                );
            }
            if tx.send((addr, ok)).await.is_ok() {
                guard.disarm();
            } else {
                warn!(%addr, "Key check channel closed");
            }
        });
    }

    /// Pick the next sequential signed batch and spawn an RBF dispatch task.
    fn try_dispatch_next_batch(&mut self, accumulator: &BatchAccumulator) {
        if self.dispatching_batch.is_some() {
            return;
        }

        if let Some(allowed_at) = self.global_next_dispatch_allowed {
            if tokio::time::Instant::now() < allowed_at {
                return;
            }
        }

        if self.pending_key_check.is_some() {
            return;
        }

        let Some((batch_index, signature)) = accumulator.first_sequential_signed() else {
            return;
        };

        self.dispatching_batch = Some(batch_index);
        self.spawn_rbf_worker(batch_index, signature, None);
    }

    /// Spawn an RBF worker task. The shared setup between a fresh dispatch
    /// and a startup-resume dispatch lives here; callers differ only in
    /// whether they take the `dispatching_batch` gate (fresh does, resume
    /// does not — see `spawn_rbf_resume`) and whether they pass `resume` state.
    fn spawn_rbf_worker(
        &mut self,
        batch_index: u64,
        signature: Vec<u8>,
        resume: Option<RbfResumeState>,
    ) {
        // Child token of shutdown — fires automatically on global shutdown so
        // in-flight RBF workers exit promptly. Per-batch cancellation can still
        // call cancel.cancel() explicitly.
        let cancel = self.shutdown.child_token();
        self.dispatch_cancel.insert(batch_index, cancel.clone());

        let provider = self.config.l1_provider.clone();
        let contract = self.config.l1_rollup_addr;
        let verifier = self.config.nitro_verifier_addr;
        let signer = Arc::clone(&self.config.l1_signer);
        let signer_addr = self.config.l1_signer_address;
        let bump_interval = self.config.rbf_bump_interval;
        let bump_percent = self.config.rbf_bump_percent;
        let max_fee_cap = self.config.rbf_max_fee_per_gas_wei;
        let done_tx = self.dispatch_done_tx.clone();
        let bump_tx = self.rbf_bump_tx.clone();
        let nonce_allocator = Arc::clone(&self.nonce_allocator);
        let is_resume = resume.is_some();

        tokio::spawn(async move {
            let guard = DoneGuard::arm(done_tx.clone(), (batch_index, DispatchOutcome::TaskFailed));
            let outcome = run_rbf_dispatch(
                &provider,
                contract,
                verifier,
                signer.as_ref(),
                signer_addr,
                batch_index,
                signature,
                bump_interval,
                bump_percent,
                max_fee_cap,
                cancel,
                bump_tx,
                resume,
                &nonce_allocator,
            )
            .await
            .unwrap_or_else(|e| {
                error!(batch_index, err = %e, "RBF dispatch errored — treating as Failed");
                DispatchOutcome::Failed
            });
            if done_tx.send((batch_index, outcome)).await.is_ok() {
                guard.disarm();
            } else {
                warn!(batch_index, is_resume, "Dispatch done channel closed");
            }
        });
    }

    /// Handle the final outcome of an RBF dispatch task.
    ///
    /// By the time this fires, the task has either observed a receipt
    /// (Submitted / Reverted) or given up (Failed / TaskFailed). On the happy
    /// path `mark_dispatched` was already applied via an earlier
    /// `InitialBroadcast` event, so we only need to patch the `l1_block`
    /// placeholder. On any non-Submitted outcome we undispatch the batch
    /// (if it was ever dispatched) and apply global backoff — the next
    /// retry re-spawns a fresh RBF task.
    async fn on_dispatch_done(
        &mut self,
        batch_index: u64,
        outcome: DispatchOutcome,
        accumulator: &mut BatchAccumulator,
    ) {
        // Only clear the new-dispatch gate if THIS batch was the one it was
        // guarding. Startup-resume workers run outside the gate so they must
        // not clear it when they finish.
        if self.dispatching_batch == Some(batch_index) {
            self.dispatching_batch = None;
        }
        // Remove the cancel token (no-op if main already consumed it).
        self.dispatch_cancel.remove(&batch_index);

        match outcome {
            DispatchOutcome::Submitted { tx_hash, l1_block } => {
                self.global_dispatch_attempts = 0;
                self.global_next_dispatch_allowed = None;

                accumulator.record_dispatched_l1_block(batch_index, l1_block).await;

                // `mark_dispatched` (fired on `InitialBroadcast` earlier) moved
                // the entry out of `batches` into `dispatched` — read from there.
                if let Some(batch) = accumulator.dispatched.get(&batch_index) {
                    crate::metrics::set_last_batch_dispatched(
                        batch_index,
                        batch.from_block,
                        batch.to_block,
                    );
                }

                info!(
                    batch_index,
                    %tx_hash,
                    l1_block,
                    "Batch submitted to L1 — awaiting finalization"
                );

                self.try_dispatch_next_batch(accumulator);
            }

            DispatchOutcome::Reverted { tx_hash, kind } => {
                metrics::counter!(
                    crate::metrics::L1_DISPATCH_REJECTED_TOTAL,
                    "kind" => crate::metrics::revert_kind_label(kind),
                )
                .increment(1);
                error!(
                    batch_index,
                    %tx_hash,
                    ?kind,
                    "preconfirmBatch REVERTED on L1 — undispatching"
                );
                accumulator.undispatch(batch_index).await;
                match kind {
                    RevertKind::Oog => {
                        // Skip backoff — retry immediately. The retry rebuilds
                        // the template, calling `estimate_gas` afresh, so the
                        // new gas_limit reflects the latest state with the
                        // standard +20% buffer applied.
                        self.try_dispatch_next_batch(accumulator);
                    }
                    RevertKind::Logic => {
                        self.apply_dispatch_backoff("Dispatch reverted (logic)");
                    }
                }
            }

            DispatchOutcome::AlreadyPreconfirmed { tx_hash, l1_block } => {
                self.global_dispatch_attempts = 0;
                self.global_next_dispatch_allowed = None;
                info!(
                    batch_index,
                    %tx_hash,
                    l1_block,
                    "Batch already preconfirmed on L1 — seeding dispatched state from on-chain event"
                );
                accumulator.mark_dispatched_external(batch_index, tx_hash, l1_block).await;
                if let Some(batch) = accumulator.dispatched.get(&batch_index) {
                    crate::metrics::set_last_batch_dispatched(
                        batch_index,
                        batch.from_block,
                        batch.to_block,
                    );
                }
                self.try_dispatch_next_batch(accumulator);
            }

            DispatchOutcome::Failed => {
                warn!(batch_index, "Dispatch failed — undispatching to retry");
                accumulator.undispatch(batch_index).await;
                self.apply_dispatch_backoff("Dispatch failed");
            }
            DispatchOutcome::TaskFailed => {
                error!(batch_index, "Dispatch task crashed — undispatching to retry");
                accumulator.undispatch(batch_index).await;
                self.apply_dispatch_backoff("Dispatch task crashed");
            }
        }
    }

    /// Spawn an RBF worker that resumes from persisted state for a batch
    /// dispatched in a prior process lifetime. Unlike `try_dispatch_next_batch`,
    /// this does NOT set `dispatching_batch` — multiple resume workers can run
    /// concurrently, one per already-dispatched batch. The `on_dispatch_done`
    /// gate-clear is guarded so only the worker matching the gate clears it.
    fn spawn_rbf_resume(&mut self, batch_index: u64, signature: Vec<u8>, resume: RbfResumeState) {
        info!(
            batch_index,
            nonce = resume.nonce,
            stored_tx_hash = %resume.tx_hash,
            stored_max_fee_per_gas = resume.max_fee_per_gas,
            stored_max_priority_fee_per_gas = resume.max_priority_fee_per_gas,
            "RBF: resuming dispatched batch from persisted state"
        );
        self.spawn_rbf_worker(batch_index, signature, Some(resume));
    }

    /// Apply exponential-ish global dispatch backoff. Capped at 5 minutes so
    /// a transient L1 outage does not freeze dispatch forever.
    fn apply_dispatch_backoff(&mut self, reason: &'static str) {
        self.global_dispatch_attempts += 1;
        let delay_secs = (10u64 * self.global_dispatch_attempts as u64).min(300);
        self.global_next_dispatch_allowed =
            Some(tokio::time::Instant::now() + Duration::from_secs(delay_secs));
        warn!(
            attempts = self.global_dispatch_attempts,
            delay_secs, reason, "Dispatch backoff applied"
        );
    }

    /// Handle an RBF worker progress event. Drives the accumulator — main
    /// stays the single writer to DB.
    async fn on_rbf_bump(
        &mut self,
        batch_index: u64,
        event: RbfBumpEvent,
        accumulator: &mut BatchAccumulator,
    ) {
        match event {
            RbfBumpEvent::InitialBroadcast {
                tx_hash,
                nonce,
                max_fee_per_gas,
                max_priority_fee_per_gas,
            } => {
                // First successful broadcast — clear dispatch backoff, then
                // move pending → dispatched atomically with nonce + fees.
                // `l1_block` is written as 0 (placeholder); updated on
                // `DispatchOutcome::Submitted` via `record_dispatched_l1_block`.
                self.global_dispatch_attempts = 0;
                self.global_next_dispatch_allowed = None;
                accumulator
                    .mark_dispatched(
                        batch_index,
                        tx_hash,
                        0,
                        nonce,
                        max_fee_per_gas,
                        max_priority_fee_per_gas,
                    )
                    .await;
                info!(
                    batch_index,
                    %tx_hash,
                    nonce,
                    max_fee_per_gas,
                    max_priority_fee_per_gas,
                    "RBF: initial broadcast persisted"
                );
            }
            RbfBumpEvent::Bumped { tx_hash, max_fee_per_gas, max_priority_fee_per_gas } => {
                accumulator
                    .record_rbf_bump(
                        batch_index,
                        tx_hash,
                        max_fee_per_gas,
                        max_priority_fee_per_gas,
                    )
                    .await;
                info!(
                    batch_index,
                    %tx_hash,
                    max_fee_per_gas,
                    max_priority_fee_per_gas,
                    "RBF bump persisted"
                );
            }
            RbfBumpEvent::CapReached { max_fee_per_gas } => {
                error!(
                    batch_index,
                    max_fee_per_gas,
                    "RBF fee cap reached — operator attention required; worker continues \
                     rebroadcasting at cap"
                );
            }
        }
    }

    /// Spawn a finalization-check task if none is currently in flight. The
    /// RPC work runs off the main select arm; its result arrives via
    /// `finalization_done_rx` and is handled by `on_finalization_done`.
    fn try_start_finalization(&mut self, accumulator: &BatchAccumulator) {
        if self.finalization_in_flight {
            return;
        }
        if !accumulator.has_dispatched() {
            return;
        }
        self.finalization_in_flight = true;
        let provider = self.config.l1_provider.clone();
        let snapshot = accumulator.dispatched_snapshot();
        let tx = self.finalization_done_tx.clone();
        tokio::spawn(async move {
            let guard = DoneGuard::arm(tx.clone(), FinalizationDone::TaskFailed);
            let result = check_finalized_batches_query(&provider, snapshot).await;
            if tx.send(result).await.is_ok() {
                guard.disarm();
            } else {
                warn!("Finalization done channel closed");
            }
        });
    }

    /// Apply the finalization plan returned by the spawned task. Clears the
    /// in-flight gate, then mutates the accumulator / DB / known_responses.
    async fn on_finalization_done(
        &mut self,
        done: FinalizationDone,
        accumulator: &mut BatchAccumulator,
        missing_receipt_first_seen: &mut HashMap<u64, tokio::time::Instant>,
    ) {
        self.finalization_in_flight = false;
        let outcome = apply_finalization_changes(
            done,
            accumulator,
            &self.db_tx,
            &self.orchestrator_tip,
            &self.known_responses,
            missing_receipt_first_seen,
            &mut self.last_batch_end,
        )
        .await;
        if outcome.backoff_logic {
            self.apply_dispatch_backoff("Finalization-ticker observed logic-revert");
        }
        if outcome.changed {
            self.try_sign_next_batch(accumulator);
            self.try_dispatch_next_batch(accumulator);
        }
    }
}

// ============================================================================
// L1 finality helpers
// ============================================================================

/// Narrow RPC surface for finalized-batch checks. The blanket impl for any
/// `alloy` [`Provider`] lets production code pass `&l1_provider` as-is, while
/// tests substitute a hand-rolled stub.
#[async_trait::async_trait]
pub(crate) trait FinalityRpc: Send + Sync {
    async fn finalized_block_number(&self) -> Option<u64>;
    /// `Ok(Some((success, gas_used)))` if a receipt is present; `Ok(None)` if
    /// the tx is not yet mined; `Err` on RPC failure.
    async fn receipt_status(&self, tx_hash: B256) -> Result<Option<(bool, u64)>, String>;
    /// Fetch tx body to read `gas_limit` for revert classification. Returns
    /// `Ok(None)` if tx body unavailable; caller treats unknown as Logic.
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

/// RPC-only half of the old `check_finalized_batches`. Runs inside a spawned
/// task (see [`OrchestratorState::try_start_finalization`]) and returns a
/// plan of receipt observations. Does not touch the accumulator or DB.
///
/// `dispatched_snapshot` is a point-in-time clone produced via
/// [`BatchAccumulator::dispatched_snapshot`]. Between snapshot and apply the
/// only place that removes rows from `dispatched` is the main loop itself, so
/// every observation the apply half sees corresponds to a still-dispatched
/// batch.
async fn check_finalized_batches_query(
    provider: &dyn FinalityRpc,
    dispatched_snapshot: Vec<(u64, B256, u64)>,
) -> FinalizationDone {
    let Some(finalized_block) = provider.finalized_block_number().await else {
        return FinalizationDone::NoOp;
    };
    let candidates: Vec<(u64, B256)> = dispatched_snapshot
        .into_iter()
        .filter(|(_, _, l1_block)| *l1_block <= finalized_block)
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

/// Aggregated outcome of [`apply_finalization_changes`]. `changed` triggers a
/// follow-up `try_dispatch_next_batch` (so OOG-reverted batches that were
/// undispatched here are immediately re-dispatched with a fresh estimate).
/// `backoff_logic` triggers a single `apply_dispatch_backoff` (Logic reverts
/// indicate the contract is in an unexpected state — operator should inspect
/// before we burn more gas retrying).
#[derive(Debug, Default)]
struct FinalizationApplyOutcome {
    changed: bool,
    backoff_logic: bool,
}

/// Main-loop half: merges RPC observations with `missing_receipt_first_seen`
/// and applies accumulator/DB mutations. Returns the aggregated outcome so the
/// caller can drive `oog_attempts` + backoff + re-dispatch.
async fn apply_finalization_changes(
    done: FinalizationDone,
    accumulator: &mut BatchAccumulator,
    db_tx: &mpsc::Sender<DbCommand>,
    orchestrator_tip: &Arc<AtomicU64>,
    known_responses: &KnownResponses,
    missing_receipt_first_seen: &mut HashMap<u64, tokio::time::Instant>,
    last_batch_end: &mut Option<u64>,
) -> FinalizationApplyOutcome {
    let FinalizationDone::Observed { observations } = done else {
        return FinalizationApplyOutcome::default();
    };
    let mut out = FinalizationApplyOutcome::default();
    for (batch_index, tx_hash, check) in observations {
        match check {
            ReceiptCheck::Found => {
                missing_receipt_first_seen.remove(&batch_index);
                let Some(dispatched) = accumulator.finalize_dispatched(batch_index).await else {
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
                    if db_tx.send(DbCommand::SaveLastBatchEnd(block)).await.is_err() {
                        warn!(block, "save_last_batch_end: db writer channel closed");
                    }
                    *last_batch_end = Some(match *last_batch_end {
                        Some(prev) => prev.max(block),
                        None => block,
                    });
                    // Advance the shared driver watermark monotonically so a
                    // late checkpoint update does not roll the tip backward.
                    let current = orchestrator_tip.load(Ordering::Relaxed);
                    if block > current {
                        orchestrator_tip.store(block, Ordering::Relaxed);
                    }
                }
                info!(batch_index, %tx_hash, to_block = dispatched.to_block, "Batch finalized on L1 — cleaned up");
                out.changed = true;
            }
            ReceiptCheck::Reverted { kind } => {
                missing_receipt_first_seen.remove(&batch_index);
                // Stale-observation guard: ticker snapshot may have captured a
                // tx_hash that is no longer the current dispatched tx (worker
                // already processed the revert and main spawned a fresh
                // dispatch). Skip without action — the new dispatch is
                // healthy and will be observed on its own merits.
                if accumulator.dispatched_tx_hash(batch_index) != Some(tx_hash) {
                    info!(
                        batch_index,
                        observed = %tx_hash,
                        "Stale ticker observation: dispatched tx_hash changed — skip"
                    );
                    continue;
                }
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
                let did = accumulator.undispatch(batch_index).await;
                if did {
                    if matches!(kind, RevertKind::Logic) {
                        out.backoff_logic = true;
                    }
                    out.changed = true;
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
                // With RBF in place, the RBF worker owns the broadcast lifecycle
                // and is the sole authority on "is this tx landed". Force-
                // undispatching here would collide on the same nonce the RBF
                // worker is still bumping against. Log only; the worker will
                // either eventually land the tx or bail via STUCK_AT_CAP_TIMEOUT,
                // at which point main applies backoff + retry.
                //
                // warn-level (not error) because this branch takes no action —
                // the RBF worker is authoritative. STUCK_AT_CAP_TIMEOUT caps
                // the actual stuck-forever failure mode. RECEIPT_MISSING_WINDOW
                // is deliberately chosen to be > a full cap climb so this log
                // fires only on genuinely stalled dispatches.
                if elapsed >= RECEIPT_MISSING_WINDOW {
                    warn!(
                        batch_index,
                        %tx_hash,
                        elapsed_secs = elapsed.as_secs(),
                        "Receipt still missing beyond window — RBF worker owns recovery; \
                         inspect RBF logs for batch"
                    );
                    // Reset timer so this logs at most once per window.
                    missing_receipt_first_seen.insert(batch_index, now);
                }
            }
            ReceiptCheck::CheckFailed => {
                // Already warned in the query half — the main loop does
                // nothing so the next tick retries.
            }
        }
    }
    out
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
    db_tx: mpsc::Sender<DbCommand>,
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
                    .await
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

// ============================================================================
// RBF dispatch worker
// ============================================================================

/// State carried over from a prior process lifetime, used by the startup
/// resume path to skip the initial broadcast (a tx with this nonce is
/// already in the mempool) and enter the bump loop directly.
#[derive(Debug, Clone, Copy)]
struct RbfResumeState {
    nonce: u64,
    tx_hash: B256,
    max_fee_per_gas: u128,
    max_priority_fee_per_gas: u128,
}

/// Drive a single batch's `preconfirmBatch` tx through broadcast → RBF-bump →
/// receipt. Runs inside the dispatch task spawned by
/// [`OrchestratorState::try_dispatch_next_batch`] (fresh dispatch) or by
/// [`OrchestratorState::spawn_rbf_resume`] (startup resume from persisted
/// RBF state).
///
/// Lifecycle (fresh dispatch — `resume: None`):
/// 1. Build the tx template (nonce + gas_limit + calldata) and estimate initial EIP-1559 fees,
///    clamping to `max_fee_cap`.
/// 2. Broadcast the initial tx, then emit `InitialBroadcast` so main persists the atomic
///    pending→dispatched transition with nonce + fees + tx_hash.
/// 3. Enter the bump loop.
///
/// Lifecycle (resume — `resume: Some(..)`):
/// 1. Build the tx template using the STORED nonce (so the first rebroadcast is a replacement for
///    the in-mempool tx, not a fresh send).
/// 2. Skip the initial broadcast — the pre-restart tx is already in the mempool under
///    `resume.tx_hash` at `resume.max_fee_per_gas`.
/// 3. Enter the bump loop with that state preloaded.
///
/// Bump loop (shared):
///   Sleep `bump_interval`; poll the latest tx hash's receipt; on `Some`
///   return `Submitted` / `Reverted`; on `None` bump both fees by
///   `bump_percent`, rebroadcast, emit `Bumped` / `CapReached`.
///
/// `cancel` is watched by the sleep `select!`; when fired, return `Failed`
/// so the main loop can clear the dispatch gate without double-submitting.
///
/// Returns `Err` only for unrecoverable errors during the initial setup
/// (template build, initial fee estimate, initial broadcast). Once the loop
/// is entered, transient RPC errors are logged and retried on the next
/// interval.
#[allow(clippy::too_many_arguments)]
async fn run_rbf_dispatch(
    provider: &L1WriteProvider,
    contract: Address,
    verifier: Address,
    signer: &(dyn TxSigner<Signature> + Send + Sync),
    signer_addr: Address,
    batch_index: u64,
    signature: Vec<u8>,
    bump_interval: Duration,
    bump_percent: u32,
    max_fee_cap: u128,
    cancel: CancellationToken,
    bump_tx: mpsc::Sender<(u64, RbfBumpEvent)>,
    resume: Option<RbfResumeState>,
    nonce_allocator: &NonceAllocator,
) -> eyre::Result<DispatchOutcome> {
    // Pre-flight on-chain reconciliation.
    //
    // A crash window between `broadcast_preconfirm` and the first
    // `InitialBroadcast` event can leave a batch preconfirmed on L1 while
    // SQLite still holds it in `pending_batches` with no dispatched row.
    // On the next startup the `l1_checkpoint` may already sit past the
    // original `BatchPreconfirmed` event, so the live listener will never
    // replay it, and every retry here would fail deterministically inside
    // `build_preconfirm_tx → estimate_gas → execution reverted:
    // InvalidBatchStatus` — classic infinite backoff loop.
    //
    // The resume path is just as vulnerable: a stored nonce does NOT let
    // us skip `estimate_gas` — `build_preconfirm_tx` re-runs it on every
    // RBF iteration, and it reverts the instant the batch moves past
    // `Submitted`. So the pre-flight has to run regardless of `resume`.
    //
    // Reconciliation cheap-path: one `eth_call getBatch(i)` tells us the
    // real on-chain status. Any of `Preconfirmed`, `Challenged`, `Finalized`
    // means the `BatchPreconfirmed(batchIndex)` event *may* have been
    // emitted — Preconfirmed and Finalized unambiguously so, Challenged
    // conditionally (a block-challenge can be opened from either `Submitted`
    // or `Preconfirmed`; only the latter carries a preceding event). We
    // treat the three uniformly: look for the event in the safe (finalized)
    // L1 range; if found, surface `AlreadyPreconfirmed`; if not, the batch
    // was challenged out of `Submitted` (or the event is still in the
    // unfinalized window) and we back off.
    //
    // The event scan is bounded at the L1 `finalized` head. Without that
    // bound a reorg could revert the event out of canonical history while
    // we've already seeded `dispatched_batches` from its tx_hash, leaving
    // the finalization ticker forever waiting for a receipt that no longer
    // exists. Reconciliation latency = L1 finality delay (~13 min on
    // mainnet), which is fine — the alternative was an infinite retry loop.
    {
        // Honor cancel/shutdown across pre-flight RPC calls so workers exit
        // promptly without an extra L1 round-trip after the process starts
        // shutting down.
        let on_chain = tokio::select! {
            _ = cancel.cancelled() => return Ok(DispatchOutcome::Failed),
            res = get_batch_on_chain(provider, contract, batch_index) => res
                .map_err(|e| eyre::eyre!("pre-flight getBatch({batch_index}) failed: {e}"))?,
        };
        match on_chain.status {
            batch_status::SUBMITTED => {
                // Normal path — proceed to build + broadcast.
            }
            batch_status::PRECONFIRMED | batch_status::CHALLENGED | batch_status::FINALIZED => {
                let finalized_block = tokio::select! {
                    _ = cancel.cancelled() => return Ok(DispatchOutcome::Failed),
                    res = provider.get_block_by_number(BlockNumberOrTag::Finalized) => res
                        .map_err(|e| eyre::eyre!("get_block(Finalized) failed: {e}"))?,
                };
                let finalized_head = finalized_block
                    .ok_or_else(|| {
                        eyre::eyre!("L1 RPC returned no finalized block — chain not progressing?")
                    })?
                    .header
                    .number;
                if on_chain.accepted_at_block > finalized_head {
                    // Batch was committed more recently than finality — its
                    // preconfirm event cannot possibly be in the finalized
                    // range yet. Back off and re-check after L1 finality
                    // catches up.
                    warn!(
                        batch_index,
                        status = on_chain.status,
                        accepted_at_block = on_chain.accepted_at_block,
                        finalized_head,
                        "pre-flight: batch commit still unfinalized on L1 — backing off"
                    );
                    return Ok(DispatchOutcome::Failed);
                }
                let info = tokio::select! {
                    _ = cancel.cancelled() => return Ok(DispatchOutcome::Failed),
                    res = find_batch_preconfirm_event(
                        provider,
                        contract,
                        batch_index,
                        on_chain.accepted_at_block,
                        finalized_head,
                    ) => res.map_err(|e| {
                        eyre::eyre!("find_batch_preconfirm_event({batch_index}) failed: {e}")
                    })?,
                };
                let Some(info) = info else {
                    // Two legitimate reasons for a miss:
                    // 1. `Challenged` opened from `Submitted` — no preceding BatchPreconfirmed
                    //    event was ever emitted.
                    // 2. Event was emitted but not yet finalized; we'll pick it up on the next
                    //    retry once finality catches up.
                    // Either way, do not broadcast — preconfirmBatch would
                    // revert with InvalidBatchStatus.
                    warn!(
                        batch_index,
                        status = on_chain.status,
                        "pre-flight: batch not Submitted and no finalized \
                         BatchPreconfirmed event — backing off"
                    );
                    return Ok(DispatchOutcome::Failed);
                };
                info!(
                    batch_index,
                    status = on_chain.status,
                    tx_hash = %info.tx_hash,
                    l1_block = info.l1_block,
                    "pre-flight: batch already preconfirmed on L1 — skipping broadcast"
                );
                return Ok(DispatchOutcome::AlreadyPreconfirmed {
                    tx_hash: info.tx_hash,
                    l1_block: info.l1_block,
                });
            }
            batch_status::NONE | batch_status::COMMITTED => {
                // Either the batch doesn't exist on L1 yet (listener hasn't
                // caught up to its BatchCommitted) or DA is still pending
                // (BatchSubmitted not yet emitted). Either way `preconfirmBatch`
                // would revert with InvalidBatchStatus. Back off; the normal
                // L1 event stream will wake us up when the batch reaches
                // Submitted.
                warn!(
                    batch_index,
                    status = on_chain.status,
                    "pre-flight: batch not yet Submitted on L1 — backing off"
                );
                return Ok(DispatchOutcome::Failed);
            }
            other => {
                warn!(
                    batch_index,
                    status = other,
                    "pre-flight: unexpected on-chain batch status — backing off"
                );
                return Ok(DispatchOutcome::Failed);
            }
        }
    }

    // Nonce assignment: fresh dispatches pull from the shared allocator (a
    // single-writer `fetch_add`, so no race against concurrent resume workers);
    // resume carries the persisted nonce verbatim so rebroadcast replaces the
    // already-in-mempool tx.
    let nonce = match resume {
        Some(r) => r.nonce,
        None => nonce_allocator.allocate(),
    };

    // For fresh dispatches, any failure before `broadcast_preconfirm` succeeds
    // must return the allocated nonce so future allocations don't skip a slot
    // (which would leave the signer's outbox wedged until manual top-up).
    // `release` is a tail-CAS: it closes the gap only when no other allocation
    // raced in between, which is the common case under `dispatching_batch`
    // serialization.
    let template = tokio::select! {
        _ = cancel.cancelled() => {
            if resume.is_none() {
                nonce_allocator.release(nonce);
            }
            return Ok(DispatchOutcome::Failed);
        }
        res = build_preconfirm_tx(
            provider,
            contract,
            verifier,
            batch_index,
            signature,
            signer_addr,
            nonce,
        ) => match res {
            Ok(t) => t,
            Err(e) => {
                if resume.is_none() {
                    nonce_allocator.release(nonce);
                }
                return Err(e);
            }
        }
    };

    let (mut max_fee_per_gas, mut max_priority_fee_per_gas, initial_hash, emit_initial) =
        match resume {
            Some(r) => (r.max_fee_per_gas, r.max_priority_fee_per_gas, r.tx_hash, false),
            None => {
                let est = tokio::select! {
                    _ = cancel.cancelled() => {
                        nonce_allocator.release(nonce);
                        return Ok(DispatchOutcome::Failed);
                    }
                    res = provider.estimate_eip1559_fees() => match res {
                        Ok(est) => est,
                        Err(e) => {
                            nonce_allocator.release(nonce);
                            return Err(eyre::eyre!("estimate_eip1559_fees failed: {e}"));
                        }
                    }
                };
                let mut fee = est.max_fee_per_gas;
                let mut tip = est.max_priority_fee_per_gas;
                if fee >= max_fee_cap {
                    fee = max_fee_cap;
                    if tip > max_fee_cap {
                        tip = max_fee_cap;
                    }
                    warn!(
                        batch_index,
                        max_fee_cap, "RBF: initial fee at/above cap — clamping and proceeding"
                    );
                }
                let broadcast_res = tokio::select! {
                    _ = cancel.cancelled() => {
                        nonce_allocator.release(nonce);
                        return Ok(DispatchOutcome::Failed);
                    }
                    res = broadcast_preconfirm(provider, signer, &template, fee, tip) => res,
                };
                let hash = match broadcast_res {
                    Ok(h) => h,
                    Err(e) => {
                        let msg = e.to_string();
                        metrics::counter!(
                            crate::metrics::L1_BROADCAST_FAILURES_TOTAL,
                            "kind" => crate::metrics::broadcast_failure_kind(&msg),
                        )
                        .increment(1);
                        if is_nonce_too_low_error(&msg) {
                            // Our `pending` view was stale; chain is ahead.
                            // Resync the allocator so the next fresh dispatch
                            // skips any consumed slots rather than replaying
                            // the same error.
                            if let Err(sync_err) =
                                nonce_allocator.resync(provider, signer_addr).await
                            {
                                warn!(
                                    batch_index,
                                    err = %sync_err,
                                    "NonceAllocator resync after nonce-too-low failed"
                                );
                            }
                            // Do NOT release: a tx at this nonce already
                            // exists on-chain (whoever beat us to it). The
                            // caller will observe Failed, undispatch, and
                            // pre-flight reconciliation on the next retry
                            // will surface AlreadyPreconfirmed if it was us.
                        } else {
                            nonce_allocator.release(nonce);
                        }
                        return Err(eyre::eyre!("initial broadcast failed: {msg}"));
                    }
                };
                info!(
                    batch_index,
                    nonce = template.nonce,
                    %hash,
                    max_fee_per_gas = fee,
                    max_priority_fee_per_gas = tip,
                    "preconfirmBatch tx broadcast (initial)"
                );
                (fee, tip, hash, true)
            }
        };

    let mut at_cap_logged = max_fee_per_gas >= max_fee_cap;
    // When bumping clamps to the cap for the first time, we stamp the
    // instant so a subsequent stuck-at-cap window can time out the worker
    // rather than loop forever against a mempool that refuses to mine.
    let mut stuck_at_cap_since: Option<tokio::time::Instant> =
        at_cap_logged.then(tokio::time::Instant::now);

    if emit_initial &&
        bump_tx
            .send((
                batch_index,
                RbfBumpEvent::InitialBroadcast {
                    tx_hash: initial_hash,
                    nonce: template.nonce,
                    max_fee_per_gas,
                    max_priority_fee_per_gas,
                },
            ))
            .await
            .is_err()
    {
        warn!(batch_index, "RBF bump channel closed — aborting dispatch");
        return Ok(DispatchOutcome::Failed);
    }

    let mut current_hash = initial_hash;

    loop {
        tokio::select! {
            biased;
            _ = cancel.cancelled() => {
                info!(batch_index, "RBF dispatch cancelled (orphan prevention)");
                return Ok(DispatchOutcome::Failed);
            }
            _ = tokio::time::sleep(bump_interval) => {}
        }

        match provider.get_transaction_receipt(current_hash).await {
            Ok(Some(receipt)) => {
                crate::metrics::observe_dispatch_cost(&receipt);
                let Some(l1_block) = receipt.block_number else {
                    warn!(
                        batch_index,
                        %current_hash,
                        "Receipt present but block_number is None — retrying next interval"
                    );
                    continue;
                };
                if !receipt.status() {
                    let kind = classify_revert(receipt.gas_used, template.gas_limit);
                    warn!(
                        batch_index,
                        %current_hash,
                        l1_block,
                        ?kind,
                        gas_used = receipt.gas_used,
                        gas_limit = template.gas_limit,
                        "preconfirmBatch REVERTED on L1"
                    );
                    return Ok(DispatchOutcome::Reverted { tx_hash: current_hash, kind });
                }
                info!(
                    batch_index,
                    %current_hash,
                    l1_block,
                    "preconfirmBatch confirmed on L1"
                );
                return Ok(DispatchOutcome::Submitted { tx_hash: current_hash, l1_block });
            }
            Ok(None) => {
                // Not mined yet — bump and rebroadcast below.
            }
            Err(e) => {
                warn!(
                    batch_index,
                    %current_hash,
                    err = %e,
                    "get_transaction_receipt failed — retrying next interval"
                );
                continue;
            }
        }

        // Bail if we've been pinned at the fee cap for longer than the
        // configured timeout. Returning Failed here lets the main loop
        // undispatch, apply global backoff, and re-run pre-flight
        // reconciliation on retry — which will surface AlreadyPreconfirmed
        // if a bumped hash we stopped tracking actually landed.
        if let Some(since) = stuck_at_cap_since {
            let elapsed = since.elapsed();
            if elapsed >= STUCK_AT_CAP_TIMEOUT {
                metrics::counter!(
                    crate::metrics::L1_BROADCAST_FAILURES_TOTAL,
                    "kind" => "stuck_at_cap",
                )
                .increment(1);
                warn!(
                    batch_index,
                    elapsed_secs = elapsed.as_secs(),
                    stuck_at_cap_timeout_secs = STUCK_AT_CAP_TIMEOUT.as_secs(),
                    "RBF: stuck at fee cap past timeout — giving up so main can retry"
                );
                return Ok(DispatchOutcome::Failed);
            }
        }

        let (new_fee, new_tip, clamped) =
            bump_fees(max_fee_per_gas, max_priority_fee_per_gas, bump_percent, max_fee_cap);
        max_fee_per_gas = new_fee;
        max_priority_fee_per_gas = new_tip;

        if clamped {
            if stuck_at_cap_since.is_none() {
                stuck_at_cap_since = Some(tokio::time::Instant::now());
            }
            if !at_cap_logged {
                warn!(
                    batch_index,
                    max_fee_cap, "RBF: fee cap reached — continuing to rebroadcast at cap"
                );
                if bump_tx
                    .send((batch_index, RbfBumpEvent::CapReached { max_fee_per_gas: max_fee_cap }))
                    .await
                    .is_err()
                {
                    warn!(batch_index, "RBF bump channel closed after CapReached — aborting");
                    return Ok(DispatchOutcome::Failed);
                }
                at_cap_logged = true;
            }
        }

        match broadcast_preconfirm(provider, signer, &template, new_fee, new_tip).await {
            Ok(new_hash) => {
                current_hash = new_hash;
                info!(
                    batch_index,
                    %new_hash,
                    max_fee_per_gas = new_fee,
                    max_priority_fee_per_gas = new_tip,
                    "RBF bump rebroadcast"
                );
                if bump_tx
                    .send((
                        batch_index,
                        RbfBumpEvent::Bumped {
                            tx_hash: new_hash,
                            max_fee_per_gas: new_fee,
                            max_priority_fee_per_gas: new_tip,
                        },
                    ))
                    .await
                    .is_err()
                {
                    warn!(batch_index, "RBF bump channel closed after Bumped — aborting");
                    return Ok(DispatchOutcome::Failed);
                }
            }
            Err(e) => {
                let msg = format!("{e}");
                metrics::counter!(
                    crate::metrics::L1_BROADCAST_FAILURES_TOTAL,
                    "kind" => crate::metrics::broadcast_failure_kind(&msg),
                )
                .increment(1);
                // "nonce too low" during bump means a prior broadcast already
                // landed — our in-mempool replacement no longer has a slot.
                // Poll the latest observed hash for a receipt. No allocator
                // resync here: the nonce we used was already consumed by our
                // own earlier broadcast (fresh allocation) or stored (resume),
                // so the allocator's counter is already ahead of it.
                if is_nonce_too_low_error(&msg) {
                    match provider.get_transaction_receipt(current_hash).await {
                        Ok(Some(receipt)) => {
                            crate::metrics::observe_dispatch_cost(&receipt);
                            let Some(l1_block) = receipt.block_number else {
                                warn!(
                                    batch_index,
                                    %current_hash,
                                    "RBF: nonce-too-low + receipt without block_number — retrying next interval"
                                );
                                continue;
                            };
                            if receipt.status() {
                                return Ok(DispatchOutcome::Submitted {
                                    tx_hash: current_hash,
                                    l1_block,
                                });
                            }
                            let kind = classify_revert(receipt.gas_used, template.gas_limit);
                            warn!(
                                batch_index,
                                %current_hash,
                                l1_block,
                                ?kind,
                                gas_used = receipt.gas_used,
                                gas_limit = template.gas_limit,
                                "RBF: nonce-too-low fallback found REVERTED receipt"
                            );
                            return Ok(DispatchOutcome::Reverted { tx_hash: current_hash, kind });
                        }
                        Ok(None) | Err(_) => {
                            warn!(
                                batch_index,
                                %current_hash,
                                "RBF: nonce advanced but latest hash has no receipt — marking Failed"
                            );
                            return Ok(DispatchOutcome::Failed);
                        }
                    }
                }
                warn!(
                    batch_index,
                    err = %msg,
                    "RBF: bump broadcast failed — retrying next interval"
                );
            }
        }
    }
}

/// Apply a `+bump_percent%` multiplier to both `max_fee` and `tip`, clamp to
/// `cap`, and keep `tip <= max_fee` (EIP-1559 invariant). Returns the new
/// fees and a `clamped` flag indicating whether the post-bump `max_fee`
/// reached the cap.
fn bump_fees(max_fee: u128, tip: u128, bump_percent: u32, cap: u128) -> (u128, u128, bool) {
    let factor = 100u128 + bump_percent as u128;
    let new_fee = max_fee.saturating_mul(factor) / 100;
    let new_tip = tip.saturating_mul(factor) / 100;
    let clamped = new_fee >= cap;
    let new_fee = new_fee.min(cap);
    let new_tip = new_tip.min(new_fee);
    (new_fee, new_tip, clamped)
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

    async fn register_dispatched(
        acc: &mut BatchAccumulator,
        batch_index: u64,
        from_block: u64,
        to_block: u64,
        tx_hash: B256,
        l1_block: u64,
    ) {
        acc.set_batch(batch_index, from_block, to_block).await;
        acc.mark_dispatched(batch_index, tx_hash, l1_block, 0, 0, 0).await;
    }

    /// Test helper that mirrors the old combined `check_finalized_batches`
    /// call shape: snapshot → query → apply. Keeps existing tests readable
    /// while exercising the new split signatures end-to-end.
    async fn run_finalization_once(
        provider: &dyn FinalityRpc,
        db_tx: &mpsc::Sender<DbCommand>,
        orchestrator_tip: &Arc<AtomicU64>,
        accumulator: &mut BatchAccumulator,
        missing_receipt_first_seen: &mut HashMap<u64, tokio::time::Instant>,
        known_responses: &KnownResponses,
        last_batch_end: &mut Option<u64>,
    ) -> bool {
        if !accumulator.has_dispatched() {
            return false;
        }
        let snapshot = accumulator.dispatched_snapshot();
        let done = check_finalized_batches_query(provider, snapshot).await;
        apply_finalization_changes(
            done,
            accumulator,
            db_tx,
            orchestrator_tip,
            known_responses,
            missing_receipt_first_seen,
            last_batch_end,
        )
        .await
        .changed
    }

    /// With RBF in place, the missing-receipt window is log-only — the RBF
    /// worker owns rebroadcast authority, so force-undispatching from the
    /// finalization path would collide on the same nonce. The batch MUST
    /// remain dispatched past the window; only the timer is reset so logs
    /// don't spam.
    #[tokio::test(start_paused = true)]
    async fn receipt_missing_window_logs_only() {
        let db = temp_db();
        let (dummy_db_tx, _dummy_db_rx) = mpsc::channel(100);
        let mut acc = BatchAccumulator::with_db(Arc::clone(&db), dummy_db_tx.clone());
        let tip = Arc::new(AtomicU64::new(0));
        let tx_hash = B256::repeat_byte(0xAA);
        register_dispatched(&mut acc, 1, 100, 110, tx_hash, 500).await;

        let provider = StubFinality {
            finalized: Some(1000),
            receipt_statuses: HashMap::new(),
            tx_gas_limits: HashMap::new(),
        };
        let mut first_seen: HashMap<u64, tokio::time::Instant> = HashMap::new();

        let known_responses: KnownResponses = Arc::new(RwLock::new(HashSet::new()));
        let mut last_batch_end: Option<u64> = None;
        let changed = run_finalization_once(
            &provider,
            &dummy_db_tx,
            &tip,
            &mut acc,
            &mut first_seen,
            &known_responses,
            &mut last_batch_end,
        )
        .await;
        assert!(!changed, "missing receipt must not mutate state");
        assert!(acc.has_dispatched(), "batch must remain dispatched");
        assert!(first_seen.contains_key(&1));

        tokio::time::advance(RECEIPT_MISSING_WINDOW + Duration::from_secs(1)).await;
        let known_responses: KnownResponses = Arc::new(RwLock::new(HashSet::new()));
        let changed = run_finalization_once(
            &provider,
            &dummy_db_tx,
            &tip,
            &mut acc,
            &mut first_seen,
            &known_responses,
            &mut last_batch_end,
        )
        .await;
        assert!(!changed, "elapsed window must NOT mutate state (RBF owns rebroadcast)");
        assert!(acc.has_dispatched(), "batch must remain dispatched after window");
        assert!(first_seen.contains_key(&1), "timer is reset but entry stays");
    }

    /// DoneGuard must send its fallback payload when dropped without
    /// being disarmed — this is the liveness property that prevents
    /// a panicked spawned task from silently latching the main-loop gate.
    #[tokio::test]
    async fn done_guard_sends_failure_on_drop() {
        let (tx, mut rx) = mpsc::channel::<u32>(1);
        {
            let _guard = DoneGuard::arm(tx, 42);
        }
        let received = tokio::time::timeout(Duration::from_secs(1), rx.recv())
            .await
            .expect("DoneGuard drop must enqueue failure within timeout");
        assert_eq!(received, Some(42));
    }

    /// DoneGuard must NOT send anything after `disarm` — the happy path
    /// is that the task sends its real outcome and then disarms.
    #[tokio::test]
    async fn done_guard_disarm_suppresses_failure() {
        let (tx, mut rx) = mpsc::channel::<u32>(1);
        {
            let guard = DoneGuard::arm(tx, 42);
            guard.disarm();
        }
        // Channel is now closed (sender dropped). `recv()` must return `None`,
        // NOT the failure payload.
        assert_eq!(rx.recv().await, None, "disarmed guard must not emit a failure payload");
    }

    /// A single transient `Ok(false)` on an early candidate must NOT
    /// stop the loop — subsequent candidates with receipts must still
    /// be finalized in the same tick.
    #[tokio::test(start_paused = true)]
    async fn finalization_no_break_after_transient_none() {
        let db = temp_db();
        let (dummy_db_tx, _dummy_db_rx) = mpsc::channel(100);
        let mut acc = BatchAccumulator::with_db(Arc::clone(&db), dummy_db_tx.clone());
        let tip = Arc::new(AtomicU64::new(0));

        let tx_a = B256::repeat_byte(0x01);
        let tx_b = B256::repeat_byte(0x02);
        register_dispatched(&mut acc, 1, 100, 110, tx_a, 500).await;
        register_dispatched(&mut acc, 2, 111, 120, tx_b, 501).await;

        let mut receipt_statuses = HashMap::new();
        receipt_statuses.insert(tx_a, Ok(None));
        receipt_statuses.insert(tx_b, Ok(Some((true, 50_000u64))));

        let provider =
            StubFinality { finalized: Some(1000), receipt_statuses, tx_gas_limits: HashMap::new() };
        let mut first_seen: HashMap<u64, tokio::time::Instant> = HashMap::new();

        let known_responses: KnownResponses = Arc::new(RwLock::new(HashSet::new()));
        let mut last_batch_end: Option<u64> = None;
        let changed = run_finalization_once(
            &provider,
            &dummy_db_tx,
            &tip,
            &mut acc,
            &mut first_seen,
            &known_responses,
            &mut last_batch_end,
        )
        .await;

        assert!(changed, "batch 2 finalization must mark state as changed");
        assert!(first_seen.contains_key(&1), "batch 1 first_seen recorded");
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

    /// Reverted receipt with `gasUsed/gasLimit ≥ 95%` → OOG. Apply must
    /// undispatch and NOT signal `backoff_logic` (so the caller retries
    /// immediately with a fresh estimate).
    #[tokio::test(start_paused = true)]
    async fn finalization_ticker_oog_revert_undispatches_and_signals_retry() {
        let db = temp_db();
        let (dummy_db_tx, _dummy_db_rx) = mpsc::channel(100);
        let mut acc = BatchAccumulator::with_db(Arc::clone(&db), dummy_db_tx.clone());
        let tip = Arc::new(AtomicU64::new(0));
        let tx_hash = B256::repeat_byte(0xCC);
        register_dispatched(&mut acc, 1, 100, 110, tx_hash, 500).await;

        let mut receipt_statuses = HashMap::new();
        receipt_statuses.insert(tx_hash, Ok(Some((false, 95_000u64))));
        let mut tx_gas_limits = HashMap::new();
        tx_gas_limits.insert(tx_hash, Ok(Some(100_000u64)));
        let provider = StubFinality { finalized: Some(1000), receipt_statuses, tx_gas_limits };

        let mut first_seen: HashMap<u64, tokio::time::Instant> = HashMap::new();
        let known_responses: KnownResponses = Arc::new(RwLock::new(HashSet::new()));
        let mut last_batch_end: Option<u64> = None;

        let snapshot = acc.dispatched_snapshot();
        let done = check_finalized_batches_query(&provider, snapshot).await;
        let outcome = apply_finalization_changes(
            done,
            &mut acc,
            &dummy_db_tx,
            &tip,
            &known_responses,
            &mut first_seen,
            &mut last_batch_end,
        )
        .await;

        assert!(outcome.changed);
        assert!(!outcome.backoff_logic, "OOG must not trigger backoff");
        assert!(!acc.has_dispatched(), "batch must be undispatched");
        assert!(acc.get(1).is_some(), "batch must be back in pending after undispatch");
    }

    /// Reverted receipt with `gasUsed/gasLimit < 95%` → Logic. Apply must
    /// undispatch and signal `backoff_logic`.
    #[tokio::test(start_paused = true)]
    async fn finalization_ticker_logic_revert_undispatches_and_signals_backoff() {
        let db = temp_db();
        let (dummy_db_tx, _dummy_db_rx) = mpsc::channel(100);
        let mut acc = BatchAccumulator::with_db(Arc::clone(&db), dummy_db_tx.clone());
        let tip = Arc::new(AtomicU64::new(0));
        let tx_hash = B256::repeat_byte(0xDD);
        register_dispatched(&mut acc, 1, 100, 110, tx_hash, 500).await;

        let mut receipt_statuses = HashMap::new();
        receipt_statuses.insert(tx_hash, Ok(Some((false, 50_000u64))));
        let mut tx_gas_limits = HashMap::new();
        tx_gas_limits.insert(tx_hash, Ok(Some(100_000u64)));
        let provider = StubFinality { finalized: Some(1000), receipt_statuses, tx_gas_limits };

        let mut first_seen: HashMap<u64, tokio::time::Instant> = HashMap::new();
        let known_responses: KnownResponses = Arc::new(RwLock::new(HashSet::new()));
        let mut last_batch_end: Option<u64> = None;

        let snapshot = acc.dispatched_snapshot();
        let done = check_finalized_batches_query(&provider, snapshot).await;
        let outcome = apply_finalization_changes(
            done,
            &mut acc,
            &dummy_db_tx,
            &tip,
            &known_responses,
            &mut first_seen,
            &mut last_batch_end,
        )
        .await;

        assert!(outcome.changed);
        assert!(outcome.backoff_logic, "Logic revert must trigger backoff");
        assert!(!acc.has_dispatched(), "batch must be undispatched");
    }

    /// Stale ticker observation (snapshot tx_hash differs from current
    /// dispatched tx_hash) MUST NOT undispatch the live dispatch.
    #[tokio::test(start_paused = true)]
    async fn finalization_ticker_skips_stale_tx_hash() {
        let db = temp_db();
        let (dummy_db_tx, _dummy_db_rx) = mpsc::channel(100);
        let mut acc = BatchAccumulator::with_db(Arc::clone(&db), dummy_db_tx.clone());
        let tip = Arc::new(AtomicU64::new(0));
        let stale_hash = B256::repeat_byte(0xAA);
        let live_hash = B256::repeat_byte(0xBB);

        // Register dispatch with stale_hash, then re-mark with live_hash via
        // record_rbf_bump so accumulator's dispatched.tx_hash = live_hash.
        register_dispatched(&mut acc, 1, 100, 110, stale_hash, 500).await;
        acc.record_rbf_bump(1, live_hash, 0, 0).await;

        // Provider returns reverted for stale_hash (the snapshot value).
        let mut receipt_statuses = HashMap::new();
        receipt_statuses.insert(stale_hash, Ok(Some((false, 95_000u64))));
        let mut tx_gas_limits = HashMap::new();
        tx_gas_limits.insert(stale_hash, Ok(Some(100_000u64)));
        let provider = StubFinality { finalized: Some(1000), receipt_statuses, tx_gas_limits };

        let mut first_seen: HashMap<u64, tokio::time::Instant> = HashMap::new();
        let known_responses: KnownResponses = Arc::new(RwLock::new(HashSet::new()));
        let mut last_batch_end: Option<u64> = None;

        // Build the stale snapshot manually (mimics the production flow where
        // the snapshot is taken at try_start_finalization time and may go
        // stale before apply runs).
        let stale_snapshot = vec![(1u64, stale_hash, 500u64)];
        let done = check_finalized_batches_query(&provider, stale_snapshot).await;
        let outcome = apply_finalization_changes(
            done,
            &mut acc,
            &dummy_db_tx,
            &tip,
            &known_responses,
            &mut first_seen,
            &mut last_batch_end,
        )
        .await;

        assert!(!outcome.changed, "stale-hash observation must skip mutation");
        assert!(!outcome.backoff_logic);
        assert!(acc.has_dispatched(), "live dispatch must remain untouched");
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
