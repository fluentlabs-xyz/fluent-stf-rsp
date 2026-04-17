//! Orchestrator orchestrator: receives witnesses from the embedded forward driver,
//! dispatches them to the Nitro proxy, and drives L1 batch signing + submission.
//!
//! # Architecture
//!
//! A persistent pool of `EXECUTION_WORKERS` tasks reads from a priority channel
//! pair (`high_rx` / `normal_rx`) via `biased` select, ensuring re-execution
//! after enclave key rotation takes precedence over fresh witnesses.
//!
//! Witnesses arrive in-process via [`mpsc::Receiver<ProveRequest>`]: the main
//! select loop forwards each request into `normal_tx`, whose bounded capacity
//! provides backpressure on the driver when workers are saturated.
//!
//! On key rotation, blocks that need re-execution are fetched from the cold
//! witness store ([`WitnessHub::get_witness`]) and pushed onto the high-priority
//! queue.

use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_channel::{Receiver as AsyncReceiver, Sender as AsyncSender};
use bytes::Bytes;
use tokio::sync::mpsc;
use tokio::task::JoinSet;
use tokio::time::MissedTickBehavior;
use tokio_util::sync::CancellationToken;
use tracing::{error, info, warn};

use crate::accumulator::BatchAccumulator;
use crate::db::Db;
use crate::hub::WitnessHub;
use crate::l1_listener::L1Event;
use crate::types::{EthExecutionResponse, ProveRequest, SignBatchRootRequest, SubmitBatchResponse};
use l1_rollup_client::{nitro_verifier::is_key_registered, submit_preconfirmation};

use alloy_eips::BlockNumberOrTag;
use alloy_network::{Ethereum, EthereumWallet};
use alloy_primitives::{Address, B256};
use alloy_provider::fillers::{
    BlobGasFiller, ChainIdFiller, FillProvider, GasFiller, JoinFill, NonceFiller, WalletFiller,
};
use alloy_provider::{Identity, Provider, RootProvider};

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

/// Time window before a persistently missing receipt is treated as a reorg
/// and the batch is undispatched.
const RECEIPT_MISSING_WINDOW: Duration = Duration::from_secs(60);

/// Number of persistent execution workers sending blocks to the Nitro proxy.
const EXECUTION_WORKERS: usize = 32;

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

/// Configuration for the orchestrator.
#[derive(Clone)]
pub(crate) struct OrchestratorConfig {
    pub proxy_url: String,
    pub db_path: PathBuf,
    pub http_client: reqwest::Client,
    pub l1_rollup_addr: Address,
    pub nitro_verifier_addr: Address,
    pub l1_provider: L1WriteProvider,
    pub api_key: String,
    pub l2_provider: alloy_provider::RootProvider,
}

/// Task for the execution worker pool.
struct ExecutionTask {
    block_number: u64,
    payload: Vec<u8>,
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
}

/// Result of an L1 dispatch attempt.
enum DispatchOutcome {
    /// TX included in L1 block — awaiting finalization.
    Submitted { tx_hash: B256, l1_block: u64 },
    /// L1 transaction failed — will retry with backoff.
    Failed,
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

        let payload = Bytes::from(task.payload);
        let mut backoff = Duration::from_millis(50);
        let mut attempts: u32 = 0;
        loop {
            attempts += 1;
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
// Main orchestrator loop
// ============================================================================

/// Run the orchestrator orchestrator loop until `shutdown` fires or `prove_rx` closes.
///
/// Creates the persistent execution worker pool once and reads witnesses from
/// the in-process `prove_rx` channel supplied by the embedded forward driver.
pub(crate) async fn run(
    config: OrchestratorConfig,
    hub: Arc<WitnessHub>,
    mut prove_rx: mpsc::Receiver<ProveRequest>,
    mut l1_events: mpsc::Receiver<L1Event>,
    shutdown: CancellationToken,
) {
    let db =
        Arc::new(Mutex::new(Db::open(&config.db_path).expect("Failed to open orchestrator DB")));
    let mut accumulator = {
        let db = Arc::clone(&db);
        tokio::task::spawn_blocking(move || BatchAccumulator::with_db(db))
            .await
            .expect("startup accumulator load panicked")
    };

    let mut next_batch_from_block: Option<u64> =
        accumulator.max_to_block().map(|e| e + 1).or_else(|| {
            db.lock().unwrap_or_else(|e| e.into_inner()).get_last_batch_end().map(|e| e + 1)
        });

    // Persists across finalization ticks: a batch still dispatched but with a
    // transiently missing receipt should not reset its observation window.
    let mut missing_receipt_first_seen: HashMap<u64, tokio::time::Instant> = HashMap::new();

    if accumulator.has_dispatched() {
        info!("Checking dispatched batches from previous run...");
        let _ = check_finalized_batches(
            &config.l1_provider,
            &db,
            &mut accumulator,
            &mut missing_receipt_first_seen,
        )
        .await;
    }

    // Channels live for the entire process. Capacities are tied to
    // EXECUTION_WORKERS to bound memory: each queued ExecutionTask may hold
    // a 30-80 MB payload, so large buffers cause OOM.
    let (high_tx, high_rx) = async_channel::bounded::<ExecutionTask>(EXECUTION_WORKERS);
    let (normal_tx, normal_rx) = async_channel::bounded::<ExecutionTask>(EXECUTION_WORKERS * 2);
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
    let (key_check_tx, mut key_check_rx) = mpsc::channel::<(Address, bool)>(4);
    let mut finalization_ticker = tokio::time::interval(Duration::from_secs(30));
    finalization_ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);

    let mut state = OrchestratorState {
        config: config.clone(),
        db: Arc::clone(&db),
        hub: Arc::clone(&hub),
        high_tx: high_tx.clone(),
        sign_done_tx,
        dispatch_done_tx,
        key_check_tx,
        checkpoint: from_block.saturating_sub(1),
        confirmed: HashSet::new(),
        signing_batch: None,
        dispatching_batch: None,
        global_dispatch_attempts: 0,
        global_next_dispatch_allowed: None,
        pending_key_check: None,
        key_check_attempts: 0,
    };

    info!(from_block, "Orchestrator ready — awaiting witnesses");

    loop {
        tokio::select! {
            biased;
            _ = shutdown.cancelled() => {
                info!("Shutdown requested — exiting orchestrator loop");
                break;
            }
            // ── Witness intake from the embedded driver ─────────────────
            Some(req) = prove_rx.recv() => {
                if req.block_number <= state.checkpoint {
                    warn!(
                        block_number = req.block_number,
                        checkpoint = state.checkpoint,
                        "Ignoring stale prove request"
                    );
                    continue;
                }
                if normal_tx
                    .send(ExecutionTask { block_number: req.block_number, payload: req.payload })
                    .await
                    .is_err()
                {
                    warn!(block_number = req.block_number, "Normal execution channel closed");
                    break;
                }
            }
            // ── Block execution results ────────────────────────────────
            Some(result) = result_rx.recv() =>
                state.on_block_result(result, &mut accumulator).await,

            // ── L1 events ──────────────────────────────────────────────
            Some(event) = l1_events.recv() =>
                state.on_l1_event(event, &mut accumulator, &mut next_batch_from_block, from_block).await,

            // ── Batch signing completions ──────────────────────────────
            Some((batch_index, outcome)) = sign_done_rx.recv() =>
                state.on_sign_done(batch_index, outcome, &mut accumulator).await,

            // ── Batch dispatch completions ─────────────────────────────
            Some((batch_index, outcome)) = dispatch_done_rx.recv() =>
                state.on_dispatch_done(batch_index, outcome, &mut accumulator).await,

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

            // ── Finalization checker ───────────────────────────────────
            _ = finalization_ticker.tick() =>
                state.on_finalization_tick(&mut accumulator, &mut missing_receipt_first_seen).await,
        }
    }

    // ── Graceful drain ────────────────────────────────────────────────
    info!("Closing worker task channels — draining workers");
    drop(high_tx);
    drop(normal_tx);
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
    db: Arc<Mutex<Db>>,
    hub: Arc<WitnessHub>,
    high_tx: AsyncSender<ExecutionTask>,
    sign_done_tx: mpsc::Sender<(u64, SignOutcome)>,
    dispatch_done_tx: mpsc::Sender<(u64, DispatchOutcome)>,
    key_check_tx: mpsc::Sender<(Address, bool)>,
    checkpoint: u64,
    confirmed: HashSet<u64>,
    signing_batch: Option<u64>,
    dispatching_batch: Option<u64>,
    global_dispatch_attempts: u32,
    global_next_dispatch_allowed: Option<tokio::time::Instant>,
    pending_key_check: Option<Address>,
    /// Number of consecutive failed L1 reads for the currently pending
    /// key rotation. Reset on successful confirmation and whenever a fresh
    /// `InvalidSignatures` rotation starts. Used by `spawn_key_check` to
    /// thin logs at 1, 2, 4, 8, ... attempts during long outages.
    key_check_attempts: u64,
}

impl OrchestratorState {
    /// Handle a completed block execution response: advance watermark, persist, try dispatch.
    async fn on_block_result(&mut self, result: BlockResult, accumulator: &mut BatchAccumulator) {
        let block_number = result.block_number;

        if block_number <= self.checkpoint {
            warn!(
                block_number,
                checkpoint = self.checkpoint,
                "Ignoring stale block result (orphaned task)"
            );
            return;
        }

        info!(block_number, "Block execution response received");
        accumulator.insert_response(result.response).await;

        self.confirmed.insert(block_number);
        while self.confirmed.contains(&(self.checkpoint + 1)) {
            self.checkpoint += 1;
            self.confirmed.remove(&self.checkpoint);
        }
        {
            let db = Arc::clone(&self.db);
            let cp = self.checkpoint;
            if let Err(e) = tokio::task::spawn_blocking(move || {
                db.lock().unwrap_or_else(|e| e.into_inner()).save_checkpoint(cp);
            })
            .await
            {
                warn!(cp, err = %e, "save_checkpoint: spawn_blocking failed");
            }
        }

        self.try_sign_next_batch(accumulator);
        self.try_dispatch_next_batch(accumulator);
    }

    /// Handle an L1 event: register a new batch or mark blobs accepted.
    async fn on_l1_event(
        &mut self,
        event: L1Event,
        accumulator: &mut BatchAccumulator,
        next_batch_from_block: &mut Option<u64>,
        from_block: u64,
    ) {
        match event {
            L1Event::BatchCommitted { batch_index, num_blocks } => {
                let from = next_batch_from_block.unwrap_or(from_block);
                let to = from + num_blocks.saturating_sub(1);
                info!(batch_index, from, to, num_blocks, "Setting batch from L1 event");
                accumulator.set_batch(batch_index, from, to).await;
                *next_batch_from_block = Some(to + 1);
            }
            L1Event::BatchSubmitted { batch_index } => {
                accumulator.mark_batch_submitted(batch_index).await;
                self.try_sign_next_batch(accumulator);
                self.try_dispatch_next_batch(accumulator);
            }
            L1Event::BatchPreconfirmed { batch_index, tx_hash, l1_block } => {
                accumulator.mark_dispatched(batch_index, tx_hash, l1_block).await;
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
                let db = Arc::clone(&self.db);
                if let Err(e) = tokio::task::spawn_blocking(move || {
                    db.lock().unwrap_or_else(|e| e.into_inner()).save_l1_checkpoint(l1_block);
                })
                .await
                {
                    warn!(l1_block, err = %e, "save_l1_checkpoint: spawn_blocking failed");
                }
            }
        }
    }

    /// Queue a block for re-execution after key rotation.
    ///
    /// Fetches the witness from the cold store and pushes an eager task
    /// onto the high-priority execution queue.
    fn spawn_re_execution(&self, block_number: u64) {
        let h_tx = self.high_tx.clone();
        let hub = Arc::clone(&self.hub);
        tokio::spawn(async move {
            match hub.get_witness(block_number).await {
                Some(req) => {
                    if h_tx
                        .send(ExecutionTask { block_number, payload: req.payload })
                        .await
                        .is_err()
                    {
                        warn!(block_number, "High-priority channel closed during re-execution");
                    }
                }
                None => {
                    error!(
                        block_number,
                        "Re-execution: witness not in cold store — block permanently stuck"
                    );
                }
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
        let from_block = batch.from_block;
        let to_block = batch.to_block;
        let l2_provider = cfg.l2_provider.clone();

        tokio::spawn(async move {
            let outcome = sign_batch_io(
                &cfg.http_client,
                &cfg.proxy_url,
                &cfg.api_key,
                batch_index,
                from_block,
                to_block,
                responses,
                db,
                &l2_provider,
            )
            .await;
            if tx.send((batch_index, outcome)).await.is_err() {
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

                // Acknowledge cold storage immediately after signing — the
                // signature is durable in DB, so raw witnesses are no longer
                // needed.
                if let Some(batch) = accumulator.get(batch_index) {
                    let hub = Arc::clone(&self.hub);
                    let fb = batch.from_block;
                    let tb = batch.to_block;
                    tokio::spawn(async move {
                        hub.acknowledge_range(fb, tb).await;
                    });
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

                for &block_number in &invalid_blocks {
                    self.spawn_re_execution(block_number);
                }

                self.pending_key_check = Some(enclave_address);
                // Fresh rotation — reset the counter so log thinning works
                // correctly across consecutive rotations.
                self.key_check_attempts = 0;
                self.spawn_key_check(enclave_address, None);
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
            if tx.send((addr, ok)).await.is_err() {
                warn!(%addr, "Key check channel closed");
            }
        });
    }

    /// Pick the next sequential signed batch and spawn a dispatch task.
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

        let provider = self.config.l1_provider.clone();
        let contract = self.config.l1_rollup_addr;
        let verifier = self.config.nitro_verifier_addr;
        let tx = self.dispatch_done_tx.clone();

        tokio::spawn(async move {
            let outcome =
                match submit_preconfirmation(&provider, contract, verifier, batch_index, signature)
                    .await
                {
                    Ok(receipt) => DispatchOutcome::Submitted {
                        tx_hash: receipt.tx_hash,
                        l1_block: receipt.l1_block,
                    },
                    Err(e) => {
                        error!(batch_index, err = %e, "preconfirmBatch failed — will retry");
                        DispatchOutcome::Failed
                    }
                };
            if tx.send((batch_index, outcome)).await.is_err() {
                warn!(batch_index, "Dispatch done channel closed");
            }
        });
    }

    /// Handle the result of a background L1 dispatch task.
    async fn on_dispatch_done(
        &mut self,
        batch_index: u64,
        outcome: DispatchOutcome,
        accumulator: &mut BatchAccumulator,
    ) {
        self.dispatching_batch = None;

        match outcome {
            DispatchOutcome::Submitted { tx_hash, l1_block } => {
                self.global_dispatch_attempts = 0;
                self.global_next_dispatch_allowed = None;

                accumulator.mark_dispatched(batch_index, tx_hash, l1_block).await;
                info!(
                    batch_index,
                    %tx_hash,
                    l1_block,
                    "Batch submitted to L1 — awaiting finalization"
                );

                self.try_dispatch_next_batch(accumulator);
            }

            DispatchOutcome::Failed => {
                self.global_dispatch_attempts += 1;
                let delay_secs = (10u64 * self.global_dispatch_attempts as u64).min(300);
                self.global_next_dispatch_allowed =
                    Some(tokio::time::Instant::now() + Duration::from_secs(delay_secs));
                warn!(
                    batch_index,
                    attempts = self.global_dispatch_attempts,
                    delay_secs,
                    "Dispatch failed — global backoff"
                );
            }
        }
    }

    /// Check finalized batches and process results.
    async fn on_finalization_tick(
        &mut self,
        accumulator: &mut BatchAccumulator,
        missing_receipt_first_seen: &mut HashMap<u64, tokio::time::Instant>,
    ) {
        let (changed, finalized_ranges) = check_finalized_batches(
            &self.config.l1_provider,
            &self.db,
            accumulator,
            missing_receipt_first_seen,
        )
        .await;

        // Safety net: acknowledge cold files for finalized batches
        for (fb, tb) in finalized_ranges {
            let hub = Arc::clone(&self.hub);
            tokio::spawn(async move {
                hub.acknowledge_range(fb, tb).await;
            });
        }

        if changed {
            self.try_sign_next_batch(accumulator);
            self.try_dispatch_next_batch(accumulator);
        }
    }
}

// ============================================================================
// L1 finality helpers
// ============================================================================

/// Narrow RPC surface used by [`check_finalized_batches`]. The blanket impl
/// for any `alloy` [`Provider`] lets production code pass `&l1_provider` as-is,
/// while tests substitute a hand-rolled stub.
#[async_trait::async_trait]
pub(crate) trait FinalityRpc: Send + Sync {
    async fn finalized_block_number(&self) -> Option<u64>;
    async fn receipt_exists(&self, tx_hash: B256) -> Result<bool, String>;
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

    async fn receipt_exists(&self, tx_hash: B256) -> Result<bool, String> {
        match self.get_transaction_receipt(tx_hash).await {
            Ok(Some(_)) => Ok(true),
            Ok(None) => Ok(false),
            Err(e) => Err(e.to_string()),
        }
    }
}

/// Fetch L1 finalized block, then process dispatched batches contiguously:
/// finalized + receipt present → cleanup; receipt missing for longer than
/// [`RECEIPT_MISSING_WINDOW`] → undispatch (reorg).
async fn check_finalized_batches(
    provider: &dyn FinalityRpc,
    db: &Arc<Mutex<Db>>,
    accumulator: &mut BatchAccumulator,
    missing_receipt_first_seen: &mut HashMap<u64, tokio::time::Instant>,
) -> (bool, Vec<(u64, u64)>) {
    if !accumulator.has_dispatched() {
        return (false, vec![]);
    }

    let Some(finalized_block) = provider.finalized_block_number().await else {
        return (false, vec![]);
    };

    let candidates = accumulator.dispatched_finalization_candidates(finalized_block);
    if candidates.is_empty() {
        return (false, vec![]);
    }

    let mut changed = false;
    let mut finalized_ranges = Vec::new();

    for batch_index in candidates {
        let Some(tx_hash) = accumulator.dispatched_tx_hash(batch_index) else {
            continue;
        };

        match provider.receipt_exists(tx_hash).await {
            Ok(true) => {
                missing_receipt_first_seen.remove(&batch_index);
                let Some(dispatched) = accumulator.finalize_dispatched(batch_index).await else {
                    continue;
                };
                {
                    let db = Arc::clone(db);
                    let block = dispatched.to_block;
                    if let Err(e) = tokio::task::spawn_blocking(move || {
                        db.lock().unwrap_or_else(|e| e.into_inner()).save_last_batch_end(block);
                    })
                    .await
                    {
                        warn!(block, err = %e, "save_last_batch_end: spawn_blocking failed");
                    }
                }
                info!(batch_index, %tx_hash, to_block = dispatched.to_block, "Batch finalized on L1 — cleaned up");
                finalized_ranges.push((dispatched.from_block, dispatched.to_block));
                changed = true;
            }
            Ok(false) => {
                let now = tokio::time::Instant::now();
                let first = *missing_receipt_first_seen.entry(batch_index).or_insert(now);
                let elapsed = now.duration_since(first);
                warn!(
                    batch_index,
                    %tx_hash,
                    elapsed_secs = elapsed.as_secs(),
                    "Receipt missing after finalization"
                );
                if elapsed >= RECEIPT_MISSING_WINDOW {
                    warn!(
                        batch_index,
                        %tx_hash,
                        elapsed_secs = elapsed.as_secs(),
                        "Receipt missing beyond window — treating as reorg, re-dispatching"
                    );
                    missing_receipt_first_seen.remove(&batch_index);
                    accumulator.undispatch(batch_index).await;
                    changed = true;
                }
            }
            Err(e) => {
                warn!(batch_index, %tx_hash, err = %e, "Receipt check failed — will retry");
            }
        }
    }

    (changed, finalized_ranges)
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
    l2_provider: &alloy_provider::RootProvider,
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
                    tokio::time::sleep(backoff).await;
                    backoff = (backoff * 2).min(Duration::from_secs(30));
                }
            }
        }
    };

    info!(batch_index, num_blobs = blobs.len(), "Blobs built from L2 tx data");

    let mut backoff = Duration::from_secs(1);
    loop {
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
                let db = Arc::clone(&db);
                let resp_clone = resp.clone();
                if let Err(e) = tokio::task::spawn_blocking(move || {
                    db.lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .save_batch_signature(batch_index, &resp_clone);
                })
                .await
                {
                    warn!(batch_index, err = %e, "save_batch_signature: spawn_blocking failed");
                }
                info!(batch_index, "Batch root signed and persisted");
                return SignOutcome::Signed { response: resp };
            }
            Err(SignBatchError::InvalidSignatures { invalid_blocks, enclave_address }) => {
                warn!(
                    batch_index,
                    ?invalid_blocks,
                    %enclave_address,
                    "Batch has stale signatures — key rotation detected"
                );
                return SignOutcome::InvalidSignatures { invalid_blocks, enclave_address };
            }
            Err(SignBatchError::Other(e)) => {
                warn!(batch_index, err = %e, ?backoff, "sign-batch-root failed — retrying");
                tokio::time::sleep(backoff).await;
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
        return Err(SignBatchError::Other(eyre::eyre!(
            "sign-batch-root returned {status}: {text}"
        )));
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
    let resp = http_client
        .post(&url)
        .timeout(Duration::from_secs(30))
        .header("content-type", "application/octet-stream")
        .header("x-block-number", block_number.to_string())
        .header("x-api-key", api_key)
        .body(payload)
        .send()
        .await
        .map_err(|e| eyre::eyre!("HTTP POST failed: {e}"))?;

    let status = resp.status();
    if !status.is_success() {
        let body = resp.text().await.unwrap_or_else(|_| "<unreadable>".into());
        return Err(eyre::eyre!("proxy returned {status}: {body}"));
    }

    resp.json::<EthExecutionResponse>()
        .await
        .map_err(|e| eyre::eyre!("Failed to parse response: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::accumulator::BatchAccumulator;
    use crate::db::Db;
    use std::collections::HashMap;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::Mutex as StdMutex;

    fn temp_db() -> Arc<StdMutex<Db>> {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let id = COUNTER.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!("client_test_{id}_{}.db", std::process::id()));
        let db = Db::open(&path).unwrap();
        Arc::new(StdMutex::new(db))
    }

    /// Hand-rolled stub implementing only the two RPC methods
    /// [`check_finalized_batches`] actually touches.
    struct StubFinality {
        finalized: Option<u64>,
        receipts: HashMap<B256, Result<bool, String>>,
    }

    #[async_trait::async_trait]
    impl FinalityRpc for StubFinality {
        async fn finalized_block_number(&self) -> Option<u64> {
            self.finalized
        }
        async fn receipt_exists(&self, tx_hash: B256) -> Result<bool, String> {
            self.receipts.get(&tx_hash).cloned().unwrap_or(Ok(false))
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
        acc.mark_dispatched(batch_index, tx_hash, l1_block).await;
    }

    /// First `Ok(false)` must only record `first_seen` — no undispatch.
    /// After advancing past `RECEIPT_MISSING_WINDOW`, the next tick must
    /// undispatch the batch (simulated reorg recovery).
    #[tokio::test(start_paused = true)]
    async fn receipt_missing_window_elapsed() {
        let db = temp_db();
        let mut acc = BatchAccumulator::with_db(Arc::clone(&db));
        let tx_hash = B256::repeat_byte(0xAA);
        register_dispatched(&mut acc, 1, 100, 110, tx_hash, 500).await;

        let provider = StubFinality { finalized: Some(1000), receipts: HashMap::new() };
        let mut first_seen: HashMap<u64, tokio::time::Instant> = HashMap::new();

        let (changed, _) = check_finalized_batches(&provider, &db, &mut acc, &mut first_seen).await;
        assert!(!changed, "first missing receipt must not cause undispatch");
        assert!(acc.has_dispatched(), "batch must remain dispatched");
        assert!(first_seen.contains_key(&1));

        tokio::time::advance(RECEIPT_MISSING_WINDOW + Duration::from_secs(1)).await;
        let (changed, _) = check_finalized_batches(&provider, &db, &mut acc, &mut first_seen).await;
        assert!(changed, "elapsed window must trigger undispatch");
        assert!(!acc.has_dispatched(), "batch must be undispatched after window");
        assert!(!first_seen.contains_key(&1), "first_seen entry cleared on undispatch");
    }

    /// A single transient `Ok(false)` on an early candidate must NOT
    /// stop the loop — subsequent candidates with receipts must still
    /// be finalized in the same tick.
    #[tokio::test(start_paused = true)]
    async fn finalization_no_break_after_transient_none() {
        let db = temp_db();
        let mut acc = BatchAccumulator::with_db(Arc::clone(&db));

        let tx_a = B256::repeat_byte(0x01);
        let tx_b = B256::repeat_byte(0x02);
        register_dispatched(&mut acc, 1, 100, 110, tx_a, 500).await;
        register_dispatched(&mut acc, 2, 111, 120, tx_b, 501).await;

        let mut receipts = HashMap::new();
        receipts.insert(tx_a, Ok(false));
        receipts.insert(tx_b, Ok(true));

        let provider = StubFinality { finalized: Some(1000), receipts };
        let mut first_seen: HashMap<u64, tokio::time::Instant> = HashMap::new();

        let (changed, finalized) =
            check_finalized_batches(&provider, &db, &mut acc, &mut first_seen).await;

        assert!(changed, "batch 2 finalization must mark state as changed");
        assert_eq!(finalized, vec![(111, 120)], "batch 2 range must be reported");
        assert!(first_seen.contains_key(&1), "batch 1 first_seen recorded");
        assert!(acc.has_dispatched(), "batch 1 remains dispatched (transient None)");
        assert!(
            acc.dispatched_tx_hash(2).is_none(),
            "batch 2 must be removed from dispatched after finalization"
        );
    }
}
