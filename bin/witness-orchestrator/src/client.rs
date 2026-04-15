//! gRPC client with persistent MPMC worker pools, priority queues, and batch
//! orchestration.
//!
//! # Architecture
//!
//! The courier runs two persistent worker pools for the lifetime of the process:
//!
//! 1. **Execution workers** (`EXECUTION_WORKERS` tasks) — read from a priority
//!    channel pair (`high_rx` / `normal_rx`) via `biased` select, ensuring
//!    re-execution after key rotation takes precedence over fresh witnesses.
//!    Each worker retries with aggressive backoff (50ms → 2s).
//!
//! 2. **Fallback workers** (`max_concurrent_fallbacks` tasks) — recover missing
//!    witnesses via L3 (local Reth RPC) / L4 (remote archive RPC), then feed
//!    recovered payloads into the high-priority execution queue.
//!
//! A dedicated gRPC reader task feeds the `normal_tx` channel, providing native
//! HTTP/2 flow-control backpressure when workers are saturated.
//!
//! # Reconnect
//!
//! Worker pools and channels are created once in [`run`] and survive reconnects.
//! Only the gRPC stream and per-session state are recreated on each attempt.

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
use tonic::transport::Channel;
use tracing::{error, info, warn};

use crate::accumulator::BatchAccumulator;
use crate::db::Db;
use crate::l1_listener::L1Event;
use l1_rollup_client::{nitro_verifier::is_key_registered, submit_preconfirmation};
use witness_orchestrator::proto::witness_service_client::WitnessServiceClient;
use witness_orchestrator::proto::SubscribeRequest;
use witness_orchestrator::types::{EthExecutionResponse, SubmitBatchResponse};

use alloy_eips::BlockNumberOrTag;
use alloy_network::Ethereum;
use alloy_primitives::{Address, B256};
use alloy_provider::Provider;
use fluent_stf_primitives::fluent_chainspec;
use rsp_client_executor::{evm::FluentEvmConfig, io::ClientExecutorInput};
use rsp_host_executor::HostExecutor;
use rsp_provider::create_provider;

use witness_orchestrator::MAX_GRPC_MESSAGE_SIZE;

/// Time window before a persistently missing receipt is treated as a reorg
/// and the batch is undispatched. Time-based (not count-based) so it is
/// robust against changes to the finalization tick period.
const RECEIPT_MISSING_WINDOW: Duration = Duration::from_secs(60);

const MAX_BACKOFF: Duration = Duration::from_secs(30);
const INITIAL_BACKOFF: Duration = Duration::from_millis(500);

/// Number of persistent execution workers sending blocks to the Nitro proxy.
const EXECUTION_WORKERS: usize = 32;

/// Blocks past the head before a gap triggers L3/L4 fallback.
const FALLBACK_GAP_M: u64 = 32;

/// Maximum fallback tasks dispatched per tick (caps `fallback_active` set).
const FALLBACK_BATCH_SIZE: usize = 128;

/// Bounded wait for workers to finish their in-flight HTTP calls on
/// shutdown. Longer than a typical request, shorter than a systemd
/// `TimeoutStopSec`.
const SHUTDOWN_DRAIN_TIMEOUT: Duration = Duration::from_secs(30);

/// Configuration for the orchestrator.
#[derive(Clone)]
pub(crate) struct OrchestratorConfig<P: Provider + Clone + 'static> {
    pub server_addr: String,
    pub proxy_url: String,
    pub db_path: PathBuf,
    pub http_client: reqwest::Client,
    pub l1_contract_addr: Address,
    pub nitro_verifier_addr: Address,
    pub l1_provider: P,
    pub api_key: String,
    pub fallback_local_rpc: Option<String>,
    pub fallback_remote_rpc: Option<String>,
    pub max_concurrent_fallbacks: usize,
    pub l2_provider: alloy_provider::RootProvider,
}

/// Task for the execution worker pool.
///
/// `payload` is `None` for lazy (re-execution) tasks: the worker fetches the
/// witness JIT via gRPC `GetWitness`, avoiding upfront memory allocation for
/// hundreds of blocks during key rotation recovery.
struct ExecutionTask {
    block_number: u64,
    payload: Option<Vec<u8>>,
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
    Submitted { tx_hash: alloy_primitives::B256, l1_block: u64 },
    /// L1 transaction failed — will retry with backoff.
    Failed,
}

/// Error from `/sign-batch-root` call.
enum SignBatchError {
    InvalidSignatures { invalid_blocks: Vec<u64>, enclave_address: Address },
    Other(eyre::Report),
}

/// Events from the dedicated gRPC reader task to the main orchestrator.
enum GrpcEvent {
    /// A witness was queued into the normal execution channel.
    WitnessQueued(u64),
    /// The gRPC stream encountered an error.
    StreamError(String),
}

// ============================================================================
// Persistent execution worker pool
// ============================================================================

/// Reads tasks from the priority channel pair (high before normal) and sends
/// `/sign-block-execution` requests with aggressive retry.
///
/// For lazy tasks (`payload: None`), fetches the witness JIT via gRPC
/// `GetWitness` — this avoids holding large payloads in memory while
/// waiting in the channel queue.
#[allow(clippy::too_many_arguments)]
async fn execution_worker(
    worker_id: usize,
    high_rx: AsyncReceiver<ExecutionTask>,
    normal_rx: AsyncReceiver<ExecutionTask>,
    result_tx: mpsc::Sender<BlockResult>,
    http_client: reqwest::Client,
    proxy_url: String,
    api_key: String,
    mut witness_client: WitnessServiceClient<Channel>,
    fallback_tx: AsyncSender<FallbackTask>,
    shutdown: CancellationToken,
) {
    info!(worker_id, "Execution worker started");
    loop {
        // biased: always drain high-priority (re-execution) before normal.
        // Cancel is checked ONLY between tasks — never mid-HTTP-call —
        // so an in-flight payload is either fully sent and answered, or
        // not started at all. This prevents the proxy from landing in an
        // inconsistent state on an abrupt worker exit.
        let task = tokio::select! {
            biased;
            _ = shutdown.cancelled() => break,
            Ok(t) = high_rx.recv() => t,
            Ok(t) = normal_rx.recv() => t,
            else => break, // channels closed — shutting down
        };

        // Resolve payload: eager (from stream/fallback) or lazy (re-execution)
        let payload = match task.payload {
            Some(p) => p,
            None => {
                // JIT fetch — only allocates memory when a worker is ready
                match witness_client
                    .get_witness(witness_orchestrator::proto::GetWitnessRequest {
                        block_number: task.block_number,
                    })
                    .await
                {
                    Ok(resp) => {
                        let w: witness_orchestrator::proto::GetWitnessResponse = resp.into_inner();
                        if w.found && !w.data.is_empty() {
                            w.data
                        } else {
                            warn!(
                                worker_id,
                                block = task.block_number,
                                "Lazy fetch: witness not found in hub — dispatching to fallback"
                            );
                            if fallback_tx
                                .send(FallbackTask { block_number: task.block_number })
                                .await
                                .is_err()
                            {
                                warn!(
                                    worker_id,
                                    block = task.block_number,
                                    "Fallback channel closed"
                                );
                            }
                            continue;
                        }
                    }
                    Err(e) => {
                        warn!(worker_id, block = task.block_number, err = %e, "Lazy fetch: gRPC GetWitness failed — dispatching to fallback");
                        if fallback_tx
                            .send(FallbackTask { block_number: task.block_number })
                            .await
                            .is_err()
                        {
                            warn!(worker_id, block = task.block_number, "Fallback channel closed");
                        }
                        continue;
                    }
                }
            }
        };

        let payload = Bytes::from(payload);
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
                    // Cancel check belongs here — between HTTP calls, not
                    // mid-call. Mid-call cancel risks a "proxy executed,
                    // orchestrator gave up" divergence. Blocks are
                    // sequential, so giving up on block n would only
                    // create a gap — retry forever until proxy recovers
                    // or operator intervenes.
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
// Persistent fallback worker pool (GetWitness / L3 / L4 recovery)
// ============================================================================

struct FallbackTask {
    block_number: u64,
}

/// Recovers missing witnesses via GetWitness (hub), then L3/L4 RPC,
/// and feeds recovered payloads into the high-priority execution queue.
#[allow(clippy::too_many_arguments)]
async fn fallback_worker(
    worker_id: usize,
    fallback_rx: AsyncReceiver<FallbackTask>,
    high_tx: AsyncSender<ExecutionTask>,
    fallback_done_tx: mpsc::Sender<(u64, bool)>,
    mut witness_client: WitnessServiceClient<Channel>,
    config: OrchestratorConfig<impl Provider + Clone + 'static>,
    shutdown: CancellationToken,
) {
    info!(worker_id, "Fallback worker started");
    loop {
        // Cancel only between tasks, same invariant as execution_worker:
        // never abort a running L3/L4 recovery mid-flight.
        let task = tokio::select! {
            biased;
            _ = shutdown.cancelled() => break,
            res = fallback_rx.recv() => match res {
                Ok(t) => t,
                Err(_) => break,
            }
        };
        let block_number = task.block_number;

        // L2: try GetWitness from hub (hot buffer + cold tier)
        let hub_payload = match witness_client
            .get_witness(witness_orchestrator::proto::GetWitnessRequest { block_number })
            .await
        {
            Ok(resp) => {
                let w: witness_orchestrator::proto::GetWitnessResponse = resp.into_inner();
                if w.found && !w.data.is_empty() {
                    info!(worker_id, block_number, "GetWitness hit — skipping L3/L4");
                    Some(w.data)
                } else {
                    None
                }
            }
            Err(e) => {
                warn!(worker_id, block_number, err = %e, "GetWitness failed — trying L3/L4");
                None
            }
        };

        let payload = if let Some(p) = hub_payload {
            Some(p)
        } else {
            info!(worker_id, block_number, "Executing L3/L4 recovery");
            generate_fallback_payload(block_number, &config).await
        };

        match payload {
            Some(payload) => {
                info!(worker_id, block_number, "Fallback success — prioritizing execution");
                if high_tx
                    .send(ExecutionTask { block_number, payload: Some(payload) })
                    .await
                    .is_err()
                {
                    warn!(worker_id, block_number, "High-priority channel closed");
                }
                if fallback_done_tx.send((block_number, true)).await.is_err() {
                    warn!(worker_id, block_number, "Fallback done channel closed");
                }
            }
            None => {
                error!(worker_id, block_number, "Fallback exhausted — block permanently missing");
                if fallback_done_tx.send((block_number, false)).await.is_err() {
                    warn!(worker_id, block_number, "Fallback done channel closed");
                }
            }
        }
    }
    info!(worker_id, "Fallback worker exiting");
}

// ============================================================================
// Main orchestrator loop
// ============================================================================

/// Run the courier orchestrator loop forever.
///
/// Creates persistent worker pools and channels once, then reconnects to the
/// gRPC witness stream on failure with exponential backoff.
pub(crate) async fn run<P: Provider + Clone + 'static>(
    config: OrchestratorConfig<P>,
    mut l1_events: mpsc::Receiver<L1Event>,
    shutdown: CancellationToken,
) {
    let db = Arc::new(Mutex::new(Db::open(&config.db_path).expect("Failed to open courier DB")));
    let mut accumulator = {
        let db = Arc::clone(&db);
        tokio::task::spawn_blocking(move || BatchAccumulator::with_db(db))
            .await
            .expect("startup accumulator load panicked")
    };
    let mut backoff = INITIAL_BACKOFF;

    let mut next_batch_from_block: Option<u64> =
        accumulator.max_to_block().map(|e| e + 1).or_else(|| {
            db.lock().unwrap_or_else(|e| e.into_inner()).get_last_batch_end().map(|e| e + 1)
        });

    // Persists across reconnects — a batch still dispatched but with a
    // transiently missing receipt should not reset its observation window
    // when the gRPC stream drops and run_stream recreates its state.
    let mut missing_receipt_first_seen: HashMap<u64, tokio::time::Instant> = HashMap::new();

    // Check dispatched batches from previous run. On startup the map is
    // empty, so the first `Ok(None)` only records `now` (elapsed = 0) and
    // never immediately undispatches a correctly submitted batch.
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

    // Channels live for the entire process — workers survive reconnects.
    // Capacities are tied to EXECUTION_WORKERS to bound memory: each queued
    // ExecutionTask may hold a 30-80 MB payload, so large buffers cause OOM.
    let (high_tx, high_rx) = async_channel::bounded::<ExecutionTask>(EXECUTION_WORKERS);
    let (normal_tx, normal_rx) = async_channel::bounded::<ExecutionTask>(EXECUTION_WORKERS * 2);
    let (fallback_tx, fallback_rx) = async_channel::bounded::<FallbackTask>(1024);
    let (result_tx, mut result_rx) = mpsc::channel::<BlockResult>(EXECUTION_WORKERS * 2);
    let (fallback_done_tx, mut fallback_done_rx) = mpsc::channel::<(u64, bool)>(128);

    // Persistent gRPC channel for execution and fallback workers.
    // Execution workers use this for GetWitness JIT (re-execution tasks).
    // Fallback workers use this to try GetWitness before L3/L4 RPC recovery.
    //
    // Eager connect with retry: `connect_lazy` hides startup failures
    // behind a "healthy" facade, so we poll `.connect()` until the gRPC
    // server is reachable (or shutdown cancels us). The per-request
    // `.timeout(600s)` from the previous version was removed because
    // tonic applies it to server-streaming Subscribe as well, which would
    // rip the long-lived witness stream every 10 minutes. Unary calls
    // that need a timeout set it via `Request::set_timeout` at the call
    // site (see acknowledge_range below and sign_batch_root in 4.2).
    let worker_grpc_channel = loop {
        if shutdown.is_cancelled() {
            info!("Shutdown requested during worker gRPC connect — aborting startup");
            return;
        }
        match Channel::from_shared(config.server_addr.clone())
            .expect("invalid server address")
            .connect_timeout(Duration::from_secs(5))
            .connect()
            .await
        {
            Ok(ch) => break ch,
            Err(e) => {
                warn!(err = %e, "Failed to connect worker gRPC channel — retrying in 5s");
                tokio::select! {
                    _ = shutdown.cancelled() => return,
                    _ = tokio::time::sleep(Duration::from_secs(5)) => {}
                }
            }
        }
    };
    let worker_witness_client = WitnessServiceClient::new(worker_grpc_channel)
        .max_decoding_message_size(MAX_GRPC_MESSAGE_SIZE)
        .max_encoding_message_size(MAX_GRPC_MESSAGE_SIZE);

    // Spawn persistent worker pools into a JoinSet so they can be drained
    // (rather than abruptly dropped by runtime teardown) on shutdown.
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
            worker_witness_client.clone(),
            fallback_tx.clone(),
            shutdown.clone(),
        ));
    }
    for i in 0..config.max_concurrent_fallbacks {
        workers.spawn(fallback_worker(
            i,
            fallback_rx.clone(),
            high_tx.clone(),
            fallback_done_tx.clone(),
            worker_witness_client.clone(),
            config.clone(),
            shutdown.clone(),
        ));
    }

    // Drop result_tx / fallback_done_tx clones held only by this scope —
    // we still own copies for cloning into worker pools but the pools
    // carry their own, so the ones held in `run` itself shouldn't block
    // drain. (We keep them because run_stream reads from result_rx and
    // fallback_done_rx — cloning into workers is enough.)

    loop {
        if shutdown.is_cancelled() {
            info!("Shutdown requested — exiting reconnect loop");
            break;
        }
        let (from_block, confirmed) = {
            let db_guard = db.lock().unwrap_or_else(|e| e.into_inner());
            let from = db_guard.get_checkpoint() + 1;
            let confirmed: HashSet<u64> = db_guard
                .get_all_response_block_numbers()
                .into_iter()
                .filter(|&b| b >= from)
                .collect();
            (from, confirmed)
        };
        info!(from_block, confirmed_count = confirmed.len(), "Connecting to witness server");

        let stream_res = tokio::select! {
            biased;
            _ = shutdown.cancelled() => {
                info!("Shutdown requested while connecting stream");
                break;
            }
            res = run_stream(
                &config,
                &db,
                from_block,
                confirmed,
                &normal_tx,
                &high_tx,
                &fallback_tx,
                &mut result_rx,
                &mut fallback_done_rx,
                &mut l1_events,
                &mut accumulator,
                &mut next_batch_from_block,
                &mut missing_receipt_first_seen,
                shutdown.clone(),
            ) => res,
        };
        match stream_res {
            Ok(()) => {
                info!("Stream ended gracefully");
                backoff = INITIAL_BACKOFF;
            }
            Err(e) => {
                warn!(
                    err = %e,
                    backoff_ms = backoff.as_millis(),
                    "Stream interrupted — reconnecting"
                );
            }
        }

        tokio::select! {
            _ = shutdown.cancelled() => break,
            _ = tokio::time::sleep(backoff) => {}
        }
        backoff = (backoff * 2).min(MAX_BACKOFF);
    }

    // ── Graceful drain ────────────────────────────────────────────────
    // Close the task channels so workers observe `Err` on recv() and
    // exit cleanly after their current task. Then JoinSet.join_next()
    // awaits their completion, bounded by SHUTDOWN_DRAIN_TIMEOUT.
    // Workers check `shutdown.cancelled()` only between HTTP calls —
    // an in-flight payload either completes its round-trip or is never
    // started, preventing "proxy executed, orchestrator gave up" drift.
    info!("Closing worker task channels — draining workers");
    drop(high_tx);
    drop(normal_tx);
    drop(fallback_tx);
    drop(result_tx);
    drop(fallback_done_tx);
    // Drop the receiver halves too: workers completing their final HTTP
    // call will try to `.send()` results. With the receivers still alive
    // those sends buffer up to channel capacity; dropping the receivers
    // makes every such send fail fast so workers exit immediately rather
    // than parking on a full channel.
    drop(result_rx);
    drop(fallback_done_rx);

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
// Per-session orchestration state
// ============================================================================

/// Per-session orchestration state — lives for one gRPC connection.
///
/// Created fresh on each [`run_stream`] call; dropped on disconnect.
/// Cross-session state (`accumulator`, `next_batch_from_block`) lives in [`run`]
/// and is passed by `&mut` so it survives reconnects.
struct StreamState<P: Provider + Clone + 'static> {
    config: OrchestratorConfig<P>,
    db: Arc<Mutex<Db>>,
    high_tx: AsyncSender<ExecutionTask>,
    fallback_tx: AsyncSender<FallbackTask>,
    ack_client: WitnessServiceClient<Channel>,
    sign_done_tx: mpsc::Sender<(u64, SignOutcome)>,
    dispatch_done_tx: mpsc::Sender<(u64, DispatchOutcome)>,
    key_check_tx: mpsc::Sender<(Address, bool)>,
    checkpoint: u64,
    confirmed: HashSet<u64>,
    signing_batch: Option<u64>,
    dispatching_batch: Option<u64>,
    pending_requests: HashSet<u64>,
    highest_witness_received: u64,
    fallback_active: HashSet<u64>,
    fallback_exhausted: HashSet<u64>,
    global_dispatch_attempts: u32,
    global_next_dispatch_allowed: Option<tokio::time::Instant>,
    pending_key_check: Option<Address>,
}

impl<P: Provider + Clone + 'static> StreamState<P> {
    /// Handle a completed block execution response: advance watermark, persist, try dispatch.
    async fn on_block_result(&mut self, result: BlockResult, accumulator: &mut BatchAccumulator) {
        let block_number = result.block_number;
        self.pending_requests.remove(&block_number);

        // Ignore stale results (e.g. from orphaned tasks after reconnect)
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

        // Advance contiguous watermark
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
                accumulator.mark_blobs_accepted(batch_index).await;
                self.try_sign_next_batch(accumulator);
                self.try_dispatch_next_batch(accumulator);
            }
            L1Event::Preconfirmed { batch_index, tx_hash, l1_block } => {
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

    /// Scan for witness gaps and dispatch to the fallback worker pool.
    fn on_fallback_tick(&mut self) {
        if self.highest_witness_received < FALLBACK_GAP_M {
            return;
        }

        if self.fallback_active.len() >= FALLBACK_BATCH_SIZE {
            return;
        }

        let gap_threshold = self.highest_witness_received - FALLBACK_GAP_M;
        let budget = FALLBACK_BATCH_SIZE - self.fallback_active.len();

        let gaps: Vec<u64> = (self.checkpoint + 1..=gap_threshold)
            .filter(|b| {
                !self.confirmed.contains(b)
                    && !self.pending_requests.contains(b)
                    && !self.fallback_active.contains(b)
                    && !self.fallback_exhausted.contains(b)
            })
            .take(budget)
            .collect();

        for block_number in gaps {
            warn!(block_number, "Gap detected — dispatching to fallback pool");
            self.fallback_active.insert(block_number);
            // try_send is safe here: channel capacity (1024) >> FALLBACK_BATCH_SIZE (128)
            if let Err(e) = self.fallback_tx.try_send(FallbackTask { block_number }) {
                warn!(block_number, err = %e, "Fallback channel full — skipping");
                self.fallback_active.remove(&block_number);
            }
        }
    }

    /// Handle a fallback task completion.
    fn on_fallback_done(&mut self, block_number: u64, success: bool) {
        self.fallback_active.remove(&block_number);
        if success {
            self.pending_requests.insert(block_number);
        } else {
            self.fallback_exhausted.insert(block_number);
            error!(
                block_number,
                "Witness fallback exhausted (GetWitness + L3 + L4 failed) — block permanently missing, batch will stall"
            );
        }
    }

    /// Queue a block for re-execution with lazy payload fetch.
    ///
    /// Sends a task with `payload: None` to the high-priority queue.
    /// The execution worker will fetch the witness JIT via gRPC when ready,
    /// avoiding upfront memory allocation for large batches of invalidated blocks.
    fn spawn_re_execution(&mut self, block_number: u64) {
        self.pending_requests.insert(block_number);
        let h_tx = self.high_tx.clone();
        tokio::spawn(async move {
            if h_tx.send(ExecutionTask { block_number, payload: None }).await.is_err() {
                warn!(block_number, "High-priority channel closed during re-execution");
            }
        });
    }

    /// Pick the next ready-but-unsigned batch and spawn a signing task.
    /// No-op if a signing task is already in flight.
    fn try_sign_next_batch(&mut self, accumulator: &BatchAccumulator) {
        if self.signing_batch.is_some() {
            return;
        }

        let batch_index = accumulator.first_ready_unsigned();

        let Some(batch_index) = batch_index else { return };
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

                // Acknowledge cold storage immediately after signing —
                // the signature is durable in DB, so raw witnesses are no longer needed.
                if let Some(batch) = accumulator.get(batch_index) {
                    let mut ack = self.ack_client.clone();
                    let fb = batch.from_block;
                    let tb = batch.to_block;
                    tokio::spawn(async move {
                        let mut backoff = Duration::from_secs(1);
                        const MAX_ACK_RETRIES: u32 = 10;
                        for attempt in 1..=MAX_ACK_RETRIES {
                            let mut req = tonic::Request::new(
                                witness_orchestrator::proto::AcknowledgeRangeRequest {
                                    from_block: fb,
                                    to_block: tb,
                                },
                            );
                            req.set_timeout(Duration::from_secs(10));
                            match ack.acknowledge_range(req).await {
                                Ok(_) => break,
                                Err(e) => {
                                    if attempt == MAX_ACK_RETRIES {
                                        error!(fb, tb, attempt, err = %e, "acknowledge_range failed after all retries — cold files may leak");
                                    } else {
                                        warn!(fb, tb, attempt, err = %e, "acknowledge_range failed — retrying");
                                    }
                                    tokio::time::sleep(backoff).await;
                                    backoff = (backoff * 2).min(Duration::from_secs(30));
                                }
                            }
                        }
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
                self.spawn_key_check(enclave_address, None);
            }
        }
    }

    /// Spawn an async task that checks whether `addr` is registered on L1.
    /// If `delay` is provided, sleeps before checking.
    fn spawn_key_check(&self, addr: Address, delay: Option<Duration>) {
        let tx = self.key_check_tx.clone();
        let provider = self.config.l1_provider.clone();
        let verifier = self.config.nitro_verifier_addr;
        tokio::spawn(async move {
            if let Some(d) = delay {
                tokio::time::sleep(d).await;
            }
            let ok = is_key_registered(&provider, verifier, addr).await.unwrap_or(false);
            if tx.send((addr, ok)).await.is_err() {
                warn!(%addr, "Key check channel closed");
            }
        });
    }

    /// Pick the next sequential signed batch and spawn a dispatch task.
    /// No-op if a dispatch is already in flight or blocked by key check / backoff.
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

        let result = accumulator.first_sequential_signed();

        let Some((batch_index, signature)) = result else { return };

        self.dispatching_batch = Some(batch_index);

        let provider = self.config.l1_provider.clone();
        let contract = self.config.l1_contract_addr;
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
            let mut ack = self.ack_client.clone();
            tokio::spawn(async move {
                let mut req =
                    tonic::Request::new(witness_orchestrator::proto::AcknowledgeRangeRequest {
                        from_block: fb,
                        to_block: tb,
                    });
                req.set_timeout(Duration::from_secs(10));
                if let Err(e) = ack.acknowledge_range(req).await {
                    warn!(fb, tb, err = %e, "Safety-net acknowledge_range failed");
                }
            });
        }

        if changed {
            self.try_sign_next_batch(accumulator);
            self.try_dispatch_next_batch(accumulator);
        }
    }
}

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
///
/// `missing_receipt_first_seen` persists across reconnects so a transiently
/// missing receipt does not reset its observation window whenever the gRPC
/// stream drops. Passing an empty map from a startup call is safe — the
/// first `Ok(None)` records `now` and never immediately undispatches.
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
                // No `break`: keep checking other candidates. A single
                // transient None on one batch must not stall processing of
                // subsequent finalized batches.
            }
            Err(e) => {
                // RPC error is transient — don't advance the window and
                // don't break (other candidates may still have answers).
                warn!(batch_index, %tx_hash, err = %e, "Receipt check failed — will retry");
            }
        }
    }

    (changed, finalized_ranges)
}

// ============================================================================
// Stream session
// ============================================================================

/// Single stream session: connect, spawn gRPC reader, run select! loop.
#[allow(clippy::too_many_arguments)]
async fn run_stream<P: Provider + Clone + 'static>(
    config: &OrchestratorConfig<P>,
    db: &Arc<Mutex<Db>>,
    from_block: u64,
    mut confirmed: HashSet<u64>,
    normal_tx: &AsyncSender<ExecutionTask>,
    high_tx: &AsyncSender<ExecutionTask>,
    fallback_tx: &AsyncSender<FallbackTask>,
    result_rx: &mut mpsc::Receiver<BlockResult>,
    fallback_done_rx: &mut mpsc::Receiver<(u64, bool)>,
    l1_events: &mut mpsc::Receiver<L1Event>,
    accumulator: &mut BatchAccumulator,
    next_batch_from_block: &mut Option<u64>,
    missing_receipt_first_seen: &mut HashMap<u64, tokio::time::Instant>,
    shutdown: CancellationToken,
) -> eyre::Result<()> {
    // NOTE: no `.timeout(..)` on the Channel. Applying a per-request
    // timeout to this Channel would also enforce it on the long-lived
    // server-streaming Subscribe call, ripping the stream periodically.
    // Unary calls set their own timeout via `Request::set_timeout`.
    let channel = Channel::from_shared(config.server_addr.clone())?
        .connect_timeout(Duration::from_secs(5))
        .connect()
        .await?;

    let mut client = WitnessServiceClient::new(channel)
        .max_decoding_message_size(MAX_GRPC_MESSAGE_SIZE)
        .max_encoding_message_size(MAX_GRPC_MESSAGE_SIZE);
    let ack_client = client.clone();
    let mut stream = client.subscribe(SubscribeRequest { from_block }).await?.into_inner();
    info!(from_block, "Subscribed to witness stream");

    // Advance watermark through any already-loaded DB responses
    let mut checkpoint: u64 = from_block.saturating_sub(1);
    while confirmed.contains(&(checkpoint + 1)) {
        checkpoint += 1;
        confirmed.remove(&checkpoint);
    }

    let (sign_done_tx, mut sign_done_rx) = mpsc::channel::<(u64, SignOutcome)>(8);
    let (dispatch_done_tx, mut dispatch_done_rx) = mpsc::channel::<(u64, DispatchOutcome)>(8);
    let (key_check_tx, mut key_check_rx) = mpsc::channel::<(Address, bool)>(4);
    let mut fallback_ticker = tokio::time::interval(Duration::from_secs(5));
    fallback_ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);
    let mut finalization_ticker = tokio::time::interval(Duration::from_secs(30));
    finalization_ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);

    let mut state = StreamState {
        config: config.clone(),
        db: Arc::clone(db),
        high_tx: high_tx.clone(),
        fallback_tx: fallback_tx.clone(),
        ack_client,
        sign_done_tx,
        dispatch_done_tx,
        key_check_tx,
        checkpoint,
        confirmed,
        signing_batch: None,
        dispatching_batch: None,
        pending_requests: HashSet::new(),
        highest_witness_received: from_block.saturating_sub(1),
        fallback_active: HashSet::new(),
        fallback_exhausted: HashSet::new(),
        global_dispatch_attempts: 0,
        global_next_dispatch_allowed: None,
        pending_key_check: None,
    };

    // Dedicated gRPC reader task — provides native HTTP/2 backpressure via
    // blocking .send().await on normal_tx when workers are saturated.
    let session_token = CancellationToken::new();
    let (grpc_event_tx, mut grpc_event_rx) = mpsc::channel::<GrpcEvent>(1024);
    {
        let normal_tx = normal_tx.clone();
        let grpc_event_tx = grpc_event_tx.clone();
        let token = session_token.clone();
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    biased;
                    _ = token.cancelled() => break,
                    msg = stream.message() => match msg {
                        Ok(Some(msg)) => {
                            use witness_orchestrator::proto::witness_message::Content;
                            match msg.content {
                                Some(Content::Witness(w)) => {
                                    let bn = w.block_number;
                                    if grpc_event_tx.send(GrpcEvent::WitnessQueued(bn)).await.is_err() {
                                        warn!(bn, "gRPC event channel closed");
                                    }
                                    if normal_tx.send(ExecutionTask {
                                        block_number: bn,
                                        payload: Some(w.data),
                                    }).await.is_err() {
                                        break;
                                    }
                                }
                                None => {}
                            }
                        }
                        Ok(None) => break,
                        Err(e) => {
                            if grpc_event_tx.send(
                                GrpcEvent::StreamError(e.to_string())
                            ).await.is_err() {
                                warn!("gRPC event channel closed");
                            }
                            break;
                        }
                    },
                }
            }
        });
    }

    let result = async {
        loop {
            tokio::select! {
                biased;
                // ── Shutdown — highest priority so we stop the loop
                //    instead of starting new work under cancellation.
                _ = shutdown.cancelled() => {
                    info!("Shutdown requested — exiting stream session");
                    return Ok(());
                }
                // ── Stream A: gRPC reader events ────────────────────────
                event = grpc_event_rx.recv() => match event {
                    Some(GrpcEvent::WitnessQueued(bn)) => {
                        state.highest_witness_received = state.highest_witness_received.max(bn);
                        state.pending_requests.insert(bn);
                    }
                    Some(GrpcEvent::StreamError(e)) => {
                        return Err(eyre::eyre!("gRPC stream error: {e}"));
                    }
                    None => {
                        info!("Witness stream ended");
                        return Ok(());
                    }
                },

                // ── Stream B: block execution results ───────────────────
                Some(result) = result_rx.recv() =>
                    state.on_block_result(result, accumulator).await,

                // ── Stream C: L1 events ─────────────────────────────────
                Some(event) = l1_events.recv() =>
                    state.on_l1_event(event, accumulator, next_batch_from_block, from_block).await,

                // ── Stream D1: batch signing completions ──────────────
                Some((batch_index, outcome)) = sign_done_rx.recv() =>
                    state.on_sign_done(batch_index, outcome, accumulator).await,

                // ── Stream D2: batch dispatch completions ─────────────
                Some((batch_index, outcome)) = dispatch_done_rx.recv() =>
                    state.on_dispatch_done(batch_index, outcome, accumulator).await,

                // ── Stream E: fallback gap checker ──────────────────────
                _ = fallback_ticker.tick() => state.on_fallback_tick(),

                // ── Stream F: fallback task completions ─────────────────
                Some((block_number, success)) = fallback_done_rx.recv() =>
                    state.on_fallback_done(block_number, success),

                // ── Stream G: key registration check results ────────────
                Some((addr, registered)) = key_check_rx.recv() => {
                    if registered {
                        info!(%addr, "Enclave key confirmed on L1");
                        state.pending_key_check = None;
                        state.try_sign_next_batch(accumulator);
                        state.try_dispatch_next_batch(accumulator);
                    } else {
                        state.spawn_key_check(addr, Some(Duration::from_secs(10)));
                    }
                },

                // ── Stream H: finalization checker ─────────────────────
                _ = finalization_ticker.tick() =>
                    state.on_finalization_tick(accumulator, missing_receipt_first_seen).await,
            }
        }
    }
    .await;

    // Cancel the gRPC reader task for this session
    session_token.cancel();
    result
}

// ============================================================================
// Batch signing I/O
// ============================================================================

/// Sign a batch root via the proxy with retry until definitive result.
///
/// Returns `SignOutcome::Signed` on success (signature persisted to DB),
/// or `SignOutcome::InvalidSignatures` on key rotation (409).
/// Transient errors are retried with exponential backoff (50ms → 2s).
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

    // Build blobs from L2 tx data (with retry — L2 data is immutable so build once)
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

    let body = serde_json::json!({
        "from_block": from_block,
        "to_block": to_block,
        "batch_index": batch_index,
        "responses": responses,
        "blobs": blobs,
    });

    let resp = http_client
        .post(&url)
        // Explicit per-request timeout: the HTTP client default (120s) is
        // too tight for large batches where proxy constructs blobs before
        // signing. 5 minutes is a hard upper bound for a single attempt.
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

    // Key rotation: proxy returns 409 with InvalidSignaturesResponse
    if status == reqwest::StatusCode::CONFLICT {
        let parsed: witness_orchestrator::types::InvalidSignaturesResponse = resp
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

// ============================================================================
// L3/L4 fallback witness generation
// ============================================================================

type FallbackInput = ClientExecutorInput<<FluentEvmConfig as reth_evm::ConfigureEvm>::Primitives>;

/// Generate a witness payload via L3 (local RPC) then L4 (remote archive RPC).
///
/// Returns serialized bincode bytes on success, None if both sources fail.
async fn generate_fallback_payload<P: Provider + Clone + 'static>(
    block_number: u64,
    config: &OrchestratorConfig<P>,
) -> Option<Vec<u8>> {
    let chain_spec = std::sync::Arc::new(fluent_chainspec());
    let evm_config = rsp_host_executor::create_eth_block_execution_strategy_factory(None);
    let executor = HostExecutor::new(evm_config, chain_spec);

    let mut input: Option<FallbackInput> = None;

    // L3 — local Reth JSON-RPC
    if let Some(url_str) = &config.fallback_local_rpc {
        match url::Url::parse(url_str) {
            Ok(url) => {
                let provider = create_provider::<Ethereum>(url);
                match executor.execute(block_number, &provider, None, false).await {
                    Ok(res) => {
                        info!(block_number, "L3 fallback succeeded");
                        input = Some(res);
                    }
                    Err(e) => warn!(block_number, err = %e, "L3 fallback failed — trying L4"),
                }
            }
            Err(e) => warn!(block_number, err = %e, "L3: invalid fallback_local_rpc URL"),
        }
    }

    // L4 — remote archive RPC
    if input.is_none() {
        if let Some(url_str) = &config.fallback_remote_rpc {
            match url::Url::parse(url_str) {
                Ok(url) => {
                    let provider = create_provider::<Ethereum>(url);
                    match executor.execute(block_number, &provider, None, false).await {
                        Ok(res) => {
                            info!(block_number, "L4 fallback succeeded");
                            input = Some(res);
                        }
                        Err(e) => warn!(block_number, err = %e, "L4 fallback failed"),
                    }
                }
                Err(e) => warn!(block_number, err = %e, "L4: invalid fallback_remote_rpc URL"),
            }
        }
    }

    let input = input?;
    match tokio::task::spawn_blocking(move || bincode::serialize(&input)).await {
        Ok(Ok(bytes)) => Some(bytes),
        Ok(Err(e)) => {
            error!(block_number, err = %e, "Fallback: bincode serialization failed");
            None
        }
        Err(e) => {
            error!(block_number, err = %e, "Fallback: spawn_blocking panicked");
            None
        }
    }
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
    /// [`check_finalized_batches`] actually touches. Per-tx receipt answers
    /// come from the provided map (default: `Ok(false)` = missing).
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

        let provider = StubFinality {
            finalized: Some(1000),
            receipts: HashMap::new(), // default Ok(false) — missing
        };
        let mut first_seen: HashMap<u64, tokio::time::Instant> = HashMap::new();

        // First tick: records first_seen, must NOT undispatch.
        let (changed, _) = check_finalized_batches(&provider, &db, &mut acc, &mut first_seen).await;
        assert!(!changed, "first missing receipt must not cause undispatch");
        assert!(acc.has_dispatched(), "batch must remain dispatched");
        assert!(first_seen.contains_key(&1));

        // Advance past the window, then tick again: undispatch expected.
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
        // Batch 1: missing receipt (transient None).
        receipts.insert(tx_a, Ok(false));
        // Batch 2: present — must still finalize in same tick.
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
