//! L1 event listener for batch lifecycle events.
//!
//! Polls the rollup contract on L1 for:
//! - `BatchCommitted(batchIndex, batchRoot, numberOfBlocks, expectedBlobsCount)` — new batch declared
//! - `BatchSubmitted(batchIndex)` — all blobs submitted for the batch
//! - `BatchPreconfirmed(batchIndex, nitroVerifier, verifier)` — preconfirmation accepted
//!
//! Events are sent to the orchestrator via an mpsc channel.
//!
//! Contract ABI lives in `l1-rollup-client`.

use alloy_primitives::{Address, B256};
use alloy_provider::{Provider, RootProvider};
use alloy_rpc_types::Filter;
use alloy_sol_types::SolEvent;
use eyre::{eyre, Result};
use l1_rollup_client::{BatchCommitted, BatchPreconfirmed, BatchSubmitted};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};

// ---------------------------------------------------------------------------
// Event types sent to orchestrator
// ---------------------------------------------------------------------------

/// Events the L1 listener sends to the orchestrator.
///
/// Variant names mirror the v0.1.0 contract event names 1:1.
#[derive(Debug)]
pub(crate) enum L1Event {
    /// `BatchCommitted` — a new batch has been declared on L1.
    BatchCommitted {
        batch_index: u64,
        /// Number of L2 block headers in the batch (`numberOfBlocks` from the event).
        num_blocks: u64,
    },
    /// `BatchSubmitted` — all blobs for the batch have been submitted.
    BatchSubmitted { batch_index: u64 },
    /// `BatchPreconfirmed` — carries the real tx_hash and l1_block.
    Preconfirmed { batch_index: u64, tx_hash: B256, l1_block: u64 },
    /// All events up to this L1 block have been sent.
    /// Orchestrator persists this as the L1 checkpoint.
    Checkpoint(u64),
}

// ---------------------------------------------------------------------------
// Listener loop
// ---------------------------------------------------------------------------

const POLL_INTERVAL_SECS: u64 = 6;
const MAX_POLL_BACKOFF_SECS: u64 = 120;

const MIN_PAGE: u64 = 100;
const MAX_PAGE: u64 = 10_000;
const INITIAL_PAGE: u64 = 2_000;

fn is_too_many_results(err_msg: &str) -> bool {
    let s = err_msg.to_lowercase();
    s.contains("-32005")
        || s.contains("limit exceeded")
        || s.contains("too many results")
        || s.contains("log response size exceeded")
        || s.contains("query returned more than")
        || s.contains("please limit your query")
        || s.contains("range is too large")
}

/// Number of blocks to lag behind `latest` to avoid L1 reorgs.
const L1_SAFE_BLOCKS: u64 = 3;

/// Result of a single poll iteration.
enum PollOutcome {
    /// All pages processed successfully up to this block.
    Complete(u64),
    /// Some pages failed; progress saved up to this block.
    Partial(u64),
}

/// Run the L1 event listener loop.
///
/// Polls L1 logs starting from `from_block` and sends parsed events to `tx`.
/// This function runs forever.
pub(crate) async fn run(
    l1_provider: RootProvider,
    contract_addr: Address,
    mut from_block: u64,
    tx: mpsc::Sender<L1Event>,
    shutdown: CancellationToken,
) {
    info!(
        %contract_addr,
        from_block,
        "L1 listener started"
    );

    let mut backoff_secs = POLL_INTERVAL_SECS;
    let mut page_size: u64 = INITIAL_PAGE;

    loop {
        if shutdown.is_cancelled() {
            info!("Shutdown requested — exiting listener");
            break;
        }
        // Secondary guard: if the consumer dropped the receiver without
        // going through the shutdown token, the Partial/Err retry cycle
        // would otherwise spin forever.
        if tx.is_closed() {
            warn!("L1 event channel closed — exiting listener");
            break;
        }

        match poll_once(&l1_provider, contract_addr, from_block, &mut page_size, &tx, &shutdown)
            .await
        {
            Ok(PollOutcome::Complete(latest)) => {
                if tx.send(L1Event::Checkpoint(latest)).await.is_err() {
                    warn!(latest, "L1 event channel closed");
                    break;
                }
                from_block = latest + 1;
                backoff_secs = POLL_INTERVAL_SECS; // reset on full success
            }
            Ok(PollOutcome::Partial(last_ok)) => {
                if tx.send(L1Event::Checkpoint(last_ok)).await.is_err() {
                    warn!(last_ok, "L1 event channel closed");
                    break;
                }
                from_block = last_ok + 1;
                // Escalate backoff — don't reset, we hit rate limits
                backoff_secs = (backoff_secs * 2).min(MAX_POLL_BACKOFF_SECS);
                warn!(from_block, backoff_secs, "Partial progress — backing off");
            }
            Err(e) => {
                warn!(err = %e, backoff_secs, "L1 poll failed — retrying");
                backoff_secs = (backoff_secs * 2).min(MAX_POLL_BACKOFF_SECS);
            }
        }

        tokio::select! {
            _ = shutdown.cancelled() => {
                info!("Shutdown requested mid-backoff — exiting listener");
                break;
            }
            _ = tokio::time::sleep(std::time::Duration::from_secs(backoff_secs)) => {}
        }
    }

    info!("L1 listener exiting");
}

/// Single poll iteration: fetch logs from `from_block` to latest, paginated.
/// Returns `Complete` on full success, `Partial` on page failure with progress saved.
async fn poll_once(
    provider: &RootProvider,
    contract_addr: Address,
    from_block: u64,
    page_size: &mut u64,
    tx: &mpsc::Sender<L1Event>,
    shutdown: &CancellationToken,
) -> Result<PollOutcome> {
    let raw_latest =
        provider.get_block_number().await.map_err(|e| eyre!("Failed to get latest block: {e}"))?;
    let latest_block = raw_latest.saturating_sub(L1_SAFE_BLOCKS);

    if from_block > latest_block {
        return Ok(PollOutcome::Complete(from_block.saturating_sub(1)));
    }

    let mut current = from_block;
    let mut last_ok = from_block.saturating_sub(1);

    while current <= latest_block {
        let page_end = (current + *page_size - 1).min(latest_block);

        match process_page(provider, contract_addr, current, page_end, tx).await {
            Ok(()) => {
                last_ok = page_end;
                current = page_end + 1;
                *page_size = (*page_size + 100).min(MAX_PAGE);
            }
            Err(e) if is_too_many_results(&format!("{e}")) => {
                if shutdown.is_cancelled() {
                    return Ok(PollOutcome::Partial(last_ok));
                }
                let prev = *page_size;
                *page_size = (*page_size / 2).max(MIN_PAGE);
                warn!(new_page_size = *page_size, "RPC log limit hit — shrinking page");
                // If already at MIN_PAGE and still hitting the limit, bail
                // with partial progress so the outer backoff can kick in —
                // otherwise we spin retrying the same range forever.
                if prev == MIN_PAGE {
                    warn!(
                        current,
                        page_end, "RPC limit hit at MIN_PAGE — returning partial progress"
                    );
                    return Ok(PollOutcome::Partial(last_ok));
                }
                continue;
            }
            Err(e) => {
                warn!(err = %e, current, page_end, "Page failed — returning partial progress");
                return Ok(PollOutcome::Partial(last_ok));
            }
        }
    }

    Ok(PollOutcome::Complete(latest_block))
}

/// Process a single page of blocks: fetch and emit all event types in one query.
async fn process_page(
    provider: &RootProvider,
    contract_addr: Address,
    from: u64,
    to: u64,
    tx: &mpsc::Sender<L1Event>,
) -> Result<()> {
    let filter = Filter::new()
        .address(contract_addr)
        .event_signature(vec![
            BatchCommitted::SIGNATURE_HASH,
            BatchSubmitted::SIGNATURE_HASH,
            BatchPreconfirmed::SIGNATURE_HASH,
        ])
        .from_block(from)
        .to_block(to);

    let logs = provider
        .get_logs(&filter)
        .await
        .map_err(|e| eyre!("Log query failed [{from}..{to}]: {e}"))?;

    for log in &logs {
        let topic0 = log.topic0().copied().unwrap_or_default();

        if topic0 == BatchCommitted::SIGNATURE_HASH {
            let event = BatchCommitted::decode_log_data(&log.inner.data).map_err(|e| {
                eyre!("Failed to decode BatchCommitted at L1 block {:?}: {e}", log.block_number)
            })?;
            let batch_index: u64 = event
                .batchIndex
                .try_into()
                .map_err(|_| eyre!("batchIndex overflow: {}", event.batchIndex))?;
            let num_blocks: u64 = event
                .numberOfBlocks
                .try_into()
                .map_err(|_| eyre!("numberOfBlocks overflow: {}", event.numberOfBlocks))?;
            if num_blocks == 0 {
                return Err(eyre!(
                    "BatchCommitted with num_blocks=0 (batch_index={batch_index}) — refusing to advance checkpoint"
                ));
            }
            info!(batch_index, num_blocks, "BatchCommitted event");

            if tx.send(L1Event::BatchCommitted { batch_index, num_blocks }).await.is_err() {
                return Err(eyre!("L1 event channel closed"));
            }
        } else if topic0 == BatchSubmitted::SIGNATURE_HASH {
            let event = BatchSubmitted::decode_log_data(&log.inner.data).map_err(|e| {
                eyre!("Failed to decode BatchSubmitted at L1 block {:?}: {e}", log.block_number)
            })?;
            let batch_index: u64 = event
                .batchIndex
                .try_into()
                .map_err(|_| eyre!("batchIndex overflow: {}", event.batchIndex))?;
            info!(batch_index, "BatchSubmitted event");
            if tx.send(L1Event::BatchSubmitted { batch_index }).await.is_err() {
                return Err(eyre!("L1 event channel closed"));
            }
        } else if topic0 == BatchPreconfirmed::SIGNATURE_HASH {
            let event = BatchPreconfirmed::decode_log_data(&log.inner.data).map_err(|e| {
                eyre!("Failed to decode BatchPreconfirmed at L1 block {:?}: {e}", log.block_number)
            })?;
            let batch_index: u64 = event
                .batchIndex
                .try_into()
                .map_err(|_| eyre!("batchIndex overflow: {}", event.batchIndex))?;
            let tx_hash = log
                .transaction_hash
                .ok_or_else(|| eyre!("BatchPreconfirmed log missing transaction_hash"))?;
            let l1_block = log
                .block_number
                .ok_or_else(|| eyre!("BatchPreconfirmed log missing block_number"))?;
            info!(batch_index, %tx_hash, l1_block, "BatchPreconfirmed event");
            if tx.send(L1Event::Preconfirmed { batch_index, tx_hash, l1_block }).await.is_err() {
                return Err(eyre!("L1 event channel closed"));
            }
        }
    }

    Ok(())
}
