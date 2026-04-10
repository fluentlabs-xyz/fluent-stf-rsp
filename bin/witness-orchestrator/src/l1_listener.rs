//! L1 event listener for batch lifecycle events.
//!
//! Polls the rollup contract on L1 for:
//! - `BatchHeadersSubmitted(batchIndex, batchRoot, expectedBlobsCount)` — new batch declared
//! - `BatchAccepted(batchIndex)` — all blobs submitted for the batch
//!
//! Events are sent to the orchestrator via an mpsc channel.
//!
//! Contract ABI + stateless decode helpers live in `l1-rollup-client`.

use alloy_primitives::{Address, B256};
use alloy_provider::{Provider, RootProvider};
use alloy_rpc_types::Filter;
use alloy_sol_types::SolEvent;
use eyre::{eyre, Result};
use l1_rollup_client::{
    fetch_block_count_from_tx, BatchAccepted, BatchHeadersSubmitted, BatchPreconfirmed,
};
use tokio::sync::mpsc;
use tracing::{error, info, warn};

// ---------------------------------------------------------------------------
// Event types sent to orchestrator
// ---------------------------------------------------------------------------

/// Events the L1 listener sends to the orchestrator.
#[derive(Debug)]
pub enum L1Event {
    /// A new batch has been declared on L1.
    BatchHeaders {
        batch_index: u64,
        batch_root: B256,
        expected_blobs: u64,
        /// Number of block headers in the `acceptNextBatch` calldata.
        /// Used with sequential tracking to determine from_block/to_block.
        num_blocks: u64,
    },
    /// All blobs for the batch have been accepted.
    BlobsAccepted { batch_index: u64 },
    /// Batch was preconfirmed on L1 — carries the real tx_hash and l1_block.
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
pub async fn run(
    l1_provider: RootProvider,
    contract_addr: Address,
    mut from_block: u64,
    tx: mpsc::Sender<L1Event>,
) -> ! {
    info!(
        %contract_addr,
        from_block,
        "L1 listener started"
    );

    let mut backoff_secs = POLL_INTERVAL_SECS;

    loop {
        match poll_once(&l1_provider, contract_addr, from_block, &tx).await {
            Ok(PollOutcome::Complete(latest)) => {
                if tx.send(L1Event::Checkpoint(latest)).await.is_err() {
                    warn!(latest, "L1 event channel closed");
                }
                from_block = latest + 1;
                backoff_secs = POLL_INTERVAL_SECS; // reset on full success
            }
            Ok(PollOutcome::Partial(last_ok)) => {
                if tx.send(L1Event::Checkpoint(last_ok)).await.is_err() {
                    warn!(last_ok, "L1 event channel closed");
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

        tokio::time::sleep(std::time::Duration::from_secs(backoff_secs)).await;
    }
}

const PAGE_SIZE: u64 = 2_000;
const MAX_RPC_RETRIES: u32 = 5;

/// Fetch block count with retry and exponential backoff for transient RPC errors (429, timeouts).
async fn retry_fetch_block_count(
    provider: &RootProvider,
    tx_hash: Option<B256>,
    batch_index: u64,
) -> Result<u64> {
    let mut backoff = std::time::Duration::from_millis(500);
    let mut last_err = None;
    for attempt in 1..=MAX_RPC_RETRIES {
        match fetch_block_count_from_tx(provider, tx_hash).await {
            Ok(n) => return Ok(n),
            Err(e) => {
                warn!(batch_index, attempt, err = %e, ?backoff, "fetch_block_count failed — retrying");
                last_err = Some(e);
                tokio::time::sleep(backoff).await;
                backoff *= 2;
            }
        }
    }
    Err(last_err.unwrap_or_else(|| eyre!("fetch_block_count failed with 0 retries")))
}

/// Single poll iteration: fetch logs from `from_block` to latest, paginated.
/// Returns `Complete` on full success, `Partial` on page failure with progress saved.
async fn poll_once(
    provider: &RootProvider,
    contract_addr: Address,
    from_block: u64,
    tx: &mpsc::Sender<L1Event>,
) -> Result<PollOutcome> {
    let raw_latest =
        provider.get_block_number().await.map_err(|e| eyre!("Failed to get latest block: {e}"))?;
    let latest_block = raw_latest.saturating_sub(L1_SAFE_BLOCKS);

    if from_block > latest_block {
        return Ok(PollOutcome::Complete(from_block.saturating_sub(1)));
    }

    let mut current = from_block;
    // Track last fully-processed page so we can return partial progress on error.
    let mut last_ok = from_block.saturating_sub(1);

    while current <= latest_block {
        let page_end = (current + PAGE_SIZE - 1).min(latest_block);

        if let Err(e) = process_page(provider, contract_addr, current, page_end, tx).await {
            warn!(err = %e, current, page_end, "Page failed — returning partial progress");
            return Ok(PollOutcome::Partial(last_ok));
        }

        last_ok = page_end;
        current = page_end + 1;
    }

    Ok(PollOutcome::Complete(latest_block))
}

/// Process a single page of blocks: fetch and emit both event types in one query.
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
            BatchHeadersSubmitted::SIGNATURE_HASH,
            BatchAccepted::SIGNATURE_HASH,
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

        if topic0 == BatchHeadersSubmitted::SIGNATURE_HASH {
            match BatchHeadersSubmitted::decode_log_data(&log.inner.data) {
                Ok(event) => {
                    let batch_index: u64 = event
                        .batchIndex
                        .try_into()
                        .map_err(|_| eyre!("batchIndex overflow: {}", event.batchIndex))?;
                    let expected_blobs: u64 =
                        event.expectedBlobsCount.try_into().map_err(|_| {
                            eyre!("expectedBlobsCount overflow: {}", event.expectedBlobsCount)
                        })?;

                    let num_blocks =
                        retry_fetch_block_count(provider, log.transaction_hash, batch_index)
                            .await?;

                    info!(batch_index, expected_blobs, num_blocks, "BatchHeadersSubmitted event");

                    if tx
                        .send(L1Event::BatchHeaders {
                            batch_index,
                            batch_root: event.batchRoot,
                            expected_blobs,
                            num_blocks,
                        })
                        .await
                        .is_err()
                    {
                        warn!(batch_index, "L1 event channel closed");
                    }
                }
                Err(e) => error!(err = %e, "Failed to decode BatchHeadersSubmitted"),
            }
        } else if topic0 == BatchAccepted::SIGNATURE_HASH {
            match BatchAccepted::decode_log_data(&log.inner.data) {
                Ok(event) => {
                    let batch_index: u64 = event
                        .batchIndex
                        .try_into()
                        .map_err(|_| eyre!("batchIndex overflow: {}", event.batchIndex))?;
                    info!(batch_index, "BatchAccepted event");
                    if tx.send(L1Event::BlobsAccepted { batch_index }).await.is_err() {
                        warn!(batch_index, "L1 event channel closed");
                    }
                }
                Err(e) => error!(err = %e, "Failed to decode BatchAccepted"),
            }
        } else if topic0 == BatchPreconfirmed::SIGNATURE_HASH {
            match BatchPreconfirmed::decode_log_data(&log.inner.data) {
                Ok(event) => {
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
                    if tx
                        .send(L1Event::Preconfirmed { batch_index, tx_hash, l1_block })
                        .await
                        .is_err()
                    {
                        warn!(batch_index, "L1 event channel closed");
                    }
                }
                Err(e) => error!(err = %e, "Failed to decode BatchPreconfirmed"),
            }
        }
    }

    Ok(())
}
