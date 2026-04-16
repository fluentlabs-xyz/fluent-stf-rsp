//! L1 rollup contract bindings and helpers — the read+write surface for the
//! Fluent rollup contract on L1. Used by `bin/witness-orchestrator` (read +
//! write) and `bin/proxy` (read only, for batch metadata lookup).
//!
//! Targets the `release/v0.1.0` deployment of `Rollup.sol`.
//!
//! What lives here:
//! - sol! ABI: events (`BatchCommitted`, `BatchSubmitted`, `BatchPreconfirmed`)
//!   and functions (`preconfirmBatch`).
//! - Read helpers: `find_batch_log`, `resolve_l2_start_checkpoint`, `fetch_batch_range`.
//! - Write helpers: `submit_preconfirmation`.
//!
//! What does NOT live here (intentionally):
//! - Polling loop — orchestrator-specific.
//! - L1Event enum — orchestrator-specific event channel type.
//! - NitroVerifier ABI — see `nitro_verifier` submodule.

pub mod nitro_verifier;

pub use nitro_verifier::is_key_registered;

use alloy_primitives::{Address, Bytes, B256, U256};
use alloy_provider::{Provider, RootProvider};
use alloy_rpc_types::{Filter, Log, TransactionRequest};
use alloy_sol_types::{sol, SolCall, SolEvent};
use eyre::{eyre, Result};
use tracing::{info, warn};

// =====================================================================
// Contract ABI (Rollup.sol @ release/v0.1.0)
// =====================================================================

sol! {
    /// Emitted by `commitBatch` — declares a new batch with its block count.
    event BatchCommitted(
        uint256 indexed batchIndex,
        bytes32 batchRoot,
        uint24 numberOfBlocks,
        uint8 expectedBlobsCount
    );

    /// Emitted when all blobs for the batch have been submitted.
    event BatchSubmitted(uint256 indexed batchIndex);

    /// Emitted when `preconfirmBatch` succeeds.
    event BatchPreconfirmed(
        uint256 indexed batchIndex,
        address nitroVerifier,
        address verifier
    );

    /// Submit enclave signature to L1, proving batch validity.
    function preconfirmBatch(
        address nitroVerifier,
        uint256 batchIndex,
        bytes signature
    ) external;
}

// =====================================================================
// Read helpers
// =====================================================================

/// Find the `BatchCommitted` log for a specific batch index.
///
/// Tries a single full-range query first. If the RPC rejects it (rate limit
/// or block range cap), falls back to a paginated scan with 50k-block pages.
pub async fn find_batch_log(
    provider: &RootProvider,
    contract_addr: Address,
    batch_topic: B256,
    from: u64,
    to: u64,
) -> Result<Option<Log>> {
    let make_filter = |f: u64, t: u64| {
        Filter::new()
            .address(contract_addr)
            .event_signature(BatchCommitted::SIGNATURE_HASH)
            .topic1(batch_topic)
            .from_block(f)
            .to_block(t)
    };

    // Fast path: single query.
    match provider.get_logs(&make_filter(from, to)).await {
        Ok(logs) => return Ok(logs.into_iter().next()),
        Err(e) => warn!(err = %e, "Full-range eth_getLogs failed — falling back to paginated scan"),
    }

    // Slow path: paginated with throttle to avoid rate limiting.
    const PAGE: u64 = 50_000;
    const SCAN_DELAY: std::time::Duration = std::time::Duration::from_millis(500);
    let mut current = from;
    while current <= to {
        let page_end = (current + PAGE - 1).min(to);
        let logs = provider
            .get_logs(&make_filter(current, page_end))
            .await
            .map_err(|e| eyre!("eth_getLogs [{current}..{page_end}] failed: {e}"))?;
        if let Some(log) = logs.into_iter().next() {
            return Ok(Some(log));
        }
        current = page_end + 1;
        if current <= to {
            tokio::time::sleep(SCAN_DELAY).await;
        }
    }

    Ok(None)
}

/// Walk all `BatchCommitted` events from `l1_deploy_block` until the event
/// for `batch_id` is found, summing `numberOfBlocks` for prior batches to
/// derive the L2 starting block.
///
/// Returns `(l2_from_block, l1_event_block, num_blocks)`:
/// - `l2_from_block`: first L2 block in the batch (`1 + sum(prior numberOfBlocks)`)
/// - `l1_event_block`: L1 block containing the `BatchCommitted` event
/// - `num_blocks`: number of L2 block headers in this batch
///
/// Note: this is O(batch_id) on cold start. Callers should treat it as a
/// rare manual operation (e.g., explicit `L1_START_BATCH_ID`).
pub async fn resolve_l2_start_checkpoint(
    l1_provider: &RootProvider,
    contract_addr: Address,
    batch_id: u64,
    l1_deploy_block: u64,
) -> Result<(u64, u64, u64)> {
    let latest = l1_provider
        .get_block_number()
        .await
        .map_err(|e| eyre!("Failed to get latest L1 block: {e}"))?;

    const PAGE: u64 = 50_000;
    const SCAN_DELAY: std::time::Duration = std::time::Duration::from_millis(500);

    let mut sum_blocks: u64 = 0;
    let mut target: Option<(u64, u64)> = None; // (l1_event_block, num_blocks)
    let mut current = l1_deploy_block;

    'outer: while current <= latest {
        let page_end = (current + PAGE - 1).min(latest);
        let filter = Filter::new()
            .address(contract_addr)
            .event_signature(BatchCommitted::SIGNATURE_HASH)
            .from_block(current)
            .to_block(page_end);
        let logs = l1_provider
            .get_logs(&filter)
            .await
            .map_err(|e| eyre!("eth_getLogs [{current}..{page_end}] failed: {e}"))?;

        for log in logs {
            let event = BatchCommitted::decode_log_data(&log.inner.data)
                .map_err(|e| eyre!("decode BatchCommitted: {e}"))?;
            let idx: u64 = event
                .batchIndex
                .try_into()
                .map_err(|_| eyre!("batchIndex overflow: {}", event.batchIndex))?;
            let num_blocks: u64 = event
                .numberOfBlocks
                .try_into()
                .map_err(|_| eyre!("numberOfBlocks overflow: {}", event.numberOfBlocks))?;

            if idx < batch_id {
                sum_blocks += num_blocks;
            } else if idx == batch_id {
                let l1_block = log
                    .block_number
                    .ok_or_else(|| eyre!("BatchCommitted log missing block_number"))?;
                target = Some((l1_block, num_blocks));
                break 'outer;
            }
        }

        current = page_end + 1;
        if current <= latest {
            tokio::time::sleep(SCAN_DELAY).await;
        }
    }

    let (l1_block, num_blocks) = target.ok_or_else(|| {
        eyre!(
            "BatchCommitted for batch {batch_id} not found in L1 blocks \
             [{l1_deploy_block}..{latest}]. \
             Ensure L1_ROLLUP_DEPLOY_BLOCK is ≤ the block where batch 0 was committed."
        )
    })?;

    let l2_from_block = 1 + sum_blocks;

    info!(
        batch_id,
        l2_from_block,
        num_blocks,
        l1_block,
        "Resolved L2 start checkpoint by walking BatchCommitted events"
    );

    Ok((l2_from_block, l1_block, num_blocks))
}

/// Resolve `(from_block, to_block)` for a given `batch_id` using only L1
/// reads. Used by `bin/proxy` to map a challenge request's `batch_index` →
/// L2 block range without requiring the caller to know it.
pub async fn fetch_batch_range(
    l1_provider: &RootProvider,
    contract_addr: Address,
    batch_id: u64,
    l1_deploy_block: u64,
) -> Result<(u64, u64)> {
    let (l2_from_block, _l1_event_block, num_blocks) =
        resolve_l2_start_checkpoint(l1_provider, contract_addr, batch_id, l1_deploy_block).await?;
    let to_block = l2_from_block + num_blocks - 1;
    Ok((l2_from_block, to_block))
}

// =====================================================================
// Write helpers
// =====================================================================

/// Metadata from a confirmed L1 transaction, used for finalization tracking.
#[derive(Debug, Clone)]
pub struct SubmitReceipt {
    pub tx_hash: B256,
    pub l1_block: u64,
}

/// Submit `preconfirmBatch` to L1 and wait for the receipt.
pub async fn submit_preconfirmation(
    provider: &impl Provider,
    contract_addr: Address,
    nitro_verifier_addr: Address,
    batch_index: u64,
    signature: Vec<u8>,
) -> Result<SubmitReceipt> {
    let call = preconfirmBatchCall {
        nitroVerifier: nitro_verifier_addr,
        batchIndex: U256::from(batch_index),
        signature: Bytes::from(signature),
    };

    let tx = TransactionRequest {
        to: Some(contract_addr.into()),
        input: Bytes::from(call.abi_encode()).into(),
        ..Default::default()
    };

    let pending = provider
        .send_transaction(tx)
        .await
        .map_err(|e| eyre!("preconfirmBatch tx send failed: {e}"))?;

    let tx_hash = *pending.tx_hash();
    info!(%tx_hash, batch_index, "preconfirmBatch tx sent");

    let receipt =
        pending.get_receipt().await.map_err(|e| eyre!("preconfirmBatch receipt failed: {e}"))?;

    if !receipt.status() {
        return Err(eyre!("preconfirmBatch reverted (tx {tx_hash}, batch {batch_index})"));
    }

    let l1_block =
        receipt.block_number.ok_or_else(|| eyre!("receipt missing block_number (tx {tx_hash})"))?;

    info!(
        %tx_hash,
        batch_index,
        l1_block,
        gas_used = receipt.gas_used,
        "preconfirmBatch confirmed"
    );

    Ok(SubmitReceipt { tx_hash, l1_block })
}
