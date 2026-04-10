//! L1 rollup contract bindings and helpers — the read+write surface for the
//! Fluent rollup contract on L1. Used by `bin/witness-orchestrator` (read +
//! write) and `bin/proxy` (read only, for batch metadata lookup).
//!
//! What lives here:
//! - sol! ABI: events (BatchHeadersSubmitted, BatchAccepted, BatchPreconfirmed)
//!   and functions (acceptNextBatch, preconfirmBatch, verifiedPubkeys).
//! - Read helpers: decode_accept_next_batch, fetch_block_count_from_tx,
//!   find_batch_log, resolve_l2_start_checkpoint, fetch_batch_range.
//! - Write helpers: submit_preconfirmation, is_key_registered.
//!
//! What does NOT live here (intentionally):
//! - Polling loop (run/poll_once/process_page) — orchestrator-specific,
//!   coupled to mpsc channels and backoff state.
//! - L1Event enum — orchestrator-specific event channel type.

use alloy_primitives::{Address, Bytes, B256, U256};
use alloy_provider::{Provider, RootProvider};
use alloy_rpc_types::{Filter, Log, TransactionRequest};
use alloy_sol_types::{sol, SolCall, SolEvent};
use eyre::{eyre, Result};
use tracing::{info, warn};

// =====================================================================
// Contract ABI
// =====================================================================

sol! {
    /// Emitted by `acceptNextBatch` — declares a new batch with its block range.
    event BatchHeadersSubmitted(
        uint256 indexed batchIndex,
        bytes32 batchRoot,
        uint256 expectedBlobsCount
    );

    /// Emitted when all blobs for a batch have been submitted via `submitBlobs`.
    event BatchAccepted(uint256 indexed batchIndex);

    /// Emitted when `preconfirmBatch` succeeds.
    event BatchPreconfirmed(
        uint256 indexed batchIndex,
        address indexed verifierContract,
        address indexed verifier
    );

    /// L2 block header committed in `acceptNextBatch` calldata.
    struct L2BlockHeader {
        bytes32 previousBlockHash;
        bytes32 blockHash;
        bytes32 withdrawalRoot;
        bytes32 depositRoot;
        uint256 depositCount;
    }

    /// Function ABI for calldata decoding.
    function acceptNextBatch(L2BlockHeader[] calldata blockHeaders, uint256 expectedBlobsCount) external;

    /// Submit enclave signature to L1, proving batch validity.
    function preconfirmBatch(
        address nitroVerifier,
        uint256 batchIndex,
        bytes signature
    ) external;

    /// NitroVerifier view function (auto-generated getter for mapping).
    function verifiedPubkeys(address) external view returns (bool);
}

// =====================================================================
// Read helpers (moved from witness-orchestrator/src/l1_listener.rs)
// =====================================================================

/// Decode `acceptNextBatch` calldata from a transaction hash.
///
/// Returns the decoded call struct containing all block headers.
/// The caller decides whether to retry or abort on error.
pub async fn decode_accept_next_batch(
    provider: &RootProvider,
    tx_hash: Option<B256>,
) -> Result<acceptNextBatchCall> {
    let hash = tx_hash.ok_or_else(|| eyre!("log has no transaction hash"))?;

    let tx = provider
        .get_transaction_by_hash(hash)
        .await
        .map_err(|e| eyre!("get_transaction_by_hash failed: {e}"))?
        .ok_or_else(|| eyre!("transaction {hash} not found"))?;

    let input = alloy_rpc_types::TransactionTrait::input(&tx);

    acceptNextBatchCall::abi_decode(input)
        .map_err(|e| eyre!("Failed to decode acceptNextBatch calldata: {e}"))
}

/// Attempt to determine the number of block headers from the `acceptNextBatch`
/// transaction calldata.
///
/// Returns `Err` on network failure or malformed calldata.
/// The caller decides whether to retry or abort.
pub async fn fetch_block_count_from_tx(
    provider: &RootProvider,
    tx_hash: Option<B256>,
) -> Result<u64> {
    Ok(decode_accept_next_batch(provider, tx_hash).await?.blockHeaders.len() as u64)
}

/// Find the `BatchHeadersSubmitted` log for a specific batch index.
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
            .event_signature(BatchHeadersSubmitted::SIGNATURE_HASH)
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

/// Resolve the L2 starting block for a given `batch_id` by looking up the
/// `acceptNextBatch` calldata on L1 and then querying the L2 node for the
/// block number corresponding to `blockHeaders[0].previousBlockHash`.
///
/// Returns `(l2_from_block, l1_event_block, num_blocks)`:
/// - `l2_from_block`: first L2 block in the batch
/// - `l1_event_block`: L1 block containing the `BatchHeadersSubmitted` event
/// - `num_blocks`: number of L2 block headers committed in the batch
pub async fn resolve_l2_start_checkpoint(
    l1_provider: &RootProvider,
    l2_provider: &RootProvider,
    contract_addr: Address,
    batch_id: u64,
    l1_deploy_block: u64,
) -> Result<(u64, u64, u64)> {
    let latest = l1_provider
        .get_block_number()
        .await
        .map_err(|e| eyre!("Failed to get latest L1 block: {e}"))?;

    let batch_topic = B256::from(U256::from(batch_id));

    // Find the BatchHeadersSubmitted log for the target batch.
    // Try full-range first; fall back to paginated scan if the RPC rejects
    // a wide block range (Infura/Alchemy cap ~10k blocks per query).
    let log = find_batch_log(l1_provider, contract_addr, batch_topic, l1_deploy_block, latest)
        .await?
        .ok_or_else(|| {
            eyre!(
                "BatchHeadersSubmitted for batch {batch_id} not found in L1 blocks \
             [{l1_deploy_block}..{latest}]. \
             Ensure FLUENT_L1_DEPLOY_BLOCK is ≤ the block where batch 0 was submitted, \
             and that L1_RPC_URL is correct."
            )
        })?;

    let l1_block =
        log.block_number.ok_or_else(|| eyre!("BatchHeadersSubmitted log missing block_number"))?;

    let decoded = decode_accept_next_batch(l1_provider, log.transaction_hash)
        .await
        .map_err(|e| eyre!("Failed to decode calldata for batch {batch_id}: {e}"))?;

    let num_blocks = decoded.blockHeaders.len() as u64;

    // Batch 0 always starts at L2 block 1 (genesis).
    let l2_from_block = if batch_id == 0 {
        1
    } else {
        let prev_hash = decoded.blockHeaders[0].previousBlockHash;
        let block = l2_provider
            .get_block_by_hash(prev_hash)
            .await
            .map_err(|e| eyre!("L2 eth_getBlockByHash({prev_hash}) failed: {e}"))?
            .ok_or_else(|| {
                eyre!(
                    "L2 block with hash {prev_hash} not found — \
                 is the L2 RPC (FLUENT_FALLBACK_LOCAL_RPC) synced?"
                )
            })?;
        block.header.number + 1
    };

    info!(
        batch_id,
        l2_from_block,
        num_blocks,
        l1_block,
        "Resolved L2 start checkpoint from L1 calldata + L2 block lookup"
    );

    Ok((l2_from_block, l1_block, num_blocks))
}

/// Resolve `(from_block, to_block)` for a given `batch_id` using only L1
/// reads (plus one L2 lookup for `previousBlockHash` resolution).
/// Used by `bin/proxy` to map a challenge request's `batch_index` →
/// L2 block range without requiring the caller to know it.
///
/// Thin wrapper around `resolve_l2_start_checkpoint` — discards the
/// `l1_event_block` field that proxy doesn't need.
pub async fn fetch_batch_range(
    l1_provider: &RootProvider,
    l2_provider: &RootProvider,
    contract_addr: Address,
    batch_id: u64,
    l1_deploy_block: u64,
) -> Result<(u64, u64)> {
    let (l2_from_block, _l1_event_block, num_blocks) = resolve_l2_start_checkpoint(
        l1_provider,
        l2_provider,
        contract_addr,
        batch_id,
        l1_deploy_block,
    )
    .await?;
    let to_block = l2_from_block + num_blocks - 1;
    Ok((l2_from_block, to_block))
}

// =====================================================================
// Write helpers (moved from witness-orchestrator/src/l1_submitter.rs)
// =====================================================================

/// Metadata from a confirmed L1 transaction, used for finalization tracking.
#[derive(Debug, Clone)]
pub struct SubmitReceipt {
    pub tx_hash: B256,
    pub l1_block: u64,
}

/// Check if an enclave address is registered in NitroVerifier.
pub async fn is_key_registered(
    provider: &impl Provider,
    nitro_verifier_addr: Address,
    enclave_address: Address,
) -> Result<bool> {
    let call = verifiedPubkeysCall(enclave_address);
    let tx = TransactionRequest {
        to: Some(nitro_verifier_addr.into()),
        input: Bytes::from(call.abi_encode()).into(),
        ..Default::default()
    };
    let result = provider.call(tx).await.map_err(|e| eyre!("verifiedPubkeys call failed: {e}"))?;
    let registered = verifiedPubkeysCall::abi_decode_returns(&result)
        .map_err(|e| eyre!("Failed to decode verifiedPubkeys result: {e}"))?;
    Ok(registered)
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
