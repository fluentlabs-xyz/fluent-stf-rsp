//! L1 rollup contract bindings and helpers — the read+write surface for the
//! Fluent rollup contract on L1. Used by `bin/witness-orchestrator` (read +
//! write) and `bin/proxy` (read only, for batch metadata lookup).
//!
//! Targets the `release/v1.0.0` deployment of `Rollup.sol`.
//!
//! What lives here:
//! - sol! ABI: all on-chain events (lifecycle, challenge, rewards) and the `preconfirmBatch`
//!   function.
//! - Read helpers: `resolve_l2_start_checkpoint`, `fetch_batch_range`.
//! - Write helpers: `submit_preconfirmation`.
//!
//! What does NOT live here (intentionally):
//! - Polling loop — orchestrator-specific.
//! - L1Event enum — orchestrator-specific event channel type.
//! - NitroVerifier ABI — see `nitro_verifier` submodule.

pub mod nitro_verifier;

pub use nitro_verifier::is_key_registered;

use alloy_consensus::{SignableTransaction, TxEip1559, TxEnvelope};
use alloy_eips::eip2718::Encodable2718;
use alloy_network::TxSigner;
use alloy_primitives::{Address, Bytes, FixedBytes, Signature, TxKind, B256, U256};
use alloy_provider::{Provider, RootProvider};
use alloy_rpc_types::{Filter, TransactionRequest};
use alloy_sol_types::{sol, SolCall, SolEvent};
use eyre::{eyre, Result};
use tracing::info;

// =====================================================================
// Contract ABI (Rollup.sol @ release/v1.0.0)
// =====================================================================

sol! {
    // ============ Batch lifecycle ============

    /// Emitted by `commitBatch` — declares a new batch with its batch root,
    /// first/last block hashes, block count, and expected blob count.
    event BatchCommitted(
        uint256 indexed batchIndex,
        bytes32 batchRoot,
        bytes32 fromBlockHash,
        bytes32 toBlockHash,
        uint24 numberOfBlocks,
        uint256 expectedBlobs
    );

    /// Emitted each time the sequencer submits blob hashes for a batch.
    event BatchBlobsSubmitted(
        uint256 indexed batchIndex,
        uint256 numBlobs,
        uint256 totalBlobs
    );

    /// Emitted when all expected blobs are in DA and the batch moves to Submitted.
    event BatchSubmitted(uint256 indexed batchIndex);

    /// Emitted when Nitro preconfirmation is committed for a batch.
    event BatchPreconfirmed(
        uint256 indexed batchIndex,
        address indexed verifierContract,
        address indexed verifier
    );

    /// Emitted when a batch is permanently finalized after the challenge period.
    event BatchFinalized(uint256 indexed batchIndex);

    /// Emitted when admin force-reverts batches from a given index onward.
    event BatchReverted(uint256 indexed fromBatchIndex);

    // ============ Challenge lifecycle ============

    /// Emitted when a challenger disputes a block in a preconfirmed batch.
    event BlockChallenged(
        uint256 indexed batchIndex,
        bytes32 indexed commitment,
        address indexed challenger
    );

    /// Emitted when a challenger opens a batch-root validity dispute.
    event BatchRootChallenged(uint256 indexed batchIndex);

    /// Emitted when a prover resolves a challenge with Nitro + SP1 proof.
    event ChallengeResolved(
        uint256 indexed batchIndex,
        bytes32 indexed commitment,
        address indexed prover
    );

    /// Emitted when a batch root challenge is resolved.
    event BatchRootChallengeResolved(
        uint256 indexed batchIndex,
        address indexed prover
    );

    // ============ Rewards ============

    /// Emitted when a challenger claims their reward (deposit + incentive fee).
    event ChallengerRewardClaimed(address indexed challenger, uint256 amount);

    /// Emitted when a prover claims their proof reward.
    event ProofRewardClaimed(address indexed prover, uint256 amount);

    // ============ Types ============

    /// Mirrors `enum BatchStatus` in `IRollupTypes.sol`. Ordinal values are
    /// consensus-critical — any reorder here would silently flip on-chain
    /// status comparisons.
    enum BatchStatus {
        None,
        Committed,
        Submitted,
        Preconfirmed,
        Challenged,
        Finalized
    }

    /// Mirrors `struct BatchRecord` in `IRollupTypes.sol`. Only the fields
    /// actually read by this crate are annotated in comments; the rest are
    /// kept in-struct so decoding matches the contract layout.
    struct BatchRecord {
        bytes32 batchRoot;
        uint32 acceptedAtBlock;
        uint8 expectedBlobs;
        BatchStatus status;
        uint64 sentMessageCursorStart;
        uint24 submitBlobsWindowSnapshot;
        uint24 preconfirmationWindowSnapshot;
        uint24 challengeWindowSnapshot;
        uint24 finalizationDelaySnapshot;
        uint24 numberOfBlocks;
    }

    // ============ Functions ============

    /// Submit enclave signature to L1, proving batch validity.
    function preconfirmBatch(
        address nitroVerifier,
        uint256 batchIndex,
        bytes signature
    ) external;

    /// View: full batch record, including current lifecycle status and the
    /// L1 block at which the batch was committed. Used by the orchestrator
    /// to detect already-preconfirmed / finalized batches on restart,
    /// avoiding a deterministic revert loop when dispatch retries a batch
    /// whose state moved past `Submitted` while the orchestrator was down.
    function getBatch(uint256 batchIndex) external view returns (BatchRecord memory);
}

// =====================================================================
// Read helpers
// =====================================================================

/// Walk `BatchCommitted` events from `l1_deploy_block` until the event for
/// `batch_id` is found, then derive the L2 starting block from its
/// `fromBlockHash` field.
///
/// Sequencer convention: `fromBlockHash` is the hash of the **last block of
/// the previous batch** (exclusive lower bound), `toBlockHash` is the hash of
/// the **last block of the current batch** (inclusive upper bound). The batch
/// covers `(fromBlockHash, toBlockHash]` = `[fromBlockHash.number + 1,
/// toBlockHash.number]`. So `l2_from_block = fromBlockHash.number + 1`, and
/// `numberOfBlocks = toBlockHash.number - fromBlockHash.number`.
///
/// Returns `(l2_from_block, l1_event_block, num_blocks)`:
/// - `l2_from_block`: first L2 block in the batch
/// - `l1_event_block`: L1 block containing the `BatchCommitted` event
/// - `num_blocks`: number of L2 block headers in this batch
///
/// Rejects `batch_id == 0` — batch 0 is the synthetic genesis batch and
/// cannot be reproved.
///
/// Note: this is O(batch_id) on cold start. Callers should treat it as a
/// rare manual operation (e.g., explicit `L1_START_BATCH_ID`).
pub async fn resolve_l2_start_checkpoint(
    l1_provider: &RootProvider,
    l2_provider: &RootProvider,
    contract_addr: Address,
    batch_id: u64,
    l1_deploy_block: u64,
) -> Result<(u64, u64, u64)> {
    if batch_id == 0 {
        return Err(eyre!(
            "L1_START_BATCH_ID must be >= 1. Batch 0 is the synthetic genesis \
             batch and cannot be reproved; use batch_id=1 to start at the \
             first user-facing batch."
        ));
    }

    let latest = l1_provider
        .get_block_number()
        .await
        .map_err(|e| eyre!("Failed to get latest L1 block: {e}"))?;

    const PAGE: u64 = 50_000;
    const SCAN_DELAY: std::time::Duration = std::time::Duration::from_millis(500);

    let mut target: Option<(u64, u64, B256)> = None; // (l1_event_block, num_blocks, from_block_hash)
    let mut current = l1_deploy_block;

    let mut anchor: Option<FixedBytes<32>> = None;

    'outer: while current <= latest {
        let page_end = (current + PAGE - 1).min(latest);
        let filter = Filter::new()
            .address(contract_addr)
            .event_signature(vec![BatchCommitted::SIGNATURE_HASH])
            .from_block(current)
            .to_block(page_end);
        let logs = l1_provider
            .get_logs(&filter)
            .await
            .map_err(|e| eyre!("eth_getLogs [{current}..{page_end}] failed: {e}"))?;

        for log in logs {
            let topic0 = log.topic0().copied().unwrap_or_default();
            let (idx, num_blocks_u64, anchor_candidate) =
                if topic0 == BatchCommitted::SIGNATURE_HASH {
                    let ev = BatchCommitted::decode_log_data(&log.inner.data)
                        .map_err(|e| eyre!("decode BatchCommitted v1: {e}"))?;
                    let idx: u64 = ev
                        .batchIndex
                        .try_into()
                        .map_err(|_| eyre!("batchIndex overflow: {}", ev.batchIndex))?;
                    let nb: u64 = ev
                        .numberOfBlocks
                        .try_into()
                        .map_err(|_| eyre!("numberOfBlocks overflow: {}", ev.numberOfBlocks))?;
                    (idx, nb, ev.fromBlockHash)
                } else {
                    continue;
                };

            if idx == batch_id {
                let l1_block = log
                    .block_number
                    .ok_or_else(|| eyre!("BatchCommitted log missing block_number"))?;
                target = Some((l1_block, num_blocks_u64, B256::ZERO));
                anchor = Some(anchor_candidate);
                break 'outer;
            }
        }

        current = page_end + 1;
        if current <= latest {
            tokio::time::sleep(SCAN_DELAY).await;
        }
    }

    let (l1_block, num_blocks, _) = target.ok_or_else(|| {
        eyre!(
            "BatchCommitted for batch {batch_id} not found in L1 blocks \
             [{l1_deploy_block}..{latest}]. \
             Ensure L1_ROLLUP_DEPLOY_BLOCK is ≤ the block where batch {batch_id} was committed. \
             If the block range is correct, the deployed Rollup contract's ABI \
             may have drifted from this binding — verify the BatchCommitted \
             topic hash against the release the contract was deployed from."
        )
    })?;
    let anchor = anchor.expect("anchor set whenever target is set");

    let (anchor_hash, l2_from_block) = {
        let h = anchor;

        // `fromBlockHash` is the LAST block of the PREVIOUS batch
        // (exclusive lower bound), so the first block of THIS batch is `n + 1`.
        let n = l2_provider
            .get_block_by_hash(anchor)
            .await
            .map_err(|e| eyre!("eth_getBlockByHash({h}) on L2: {e}"))?
            .ok_or_else(|| {
                eyre!(
                    "L2 block with hash {h} (from BatchCommitted.fromBlockHash \
                         for batch {batch_id}) not found — L2 RPC may be pointing \
                         at the wrong chain or be missing history."
                )
            })?
            .header
            .number;
        (h, n + 1)
    };
    let from_block_hash = anchor_hash;

    info!(
        batch_id,
        %from_block_hash,
        l2_from_block,
        l2_to_block = l2_from_block + num_blocks.saturating_sub(1),
        num_blocks,
        l1_block,
        "Resolved L2 start checkpoint"
    );

    Ok((l2_from_block, l1_block, num_blocks))
}

/// Resolve `(from_block, to_block)` for a given `batch_id` using L1 + L2
/// reads. Used by `bin/proxy` to map a challenge request's `batch_index` →
/// L2 block range without requiring the caller to know it.
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

/// Resolved L1 identity of a `BatchPreconfirmed` event for a given batch.
/// Populated by [`find_batch_preconfirm_event`] and consumed by the
/// orchestrator's startup-reconciliation path to seed `dispatched_batches`
/// with the winning transaction's coordinates (so the finalization ticker
/// can drive the batch to completion).
#[derive(Debug, Clone, Copy)]
pub struct BatchPreconfirmInfo {
    pub tx_hash: B256,
    pub l1_block: u64,
}

/// Canonical lifecycle status ordinals for `enum BatchStatus` in
/// `IRollupTypes.sol`. Kept as `u8` constants (not an enum) to avoid coupling
/// callers to the `sol!`-generated type's local module path.
pub mod batch_status {
    pub const NONE: u8 = 0;
    pub const COMMITTED: u8 = 1;
    pub const SUBMITTED: u8 = 2;
    pub const PRECONFIRMED: u8 = 3;
    pub const CHALLENGED: u8 = 4;
    pub const FINALIZED: u8 = 5;
}

/// Minimal subset of `BatchRecord` the orchestrator needs for on-chain
/// reconciliation: current lifecycle status and the L1 block at which the
/// batch was first committed (lower bound for a targeted event scan).
#[derive(Debug, Clone, Copy)]
pub struct BatchOnChain {
    pub status: u8,
    pub accepted_at_block: u64,
}

/// View-call `getBatch(batchIndex)` and project the fields used by the
/// orchestrator's startup-reconciliation / pre-flight path. One RPC round
/// trip; returns `status` as the `batch_status::*` ordinal alongside
/// `acceptedAtBlock` to bound subsequent event scans.
pub async fn get_batch_on_chain(
    l1_provider: &impl Provider,
    contract_addr: Address,
    batch_index: u64,
) -> Result<BatchOnChain> {
    let call = getBatchCall { batchIndex: U256::from(batch_index) };
    let input = Bytes::from(call.abi_encode());
    let req = TransactionRequest {
        to: Some(contract_addr.into()),
        input: input.into(),
        ..Default::default()
    };
    let raw = l1_provider
        .call(req)
        .await
        .map_err(|e| eyre!("eth_call getBatch({batch_index}) failed: {e}"))?;
    let decoded = getBatchCall::abi_decode_returns(&raw)
        .map_err(|e| eyre!("decode getBatch({batch_index}) return: {e}"))?;
    Ok(BatchOnChain {
        status: decoded.status as u8,
        accepted_at_block: u64::from(decoded.acceptedAtBlock),
    })
}

/// Scan L1 for the `BatchPreconfirmed(batchIndex=…)` event in the given
/// block range. Returns the first matching log's transaction hash and block
/// number, or `None` if no such event exists in the window.
///
/// Used by the orchestrator when a pre-flight status check reveals that the
/// target batch is already `Preconfirmed` or `Finalized` on L1 — the stored
/// `l1_checkpoint` may have already advanced past the event, so the
/// live-listener path will never replay it.
pub async fn find_batch_preconfirm_event(
    l1_provider: &impl Provider,
    contract_addr: Address,
    batch_index: u64,
    from_l1_block: u64,
    to_l1_block: u64,
) -> Result<Option<BatchPreconfirmInfo>> {
    if from_l1_block > to_l1_block {
        return Ok(None);
    }
    let topic1 = B256::from(U256::from(batch_index));
    let filter = Filter::new()
        .address(contract_addr)
        .event_signature(BatchPreconfirmed::SIGNATURE_HASH)
        .topic1(topic1)
        .from_block(from_l1_block)
        .to_block(to_l1_block);
    let logs = l1_provider
        .get_logs(&filter)
        .await
        .map_err(|e| eyre!("eth_getLogs BatchPreconfirmed[{batch_index}] failed: {e}"))?;
    let Some(log) = logs.into_iter().next() else { return Ok(None) };
    let tx_hash = log
        .transaction_hash
        .ok_or_else(|| eyre!("BatchPreconfirmed[{batch_index}] log missing transaction_hash"))?;
    let l1_block = log
        .block_number
        .ok_or_else(|| eyre!("BatchPreconfirmed[{batch_index}] log missing block_number"))?;
    Ok(Some(BatchPreconfirmInfo { tx_hash, l1_block }))
}

// =====================================================================
// Write helpers (RBF-aware)
// =====================================================================

/// Immutable metadata for an in-flight `preconfirmBatch` transaction. Built
/// once at dispatch start by [`build_preconfirm_tx`] and reused across RBF
/// bumps — only `max_fee_per_gas` / `max_priority_fee_per_gas` change on each
/// rebroadcast.
#[derive(Debug, Clone)]
pub struct PreconfirmTxTemplate {
    pub to: Address,
    pub input: Bytes,
    pub nonce: u64,
    pub gas_limit: u64,
    pub chain_id: u64,
    pub batch_index: u64,
}

/// Build the calldata + nonce + gas-limit for a `preconfirmBatch` dispatch.
///
/// When `stored_nonce` is `Some`, use it verbatim — this is the startup-
/// resume path, where we must replay against the same nonce that the
/// pre-restart tx was signed under (so the rebroadcast is a replacement,
/// not a fresh send at a new nonce). When `None`, query the pending
/// transaction count to obtain a fresh nonce.
pub async fn build_preconfirm_tx(
    provider: &impl Provider,
    contract_addr: Address,
    nitro_verifier_addr: Address,
    batch_index: u64,
    signature: Vec<u8>,
    signer: Address,
    stored_nonce: Option<u64>,
) -> Result<PreconfirmTxTemplate> {
    let call = preconfirmBatchCall {
        nitroVerifier: nitro_verifier_addr,
        batchIndex: U256::from(batch_index),
        signature: Bytes::from(signature),
    };
    let input = Bytes::from(call.abi_encode());

    let nonce = match stored_nonce {
        Some(n) => n,
        None => provider
            .get_transaction_count(signer)
            .pending()
            .await
            .map_err(|e| eyre!("get_transaction_count(pending) failed: {e}"))?,
    };

    let chain_id = provider.get_chain_id().await.map_err(|e| eyre!("get_chain_id failed: {e}"))?;

    let est_req = TransactionRequest {
        from: Some(signer),
        to: Some(contract_addr.into()),
        input: input.clone().into(),
        ..Default::default()
    };
    let gas_limit =
        provider.estimate_gas(est_req).await.map_err(|e| eyre!("estimate_gas failed: {e}"))?;

    Ok(PreconfirmTxTemplate { to: contract_addr, input, nonce, gas_limit, chain_id, batch_index })
}

/// Sign + broadcast one EIP-1559 transaction with explicit nonce + fees.
/// Returns the tx hash. Does NOT wait for a receipt — the caller is
/// responsible for polling and, if needed, bumping fees + rebroadcasting.
pub async fn broadcast_preconfirm(
    provider: &impl Provider,
    signer: &(dyn TxSigner<Signature> + Send + Sync),
    template: &PreconfirmTxTemplate,
    max_fee_per_gas: u128,
    max_priority_fee_per_gas: u128,
) -> Result<B256> {
    let mut tx = TxEip1559 {
        chain_id: template.chain_id,
        nonce: template.nonce,
        gas_limit: template.gas_limit,
        max_fee_per_gas,
        max_priority_fee_per_gas,
        to: TxKind::Call(template.to),
        value: U256::ZERO,
        access_list: Default::default(),
        input: template.input.clone(),
    };
    let sig = signer
        .sign_transaction(&mut tx)
        .await
        .map_err(|e| eyre!("sign_transaction failed: {e}"))?;
    let envelope = TxEnvelope::Eip1559(tx.into_signed(sig));
    let mut buf = Vec::new();
    envelope.encode_2718(&mut buf);

    let pending = provider
        .send_raw_transaction(&buf)
        .await
        .map_err(|e| eyre!("send_raw_transaction failed: {e}"))?;
    let tx_hash = *pending.tx_hash();
    info!(
        %tx_hash,
        batch_index = template.batch_index,
        nonce = template.nonce,
        max_fee_per_gas,
        max_priority_fee_per_gas,
        "broadcast_preconfirm"
    );
    Ok(tx_hash)
}
