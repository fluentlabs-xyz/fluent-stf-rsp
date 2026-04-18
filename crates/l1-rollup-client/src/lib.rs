//! L1 rollup contract bindings and helpers — the read+write surface for the
//! Fluent rollup contract on L1. Used by `bin/witness-orchestrator` (read +
//! write) and `bin/proxy` (read only, for batch metadata lookup).
//!
//! Targets the `release/v1.0.0` deployment of `Rollup.sol`.
//!
//! What lives here:
//! - sol! ABI: all on-chain events (lifecycle, challenge, rewards) and the
//!   `preconfirmBatch` function.
//! - Read helpers: `resolve_l2_start_checkpoint`, `fetch_batch_range`.
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

    // ============ Functions ============

    /// Submit enclave signature to L1, proving batch validity.
    function preconfirmBatch(
        address nitroVerifier,
        uint256 batchIndex,
        bytes signature
    ) external;
}

/// Pre-upgrade ABI of the `BatchCommitted` event. On-chain the event name is
/// still `BatchCommitted`, so the topic0 hash is `keccak256("BatchCommitted(...)")`
/// with the old parameter list. Kept in a nested `sol!` block (wrapped in its
/// own module) so the Rust type name stays distinct from the current variant.
pub mod v0 {
    use alloy_sol_types::sol;

    sol! {
        /// Historical variant: single `lastBlockHash` instead of
        /// `fromBlockHash + toBlockHash`. Proxy address is unchanged, so
        /// both variants appear in the log stream.
        event BatchCommitted(
            uint256 indexed batchIndex,
            bytes32 batchRoot,
            bytes32 lastBlockHash,
            uint24 numberOfBlocks,
            uint256 expectedBlobs
        );
    }
}

// =====================================================================
// Read helpers
// =====================================================================

/// Walk `BatchCommitted` events from `l1_deploy_block` until the event for
/// `batch_id` is found, then derive the L2 starting block from its
/// `fromBlockHash` field.
///
/// `fromBlockHash` in `BatchCommitted` is the hash of the **first** L2 block
/// inside this batch, so `l2_from_block = fromBlockHash.number` directly.
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

    // Anchor hash resolved to an L2 block number and interpretation
    // (start-of-batch vs end-of-batch) differ between ABI versions — record
    // which one we matched so post-lookup math stays correct.
    enum Anchor {
        FromBlockHash(B256),
        LastBlockHash(B256),
    }

    let mut anchor: Option<Anchor> = None;

    'outer: while current <= latest {
        let page_end = (current + PAGE - 1).min(latest);
        let filter = Filter::new()
            .address(contract_addr)
            .event_signature(vec![
                BatchCommitted::SIGNATURE_HASH,
                v0::BatchCommitted::SIGNATURE_HASH,
            ])
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
                    (idx, nb, Anchor::FromBlockHash(ev.fromBlockHash))
                } else if topic0 == v0::BatchCommitted::SIGNATURE_HASH {
                    let ev = v0::BatchCommitted::decode_log_data(&log.inner.data)
                        .map_err(|e| eyre!("decode BatchCommitted v0: {e}"))?;
                    let idx: u64 = ev
                        .batchIndex
                        .try_into()
                        .map_err(|_| eyre!("batchIndex overflow: {}", ev.batchIndex))?;
                    let nb: u64 = ev
                        .numberOfBlocks
                        .try_into()
                        .map_err(|_| eyre!("numberOfBlocks overflow: {}", ev.numberOfBlocks))?;
                    (idx, nb, Anchor::LastBlockHash(ev.lastBlockHash))
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

    let (anchor_hash, l2_from_block) = match anchor {
        Anchor::FromBlockHash(h) => {
            let n = l2_provider
                .get_block_by_hash(h)
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
            (h, n)
        }
        Anchor::LastBlockHash(h) => {
            // Pre-upgrade ABI: batch carried only the **last** block hash.
            // Derive the first-block number by subtracting (num_blocks - 1)
            // from the last-block number.
            let last_n = l2_provider
                .get_block_by_hash(h)
                .await
                .map_err(|e| eyre!("eth_getBlockByHash({h}) on L2: {e}"))?
                .ok_or_else(|| {
                    eyre!(
                        "L2 block with hash {h} (from v0::BatchCommitted.lastBlockHash \
                         for batch {batch_id}) not found — L2 RPC may be pointing \
                         at the wrong chain or be missing history."
                    )
                })?
                .header
                .number;
            if num_blocks == 0 {
                return Err(eyre!(
                    "v0::BatchCommitted for batch {batch_id} has num_blocks=0"
                ));
            }
            (h, last_n.saturating_sub(num_blocks - 1))
        }
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
