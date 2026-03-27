//! Blob retrieval for `/sign-batch-root`.
//!
//! Fetches EIP-4844 blobs from L1 contract + Beacon API:
//! 1. Read versioned hashes from `_batchBlobHashes[batchIndex]` on L1
//! 2. Query `BatchBlobsSubmitted` events → find L1 block numbers
//! 3. Map L1 blocks to beacon slots → fetch blob sidecars
//! 4. Match sidecars to versioned hashes → return ordered blobs

use alloy_primitives::{Address, Bytes, B256, U256};
use alloy_provider::{Provider, RootProvider};
use alloy_rpc_types::{Filter, TransactionRequest};
use alloy_sol_types::{sol, SolCall, SolEvent};
use eyre::{eyre, Result};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use tracing::info;

// ---------------------------------------------------------------------------
// Minimal L1 contract interface
// ---------------------------------------------------------------------------

sol! {
    /// Returns versioned hashes stored by `submitBlobs` for a given batch.
    function batchBlobHashes(uint256 batchIndex) external view returns (bytes32[] memory);

    /// Emitted by `submitBlobs` — one per call (a batch may span multiple calls).
    event BatchBlobsSubmitted(uint256 indexed batchIndex, uint256 numBlobs, uint256 totalSoFar);
}

// ---------------------------------------------------------------------------
// Beacon API types
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct BlobSidecarsResponse {
    data: Vec<BlobSidecar>,
}

#[derive(Deserialize)]
struct BlobSidecar {
    blob: String,
    kzg_commitment: String,
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Fetch all blobs for `batch_index`, ordered to match `_batchBlobHashes`.
///
/// Steps:
/// 1. `eth_call batchBlobHashes(batchIndex)` → versioned hashes
/// 2. `eth_getLogs BatchBlobsSubmitted(batchIndex)` → L1 block numbers
/// 3. For each block: compute beacon slot, `GET blob_sidecars/{slot}`
/// 4. Match blob sidecars by `0x01 || keccak256(commitment)[1..]`
pub(crate) async fn fetch_blobs_for_batch(
    l1_provider: &RootProvider,
    beacon_url: &str,
    http_client: &reqwest::Client,
    contract_addr: Address,
    batch_index: u64,
    beacon_genesis_timestamp: u64,
) -> Result<Vec<Vec<u8>>> {
    // ── 1. Read versioned hashes from L1 ────────────────────────────────
    let call = batchBlobHashesCall { batchIndex: U256::from(batch_index) };
    let tx = TransactionRequest {
        to: Some(contract_addr.into()),
        input: Bytes::from(call.abi_encode()).into(),
        ..Default::default()
    };

    let result =
        l1_provider.call(tx).await.map_err(|e| eyre!("batchBlobHashes call failed: {e}"))?;

    let decoded = batchBlobHashesCall::abi_decode_returns(&result)
        .map_err(|e| eyre!("Failed to decode batchBlobHashes: {e}"))?;

    let versioned_hashes: Vec<B256> = decoded.into_iter().map(B256::from).collect();

    if versioned_hashes.is_empty() {
        return Err(eyre!("No blob hashes for batch {batch_index}"));
    }
    info!(batch_index, count = versioned_hashes.len(), "Fetched versioned hashes from L1");

    // ── 2. Find L1 blocks where submitBlobs was called ──────────────────
    let batch_topic = B256::left_padding_from(&batch_index.to_be_bytes());
    let filter = Filter::new()
        .address(contract_addr)
        .event_signature(BatchBlobsSubmitted::SIGNATURE_HASH)
        .topic1(batch_topic);

    let logs = l1_provider
        .get_logs(&filter)
        .await
        .map_err(|e| eyre!("BatchBlobsSubmitted log query failed: {e}"))?;

    let mut l1_blocks: Vec<u64> = logs.iter().filter_map(|l| l.block_number).collect();
    l1_blocks.sort_unstable();
    l1_blocks.dedup();

    if l1_blocks.is_empty() {
        return Err(eyre!("No BatchBlobsSubmitted events for batch {batch_index}"));
    }
    info!(batch_index, ?l1_blocks, "Found submitBlobs L1 blocks");

    // ── 3. For each L1 block → beacon slot → blob sidecars ─────────────
    let mut found: Vec<(B256, Vec<u8>)> = Vec::new();

    for &block_num in &l1_blocks {
        let block = l1_provider
            .get_block_by_number(block_num.into())
            .await
            .map_err(|e| eyre!("Failed to fetch L1 block {block_num}: {e}"))?
            .ok_or_else(|| eyre!("L1 block {block_num} not found"))?;

        let slot = (block.header.timestamp - beacon_genesis_timestamp) / 12;
        let url = format!("{beacon_url}/eth/v1/beacon/blob_sidecars/{slot}");

        let resp: BlobSidecarsResponse = http_client
            .get(&url)
            .send()
            .await
            .map_err(|e| eyre!("Beacon API failed for slot {slot}: {e}"))?
            .error_for_status()
            .map_err(|e| eyre!("Beacon API error for slot {slot}: {e}"))?
            .json()
            .await
            .map_err(|e| eyre!("Failed to parse beacon blob sidecars: {e}"))?;

        for sc in resp.data {
            let commitment = hex_decode(&sc.kzg_commitment)?;
            let vh = versioned_hash_from_commitment(&commitment);
            if versioned_hashes.contains(&vh) {
                found.push((vh, hex_decode(&sc.blob)?));
            }
        }
    }

    // ── 4. Order blobs to match _batchBlobHashes order ──────────────────
    let mut ordered = Vec::with_capacity(versioned_hashes.len());
    for vh in &versioned_hashes {
        let blob = found
            .iter()
            .find(|(h, _)| h == vh)
            .map(|(_, data)| data.clone())
            .ok_or_else(|| eyre!("Blob not found for versioned hash {vh}"))?;
        ordered.push(blob);
    }

    info!(batch_index, num_blobs = ordered.len(), "Blobs fetched and ordered");
    Ok(ordered)
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// EIP-4844 versioned hash: `0x01 || SHA256(commitment)[1..]`
fn versioned_hash_from_commitment(commitment: &[u8]) -> B256 {
    let hash = Sha256::digest(commitment);
    let mut h = B256::default();
    h[0] = 0x01;
    h[1..].copy_from_slice(&hash[1..]);
    h
}

/// Decode a 0x-prefixed hex string.
fn hex_decode(s: &str) -> Result<Vec<u8>> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    alloy_primitives::hex::decode(s).map_err(|e| eyre!("hex decode: {e}"))
}
