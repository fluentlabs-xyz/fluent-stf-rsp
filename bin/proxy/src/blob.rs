//! Blob retrieval for `/sign-batch-root`.
//!
//! Fetches EIP-4844 blobs from L1 contract + Beacon API:
//! 1. Read versioned hashes from `_batchBlobHashes[batchIndex]` on L1
//! 2. Query `BatchBlobsSubmitted` events → find L1 block numbers (paginated)
//! 3. Map L1 blocks to beacon slots → fetch blob sidecars (with retries)
//! 4. Match sidecars to versioned hashes → return ordered blobs

use alloy_primitives::{Address, Bytes, B256, U256};
use alloy_provider::{Provider, RootProvider};
use alloy_rpc_types::{Filter, TransactionRequest};
use alloy_sol_types::{sol, SolCall, SolEvent};
use eyre::{eyre, Result};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::time::Duration;
use tracing::{info, warn};

/// Maximum block range per `eth_getLogs` request (Infura limit).
const LOG_PAGE_SIZE: u64 = 10_000;

/// Small delay between sequential L1 RPC calls to avoid bursts.
const RPC_INTER_CALL_DELAY: Duration = Duration::from_secs(1);

/// Maximum number of retry attempts for Beacon API requests.
const BEACON_MAX_RETRIES: u32 = 5;

/// Initial backoff duration for Beacon API retries.
const BEACON_INITIAL_BACKOFF: Duration = Duration::from_millis(500);

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
/// 2. `eth_getLogs BatchBlobsSubmitted(batchIndex)` → L1 block numbers (paginated)
/// 3. For each block: compute beacon slot, `GET blob_sidecars/{slot}` (with retries)
/// 4. Match blob sidecars by `0x01 || SHA256(commitment)[1..]`
pub(crate) async fn fetch_blobs_for_batch(
    l1_provider: &RootProvider,
    beacon_urls: &[String],
    http_client: &reqwest::Client,
    contract_addr: Address,
    batch_index: u64,
    beacon_genesis_timestamp: u64,
    contract_deploy_block: u64,
) -> Result<Vec<Vec<u8>>> {
    if beacon_urls.is_empty() {
        return Err(eyre!("No beacon URLs configured"));
    }

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

    // ── 2. Find L1 blocks where submitBlobs was called (paginated) ─────
    let l1_blocks =
        fetch_batch_log_blocks(l1_provider, contract_addr, batch_index, contract_deploy_block)
            .await?;

    info!(batch_index, ?l1_blocks, "Found submitBlobs L1 blocks");

    // ── 3. For each L1 block → beacon slot → blob sidecars ─────────────
    let mut found: Vec<(B256, Vec<u8>)> = Vec::new();

    for (i, &block_num) in l1_blocks.iter().enumerate() {
        if i > 0 {
            tokio::time::sleep(RPC_INTER_CALL_DELAY).await;
        }

        let block = l1_provider
            .get_block_by_number(block_num.into())
            .await
            .map_err(|e| eyre!("Failed to fetch L1 block {block_num}: {e}"))?
            .ok_or_else(|| eyre!("L1 block {block_num} not found"))?;

        let slot = (block.header.timestamp - beacon_genesis_timestamp) / 12;

        let resp = fetch_blob_sidecars(http_client, beacon_urls, slot).await?;

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
        let blob =
            found.iter().find(|(h, _)| h == vh).map(|(_, data)| data.clone()).ok_or_else(|| {
                eyre!(
                    "Blob not found for versioned hash {vh} — \
                     blobs may have been pruned (EIP-4844 ~18 day retention)"
                )
            })?;
        ordered.push(blob);
    }

    info!(batch_index, num_blobs = ordered.len(), "Blobs fetched and ordered");
    Ok(ordered)
}

// ---------------------------------------------------------------------------
// Paginated log fetching
// ---------------------------------------------------------------------------

/// Query `BatchBlobsSubmitted` events in paginated chunks of [`LOG_PAGE_SIZE`] blocks.
async fn fetch_batch_log_blocks(
    l1_provider: &RootProvider,
    contract_addr: Address,
    batch_index: u64,
    from_block: u64,
) -> Result<Vec<u64>> {
    let latest = l1_provider
        .get_block_number()
        .await
        .map_err(|e| eyre!("Failed to get latest block number: {e}"))?;

    let batch_topic = B256::left_padding_from(&batch_index.to_be_bytes());
    let mut l1_blocks = Vec::new();
    let mut cursor = from_block;

    while cursor <= latest {
        let chunk_end = (cursor + LOG_PAGE_SIZE - 1).min(latest);

        let filter = Filter::new()
            .address(contract_addr)
            .event_signature(BatchBlobsSubmitted::SIGNATURE_HASH)
            .topic1(batch_topic)
            .from_block(cursor)
            .to_block(chunk_end);

        let logs = l1_provider.get_logs(&filter).await.map_err(|e| {
            eyre!("BatchBlobsSubmitted log query failed ({cursor}..{chunk_end}): {e}")
        })?;

        l1_blocks.extend(logs.iter().filter_map(|l| l.block_number));

        cursor = chunk_end + 1;
        if cursor <= latest {
            tokio::time::sleep(RPC_INTER_CALL_DELAY).await;
        }
    }

    l1_blocks.sort_unstable();
    l1_blocks.dedup();

    if l1_blocks.is_empty() {
        return Err(eyre!("No BatchBlobsSubmitted events for batch {batch_index}"));
    }

    Ok(l1_blocks)
}

// ---------------------------------------------------------------------------
// Beacon API with retries + fallback
// ---------------------------------------------------------------------------

/// Fetch blob sidecars for a beacon `slot`, retrying across all `beacon_urls`.
async fn fetch_blob_sidecars(
    http_client: &reqwest::Client,
    beacon_urls: &[String],
    slot: u64,
) -> Result<BlobSidecarsResponse> {
    let mut last_err = None;

    for beacon_url in beacon_urls {
        match fetch_blob_sidecars_single(http_client, beacon_url, slot).await {
            Ok(resp) => return Ok(resp),
            Err(e) => {
                warn!(slot, beacon_url, err = %e, "Beacon API failed, trying next");
                last_err = Some(e);
            }
        }
    }

    Err(last_err.unwrap_or_else(|| eyre!("No beacon URLs configured")))
}

/// Fetch blob sidecars from a single beacon URL with exponential backoff.
async fn fetch_blob_sidecars_single(
    http_client: &reqwest::Client,
    beacon_url: &str,
    slot: u64,
) -> Result<BlobSidecarsResponse> {
    let url = format!("{beacon_url}/eth/v1/beacon/blob_sidecars/{slot}");
    let mut backoff = BEACON_INITIAL_BACKOFF;

    for attempt in 0..=BEACON_MAX_RETRIES {
        let resp = http_client.get(&url).send().await;

        match resp {
            Ok(r) if r.status() == reqwest::StatusCode::NOT_FOUND => {
                return Err(eyre!(
                    "Beacon API returned 404 for slot {slot} — \
                     blobs may have been pruned (EIP-4844 ~18 day retention)"
                ));
            }
            Ok(r) if r.status() == reqwest::StatusCode::TOO_MANY_REQUESTS => {
                if attempt < BEACON_MAX_RETRIES {
                    warn!(slot, attempt, ?backoff, "Beacon API rate-limited (429), backing off");
                    tokio::time::sleep(backoff).await;
                    backoff *= 2;
                    continue;
                }
                return Err(eyre!(
                    "Beacon API rate-limited for slot {slot} after {BEACON_MAX_RETRIES} retries"
                ));
            }
            Ok(r) if r.status().is_success() => {
                return r.json().await.map_err(|e| {
                    eyre!("Failed to parse beacon blob sidecars for slot {slot}: {e}")
                });
            }
            Ok(r) => {
                let status = r.status();
                let body = r.text().await.unwrap_or_default();
                if attempt < BEACON_MAX_RETRIES && status.is_server_error() {
                    warn!(slot, attempt, %status, ?backoff, "Beacon API server error, retrying");
                    tokio::time::sleep(backoff).await;
                    backoff *= 2;
                    continue;
                }
                return Err(eyre!("Beacon API error for slot {slot}: {status} {body}"));
            }
            Err(e) => {
                if attempt < BEACON_MAX_RETRIES {
                    warn!(slot, attempt, ?backoff, err = %e, "Beacon API request failed, retrying");
                    tokio::time::sleep(backoff).await;
                    backoff *= 2;
                    continue;
                }
                return Err(eyre!(
                    "Beacon API failed for slot {slot} after {BEACON_MAX_RETRIES} retries: {e}"
                ));
            }
        }
    }

    unreachable!()
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
