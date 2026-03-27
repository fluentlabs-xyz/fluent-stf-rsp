//! E2E full pipeline test.
//!
//! Exercises the complete path:
//!   1. Deploy MockRollup on Anvil (fake L1)
//!   2. Wait for N L2 blocks on reth
//!   3. Fetch real tx data and bridge events per block
//!   4. Build canonical blobs and block headers
//!   5. Call `acceptNextBatch` + `submitBlobs` on MockRollup
//!   6. Insert blobs into fake beacon via admin API
//!   7. Courier calls `/sign-batch-root`, then `preconfirmBatch` on MockRollup
//!   8. Verify `lastPreconfirmedBatch` on MockRollup
//!
//! # Environment variables
//!
//! | Variable | Default | Description |
//! |----------|---------|-------------|
//! | `E2E_ANVIL_URL` | `http://localhost:8546` | Anvil (fake L1) RPC |
//! | `E2E_RETH_URL` | `http://localhost:8545` | L2 reth RPC |
//! | `E2E_BEACON_URL` | *(required)* | External fake beacon URL |
//! | `E2E_CONTRACT_ADDR` | *(unset)* | Pre-deployed MockRollup; skips deployment |
//! | `E2E_BLOCK_COUNT` | `10` | Number of L2 blocks to include in the batch |
//! | `API_KEY` | `test-key` | Proxy API key |
//! | `BRIDGE_ADDRESS` | `0x0000…` | L1FluentBridge contract address |
//! | `WITHDRAWAL_TOPIC` | *(unset)* | `SentMessage` event topic hash |
//! | `ROLLBACK_TOPIC` | *(unset)* | `RollbackMessage` event topic hash |
//! | `DEPOSIT_TOPIC` | *(unset)* | `ReceivedMessage` event topic hash |

use std::time::{Duration, Instant};

use alloy_primitives::{b256, Address, Keccak256, B256, U256};
use alloy_provider::{Provider, RootProvider};
use alloy_rpc_types::{BlockNumberOrTag, TransactionReceipt};
use e2e_tests::{blob_builder, mock_l1, mock_l1::L2BlockHeader};
use eyre::{eyre, Result};
use tracing::info;

// ---------------------------------------------------------------------------
// Bridge event constants (must match events_hash.rs)
// ---------------------------------------------------------------------------

const ZERO_BYTES_HASH: B256 =
    b256!("c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470");

/// Byte offset of `messageHash` in `ReceivedMessage` log data.
const RECEIVE_EVENT_MESSAGE_HASH_OFFSET: usize = 0;
/// Byte offset of `messageHash` in `SentMessage` log data.
const SEND_EVENT_MESSAGE_HASH_OFFSET: usize = 128;
/// Byte offset of `messageHash` in `RollbackMessage` log data.
const ROLLBACK_EVENT_MESSAGE_HASH_OFFSET: usize = 0;

// ---------------------------------------------------------------------------
// Config from env
// ---------------------------------------------------------------------------

struct BridgeConfig {
    address: Address,
    withdrawal_topic: B256,
    rollback_topic: B256,
    deposit_topic: B256,
}

struct E2eConfig {
    anvil_url: String,
    reth_url: String,
    beacon_url: String,
    /// If set, skip MockRollup deployment and use this address directly.
    contract_addr: Option<Address>,
    block_count: u64,
    bridge: BridgeConfig,
}

impl E2eConfig {
    fn from_env() -> Result<Self> {
        Ok(Self {
            anvil_url: std::env::var("E2E_ANVIL_URL")
                .unwrap_or_else(|_| "http://localhost:8546".into()),
            reth_url: std::env::var("E2E_RETH_URL")
                .unwrap_or_else(|_| "http://localhost:8545".into()),
            beacon_url: std::env::var("E2E_BEACON_URL")
                .map_err(|_| eyre!("E2E_BEACON_URL is required"))?,
            contract_addr: std::env::var("E2E_CONTRACT_ADDR").ok().and_then(|s| s.parse().ok()),
            block_count: std::env::var("E2E_BLOCK_COUNT")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(10),
            bridge: BridgeConfig {
                address: std::env::var("BRIDGE_ADDRESS")
                    .ok()
                    .and_then(|s| s.parse().ok())
                    .unwrap_or(Address::ZERO),
                withdrawal_topic: std::env::var("WITHDRAWAL_TOPIC")
                    .ok()
                    .and_then(|s| s.parse().ok())
                    .unwrap_or(B256::ZERO),
                rollback_topic: std::env::var("ROLLBACK_TOPIC")
                    .ok()
                    .and_then(|s| s.parse().ok())
                    .unwrap_or(B256::ZERO),
                deposit_topic: std::env::var("DEPOSIT_TOPIC")
                    .ok()
                    .and_then(|s| s.parse().ok())
                    .unwrap_or(B256::ZERO),
            },
        })
    }
}

// ---------------------------------------------------------------------------
// Reth helpers
// ---------------------------------------------------------------------------

/// Poll until `target_block` exists on reth. Checks every 2 seconds.
async fn wait_for_block(provider: &RootProvider, target: u64) -> Result<()> {
    loop {
        let n = provider.get_block_number().await?;
        if n >= target {
            return Ok(());
        }
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
}

/// Fetch EIP-2718 encoded transactions for a block, concatenated into one buffer.
async fn fetch_raw_txs(provider: &RootProvider, block_number: u64) -> Result<Vec<u8>> {
    let block = provider
        .get_block_by_number(block_number.into())
        .await?
        .ok_or_else(|| eyre!("block {block_number} not found"))?;

    let mut raw = Vec::new();
    for hash in block.transactions.hashes() {
        let bytes: alloy_primitives::Bytes =
            provider.raw_request("eth_getRawTransactionByHash".into(), [hash]).await?;
        raw.extend_from_slice(&bytes);
    }
    Ok(raw)
}

/// Build an `L2BlockHeader` for a given block number.
///
/// `withdrawalRoot` and `depositRoot` are derived from bridge contract events
/// in the block receipts, matching the logic in `executor/client/src/events_hash.rs`.
async fn fetch_l2_header(
    provider: &RootProvider,
    block_number: u64,
    bridge: &BridgeConfig,
) -> Result<L2BlockHeader> {
    let block = provider
        .get_block_by_number(block_number.into())
        .await?
        .ok_or_else(|| eyre!("block {block_number} not found"))?;

    let receipts: Vec<TransactionReceipt> = provider
        .raw_request("eth_getBlockReceipts".into(), [format!("0x{block_number:x}")])
        .await?;

    let withdrawal_root = compute_withdrawal_root(&receipts, bridge);
    let deposit_root = compute_deposit_hash(&receipts, bridge);

    Ok(L2BlockHeader {
        previousBlockHash: block.header.parent_hash,
        blockHash: block.header.hash,
        withdrawalRoot: withdrawal_root,
        depositRoot: deposit_root,
        depositCount: U256::from(count_deposits(&receipts, bridge)),
    })
}

// ---------------------------------------------------------------------------
// Bridge hash helpers (mirror events_hash.rs)
// ---------------------------------------------------------------------------

fn compute_withdrawal_root(receipts: &[TransactionReceipt], bridge: &BridgeConfig) -> B256 {
    let leaves: Vec<B256> = receipts
        .iter()
        .filter(|r| r.status())
        .flat_map(|r| r.inner.logs())
        .filter(|log| log.address() == bridge.address)
        .filter_map(|log| {
            let topic = log.topics().first()?;
            if topic == &bridge.withdrawal_topic {
                extract_hash(log.data().data.as_ref(), SEND_EVENT_MESSAGE_HASH_OFFSET)
            } else if topic == &bridge.rollback_topic {
                extract_hash(log.data().data.as_ref(), ROLLBACK_EVENT_MESSAGE_HASH_OFFSET)
            } else {
                None
            }
        })
        .collect();

    merkle_root(leaves)
}

fn compute_deposit_hash(receipts: &[TransactionReceipt], bridge: &BridgeConfig) -> B256 {
    let mut hasher = Keccak256::new();
    let mut any = false;

    receipts
        .iter()
        .filter(|r| r.status())
        .flat_map(|r| r.inner.logs())
        .filter(|log| log.address() == bridge.address)
        .filter(|log| log.topics().first() == Some(&bridge.deposit_topic))
        .filter_map(|log| extract_hash(log.data().data.as_ref(), RECEIVE_EVENT_MESSAGE_HASH_OFFSET))
        .for_each(|hash| {
            hasher.update(hash);
            any = true;
        });

    if any {
        hasher.finalize()
    } else {
        ZERO_BYTES_HASH
    }
}

fn count_deposits(receipts: &[TransactionReceipt], bridge: &BridgeConfig) -> u64 {
    receipts
        .iter()
        .filter(|r| r.status())
        .flat_map(|r| r.inner.logs())
        .filter(|log| {
            log.address() == bridge.address && log.topics().first() == Some(&bridge.deposit_topic)
        })
        .count() as u64
}

fn extract_hash(data: &[u8], offset: usize) -> Option<B256> {
    if data.len() >= offset + 32 {
        Some(B256::from_slice(&data[offset..offset + 32]))
    } else {
        None
    }
}

/// Compute Merkle root from leaves (mirrors `events_hash.rs::merkle_root`).
///
/// - Empty list → `ZERO_BYTES_HASH`
/// - Odd layer → last element duplicated
/// - Pair hash: `keccak256(left ++ right)`
fn merkle_root(mut leaves: Vec<B256>) -> B256 {
    if leaves.is_empty() {
        return ZERO_BYTES_HASH;
    }

    while leaves.len() > 1 {
        if leaves.len() % 2 != 0 {
            leaves.push(*leaves.last().unwrap());
        }
        for i in 0..leaves.len() / 2 {
            let mut hasher = Keccak256::new();
            hasher.update(leaves[i * 2]);
            hasher.update(leaves[i * 2 + 1]);
            leaves[i] = hasher.finalize();
        }
        leaves.truncate(leaves.len() / 2);
    }

    leaves[0]
}

// ---------------------------------------------------------------------------
// Admin API helper
// ---------------------------------------------------------------------------

async fn insert_blobs_via_admin(
    http: &reqwest::Client,
    beacon_url: &str,
    slot: u64,
    blobs: &[blob_builder::BuiltBlob],
) -> Result<()> {
    let body = serde_json::json!({
        "slot": slot,
        "blobs": blobs.iter().map(|b| serde_json::json!({
            "blob": hex::encode(&b.blob),
            "commitment": hex::encode(&b.commitment),
            "proof": hex::encode(&b.proof),
            "versioned_hash": hex::encode(b.versioned_hash.as_slice()),
        })).collect::<Vec<_>>(),
    });

    http.post(format!("{beacon_url}/admin/insert_sidecars"))
        .json(&body)
        .send()
        .await
        .map_err(|e| eyre!("Admin insert failed: {e}"))?
        .error_for_status()
        .map_err(|e| eyre!("Admin insert error: {e}"))?;

    Ok(())
}

// ---------------------------------------------------------------------------
// Test
// ---------------------------------------------------------------------------

#[tokio::test]
async fn e2e_full_pipeline() -> Result<()> {
    tracing_subscriber::fmt::init();

    let config = E2eConfig::from_env()?;
    let http = reqwest::Client::new();

    // ── 1. Connect to Anvil (fake L1) ────────────────────────────────────
    info!(url = %config.anvil_url, "Connecting to Anvil (fake L1)");
    let anvil_url: url::Url = config.anvil_url.parse()?;
    let anvil_provider: RootProvider =
        RootProvider::new(alloy_rpc_client::RpcClient::new_http(anvil_url));

    let chain_id = anvil_provider.get_chain_id().await?;
    info!(chain_id, "Connected to Anvil");

    // ── 2. Connect to reth (L2) ───────────────────────────────────────────
    info!(url = %config.reth_url, "Connecting to reth (L2)");
    let reth_url: url::Url = config.reth_url.parse()?;
    let reth_provider: RootProvider =
        RootProvider::new(alloy_rpc_client::RpcClient::new_http(reth_url));

    // ── 3. Deploy MockRollup (or use pre-deployed address) ───────────────
    let contract_addr = match config.contract_addr {
        Some(addr) => {
            info!(%addr, "Using pre-deployed MockRollup from E2E_CONTRACT_ADDR");
            addr
        }
        None => {
            let addr = mock_l1::deploy_mock_rollup(&anvil_provider).await?;
            info!(%addr, "MockRollup deployed");
            addr
        }
    };

    // ── 4. Wait for N L2 blocks ───────────────────────────────────────────
    let start_block = reth_provider.get_block_number().await?;
    let end_block = start_block + config.block_count;
    info!(start_block, end_block, "Waiting for {} L2 blocks", config.block_count);
    wait_for_block(&reth_provider, end_block).await?;

    // ── 5. Fetch headers and raw txs ─────────────────────────────────────
    let mut l2_headers: Vec<L2BlockHeader> = Vec::with_capacity(config.block_count as usize);
    let mut tx_data_per_block: Vec<Vec<u8>> = Vec::with_capacity(config.block_count as usize);
    for bn in (start_block + 1)..=end_block {
        l2_headers.push(fetch_l2_header(&reth_provider, bn, &config.bridge).await?);
        tx_data_per_block.push(fetch_raw_txs(&reth_provider, bn).await?);
    }
    info!(count = l2_headers.len(), "Fetched L2 block headers and tx data");

    // ── 6. Build canonical blobs ──────────────────────────────────────────
    let built_blobs = blob_builder::build_blobs_from_blocks(start_block + 1, &tx_data_per_block)?;
    info!(count = built_blobs.len(), "Built canonical blobs");

    let versioned_hashes: Vec<B256> = built_blobs.iter().map(|b| b.versioned_hash).collect();

    // ── 7. acceptNextBatch on MockRollup ─────────────────────────────────
    let batch_index = mock_l1::read_next_batch_index(&anvil_provider, contract_addr).await?;
    mock_l1::accept_next_batch(
        &anvil_provider,
        contract_addr,
        l2_headers,
        built_blobs.len() as u64,
    )
    .await?;
    info!(batch_index, "acceptNextBatch executed");

    // ── 8. submitBlobs ────────────────────────────────────────────────────
    mock_l1::submit_blobs(&anvil_provider, contract_addr, batch_index, versioned_hashes.clone())
        .await?;

    // Verify blob hashes were stored.
    let stored =
        mock_l1::read_batch_blob_hashes(&anvil_provider, contract_addr, batch_index).await?;
    assert_eq!(stored, versioned_hashes, "Stored blob hashes must match");
    info!("Blob hashes verified on MockRollup");

    // ── 9. Insert blobs into fake beacon ──────────────────────────────────
    // Compute slot from the mined block's timestamp (genesis_ts = 0 on Anvil).
    let latest = anvil_provider
        .get_block_by_number(BlockNumberOrTag::Latest.into())
        .await?
        .ok_or_else(|| eyre!("no latest block on Anvil"))?;
    let slot = latest.header.timestamp / 12;
    info!(slot, timestamp = latest.header.timestamp, "Computed beacon slot");

    insert_blobs_via_admin(&http, &config.beacon_url, slot, &built_blobs).await?;
    info!(slot, "Blobs inserted into fake beacon via admin API");

    // ── 10. Poll for courier to preconfirm batch ──────────────────────────
    // The courier's BatchAccumulator gates /sign-batch-root on:
    //   1. All EthExecutionResponse for [from, to] collected
    //   2. L1Event::BlobsAccepted received (fired by BatchAccepted from submitBlobs)
    // No explicit synchronization needed — the accumulator handles timing.
    info!(batch_index, "Polling for courier to preconfirm batch");
    let timeout = Duration::from_secs(300);
    let start = Instant::now();
    loop {
        if start.elapsed() > timeout {
            return Err(eyre!("Courier did not preconfirm batch {batch_index} within 5 minutes"));
        }
        let last = mock_l1::read_last_preconfirmed_batch(&anvil_provider, contract_addr).await?;
        if last == batch_index {
            info!(batch_index, "Courier preconfirmed batch on L1");
            break;
        }
        tokio::time::sleep(Duration::from_secs(3)).await;
    }

    // ── 11. Verify result ─────────────────────────────────────────────────
    let last_batch = mock_l1::read_last_preconfirmed_batch(&anvil_provider, contract_addr).await?;
    assert_eq!(last_batch, batch_index, "lastPreconfirmedBatch must match batch_index");

    info!(batch_index = last_batch, "E2E pipeline test PASSED");
    Ok(())
}
