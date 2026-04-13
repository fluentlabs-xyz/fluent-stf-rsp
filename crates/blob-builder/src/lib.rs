//! Build EIP-4844 blobs from L2 block transactions fetched via RPC.
//!
//! Pipeline: fetch blocks + bridge logs → encode payload → brotli compress → canonicalize.
//!
//! Uses `brotlic` (C reference libbrotli) for byte-identity with the Go
//! sequencer. The pure-Rust `brotli` crate produces different output on real
//! transaction data and would break the SP1 verifier's versioned-hash check.

mod bridge_events;
mod header;

use std::collections::HashMap;
use std::io::Write;

use alloy_eips::eip2718::Encodable2718;
use alloy_primitives::B256;
use alloy_provider::{Provider, RootProvider};
use alloy_rpc_types::{Filter, Log};
use brotlic::{BrotliEncoderOptions, CompressorWriter, Quality, WindowSize};
use eyre::{eyre, Result};
use fluent_stf_primitives::{
    BRIDGE_ADDRESS, BRIDGE_DEPOSIT_TOPIC, BRIDGE_ROLLBACK_TOPIC, BRIDGE_WITHDRAWAL_TOPIC,
};
use tracing::info;

use crate::bridge_events::compute_block_roots;
use crate::header::L2BlockHeader;

/// EIP-4844 blob size: 4096 field elements × 32 bytes = 131072 bytes.
const BYTES_PER_BLOB: usize = 131_072;

const BYTES_PER_FIELD_ELEMENT: usize = 31;
const FIELD_ELEMENTS_PER_BLOB: usize = BYTES_PER_BLOB / 32;
const MAX_RAW_BYTES_PER_BLOB: usize = FIELD_ELEMENTS_PER_BLOB * BYTES_PER_FIELD_ELEMENT;

const FETCH_BATCH_SIZE: u64 = 100;

/// Per-block bundle assembled by `fetch_blocks_with_logs`.
struct BlockBundle {
    header: L2BlockHeader,
    tx_data: Vec<u8>,
}

/// Fetch L2 blocks and build canonical EIP-4844 blobs.
///
/// Returns `Vec<Vec<u8>>` where each inner Vec is exactly BYTES_PER_BLOB (131072) bytes.
pub async fn build_blobs_from_l2(
    provider: &RootProvider,
    from_block: u64,
    to_block: u64,
) -> Result<Vec<Vec<u8>>> {
    let blocks = fetch_blocks_with_logs(provider, from_block, to_block).await?;
    let payload = encode_blob_payload(from_block, to_block, &blocks);
    let compressed = brotli_compress(&payload)?;

    info!(
        from_block,
        to_block,
        raw_size = payload.len(),
        compressed_size = compressed.len(),
        "Blob payload compressed"
    );

    compressed.chunks(MAX_RAW_BYTES_PER_BLOB).map(build_single_blob).collect()
}

/// One batched `eth_getLogs` over the entire range, then concurrent block
/// fetch. For each block we assemble a `BlockBundle` (header + tx data).
async fn fetch_blocks_with_logs(
    provider: &RootProvider,
    from_block: u64,
    to_block: u64,
) -> Result<Vec<BlockBundle>> {
    let log_filter = Filter::new()
        .address(BRIDGE_ADDRESS)
        .event_signature(vec![BRIDGE_WITHDRAWAL_TOPIC, BRIDGE_DEPOSIT_TOPIC, BRIDGE_ROLLBACK_TOPIC])
        .from_block(from_block)
        .to_block(to_block);

    let all_logs = provider
        .get_logs(&log_filter)
        .await
        .map_err(|e| eyre!("eth_getLogs(bridge) [{from_block}..{to_block}] failed: {e}"))?;

    let mut logs_by_block: HashMap<u64, Vec<&Log>> = HashMap::new();
    for log in &all_logs {
        if let Some(bn) = log.block_number {
            logs_by_block.entry(bn).or_default().push(log);
        }
    }

    let mut result: Vec<BlockBundle> = Vec::with_capacity((to_block - from_block + 1) as usize);
    let mut current = from_block;

    while current <= to_block {
        let batch_end = (current + FETCH_BATCH_SIZE - 1).min(to_block);

        let futs = (current..=batch_end).map(|bn| {
            let provider = provider.clone();
            async move {
                let block = provider
                    .get_block_by_number(bn.into())
                    .full()
                    .await
                    .map_err(|e| eyre!("get_block_by_number({bn}) failed: {e}"))?
                    .ok_or_else(|| eyre!("L2 block {bn} not found"))?;

                let mut tx_data = Vec::new();
                for tx in block.transactions.txns() {
                    tx_data.extend_from_slice(&tx.inner.encoded_2718());
                }

                let previous_block_hash = B256::from(block.header.parent_hash);
                let block_hash = B256::from(block.header.hash);

                Ok::<(u64, B256, B256, Vec<u8>), eyre::Report>((
                    bn,
                    previous_block_hash,
                    block_hash,
                    tx_data,
                ))
            }
        });

        let mut results = futures::future::try_join_all(futs).await?;
        results.sort_by_key(|(bn, _, _, _)| *bn);

        for (bn, previous_block_hash, block_hash, tx_data) in results {
            let block_logs: &[&Log] = logs_by_block.get(&bn).map(Vec::as_slice).unwrap_or(&[]);
            let roots = compute_block_roots(block_logs);
            let header = L2BlockHeader {
                previous_block_hash,
                block_hash,
                withdrawal_root: roots.withdrawal_root,
                deposit_root: roots.deposit_root,
                deposit_count: roots.deposit_count,
            };
            result.push(BlockBundle { header, tx_data });
        }

        current = batch_end + 1;
    }

    Ok(result)
}

/// Encode the new blob payload format:
/// `from_block(u64BE) | to_block(u64BE) | L2BlockHeader[130×N] | tx_len[u32BE × N] | tx_data`.
fn encode_blob_payload(from_block: u64, to_block: u64, blocks: &[BlockBundle]) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.extend_from_slice(&from_block.to_be_bytes());
    payload.extend_from_slice(&to_block.to_be_bytes());
    for b in blocks {
        b.header.write_packed(&mut payload);
    }
    for b in blocks {
        payload.extend_from_slice(&(b.tx_data.len() as u32).to_be_bytes());
    }
    for b in blocks {
        payload.extend_from_slice(&b.tx_data);
    }
    payload
}

/// Brotli compress via C reference libbrotli (quality=6, lgwin=22, mode=Generic).
///
/// Uses `brotlic` which compiles the C reference libbrotli from source, guaranteeing
/// byte-identical output with the Go sequencer (andybalholm/brotli is a c2go
/// translation of the same C reference). The pure-Rust brotli crate produces
/// different output on real transaction data.
fn brotli_compress(data: &[u8]) -> Result<Vec<u8>> {
    let encoder = BrotliEncoderOptions::new()
        .quality(Quality::new(6).map_err(|e| eyre!("invalid quality: {e}"))?)
        .window_size(WindowSize::new(22).map_err(|e| eyre!("invalid window size: {e}"))?)
        .build()
        .map_err(|e| eyre!("encoder build failed: {e}"))?;

    let mut writer = CompressorWriter::with_encoder(encoder, Vec::new());
    writer.write_all(data).map_err(|e| eyre!("brotli compress failed: {e}"))?;
    let compressed = writer.into_inner().map_err(|e| eyre!("brotli finalize failed: {e}"))?;
    Ok(compressed)
}

/// Canonicalize raw bytes and build a blob buffer.
fn build_single_blob(raw: &[u8]) -> Result<Vec<u8>> {
    if raw.len() > MAX_RAW_BYTES_PER_BLOB {
        return Err(eyre!(
            "data ({} bytes) exceeds blob capacity ({MAX_RAW_BYTES_PER_BLOB})",
            raw.len()
        ));
    }
    Ok(canonicalize(raw))
}

/// Canonicalize raw bytes into BYTES_PER_BLOB-length buffer.
/// Each 32-byte field element: [0x00, raw[0..31]].
fn canonicalize(raw: &[u8]) -> Vec<u8> {
    let mut out = vec![0u8; BYTES_PER_BLOB];
    let mut src_off = 0;
    let mut dst_off = 0;
    while src_off < raw.len() {
        dst_off += 1; // skip 0x00 high byte
        let take = BYTES_PER_FIELD_ELEMENT.min(raw.len() - src_off);
        out[dst_off..dst_off + take].copy_from_slice(&raw[src_off..src_off + take]);
        src_off += take;
        dst_off += BYTES_PER_FIELD_ELEMENT;
    }
    out
}
