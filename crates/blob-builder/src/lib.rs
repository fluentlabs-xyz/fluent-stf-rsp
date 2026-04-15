//! Build EIP-4844 blobs from L2 blocks fetched via RPC.
//!
//! Pipeline: fetch blocks → into_consensus → rlp encode → concat → brotli → canonicalize.
//!
//! Uses `brotlic` (C reference libbrotli) for byte-identity with the Go
//! sequencer. The pure-Rust `brotli` crate produces different output on real
//! transaction data and would break the SP1 verifier's versioned-hash check.

use std::io::Write;

use alloy_consensus::{Block, TxEnvelope};
use alloy_provider::{Provider, RootProvider};
use alloy_rlp::Encodable;
use brotlic::{BrotliEncoderOptions, CompressorWriter, Quality, WindowSize};
use eyre::{eyre, Result};
use tracing::info;

/// EIP-4844 blob size: 4096 field elements × 32 bytes = 131072 bytes.
const BYTES_PER_BLOB: usize = 131_072;

const BYTES_PER_FIELD_ELEMENT: usize = 31;
const FIELD_ELEMENTS_PER_BLOB: usize = BYTES_PER_BLOB / 32;
const MAX_RAW_BYTES_PER_BLOB: usize = FIELD_ELEMENTS_PER_BLOB * BYTES_PER_FIELD_ELEMENT;

const FETCH_BATCH_SIZE: u64 = 100;

/// Fetch L2 blocks and build canonical EIP-4844 blobs.
///
/// Returns `Vec<Vec<u8>>` where each inner Vec is exactly BYTES_PER_BLOB (131072) bytes.
pub async fn build_blobs_from_l2(
    provider: &RootProvider,
    from_block: u64,
    to_block: u64,
) -> Result<Vec<Vec<u8>>> {
    let rlp_blocks = fetch_blocks(provider, from_block, to_block).await?;
    let payload: Vec<u8> = rlp_blocks.into_iter().flatten().collect();
    let compressed = brotli_compress(&payload)?;

    info!(
        from_block,
        to_block,
        raw_size = payload.len(),
        compressed_size = compressed.len(),
        "Blob payload compressed",
    );

    compressed.chunks(MAX_RAW_BYTES_PER_BLOB).map(build_single_blob).collect()
}

/// Concurrent block fetch batched by `FETCH_BATCH_SIZE`. Each block is
/// converted from the RPC envelope to `alloy_consensus::Block<TxEnvelope>`
/// and RLP-encoded.
async fn fetch_blocks(
    provider: &RootProvider,
    from_block: u64,
    to_block: u64,
) -> Result<Vec<Vec<u8>>> {
    let total: usize = (to_block - from_block + 1) as usize;
    let mut result: Vec<Vec<u8>> = Vec::with_capacity(total);
    let mut current = from_block;

    while current <= to_block {
        let batch_end = (current + FETCH_BATCH_SIZE - 1).min(to_block);

        let futs = (current..=batch_end).map(|bn| {
            let provider = provider.clone();
            async move {
                let rpc_block = provider
                    .get_block_by_number(bn.into())
                    .full()
                    .await
                    .map_err(|e| eyre!("get_block_by_number({bn}) failed: {e}"))?
                    .ok_or_else(|| eyre!("L2 block {bn} not found"))?;

                let consensus: Block<TxEnvelope> =
                    rpc_block.map_transactions(TxEnvelope::from).into_consensus();

                let mut buf = Vec::new();
                consensus.encode(&mut buf);
                Ok::<(u64, Vec<u8>), eyre::Report>((bn, buf))
            }
        });

        let mut batch = futures::future::try_join_all(futs).await?;
        batch.sort_by_key(|(bn, _)| *bn);
        for (_, rlp) in batch {
            result.push(rlp);
        }
        current = batch_end + 1;
    }

    Ok(result)
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

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_consensus::{BlockBody, Header};
    use std::io::Read;

    #[test]
    fn encode_decompress_roundtrip() {
        let h1 = Header { number: 100, ..Default::default() };
        let h2 = Header { number: 101, ..Default::default() };
        let empty_body: BlockBody<TxEnvelope> = BlockBody {
            transactions: vec![],
            ommers: vec![],
            withdrawals: None,
        };
        let b1 = Block { header: h1, body: empty_body.clone() };
        let b2 = Block { header: h2, body: empty_body };

        let mut expected = Vec::new();
        b1.encode(&mut expected);
        b2.encode(&mut expected);

        let compressed = brotli_compress(&expected).unwrap();

        let mut decompressed = Vec::new();
        brotli::Decompressor::new(compressed.as_slice(), 4096)
            .read_to_end(&mut decompressed)
            .unwrap();

        assert_eq!(decompressed, expected);
    }
}
