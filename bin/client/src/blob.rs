//! Shared blob decanonicalization and DA header parsing.
//!
//! Used by both SP1 (zkVM) and Nitro (enclave) runtimes.
//! All functions return Result — SP1 calls .unwrap(), Nitro propagates errors.

use std::io::Read;

use alloy_primitives::B256;

pub(crate) const BYTES_PER_FIELD: usize = 31;
#[cfg(test)]
const FIELD_SIZE: usize = 32;
pub(crate) const FIELDS_PER_BLOB: usize = 4096; // EIP-4844: fixed at 4096 field elements per blob
pub(crate) const MAX_RAW_BYTES_PER_BLOB: usize = FIELDS_PER_BLOB * BYTES_PER_FIELD;

/// 16 bytes: from_block(u64BE) | to_block(u64BE).
const RANGE_PREFIX_SIZE: usize = 16;
/// 130 bytes: previousBlockHash(32) | blockHash(32) | withdrawalRoot(32)
/// | depositRoot(32) | depositCount(u16BE).
/// Mirrors `crates/blob-builder::header::L2BlockHeader::write_packed`.
const PACKED_L2_HEADER_SIZE: usize = 32 * 4 + 2;
/// Per-block tx_len entry size (u32BE).
const TX_LEN_SIZE: usize = 4;

/// Per-block L2 header carried in the blob payload.
///
/// `deposit_count` is wire-present (parsed and skipped) but not exposed —
/// it has no consumer in the client and is not part of `compute_leaf`.
#[derive(Debug, Clone, Copy)]
pub(crate) struct L2BlockHeader {
    pub(crate) previous_block_hash: B256,
    pub(crate) block_hash: B256,
    pub(crate) withdrawal_root: B256,
    pub(crate) deposit_root: B256,
}

#[derive(Debug, Clone, Copy)]
struct BlockEntry {
    header: L2BlockHeader,
    tx_start: usize,
    tx_end: usize,
}

/// Parsed blob payload header — owns per-block entries with precomputed
/// tx-data offsets for O(1) per-block extraction.
#[derive(Debug)]
pub(crate) struct BlobHeader {
    pub(crate) from_block: u64,
    pub(crate) to_block: u64,
    blocks: Vec<BlockEntry>,
}

impl BlobHeader {
    pub(crate) fn num_blocks(&self) -> usize {
        self.blocks.len()
    }
}

/// Extracts raw bytes from a single blob's KZG field elements.
pub(crate) fn decanonicalize(blob: &[u8]) -> Result<Vec<u8>, String> {
    if !blob.len().is_multiple_of(32) {
        return Err(format!("blob length ({}) is not a multiple of 32", blob.len()));
    }
    let mut result = Vec::with_capacity(MAX_RAW_BYTES_PER_BLOB);
    let mut offset = 0;
    while offset < blob.len() && result.len() < MAX_RAW_BYTES_PER_BLOB {
        if blob[offset] != 0x00 {
            return Err(format!("non-canonical field element at offset {offset}"));
        }
        offset += 1;
        let remaining = MAX_RAW_BYTES_PER_BLOB - result.len();
        let take = remaining.min(BYTES_PER_FIELD).min(blob.len() - offset);
        result.extend_from_slice(&blob[offset..offset + take]);
        offset += BYTES_PER_FIELD;
    }
    Ok(result)
}

/// Decanonicalize all blobs, concatenate, and brotli-decompress.
/// Returns (BlobHeader, full_decompressed_payload).
pub(crate) fn decode_blob_payload(blobs: &[Vec<u8>]) -> Result<(BlobHeader, Vec<u8>), String> {
    if blobs.is_empty() {
        return Err("no blobs provided".into());
    }

    let mut all_raw = Vec::with_capacity(blobs.len() * MAX_RAW_BYTES_PER_BLOB);
    for blob in blobs {
        let raw = decanonicalize(blob)?;
        all_raw.extend_from_slice(&raw);
    }

    let mut decompressed = Vec::new();
    let mut decompressor = brotli::Decompressor::new(all_raw.as_slice(), 4096);
    decompressor
        .read_to_end(&mut decompressed)
        .map_err(|e| format!("brotli decompression failed: {e}"))?;

    let header = parse_header(&decompressed)?;
    Ok((header, decompressed))
}

fn parse_header(data: &[u8]) -> Result<BlobHeader, String> {
    if data.len() < RANGE_PREFIX_SIZE {
        return Err("blob payload too short for range prefix".into());
    }
    let from_block = u64::from_be_bytes(data[0..8].try_into().unwrap());
    let to_block = u64::from_be_bytes(data[8..16].try_into().unwrap());

    if from_block > to_block {
        return Err(format!("invalid block range: from ({from_block}) > to ({to_block})"));
    }
    let span = to_block
        .checked_sub(from_block)
        .and_then(|d| d.checked_add(1))
        .ok_or_else(|| "block range span overflow".to_string())?;
    let num_blocks: usize = span
        .try_into()
        .map_err(|_| format!("block range span ({span}) exceeds usize"))?;

    let headers_bytes = num_blocks
        .checked_mul(PACKED_L2_HEADER_SIZE)
        .ok_or_else(|| "headers region overflow".to_string())?;
    let lens_bytes = num_blocks
        .checked_mul(TX_LEN_SIZE)
        .ok_or_else(|| "tx_lens region overflow".to_string())?;
    let prefix_end = RANGE_PREFIX_SIZE
        .checked_add(headers_bytes)
        .and_then(|n| n.checked_add(lens_bytes))
        .ok_or_else(|| "fixed prefix overflow".to_string())?;
    if data.len() < prefix_end {
        return Err(format!(
            "blob payload too short: have {}, need {prefix_end} for {num_blocks} block headers + tx_lens",
            data.len(),
        ));
    }

    let mut headers = Vec::with_capacity(num_blocks);
    let mut off = RANGE_PREFIX_SIZE;
    for _ in 0..num_blocks {
        let h = L2BlockHeader {
            previous_block_hash: B256::from_slice(&data[off..off + 32]),
            block_hash: B256::from_slice(&data[off + 32..off + 64]),
            withdrawal_root: B256::from_slice(&data[off + 64..off + 96]),
            deposit_root: B256::from_slice(&data[off + 96..off + 128]),
        };
        // data[off+128..off+130] is deposit_count(u16BE) — parsed-and-skipped.
        headers.push(h);
        off += PACKED_L2_HEADER_SIZE;
    }

    let mut blocks = Vec::with_capacity(num_blocks);
    let mut tx_cursor = prefix_end;
    for header in headers {
        let len_bytes: [u8; 4] = data[off..off + 4].try_into().unwrap();
        off += 4;
        let tx_len = u32::from_be_bytes(len_bytes) as usize;

        let tx_end = tx_cursor
            .checked_add(tx_len)
            .ok_or_else(|| "tx_data offset overflow".to_string())?;
        blocks.push(BlockEntry { header, tx_start: tx_cursor, tx_end });
        tx_cursor = tx_end;
    }

    if tx_cursor != data.len() {
        return Err(format!(
            "tx_data region size mismatch: end={tx_cursor}, payload={}",
            data.len(),
        ));
    }

    Ok(BlobHeader { from_block, to_block, blocks })
}

/// Extracts the per-block L2 header and the tx_data slice for a given block.
///
/// `payload` MUST be the same buffer that was returned by `decode_blob_payload`
/// alongside `header` — offsets stored in `header` are byte-positions into
/// that exact buffer.
pub(crate) fn extract_block<'a>(
    header: &BlobHeader,
    payload: &'a [u8],
    block_number: u64,
) -> Result<(L2BlockHeader, &'a [u8]), String> {
    if block_number < header.from_block || block_number > header.to_block {
        return Err(format!(
            "block {block_number} outside blob range [{}, {}]",
            header.from_block, header.to_block,
        ));
    }
    let idx = (block_number - header.from_block) as usize;
    let entry = header.blocks[idx];
    if entry.tx_end > payload.len() {
        return Err("tx_data exceeds blob payload".into());
    }
    Ok((entry.header, &payload[entry.tx_start..entry.tx_end]))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn canonicalize(input: &[u8]) -> Vec<u8> {
        if input.is_empty() {
            return Vec::new();
        }
        let chunks = input.len().div_ceil(BYTES_PER_FIELD);
        let mut result = vec![0u8; chunks * FIELD_SIZE];
        let mut inp = 0;
        let mut out = 0;
        while inp < input.len() {
            out += 1; // skip 0x00 padding byte
            let n = BYTES_PER_FIELD.min(input.len() - inp);
            result[out..out + n].copy_from_slice(&input[inp..inp + n]);
            inp += n;
            out += BYTES_PER_FIELD;
        }
        result
    }

    fn mk_header(seed: u8) -> L2BlockHeader {
        L2BlockHeader {
            previous_block_hash: B256::from([seed; 32]),
            block_hash: B256::from([seed.wrapping_add(1); 32]),
            withdrawal_root: B256::from([seed.wrapping_add(2); 32]),
            deposit_root: B256::from([seed.wrapping_add(3); 32]),
        }
    }

    /// Hand-rolled raw payload (no brotli, no canonicalize) for parser tests.
    /// Layout: from(u64BE) | to(u64BE) | header*N | tx_len*N | tx_data
    /// Each header is 130 bytes including the trailing deposit_count u16.
    fn build_payload(
        from_block: u64,
        to_block: u64,
        per_block: &[(L2BlockHeader, u16, &[u8])],
    ) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&from_block.to_be_bytes());
        buf.extend_from_slice(&to_block.to_be_bytes());
        for (h, dep_count, _) in per_block {
            buf.extend_from_slice(h.previous_block_hash.as_slice());
            buf.extend_from_slice(h.block_hash.as_slice());
            buf.extend_from_slice(h.withdrawal_root.as_slice());
            buf.extend_from_slice(h.deposit_root.as_slice());
            buf.extend_from_slice(&dep_count.to_be_bytes());
        }
        for (_, _, tx) in per_block {
            buf.extend_from_slice(&(tx.len() as u32).to_be_bytes());
        }
        for (_, _, tx) in per_block {
            buf.extend_from_slice(tx);
        }
        buf
    }

    #[test]
    fn canonicalize_decanonicalize_roundtrip() {
        let cases: &[&[u8]] = &[b"hello", &[0xFFu8; 31], &[0xAB; 62], &[0x01; 100]];
        for input in cases {
            let encoded = canonicalize(input);
            let decoded = decanonicalize(&encoded).expect("decanonicalize failed");
            assert_eq!(
                &decoded[..input.len()],
                *input,
                "roundtrip failed for len {}",
                input.len()
            );
        }
    }

    #[test]
    fn decanonicalize_rejects_non_canonical() {
        let mut blob = vec![0u8; 64];
        blob[0] = 0x01;
        assert!(decanonicalize(&blob).is_err());
    }

    #[test]
    fn decanonicalize_extracts_raw_bytes() {
        let mut blob = vec![0u8; FIELDS_PER_BLOB * FIELD_SIZE];
        for f in 0..FIELDS_PER_BLOB {
            blob[f * FIELD_SIZE] = 0x00;
            for b in 0..BYTES_PER_FIELD {
                blob[f * FIELD_SIZE + 1 + b] = ((f * BYTES_PER_FIELD + b) % 256) as u8;
            }
        }
        let raw = decanonicalize(&blob).unwrap();
        assert_eq!(raw.len(), MAX_RAW_BYTES_PER_BLOB);
        assert_eq!(raw[0], 0);
        assert_eq!(raw[1], 1);
    }

    #[test]
    fn parse_header_single_block() {
        let h0 = mk_header(0x10);
        let tx = b"hello-tx-data";
        let payload = build_payload(42, 42, &[(h0, 7, tx)]);
        let header = parse_header(&payload).expect("parse_header");
        assert_eq!(header.from_block, 42);
        assert_eq!(header.to_block, 42);
        assert_eq!(header.num_blocks(), 1);

        let (l2, slice) = extract_block(&header, &payload, 42).expect("extract_block");
        assert_eq!(l2.previous_block_hash, h0.previous_block_hash);
        assert_eq!(l2.block_hash, h0.block_hash);
        assert_eq!(l2.withdrawal_root, h0.withdrawal_root);
        assert_eq!(l2.deposit_root, h0.deposit_root);
        assert_eq!(slice, tx.as_slice());
    }

    #[test]
    fn parse_header_multi_block_offsets() {
        let h0 = mk_header(0x20);
        let h1 = mk_header(0x30);
        let h2 = mk_header(0x40);
        let tx0: &[u8] = b"first";
        let tx1: &[u8] = b"second-block";
        let tx2: &[u8] = b"third!";
        let payload = build_payload(100, 102, &[(h0, 0, tx0), (h1, 1, tx1), (h2, 2, tx2)]);
        let header = parse_header(&payload).expect("parse_header");
        assert_eq!(header.num_blocks(), 3);

        let (l0, s0) = extract_block(&header, &payload, 100).unwrap();
        let (l1, s1) = extract_block(&header, &payload, 101).unwrap();
        let (l2, s2) = extract_block(&header, &payload, 102).unwrap();
        assert_eq!(l0.block_hash, h0.block_hash);
        assert_eq!(l1.block_hash, h1.block_hash);
        assert_eq!(l2.block_hash, h2.block_hash);
        assert_eq!(s0, tx0);
        assert_eq!(s1, tx1);
        assert_eq!(s2, tx2);
    }

    #[test]
    fn parse_header_rejects_short_payload() {
        assert!(parse_header(&[0u8; 8]).is_err());
    }

    #[test]
    fn parse_header_rejects_bad_range() {
        let mut buf = vec![0u8; 16];
        buf[0..8].copy_from_slice(&100u64.to_be_bytes());
        buf[8..16].copy_from_slice(&50u64.to_be_bytes());
        assert!(parse_header(&buf).is_err());
    }

    #[test]
    fn parse_header_rejects_truncated_tx_region() {
        let h0 = mk_header(0x50);
        let tx = b"data-here";
        let mut payload = build_payload(7, 7, &[(h0, 0, tx)]);
        payload.truncate(payload.len() - 3);
        assert!(parse_header(&payload).is_err());
    }

    #[test]
    fn extract_block_rejects_out_of_range() {
        let h0 = mk_header(0x60);
        let tx = b"x";
        let payload = build_payload(10, 10, &[(h0, 0, tx)]);
        let header = parse_header(&payload).unwrap();
        assert!(extract_block(&header, &payload, 9).is_err());
        assert!(extract_block(&header, &payload, 11).is_err());
    }
}
