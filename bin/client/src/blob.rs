//! Shared blob decanonicalization and RLP-block streaming.
//!
//! Used by both SP1 (zkVM) and Nitro (enclave) runtimes.
//! SP1 call sites `.unwrap()`, Nitro propagates errors.

use std::io::Read;

use alloy_primitives::{keccak256, B256};
use alloy_rlp::Header;

pub(crate) const BYTES_PER_FIELD: usize = 31;
#[cfg(test)]
const FIELD_SIZE: usize = 32;
pub(crate) const FIELDS_PER_BLOB: usize = 4096;
pub(crate) const MAX_RAW_BYTES_PER_BLOB: usize = FIELDS_PER_BLOB * BYTES_PER_FIELD;

/// View of one RLP-encoded Ethereum block inside the decompressed blob payload.
#[derive(Debug, Clone, Copy)]
pub(crate) struct BlockView {
    /// keccak256 over the raw RLP-encoded block header (bytes identical to
    /// `alloy_consensus::Header::hash_slow()`).
    pub(crate) block_hash: B256,
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
pub(crate) fn decode_blob_payload(blobs: &[Vec<u8>]) -> Result<Vec<u8>, String> {
    if blobs.is_empty() {
        return Err("no blobs provided".into());
    }
    let mut all_raw = Vec::with_capacity(blobs.len() * MAX_RAW_BYTES_PER_BLOB);
    for blob in blobs {
        let raw = decanonicalize(blob)?;
        all_raw.extend_from_slice(&raw);
    }
    let mut decompressed = Vec::new();
    brotli::Decompressor::new(all_raw.as_slice(), 4096)
        .read_to_end(&mut decompressed)
        .map_err(|e| format!("brotli decompression failed: {e}"))?;
    Ok(decompressed)
}

/// Streaming iterator over RLP-encoded blocks in `payload`.
///
/// Each item yields a `BlockView` whose `block_hash` is the keccak of the
/// first inner RLP list (the block header), or an error that terminates
/// iteration. Does not allocate — advances a byte cursor across `payload`.
pub(crate) fn iter_blocks(payload: &[u8]) -> BlockIter<'_> {
    BlockIter { cursor: payload, done: false }
}

pub(crate) struct BlockIter<'a> {
    cursor: &'a [u8],
    done: bool,
}

impl<'a> Iterator for BlockIter<'a> {
    type Item = Result<BlockView, String>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.done || self.cursor.is_empty() {
            return None;
        }

        // Outer list: [Header, Transactions, Uncles, Withdrawals?, ...]
        let block_start = self.cursor;
        let mut peek = self.cursor;
        let outer = match Header::decode(&mut peek) {
            Ok(h) => h,
            Err(e) => {
                self.done = true;
                return Some(Err(format!("outer RLP decode failed: {e}")));
            }
        };
        if !outer.list {
            self.done = true;
            return Some(Err("outer RLP item is not a list".into()));
        }
        let outer_header_len = block_start.len() - peek.len();
        let outer_total = outer_header_len + outer.payload_length;
        if outer_total > block_start.len() {
            self.done = true;
            return Some(Err("outer RLP item exceeds payload bounds".into()));
        }

        // Inner: first item of the outer list must be the header list.
        let inner_start = &block_start[outer_header_len..outer_total];
        let mut inner = inner_start;
        let header_meta = match Header::decode(&mut inner) {
            Ok(h) => h,
            Err(e) => {
                self.done = true;
                return Some(Err(format!("header RLP decode failed: {e}")));
            }
        };
        if !header_meta.list {
            self.done = true;
            return Some(Err("block header is not an RLP list".into()));
        }
        let header_prefix_len = inner_start.len() - inner.len();
        let header_total = header_prefix_len + header_meta.payload_length;
        if header_total > inner_start.len() {
            self.done = true;
            return Some(Err("header RLP exceeds block bounds".into()));
        }
        let header_bytes = &inner_start[..header_total];
        let block_hash = keccak256(header_bytes);

        self.cursor = &block_start[outer_total..];
        Some(Ok(BlockView { block_hash }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_consensus::{Block, BlockBody, Header as ConsensusHeader, TxEnvelope};
    use alloy_rlp::Encodable;

    fn encode_two_blocks() -> (Vec<u8>, B256, B256) {
        let h1 = ConsensusHeader { number: 100, ..Default::default() };
        let h2 = ConsensusHeader { number: 101, ..Default::default() };
        let empty_body: BlockBody<TxEnvelope> = BlockBody {
            transactions: vec![],
            ommers: vec![],
            withdrawals: None,
        };
        let b1 = Block { header: h1.clone(), body: empty_body.clone() };
        let b2 = Block { header: h2.clone(), body: empty_body };
        let mut payload = Vec::new();
        b1.encode(&mut payload);
        b2.encode(&mut payload);
        (payload, h1.hash_slow(), h2.hash_slow())
    }

    #[test]
    fn iter_blocks_yields_block_hashes_in_order() {
        let (payload, hash1, hash2) = encode_two_blocks();
        let mut it = iter_blocks(&payload);
        assert_eq!(it.next().unwrap().unwrap().block_hash, hash1);
        assert_eq!(it.next().unwrap().unwrap().block_hash, hash2);
        assert!(it.next().is_none());
    }

    #[test]
    fn iter_blocks_rejects_trailing_garbage() {
        let (mut payload, _, _) = encode_two_blocks();
        payload.push(0xFF);
        let mut it = iter_blocks(&payload);
        let _ = it.next().unwrap().unwrap();
        let _ = it.next().unwrap().unwrap();
        assert!(it.next().unwrap().is_err());
    }

    #[test]
    fn iter_blocks_rejects_truncated_stream() {
        let (payload, _, _) = encode_two_blocks();
        let truncated = &payload[..payload.len() - 5];
        let mut it = iter_blocks(truncated);
        let _ = it.next().unwrap().unwrap();
        assert!(it.next().unwrap().is_err());
    }

    #[test]
    fn canonicalize_decanonicalize_roundtrip() {
        let raw: Vec<u8> = (0..MAX_RAW_BYTES_PER_BLOB).map(|i| (i % 251) as u8).collect();
        let mut blob = vec![0u8; FIELDS_PER_BLOB * FIELD_SIZE];
        let mut src_off = 0;
        let mut dst_off = 0;
        while src_off < raw.len() {
            dst_off += 1;
            let take = BYTES_PER_FIELD.min(raw.len() - src_off);
            blob[dst_off..dst_off + take].copy_from_slice(&raw[src_off..src_off + take]);
            src_off += take;
            dst_off += BYTES_PER_FIELD;
        }
        let decoded = decanonicalize(&blob).unwrap();
        assert_eq!(decoded, raw);
    }

    #[test]
    fn decanonicalize_rejects_non_canonical() {
        let mut blob = vec![0u8; FIELDS_PER_BLOB * FIELD_SIZE];
        blob[0] = 0x01;
        assert!(decanonicalize(&blob).is_err());
    }
}
