//! Shared blob decanonicalization and DA header parsing.
//!
//! Used by both SP1 (zkVM) and Nitro (enclave) runtimes.
//! All functions return Result — SP1 calls .unwrap(), Nitro propagates errors.

use std::io::Read;

pub(crate) const BYTES_PER_FIELD: usize = 31;
#[cfg(test)]
const FIELD_SIZE: usize = 32;
pub(crate) const FIELDS_PER_BLOB: usize = 4096; // EIP-4844: fixed at 4096 field elements per blob
pub(crate) const MAX_RAW_BYTES_PER_BLOB: usize = FIELDS_PER_BLOB * BYTES_PER_FIELD;
pub(crate) const FIXED_HEADER_SIZE: usize = 8 + 8 + 4;

/// Parsed blob header.
#[derive(Debug)]
pub(crate) struct BlobHeader {
    pub(crate) from_block: u64,
    pub(crate) to_block: u64,
    pub(crate) block_boundaries: Vec<usize>,
}

impl BlobHeader {
    pub(crate) fn size(&self) -> usize {
        FIXED_HEADER_SIZE + self.block_boundaries.len() * 4
    }
}

/// Extracts raw bytes from a single blob's KZG field elements.
pub(crate) fn decanonicalize(blob: &[u8]) -> Result<Vec<u8>, String> {
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
    if data.len() < FIXED_HEADER_SIZE {
        return Err("blob payload too short for header".into());
    }

    let from_block = u64::from_be_bytes(data[0..8].try_into().unwrap());
    let to_block = u64::from_be_bytes(data[8..16].try_into().unwrap());
    let num_blocks = u32::from_be_bytes(data[16..20].try_into().unwrap()) as usize;

    if from_block > to_block {
        return Err(format!("invalid block range: from ({from_block}) > to ({to_block})"));
    }
    if (to_block - from_block + 1) as usize != num_blocks {
        return Err(format!(
            "block range [{from_block}, {to_block}] doesn't match num_blocks ({num_blocks})"
        ));
    }

    let full_header_size = FIXED_HEADER_SIZE + num_blocks * 4;
    if data.len() < full_header_size {
        return Err(format!("blob payload too short for {num_blocks} block boundaries"));
    }

    let mut block_boundaries = Vec::with_capacity(num_blocks);
    for i in 0..num_blocks {
        let off = FIXED_HEADER_SIZE + i * 4;
        let len = u32::from_be_bytes(data[off..off + 4].try_into().unwrap()) as usize;
        block_boundaries.push(len);
    }

    Ok(BlobHeader { from_block, to_block, block_boundaries })
}

/// Extracts the tx_data slice for a specific block.
pub(crate) fn extract_block_tx_data<'a>(
    header: &BlobHeader,
    payload: &'a [u8],
    block_number: u64,
) -> Result<&'a [u8], String> {
    if block_number < header.from_block {
        return Err(format!(
            "block {block_number} before blob range (from={})",
            header.from_block
        ));
    }
    let idx = (block_number - header.from_block) as usize;
    if idx >= header.block_boundaries.len() {
        return Err(format!(
            "block {block_number} outside blob range [{}, {}]",
            header.from_block, header.to_block,
        ));
    }

    let data_offset = header.size() + header.block_boundaries[..idx].iter().sum::<usize>();
    let chunk_len = header.block_boundaries[idx];

    if data_offset.saturating_add(chunk_len) > payload.len() {
        return Err("tx_data exceeds blob payload".into());
    }

    Ok(&payload[data_offset..data_offset + chunk_len])
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
}
