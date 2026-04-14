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
    pub(crate) fn size(&self) -> Result<usize, String> {
        self.block_boundaries
            .len()
            .checked_mul(4)
            .and_then(|n| n.checked_add(FIXED_HEADER_SIZE))
            .ok_or_else(|| "header size overflow".to_string())
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
    let [
        f0, f1, f2, f3, f4, f5, f6, f7,
        t0, t1, t2, t3, t4, t5, t6, t7,
        n0, n1, n2, n3,
        ..
    ] = *data
    else {
        return Err("blob payload too short for header".into());
    };

    let from_block = u64::from_be_bytes([f0, f1, f2, f3, f4, f5, f6, f7]);
    let to_block = u64::from_be_bytes([t0, t1, t2, t3, t4, t5, t6, t7]);
    let num_blocks = u32::from_be_bytes([n0, n1, n2, n3]) as usize;

    if from_block > to_block {
        return Err(format!("invalid block range: from ({from_block}) > to ({to_block})"));
    }
    let span = to_block
        .checked_sub(from_block)
        .and_then(|d| d.checked_add(1))
        .ok_or_else(|| "block range span overflow".to_string())?;
    if span != num_blocks as u64 {
        return Err(format!(
            "block range [{from_block}, {to_block}] doesn't match num_blocks ({num_blocks})"
        ));
    }

    let full_header_size = num_blocks
        .checked_mul(4)
        .and_then(|n| n.checked_add(FIXED_HEADER_SIZE))
        .ok_or_else(|| "header size overflow".to_string())?;
    if data.len() < full_header_size {
        return Err(format!("blob payload too short for {num_blocks} block boundaries"));
    }

    let block_boundaries: Vec<usize> = data[FIXED_HEADER_SIZE..full_header_size]
        .chunks_exact(4)
        .map(|chunk| {
            let &[b0, b1, b2, b3] = chunk else { unreachable!("chunks_exact(4)") };
            u32::from_be_bytes([b0, b1, b2, b3]) as usize
        })
        .collect();

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

    let mut data_offset = header.size()?;
    for b in &header.block_boundaries[..idx] {
        data_offset = data_offset
            .checked_add(*b)
            .ok_or_else(|| "tx_data offset overflow".to_string())?;
    }
    let chunk_len = header.block_boundaries[idx];
    let end = data_offset
        .checked_add(chunk_len)
        .ok_or_else(|| "tx_data end overflow".to_string())?;

    if end > payload.len() {
        return Err("tx_data exceeds blob payload".into());
    }

    Ok(&payload[data_offset..end])
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
