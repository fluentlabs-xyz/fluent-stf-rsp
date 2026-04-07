#![cfg_attr(not(test), no_main)]

#[cfg(not(test))]
sp1_zkvm::entrypoint!(main);

#[cfg(not(test))]
use rsp_client_executor::executor::DESERIALZE_INPUTS;
use rsp_client_executor::executor::EthClientExecutor;
use rsp_client_executor::io::EthClientExecutorInput;
use rsp_client_executor::utils::profile_report;

use alloy_eips::eip2718::Encodable2718;
use alloy_primitives::B256;
use bytes::{buf::UninitSlice, BufMut};
use sha2::{Digest, Sha256};
use std::io::Read;
use std::sync::Arc;

use kzg_rs::{Blob, Bytes48, KzgProof, KzgSettings};

const BYTES_PER_FIELD: usize = 31;
const FIELD_SIZE: usize = 32;
const FIELDS_PER_BLOB: usize = 4096;
const MAX_RAW_BYTES_PER_BLOB: usize = FIELDS_PER_BLOB * BYTES_PER_FIELD;
const FIXED_HEADER_SIZE: usize = 8 + 8 + 4; // from_block (8) + to_block (8) + num_blocks (4)

#[derive(serde::Deserialize)]
pub struct BlobVerificationInput {
    pub blobs: Vec<Vec<u8>>,
    pub commitments: Vec<Vec<u8>>,
    pub proofs: Vec<Vec<u8>>,
}

/// Extracts raw bytes from a single blob's KZG field elements.
/// Inverse of canonicalize: skips the 0x00 high byte of each 32-byte field.
fn decanonicalize(blob: &[u8]) -> Vec<u8> {
    let mut result = Vec::with_capacity(MAX_RAW_BYTES_PER_BLOB);
    let mut offset = 0;
    while offset < blob.len() && result.len() < MAX_RAW_BYTES_PER_BLOB {
        assert_eq!(blob[offset], 0x00, "non-canonical field element at offset {offset}");
        offset += 1;
        let remaining = MAX_RAW_BYTES_PER_BLOB - result.len();
        let take = remaining.min(BYTES_PER_FIELD);
        result.extend_from_slice(&blob[offset..offset + take]);
        offset += BYTES_PER_FIELD;
    }
    result
}

/// Decanonicalize all blobs, concatenate, and brotli-decompress the payload.
pub(crate) fn decode_blob_payload(blobs: &[Vec<u8>]) -> Vec<u8> {
    let mut all_raw = Vec::with_capacity(blobs.len() * MAX_RAW_BYTES_PER_BLOB);
    for blob in blobs {
        all_raw.extend_from_slice(&decanonicalize(blob));
    }

    let mut decompressed = Vec::new();
    let mut decompressor = brotli::Decompressor::new(all_raw.as_slice(), 4096);
    decompressor.read_to_end(&mut decompressed).expect("brotli decompression failed");
    decompressed
}

/// Validates that all fields within the provided DA blobs adhere to the canonical KZG padding rules.
/// Ensures the first byte of every 32-byte field is 0x00 to guarantee field element validity.
///
/// # Panics
/// Panics if any field contains a non-zero leading byte.
#[inline]
pub fn validate_canonical_padding(blobs: &[Vec<u8>]) {
    for (b_idx, blob) in blobs.iter().enumerate() {
        for f_idx in 0..FIELDS_PER_BLOB {
            assert_eq!(
                blob[f_idx * FIELD_SIZE],
                0x00,
                "Non-canonical padding at blob {} field {}",
                b_idx,
                f_idx
            );
        }
    }
}

/// Parses the DA header from a decompressed flat buffer to locate tx_data for a specific block.
///
/// Returns `(tx_data_offset, tx_data_len)` within the decompressed buffer.
pub(crate) fn parse_da_header(data: &[u8], block_number: u64) -> (usize, usize) {
    assert!(data.len() >= FIXED_HEADER_SIZE, "blob payload too short for header");

    let from_block = u64::from_be_bytes(data[0..8].try_into().unwrap());
    let to_block = u64::from_be_bytes(data[8..16].try_into().unwrap());
    let num_blocks = u32::from_be_bytes(data[16..20].try_into().unwrap()) as usize;

    assert!(
        block_number >= from_block && block_number <= to_block,
        "Block number out of DA range"
    );

    let full_header_size = FIXED_HEADER_SIZE + num_blocks * 4;
    assert!(
        data.len() >= full_header_size,
        "blob payload too short for {num_blocks} block boundaries"
    );

    let target_idx = (block_number - from_block) as usize;
    let mut tx_data_offset = full_header_size;
    let boundary_base = FIXED_HEADER_SIZE;

    for i in 0..target_idx {
        let off = boundary_base + i * 4;
        tx_data_offset += u32::from_be_bytes(data[off..off + 4].try_into().unwrap()) as usize;
    }

    let len_off = boundary_base + target_idx * 4;
    let tx_data_len = u32::from_be_bytes(data[len_off..len_off + 4].try_into().unwrap()) as usize;

    assert!(
        tx_data_offset + tx_data_len <= data.len(),
        "tx_data exceeds blob payload"
    );

    (tx_data_offset, tx_data_len)
}

/// O(1) Memory Data Sink for alloy_rlp.
/// Internal buffer lives on the stack. Large slices are streamed directly to SHA256 precompile.
struct Sha256Stream<'a> {
    hasher: &'a mut Sha256,
    buf: [u8; 2048],
    pos: usize,
}

impl<'a> Sha256Stream<'a> {
    fn new(hasher: &'a mut Sha256) -> Self {
        Self { hasher, buf: [0; 2048], pos: 0 }
    }

    #[inline]
    fn flush(&mut self) {
        if self.pos > 0 {
            self.hasher.update(&self.buf[..self.pos]);
            self.pos = 0;
        }
    }
}

unsafe impl<'a> BufMut for Sha256Stream<'a> {
    #[inline]
    fn remaining_mut(&self) -> usize {
        usize::MAX
    }

    #[inline]
    unsafe fn advance_mut(&mut self, cnt: usize) {
        assert!(self.pos + cnt <= self.buf.len(), "advance_mut bounds violation");
        self.pos += cnt;
        if self.pos == self.buf.len() {
            self.flush();
        }
    }

    #[inline]
    fn chunk_mut(&mut self) -> &mut UninitSlice {
        if self.pos == self.buf.len() {
            self.flush();
        }
        let remaining = &mut self.buf[self.pos..];
        unsafe { &mut *(remaining as *mut [u8] as *mut UninitSlice) }
    }

    #[inline]
    fn put_slice(&mut self, mut src: &[u8]) {
        if src.len() >= self.buf.len() {
            self.flush();
            self.hasher.update(src);
            return;
        }
        while !src.is_empty() {
            if self.pos == self.buf.len() {
                self.flush();
            }
            let space = self.buf.len() - self.pos;
            let take = space.min(src.len());
            self.buf[self.pos..self.pos + take].copy_from_slice(&src[..take]);
            self.pos += take;
            src = &src[take..];
        }
    }

    #[inline]
    fn put_u8(&mut self, n: u8) {
        if self.pos == self.buf.len() {
            self.flush();
        }
        self.buf[self.pos] = n;
        self.pos += 1;
    }
}

impl<'a> Drop for Sha256Stream<'a> {
    fn drop(&mut self) {
        self.flush();
    }
}

pub fn main() {
    // 1. Read and deserialize inputs using read_vec
    let (executor_input, blob_input) = profile_report!(DESERIALZE_INPUTS, {
        let exec_bytes = sp1_zkvm::io::read_vec();
        let exec_input = bincode::deserialize::<EthClientExecutorInput>(&exec_bytes).unwrap();

        let blob_bytes = sp1_zkvm::io::read_vec();
        let blob_input = bincode::deserialize::<BlobVerificationInput>(&blob_bytes).unwrap();

        (exec_input, blob_input)
    });

    let block_number = executor_input.current_block.header.number;

    // Load pre-compiled Trusted Setup from the crate's internal binary storage (Zero-Copy)
    let kzg_settings =
        KzgSettings::load_trusted_setup_file().expect("Failed to load embedded trusted setup");

    // 2. Fast validation of canonical padding for all fields (Zero-Alloc)
    validate_canonical_padding(&blob_input.blobs);

    // 3. Decanonicalize + brotli decompress + hash blob tx_data
    //    Compute blob_tx_data_hash early and drop decompressed BEFORE STF execution
    //    to avoid holding ~MBs of decompressed payload during the memory-heavy executor step.
    let blob_tx_data_hash = {
        let decompressed = decode_blob_payload(&blob_input.blobs);
        let (tx_data_offset, tx_data_len) = parse_da_header(&decompressed, block_number);
        B256::from_slice(&Sha256::digest(&decompressed[tx_data_offset..tx_data_offset + tx_data_len]))
        // decompressed dropped here
    };

    // 4. Execution & Zero-Alloc Streaming Hashing of transactions
    let tx_data_hash_exec = {
        let mut hasher = Sha256::new();
        {
            let mut stream = Sha256Stream::new(&mut hasher);
            for tx in executor_input.current_block.body.transactions.iter() {
                tx.encode_2718(&mut stream);
            }
        }
        B256::from_slice(&hasher.finalize())
    };

    let executor = EthClientExecutor::eth(
        Arc::new((&executor_input.genesis).try_into().expect("Invalid genesis")),
        executor_input.custom_beneficiary,
    );
    let (header, events_hash) = executor.execute(executor_input).expect("STF execution failed");

    // 5. KZG Verification (Using pre-computed host witnesses)
    let mut versioned_hashes = Vec::with_capacity(blob_input.commitments.len());
    for i in 0..blob_input.blobs.len() {
        let blob = Blob::from_slice(&blob_input.blobs[i]).expect("Invalid blob slice");
        let commitment =
            Bytes48::from_slice(&blob_input.commitments[i]).expect("Invalid commitment slice");
        let proof = Bytes48::from_slice(&blob_input.proofs[i]).expect("Invalid proof slice");

        let is_valid = KzgProof::verify_blob_kzg_proof(blob, &commitment, &proof, &kzg_settings)
            .expect("KZG internal error");

        assert!(is_valid, "KZG verification failed at blob index {i}");

        let hash = Sha256::digest(commitment.as_slice());
        let mut vh = B256::default();
        vh.0[0] = 0x01;
        vh.0[1..].copy_from_slice(&hash[1..]);
        versioned_hashes.push(vh);
    }

    // 6. Compare blob tx_data hash with execution tx_data hash
    assert_eq!(tx_data_hash_exec, blob_tx_data_hash, "Data integrity mismatch: EXEC vs DA");

    // 7. Commit results for L1 Verifier
    let block_hash = header.hash_slow();
    sp1_zkvm::io::commit(&header.parent_hash);
    sp1_zkvm::io::commit(&block_hash);
    sp1_zkvm::io::commit(&events_hash.withdrawal_hash);
    sp1_zkvm::io::commit(&events_hash.deposit_hash);
    sp1_zkvm::io::commit(&versioned_hashes);
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::BufMut;
    use sha2::{Digest, Sha256};

    // --- Test Utilities ---

    /// Generates a mock DA blob adhering to the canonical KZG padding rules.
    /// The first byte of every 32-byte field is guaranteed to be 0x00.
    /// The remaining 31 bytes are filled with a sequential wrapping counter.
    fn generate_mock_blob(start_val: u8) -> Vec<u8> {
        let mut blob = vec![0u8; FIELDS_PER_BLOB * FIELD_SIZE];
        let mut counter = start_val;

        for f_idx in 0..FIELDS_PER_BLOB {
            let start = f_idx * FIELD_SIZE;
            // Enforce KZG canonical padding
            blob[start] = 0x00;

            for byte_idx in 1..FIELD_SIZE {
                blob[start + byte_idx] = counter;
                counter = counter.wrapping_add(1);
            }
        }
        blob
    }

    // --- validate_canonical_padding Tests ---

    #[test]
    fn test_canonical_padding_success() {
        let blobs = vec![generate_mock_blob(1), generate_mock_blob(50)];
        validate_canonical_padding(&blobs);
    }

    #[test]
    #[should_panic(expected = "Non-canonical padding at blob 1 field 5")]
    fn test_canonical_padding_failure() {
        let mut blobs = vec![generate_mock_blob(1), generate_mock_blob(50)];

        // Corrupt the canonical padding in the second blob, 6th field
        let corrupted_index = 5 * FIELD_SIZE;
        blobs[1][corrupted_index] = 0x01;

        validate_canonical_padding(&blobs);
    }

    // --- decanonicalize Tests ---

    #[test]
    fn test_decanonicalize_extracts_raw_bytes() {
        let mut blob = vec![0u8; FIELDS_PER_BLOB * FIELD_SIZE];
        for f in 0..FIELDS_PER_BLOB {
            blob[f * FIELD_SIZE] = 0x00;
            for b in 0..BYTES_PER_FIELD {
                blob[f * FIELD_SIZE + 1 + b] = ((f * BYTES_PER_FIELD + b) % 256) as u8;
            }
        }
        let raw = decanonicalize(&blob);
        assert_eq!(raw.len(), MAX_RAW_BYTES_PER_BLOB);
        assert_eq!(raw[0], 0);
        assert_eq!(raw[1], 1);
        assert_eq!(raw[31], 31);
    }

    #[test]
    #[should_panic(expected = "non-canonical field element")]
    fn test_decanonicalize_rejects_non_canonical() {
        let mut blob = vec![0u8; FIELDS_PER_BLOB * FIELD_SIZE];
        blob[0] = 0x01;
        decanonicalize(&blob);
    }

    // --- decode_blob_payload + parse_da_header Tests ---

    fn build_test_blobs(from_block: u64, tx_data_per_block: &[Vec<u8>]) -> Vec<Vec<u8>> {
        rsp_blob_builder::build_blobs_from_blocks(from_block, tx_data_per_block)
            .expect("build_blobs_from_blocks failed")
            .into_iter()
            .map(|b| b.blob)
            .collect()
    }

    #[test]
    fn test_decode_and_parse_single_block() {
        let tx_data = vec![0xAA; 500];
        let blobs = build_test_blobs(100, &[tx_data.clone()]);
        let decompressed = decode_blob_payload(&blobs);
        let (offset, len) = parse_da_header(&decompressed, 100);
        assert_eq!(len, 500);
        assert_eq!(&decompressed[offset..offset + len], tx_data.as_slice());
    }

    #[test]
    fn test_decode_and_parse_multi_block() {
        let blocks = vec![vec![0x01; 100], vec![0x02; 200], vec![0x03; 300]];
        let blobs = build_test_blobs(10, &blocks);
        let decompressed = decode_blob_payload(&blobs);

        let (off1, len1) = parse_da_header(&decompressed, 10);
        assert_eq!(len1, 100);
        assert_eq!(&decompressed[off1..off1 + len1], vec![0x01; 100].as_slice());

        let (off2, len2) = parse_da_header(&decompressed, 11);
        assert_eq!(len2, 200);
        assert_eq!(&decompressed[off2..off2 + len2], vec![0x02; 200].as_slice());

        let (off3, len3) = parse_da_header(&decompressed, 12);
        assert_eq!(len3, 300);
        assert_eq!(&decompressed[off3..off3 + len3], vec![0x03; 300].as_slice());
    }

    #[test]
    #[should_panic(expected = "Block number out of DA range")]
    fn test_parse_da_header_out_of_range() {
        let blobs = build_test_blobs(100, &[vec![0xAA; 50]]);
        let decompressed = decode_blob_payload(&blobs);
        parse_da_header(&decompressed, 99);
    }

    // --- Sha256Stream (BufMut) Tests ---

    #[test]
    fn test_sha256_stream_put_u8_triggers_flush() {
        let mut hasher = Sha256::new();
        let mut reference_hasher = Sha256::new();
        {
            let mut stream = Sha256Stream::new(&mut hasher);
            for i in 0..3000u16 {
                let val = (i % 256) as u8;
                stream.put_u8(val);
                reference_hasher.update(&[val]);
            }
        }
        assert_eq!(hasher.finalize(), reference_hasher.finalize(), "Stream hash mismatch");
    }

    #[test]
    fn test_sha256_stream_put_slice_buffered() {
        let mut hasher = Sha256::new();
        let mut reference_hasher = Sha256::new();
        let payload = b"eth_da_blob_verification_test_payload";
        {
            let mut stream = Sha256Stream::new(&mut hasher);
            stream.put_slice(payload);
            stream.put_slice(payload);
        }
        reference_hasher.update(payload);
        reference_hasher.update(payload);
        assert_eq!(hasher.finalize(), reference_hasher.finalize(), "Stream hash mismatch");
    }

    #[test]
    fn test_sha256_stream_put_slice_bypasses_buffer() {
        let mut hasher = Sha256::new();
        let mut reference_hasher = Sha256::new();
        let payload = vec![0xAB; 5000];
        {
            let mut stream = Sha256Stream::new(&mut hasher);
            stream.put_slice(&payload);
        }
        reference_hasher.update(&payload);
        assert_eq!(hasher.finalize(), reference_hasher.finalize(), "Stream hash mismatch");
    }

    #[test]
    fn test_sha256_stream_mixed_io_operations() {
        let mut hasher = Sha256::new();
        let mut reference_hasher = Sha256::new();
        let chunk1 = vec![0x01; 1000];
        let chunk2 = vec![0x02; 3000];
        {
            let mut stream = Sha256Stream::new(&mut hasher);
            stream.put_slice(&chunk1);
            stream.put_u8(0xFF);
            stream.put_slice(&chunk2);
            stream.put_u8(0xEE);
        }
        reference_hasher.update(&chunk1);
        reference_hasher.update(&[0xFF]);
        reference_hasher.update(&chunk2);
        reference_hasher.update(&[0xEE]);
        assert_eq!(hasher.finalize(), reference_hasher.finalize(), "Stream hash mismatch");
    }

    #[test]
    fn test_sha256_stream_chunk_and_advance() {
        let mut hasher = Sha256::new();
        let mut reference_hasher = Sha256::new();
        {
            let mut stream = Sha256Stream::new(&mut hasher);
            let chunk = stream.chunk_mut();
            assert!(chunk.len() >= 4, "Chunk should have enough space");

            unsafe {
                let ptr = chunk.as_mut_ptr();
                ptr.write(0xDE);
                ptr.add(1).write(0xAD);
                ptr.add(2).write(0xBE);
                ptr.add(3).write(0xEF);
                stream.advance_mut(4);
            }
            stream.put_u8(0x00);
        }
        reference_hasher.update(&[0xDE, 0xAD, 0xBE, 0xEF, 0x00]);
        assert_eq!(
            hasher.finalize(),
            reference_hasher.finalize(),
            "Stream hash mismatch after manual chunk writes"
        );
    }

    #[test]
    #[should_panic(expected = "advance_mut bounds violation")]
    fn test_sha256_stream_advance_mut_overflow() {
        let mut hasher = Sha256::new();
        let mut stream = Sha256Stream::new(&mut hasher);
        unsafe {
            stream.advance_mut(3000);
        }
    }
}
