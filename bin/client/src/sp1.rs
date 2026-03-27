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

/// Utility for reading raw logical bytes into a provided buffer (stack-allocated).
/// Ensures zero heap allocations during header parsing.
///
/// # Panics
/// Panics if the requested read exceeds the available logical payload in the blobs.
pub(crate) fn read_logical(blobs: &[Vec<u8>], logical_offset: usize, buf: &mut [u8]) {
    let mut current_offset = logical_offset;
    let mut remaining = buf.len();
    let mut buf_pos = 0;

    if remaining == 0 {
        return;
    }

    for blob in blobs.iter() {
        if remaining == 0 {
            break;
        }
        if current_offset >= MAX_RAW_BYTES_PER_BLOB {
            current_offset -= MAX_RAW_BYTES_PER_BLOB;
            continue;
        }

        let mut field_idx = current_offset / BYTES_PER_FIELD;
        let mut byte_in_field = current_offset % BYTES_PER_FIELD;

        while field_idx < FIELDS_PER_BLOB && remaining > 0 {
            let available = BYTES_PER_FIELD - byte_in_field;
            let take = remaining.min(available);
            let start = field_idx * FIELD_SIZE + 1 + byte_in_field;

            buf[buf_pos..buf_pos + take].copy_from_slice(&blob[start..start + take]);

            buf_pos += take;
            remaining -= take;
            field_idx += 1;
            byte_in_field = 0;
        }
        current_offset = 0;
    }
    assert_eq!(remaining, 0, "Unexpected end of DA blob payload");
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

/// Parses the logical DA header to locate the transaction data offset and length for a specific block.
///
/// # Arguments
/// * `blobs` - The contiguous logical representation of KZG blob data.
/// * `block_number` - The target L2 block number to extract data for.
///
/// # Returns
/// A tuple containing `(tx_data_offset, tx_data_len)`.
///
/// # Panics
/// Panics if the requested `block_number` falls outside the DA batch range.
pub fn parse_da_header(blobs: &[Vec<u8>], block_number: u64) -> (usize, usize) {
    let mut fixed_header = [0u8; FIXED_HEADER_SIZE];
    read_logical(blobs, 0, &mut fixed_header);

    let from_block = u64::from_be_bytes(fixed_header[0..8].try_into().unwrap());
    let to_block = u64::from_be_bytes(fixed_header[8..16].try_into().unwrap());
    let num_blocks = u32::from_be_bytes(fixed_header[16..20].try_into().unwrap()) as usize;

    assert!(block_number >= from_block && block_number <= to_block, "Block number out of DA range");

    let target_idx = (block_number - from_block) as usize;
    let mut tx_data_offset = FIXED_HEADER_SIZE + (num_blocks * 4);
    let mut boundary_offset = FIXED_HEADER_SIZE;
    let mut buf4 = [0u8; 4];

    // Traverse lengths to compute the absolute offset for the target block
    for _ in 0..target_idx {
        read_logical(blobs, boundary_offset, &mut buf4);
        tx_data_offset += u32::from_be_bytes(buf4) as usize;
        boundary_offset += 4;
    }

    // Extract length for the target block
    read_logical(blobs, boundary_offset, &mut buf4);
    let tx_data_len = u32::from_be_bytes(buf4) as usize;

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

    // 3. DA Header Parsing (Stack-based)
    let (tx_data_offset, tx_data_len) = parse_da_header(&blob_input.blobs, block_number);

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

    // 6. Zero-Alloc Streaming Hashing of blob-extracted tx_data
    let mut hasher = Sha256::new();
    let mut remaining = tx_data_len;
    let mut current_offset = tx_data_offset;

    for blob in blob_input.blobs.iter() {
        if remaining == 0 {
            break;
        }
        if current_offset >= MAX_RAW_BYTES_PER_BLOB {
            current_offset -= MAX_RAW_BYTES_PER_BLOB;
            continue;
        }
        let mut field_idx = current_offset / BYTES_PER_FIELD;
        let mut byte_in_field = current_offset % BYTES_PER_FIELD;

        while field_idx < FIELDS_PER_BLOB && remaining > 0 {
            let take = remaining.min(BYTES_PER_FIELD - byte_in_field);
            let start = field_idx * FIELD_SIZE + 1 + byte_in_field;
            hasher.update(&blob[start..start + take]);
            remaining -= take;
            field_idx += 1;
            byte_in_field = 0;
        }
        current_offset = 0;
    }

    assert_eq!(remaining, 0, "DA payload is truncated");
    let blob_tx_data_hash = B256::from_slice(&hasher.finalize());

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

    /// Helper function to construct a mock blob with an embedded logical DA header.
    fn create_mock_header_blob(
        from_block: u64,
        to_block: u64,
        block_lengths: &[u32],
    ) -> Vec<Vec<u8>> {
        let mut header_data = Vec::new();
        header_data.extend_from_slice(&from_block.to_be_bytes());
        header_data.extend_from_slice(&to_block.to_be_bytes());

        let num_blocks = block_lengths.len() as u32;
        header_data.extend_from_slice(&num_blocks.to_be_bytes());

        for &length in block_lengths {
            header_data.extend_from_slice(&length.to_be_bytes());
        }

        let mut blob = vec![0u8; FIELDS_PER_BLOB * FIELD_SIZE];
        let mut current_byte = 0;

        // Scatter logical bytes into KZG fields, skipping the 0x00 padding byte
        for &byte in &header_data {
            let field_idx = current_byte / BYTES_PER_FIELD;
            let byte_in_field = current_byte % BYTES_PER_FIELD;
            blob[field_idx * FIELD_SIZE + 1 + byte_in_field] = byte;
            current_byte += 1;
        }

        vec![blob]
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

    // --- parse_da_header Tests ---

    #[test]
    fn test_parse_da_header_single_block() {
        let blobs = create_mock_header_blob(100, 100, &[500]);
        let (offset, length) = parse_da_header(&blobs, 100);

        // Fixed header (20) + 1 length field (4) = 24
        assert_eq!(offset, 24, "Incorrect offset for single block header");
        assert_eq!(length, 500, "Incorrect length for single block header");
    }

    #[test]
    fn test_parse_da_header_multi_block_middle_target() {
        // Block 100: len 500 | Block 101: len 600 | Block 102: len 700
        let blobs = create_mock_header_blob(100, 102, &[500, 600, 700]);
        let (offset, length) = parse_da_header(&blobs, 101);

        // Fixed header (20) + 3 length fields (12) + len of block 100 (500) = 532
        assert_eq!(offset, 532, "Incorrect offset calculation for multi-block header");
        assert_eq!(length, 600, "Failed to read the correct tx_data_len for the target block");
    }

    #[test]
    fn test_parse_da_header_multi_block_last_target() {
        let blobs = create_mock_header_blob(100, 102, &[500, 600, 700]);
        let (offset, length) = parse_da_header(&blobs, 102);

        // Fixed header (20) + 3 length fields (12) + len of block 100 (500) + len of block 101 (600) = 1132
        assert_eq!(offset, 1132, "Incorrect offset for the last block in DA batch");
        assert_eq!(length, 700, "Incorrect length for the last block in DA batch");
    }

    #[test]
    #[should_panic(expected = "Block number out of DA range")]
    fn test_parse_da_header_out_of_bounds_low() {
        let blobs = create_mock_header_blob(100, 102, &[500, 600, 700]);
        parse_da_header(&blobs, 99);
    }

    #[test]
    #[should_panic(expected = "Block number out of DA range")]
    fn test_parse_da_header_out_of_bounds_high() {
        let blobs = create_mock_header_blob(100, 102, &[500, 600, 700]);
        parse_da_header(&blobs, 103);
    }

    // --- read_logical Tests ---

    #[test]
    fn test_read_logical_single_field_extraction() {
        let blobs = vec![generate_mock_blob(1)];
        let mut buf = [0u8; 10];
        read_logical(&blobs, 0, &mut buf);
        let expected: Vec<u8> = (1..=10).collect();
        assert_eq!(
            buf,
            expected.as_slice(),
            "Failed to read sequential bytes within a single field"
        );
    }

    #[test]
    fn test_read_logical_cross_field_boundary() {
        let blobs = vec![generate_mock_blob(1)];
        let mut buf = [0u8; 40];
        read_logical(&blobs, 0, &mut buf);
        assert_eq!(buf[30], 31, "Incorrect read at the end of the first field");
        assert_eq!(buf[31], 32, "Failed to skip padding when crossing field boundary");
    }

    #[test]
    fn test_read_logical_cross_blob_boundary() {
        let blob1 = generate_mock_blob(1);
        let blob2 = generate_mock_blob(100);
        let blobs = vec![blob1, blob2];
        let mut buf = [0u8; 10];
        let offset = MAX_RAW_BYTES_PER_BLOB - 5;
        read_logical(&blobs, offset, &mut buf);
        assert_eq!(buf.len(), 10, "Buffer was not fully populated");
        assert_ne!(buf[4], buf[5], "Expected discontinuity in values crossing the blob boundary");
    }

    #[test]
    fn test_read_logical_absolute_offset() {
        let blob1 = generate_mock_blob(0);
        let blob2 = generate_mock_blob(50);
        let blobs = vec![blob1, blob2];
        let mut buf = [0u8; 5];
        read_logical(&blobs, MAX_RAW_BYTES_PER_BLOB, &mut buf);
        assert_eq!(
            buf,
            [50, 51, 52, 53, 54],
            "Failed to read correctly from an absolute offset targeting a subsequent blob"
        );
    }

    #[test]
    #[should_panic(expected = "Unexpected end of DA blob payload")]
    fn test_read_logical_out_of_bounds() {
        let blobs = vec![generate_mock_blob(1)];
        let mut buf = vec![0u8; MAX_RAW_BYTES_PER_BLOB + 1];
        read_logical(&blobs, 0, &mut buf);
    }

    #[test]
    fn test_read_logical_zero_size_buffer() {
        let blobs = vec![generate_mock_blob(1)];
        let mut buf = [0u8; 0];
        read_logical(&blobs, 0, &mut buf);
        assert_eq!(buf.len(), 0);
    }

    #[test]
    fn test_read_logical_exact_boundary() {
        let blobs = vec![generate_mock_blob(1)];
        let mut buf = vec![0u8; MAX_RAW_BYTES_PER_BLOB];
        read_logical(&blobs, 0, &mut buf);
        assert_eq!(buf.len(), MAX_RAW_BYTES_PER_BLOB);
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
