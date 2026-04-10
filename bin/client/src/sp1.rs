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

use crate::blob;
use nitro_types::BlobVerificationInput;

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

    // 2. Decanonicalize + brotli decompress + hash blob tx_data
    //    Compute blob_tx_data_hash early and drop decompressed BEFORE STF execution
    //    to avoid holding ~MBs of decompressed payload during the memory-heavy executor step.
    let blob_tx_data_hash = {
        let (header, decompressed) = blob::decode_blob_payload(&blob_input.blobs).unwrap();
        let tx_data = blob::extract_block_tx_data(&header, &decompressed, block_number).unwrap();
        B256::from_slice(&Sha256::digest(tx_data))
        // decompressed dropped here
    };

    // 3. Execution & Zero-Alloc Streaming Hashing of transactions
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
        Arc::new(fluent_stf_primitives::fluent_chainspec()),
        executor_input.custom_beneficiary,
    );
    let (header, events_hash) = executor.execute(executor_input).expect("STF execution failed");

    // 4. KZG Verification (Using pre-computed host witnesses)
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

    // 5. Compare blob tx_data hash with execution tx_data hash
    assert_eq!(tx_data_hash_exec, blob_tx_data_hash, "Data integrity mismatch: EXEC vs DA");

    // 6. Commit results for L1 Verifier
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
