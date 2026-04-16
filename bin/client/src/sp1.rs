#[cfg(not(test))]
sp1_zkvm::entrypoint!(main);

use rsp_client_executor::executor::EthClientExecutor;
#[cfg(target_os = "zkvm")]
use rsp_client_executor::executor::DESERIALZE_INPUTS;
use rsp_client_executor::io::EthClientExecutorInput;
use rsp_client_executor::utils::profile_report;

use alloy_primitives::B256;
use sha2::{Digest, Sha256};
use std::sync::Arc;

use kzg_rs::{Blob, Bytes48, KzgProof, KzgSettings};

use crate::blob;
use nitro_types::BlobVerificationInput;

/// Upper bound on a bincode-serialized `EthClientExecutorInput` / `BlobVerificationInput`
/// the guest is willing to decode. Bounds memory allocation during deserialization
/// so a malicious host cannot force the zkVM to allocate unbounded buffers.
const MAX_INPUT_SIZE: u64 = 256 * 1024 * 1024;

pub fn main() {
    // 1. Read and deserialize inputs using read_vec
    let (executor_input, blob_input) = profile_report!(DESERIALZE_INPUTS, {
        use bincode::Options as _;
        let opts = bincode::DefaultOptions::new()
            .with_fixint_encoding()
            .allow_trailing_bytes()
            .with_limit(MAX_INPUT_SIZE);

        let exec_bytes = sp1_zkvm::io::read_vec();
        let exec_input =
            opts.deserialize::<EthClientExecutorInput>(&exec_bytes).unwrap();

        let blob_bytes = sp1_zkvm::io::read_vec();
        let blob_input =
            opts.deserialize::<BlobVerificationInput>(&blob_bytes).unwrap();

        (exec_input, blob_input)
    });

    // Load pre-compiled Trusted Setup from the crate's internal binary storage (Zero-Copy)
    let kzg_settings =
        KzgSettings::load_trusted_setup_file().expect("Failed to load embedded trusted setup");

    // 2. Execute STF first — the heaviest phase runs with minimal live heap.
    let executor = EthClientExecutor::eth(
        Arc::new(fluent_stf_primitives::fluent_chainspec()),
        executor_input.custom_beneficiary,
    );
    let (header, events_hash) = executor.execute(executor_input).expect("STF execution failed");
    let stf_block_hash = header.hash_slow();

    // 3. Decanonicalize + brotli-decompress the blob AFTER STF: defers
    //    decompression cost past any early STF panic and keeps the brotli-
    //    output buffer out of the hottest allocation phase.
    {
        let decompressed = blob::decode_blob_payload(&blob_input.blobs).unwrap();

        // 4. Bind blob ↔ STF via block_hash equality on the target block.
        let found = blob::iter_blocks(&decompressed)
            .any(|view| matches!(view, Ok(v) if v.block_hash == stf_block_hash));
        assert!(found, "DA/STF block_hash mismatch: target block not found in blob");
        // `decompressed` dropped here before KZG verification.
    }

    // 5. KZG Verification (Using pre-computed host witnesses)
    assert_eq!(
        blob_input.blobs.len(),
        blob_input.commitments.len(),
        "blobs / commitments length mismatch"
    );
    assert_eq!(
        blob_input.blobs.len(),
        blob_input.proofs.len(),
        "blobs / proofs length mismatch"
    );
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

    // 6. Commit results for L1 Verifier
    // Use commit_slice (raw bytes) instead of commit (bincode) so the public
    // values match the flat abi.encodePacked layout expected by
    // Rollup._proveBlockWithSp1:
    //   previousBlockHash(32) || blockHash(32) || withdrawalRoot(32)
    //   || depositRoot(32) || blobHashes[0](32) || … || blobHashes[N](32)
    sp1_zkvm::io::commit_slice(header.parent_hash.as_slice());
    sp1_zkvm::io::commit_slice(stf_block_hash.as_slice());
    sp1_zkvm::io::commit_slice(events_hash.withdrawal_hash.as_slice());
    sp1_zkvm::io::commit_slice(events_hash.deposit_hash.as_slice());
    for vh in &versioned_hashes {
        sp1_zkvm::io::commit_slice(vh.as_slice());
    }
}
