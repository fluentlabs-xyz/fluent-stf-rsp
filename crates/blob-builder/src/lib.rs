//! Build EIP-4844 blobs from raw data with KZG commitments and proofs.
//!
//! Used by the e2e test driver to populate the fake beacon with blob sidecars
//! that the proxy can fetch via `blob::fetch_blobs_for_batch`.
//!
//! Canonical encoding (matches `bin/client/src/nitro/mod.rs::decanonicalize`):
//!   raw bytes → split into 31-byte chunks
//!   each chunk → `[0x00, chunk[0..31]]` (32 bytes, high byte is always 0x00)
//!   last chunk → zero-padded to 31 bytes before prefixing

use alloy_primitives::B256;
use c_kzg::{Blob, KzgSettings, BYTES_PER_BLOB};
use eyre::{eyre, Result};
use sha2::{Digest, Sha256};
use std::io::Cursor;
use std::sync::LazyLock;

// ---------------------------------------------------------------------------
// KZG trusted setup
// ---------------------------------------------------------------------------

const TRUSTED_SETUP_BYTES: &[u8] = include_bytes!("../../../bin/client/trusted_setup.txt");

static KZG_SETTINGS: LazyLock<KzgSettings> = LazyLock::new(|| {
    let setup_str =
        std::str::from_utf8(TRUSTED_SETUP_BYTES).expect("trusted setup is not valid UTF-8");
    KzgSettings::parse_kzg_trusted_setup(setup_str, 0).expect("failed to load KZG trusted setup")
});

// ---------------------------------------------------------------------------
// Encoding constants (must match mod.rs)
// ---------------------------------------------------------------------------

/// Usable raw bytes per field element (one byte reserved for the 0x00 high byte).
const BYTES_PER_FIELD_ELEMENT: usize = 31;
const FIELD_ELEMENTS_PER_BLOB: usize = BYTES_PER_BLOB / 32;
/// Maximum raw (uncanonicalised) bytes that fit in one blob.
pub const MAX_RAW_BYTES_PER_BLOB: usize = FIELD_ELEMENTS_PER_BLOB * BYTES_PER_FIELD_ELEMENT;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// A fully built blob with its KZG commitment, proof, and versioned hash.
#[derive(Clone, Debug)]
pub struct BuiltBlob {
    /// Canonical blob bytes (131072 bytes).
    pub blob: Vec<u8>,
    /// KZG commitment (48 bytes).
    pub commitment: Vec<u8>,
    /// KZG proof (48 bytes).
    pub proof: Vec<u8>,
    /// EIP-4844 versioned hash: `0x01 || SHA256(commitment)[1..]`.
    pub versioned_hash: B256,
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Build blobs from per-block raw transaction data.
///
/// `from_block`: block number of the first block in the batch.
/// `tx_data_per_block`: EIP-2718 encoded transactions concatenated per block.
///
/// Returns one or more `BuiltBlob`s (payload split across blobs if needed).
pub fn build_blobs_from_blocks(
    from_block: u64,
    tx_data_per_block: &[Vec<u8>],
) -> Result<Vec<BuiltBlob>> {
    let payload = encode_blob_payload(from_block, tx_data_per_block);
    let compressed = brotli_compress(&payload)?;
    if compressed.is_empty() {
        return build_blob(&[0u8]).map(|b| vec![b]);
    }
    compressed.chunks(MAX_RAW_BYTES_PER_BLOB).map(build_blob).collect()
}

/// Encode per-block transaction data into the canonical blob payload format.
///
/// Layout (all big-endian):
///   `from_block (8)` | `to_block (8)` | `num_blocks (4)`
///   | `tx_len[0] (4)` | … | `tx_len[N-1] (4)`
///   | `tx_data[0]` | … | `tx_data[N-1]`
pub fn encode_blob_payload(from_block: u64, tx_data_per_block: &[Vec<u8>]) -> Vec<u8> {
    let num_blocks = tx_data_per_block.len() as u32;
    let to_block = from_block + num_blocks as u64 - 1;

    let mut payload = Vec::new();
    payload.extend_from_slice(&from_block.to_be_bytes());
    payload.extend_from_slice(&to_block.to_be_bytes());
    payload.extend_from_slice(&num_blocks.to_be_bytes());
    for chunk in tx_data_per_block {
        payload.extend_from_slice(&(chunk.len() as u32).to_be_bytes());
    }
    for chunk in tx_data_per_block {
        payload.extend_from_slice(chunk);
    }
    payload
}

/// Build a single blob from at most `MAX_RAW_BYTES_PER_BLOB` raw bytes.
pub fn build_blob(raw: &[u8]) -> Result<BuiltBlob> {
    if raw.len() > MAX_RAW_BYTES_PER_BLOB {
        return Err(eyre!(
            "data ({} bytes) exceeds blob capacity ({MAX_RAW_BYTES_PER_BLOB})",
            raw.len()
        ));
    }

    let blob_bytes: [u8; BYTES_PER_BLOB] = canonicalize(raw).try_into().unwrap();
    let blob = Blob::new(blob_bytes);

    let commitment = KZG_SETTINGS
        .blob_to_kzg_commitment(&blob)
        .map_err(|e| eyre!("KZG commitment failed: {e}"))?;

    let commitment_bytes = commitment.to_bytes();

    let proof = KZG_SETTINGS
        .compute_blob_kzg_proof(&blob, &commitment_bytes)
        .map_err(|e| eyre!("KZG proof failed: {e}"))?;

    let versioned_hash = versioned_hash_from_commitment(commitment_bytes.as_ref());

    Ok(BuiltBlob {
        blob: blob_bytes.to_vec(),
        commitment: commitment_bytes.to_vec(),
        proof: proof.to_bytes().to_vec(),
        versioned_hash,
    })
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Brotli compress with quality=6 to match production Go sequencer.
fn brotli_compress(data: &[u8]) -> Result<Vec<u8>> {
    let mut output = Vec::new();
    let params = brotli::enc::BrotliEncoderParams { quality: 6, ..Default::default() };
    brotli::BrotliCompress(&mut Cursor::new(data), &mut output, &params)
        .map_err(|e| eyre!("brotli compression failed: {e}"))?;
    Ok(output)
}

/// Canonicalise `raw` bytes into a full `BYTES_PER_BLOB`-length buffer.
///
/// Each 32-byte field element has `0x00` as its high byte followed by 31 raw bytes.
/// This matches what `mod.rs::decanonicalize` expects.
fn canonicalize(raw: &[u8]) -> Vec<u8> {
    let mut out = vec![0u8; BYTES_PER_BLOB];
    let mut src_off = 0;
    let mut dst_off = 0;
    while src_off < raw.len() {
        // dst_off is the 0x00 high byte — already zeroed; skip it.
        dst_off += 1;
        let take = BYTES_PER_FIELD_ELEMENT.min(raw.len() - src_off);
        out[dst_off..dst_off + take].copy_from_slice(&raw[src_off..src_off + take]);
        src_off += take;
        dst_off += BYTES_PER_FIELD_ELEMENT;
    }
    out
}

/// EIP-4844 versioned hash: `0x01 || SHA256(commitment)[1..]`.
fn versioned_hash_from_commitment(commitment: &[u8]) -> B256 {
    let hash = Sha256::digest(commitment);
    let mut h = B256::default();
    h[0] = 0x01;
    h[1..].copy_from_slice(&hash[1..]);
    h
}
