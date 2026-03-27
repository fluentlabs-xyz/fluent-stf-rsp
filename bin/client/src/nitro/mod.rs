mod kms;
mod params;
mod vsock;

use anyhow::Context;
use hkdf::Hkdf;
pub use params::*;

use aws_nitro_enclaves_nsm_api::{
    api::{Request, Response},
    driver,
};

use k256::ecdsa::{signature::Signer, signature::Verifier, Signature, SigningKey, VerifyingKey};
use k256::SecretKey;

use alloy_eips::eip2718::Encodable2718;
use alloy_primitives::B256;
use c_kzg::{Blob, KzgSettings, BYTES_PER_BLOB};

use nitro_types::{EnclaveIncoming, EnclaveResponse, EthExecutionResponse, SubmitBatchResponse};
use rsp_client_executor::{executor::EthClientExecutor, io::EthClientExecutorInput};

use ::vsock::{VsockAddr, VsockListener, VMADDR_CID_ANY};
use serde_bytes::ByteBuf;
use sha2::{Digest, Sha256};
use sha3::Keccak256;
use std::collections::BTreeMap;
use std::sync::{Arc, LazyLock, Mutex};
use std::thread;

use crate::nitro::{kms::KmsClient, vsock::VsockChannel};

// ---------------------------------------------------------------------------
// KZG trusted setup (Ethereum ceremony)
// ---------------------------------------------------------------------------

const TRUSTED_SETUP_BYTES: &[u8] = include_bytes!("../../trusted_setup.txt");

static KZG_SETTINGS: LazyLock<KzgSettings> = LazyLock::new(|| {
    let setup_str =
        std::str::from_utf8(TRUSTED_SETUP_BYTES).expect("trusted setup is not valid UTF-8");
    KzgSettings::parse_kzg_trusted_setup(setup_str, 0).expect("failed to load KZG trusted setup")
});

// ---------------------------------------------------------------------------
// Blob canonicalization
// ---------------------------------------------------------------------------

const BYTES_PER_FIELD_ELEMENT: usize = 31;
const FIELD_ELEMENTS_PER_BLOB: usize = BYTES_PER_BLOB / 32;
const MAX_RAW_BYTES_PER_BLOB: usize = FIELD_ELEMENTS_PER_BLOB * BYTES_PER_FIELD_ELEMENT;

/// Inverse of canonicalize. Extracts raw bytes from blob field elements.
fn decanonicalize(blob: &[u8], expected_len: usize) -> anyhow::Result<Vec<u8>> {
    let mut result = Vec::with_capacity(expected_len);
    let mut offset = 0;
    while offset < blob.len() && result.len() < expected_len {
        anyhow::ensure!(blob[offset] == 0x00, "non-canonical field element at offset {offset}");
        offset += 1;
        let remaining = expected_len - result.len();
        let take = remaining.min(BYTES_PER_FIELD_ELEMENT);

        anyhow::ensure!(
            offset + take <= blob.len(),
            "blob truncated: need {} bytes at offset {}, but blob length is {}",
            take,
            offset,
            blob.len(),
        );

        result.extend_from_slice(&blob[offset..offset + take]);
        offset += BYTES_PER_FIELD_ELEMENT;
    }
    Ok(result)
}

/// Computes versioned_hash = 0x01 || SHA256(KZG_commitment)[1..]
fn blob_to_versioned_hash(blob_bytes: &[u8; BYTES_PER_BLOB]) -> anyhow::Result<B256> {
    let blob =
        Blob::from_bytes(blob_bytes).map_err(|e| anyhow::anyhow!("invalid blob bytes: {e}"))?;
    let commitment = KZG_SETTINGS
        .blob_to_kzg_commitment(&blob)
        .map_err(|e| anyhow::anyhow!("KZG commitment failed: {e}"))?;

    let hash = Sha256::digest(commitment.as_ref());

    let mut vh = B256::default();
    vh.0[0] = 0x01; // EIP-4844 version byte
    vh.0[1..].copy_from_slice(&hash[1..]);
    Ok(vh)
}

/// Computes KZG versioned hashes for all blobs.
fn compute_versioned_hashes(blobs: &[Vec<u8>]) -> anyhow::Result<Vec<B256>> {
    let mut versioned_hashes = Vec::with_capacity(blobs.len());
    for (i, blob) in blobs.iter().enumerate() {
        let arr: &[u8; BYTES_PER_BLOB] = blob
            .as_slice()
            .try_into()
            .map_err(|_| anyhow::anyhow!("blob {i} must be exactly {BYTES_PER_BLOB} bytes"))?;
        versioned_hashes.push(blob_to_versioned_hash(arr)?);
    }
    Ok(versioned_hashes)
}

// ---------------------------------------------------------------------------
// BlockStore — keeps the last MAX_ENTRIES Merkle leaves + tx_data_hashes
// ---------------------------------------------------------------------------

const MAX_ENTRIES: usize = 10_000;

/// Per-block data stored after execution.
#[derive(Clone, Copy)]
pub(crate) struct BlockEntry {
    /// keccak256(parent ‖ block ‖ withdrawal ‖ deposit)
    leaf: [u8; 32],
    /// SHA256(rlp-encoded transactions)
    tx_data_hash: B256,
}

pub(crate) struct BlockStore {
    entries: BTreeMap<u64, BlockEntry>,
}

impl BlockStore {
    pub(crate) fn new() -> Self {
        Self { entries: BTreeMap::new() }
    }

    pub(crate) fn insert(&mut self, block_number: u64, entry: BlockEntry) {
        self.entries.insert(block_number, entry);

        while self.entries.len() > MAX_ENTRIES {
            let oldest = *self.entries.keys().next().unwrap();
            self.entries.remove(&oldest);
        }
    }

    /// Returns leaves for the inclusive range [from, to].
    fn get_leaves(&self, from: u64, to: u64) -> anyhow::Result<Vec<[u8; 32]>> {
        anyhow::ensure!(from <= to, "invalid range: from ({from}) > to ({to})");

        let mut result = Vec::with_capacity((to - from + 1) as usize);
        for block in from..=to {
            let entry = self
                .entries
                .get(&block)
                .ok_or_else(|| anyhow::anyhow!("block {block} not found in store"))?;
            result.push(entry.leaf);
        }
        Ok(result)
    }

    /// Returns tx_data_hashes for the inclusive range [from, to].
    fn get_tx_data_hashes(&self, from: u64, to: u64) -> anyhow::Result<Vec<B256>> {
        anyhow::ensure!(from <= to, "invalid range: from ({from}) > to ({to})");

        let mut result = Vec::with_capacity((to - from + 1) as usize);
        for block in from..=to {
            let entry = self
                .entries
                .get(&block)
                .ok_or_else(|| anyhow::anyhow!("block {block} not found in store"))?;
            result.push(entry.tx_data_hash);
        }
        Ok(result)
    }
}

// ---------------------------------------------------------------------------
// Merkle root — compatible with Solidity _calculateMerkleRoot (keccak256)
// ---------------------------------------------------------------------------

/// keccak256(left ‖ right) — equivalent to _efficientHash in the contract.
fn keccak_pair(left: [u8; 32], right: [u8; 32]) -> [u8; 32] {
    let mut hasher = Keccak256::new();
    hasher.update(left);
    hasher.update(right);
    hasher.finalize().into()
}

/// Computes the Merkle root exactly as _calculateMerkleRoot in Solidity:
///   - pairs are hashed left-to-right
///   - an odd trailing element is hashed with itself
fn calculate_merkle_root(leaves: &[[u8; 32]]) -> anyhow::Result<[u8; 32]> {
    anyhow::ensure!(!leaves.is_empty(), "no leaves provided");

    let mut layer: Vec<[u8; 32]> = leaves.to_vec();

    while layer.len() > 1 {
        let mut next = Vec::with_capacity((layer.len() + 1) / 2);

        for i in 0..layer.len() / 2 {
            next.push(keccak_pair(layer[i * 2], layer[i * 2 + 1]));
        }

        if layer.len() % 2 == 1 {
            let last = *layer.last().unwrap();
            next.push(keccak_pair(last, last));
        }

        layer = next;
    }

    Ok(layer[0])
}

/// Computes a Merkle leaf matching the Solidity contract:
/// keccak256(abi.encodePacked(parent, block, withdrawal, deposit))
fn compute_leaf(
    parent_hash: &[u8],
    block_hash: &[u8],
    withdrawal_hash: &[u8],
    deposit_hash: &[u8],
) -> [u8; 32] {
    let mut hasher = Keccak256::new();
    hasher.update(parent_hash);
    hasher.update(block_hash);
    hasher.update(withdrawal_hash);
    hasher.update(deposit_hash);
    hasher.finalize().into()
}

// ---------------------------------------------------------------------------
// Signature verification for EthExecutionResponse
// ---------------------------------------------------------------------------

/// Verifies that an EthExecutionResponse was signed by this enclave.
///
/// Mirrors the signing logic of `execute_block` which includes tx_data_hash
/// in the hash. Only used by `handle_submit_batch_from_responses`.
fn verify_response(
    resp: &EthExecutionResponse,
    verifying_key: &VerifyingKey,
) -> anyhow::Result<()> {
    let mut hasher = Sha256::new();
    hasher.update(resp.parent_hash.as_slice());
    hasher.update(resp.block_hash.as_slice());
    hasher.update(resp.withdrawal_hash.as_slice());
    hasher.update(resp.deposit_hash.as_slice());
    hasher.update(resp.tx_data_hash.as_slice());
    let result_hash = hasher.finalize();

    anyhow::ensure!(result_hash.as_slice() == resp.result_hash.as_slice(), "result_hash mismatch");

    let signature = Signature::from_slice(&resp.signature).context("invalid signature encoding")?;

    verifying_key.verify(&result_hash, &signature).context("signature verification failed")?;

    Ok(())
}

/// Computes a leaf from an EthExecutionResponse.
fn leaf_from_response(r: &EthExecutionResponse) -> [u8; 32] {
    compute_leaf(
        r.parent_hash.as_slice(),
        r.block_hash.as_slice(),
        r.withdrawal_hash.as_slice(),
        r.deposit_hash.as_slice(),
    )
}

// ---------------------------------------------------------------------------
// Multi-blob decoding with embedded header
// ---------------------------------------------------------------------------
//
// Blob payload format (after decanonicalization & concatenation across blobs):
//
//   ┌────────────┬────────────┬──────────────┬───────────────────────────┬──────────────┐
//   │ from_block │  to_block  │  num_blocks  │  tx_len[0] … tx_len[N-1] │  tx_data ... │
//   │  8 bytes   │  8 bytes   │   4 bytes    │       N × 4 bytes         │ Σ(tx_len) B  │
//   │  u64 BE    │  u64 BE    │   u32 BE     │       u32 BE each         │              │
//   └────────────┴────────────┴──────────────┴───────────────────────────┴──────────────┘
//
// The payload may span multiple sequential blobs. Each blob is
// individually canonicalized into BLS12-381 field elements.
// ---------------------------------------------------------------------------

/// Parsed blob header.
struct BlobHeader {
    from_block: u64,
    to_block: u64,
    block_boundaries: Vec<usize>,
}

impl BlobHeader {
    /// Size of the fixed + variable header in bytes.
    fn size(&self) -> usize {
        8 + 8 + 4 + self.block_boundaries.len() * 4
    }
}

/// Decanonicalize all blobs, concatenate, and parse the embedded header.
fn decode_blob_payload(blobs: &[Vec<u8>]) -> anyhow::Result<(BlobHeader, Vec<u8>)> {
    anyhow::ensure!(!blobs.is_empty(), "no blobs provided");

    let mut all_raw = Vec::with_capacity(blobs.len() * MAX_RAW_BYTES_PER_BLOB);

    for (i, blob) in blobs.iter().enumerate() {
        let arr: &[u8; BYTES_PER_BLOB] = blob
            .as_slice()
            .try_into()
            .map_err(|_| anyhow::anyhow!("blob {i} must be exactly {BYTES_PER_BLOB} bytes"))?;
        let raw = decanonicalize(arr, MAX_RAW_BYTES_PER_BLOB)?;
        all_raw.extend_from_slice(&raw);
    }

    const FIXED_HEADER: usize = 8 + 8 + 4;
    anyhow::ensure!(all_raw.len() >= FIXED_HEADER, "blob payload too short for header");

    let from_block = u64::from_be_bytes(all_raw[0..8].try_into().unwrap());
    let to_block = u64::from_be_bytes(all_raw[8..16].try_into().unwrap());
    let num_blocks = u32::from_be_bytes(all_raw[16..20].try_into().unwrap()) as usize;

    anyhow::ensure!(
        from_block <= to_block,
        "invalid block range: from ({from_block}) > to ({to_block})"
    );
    anyhow::ensure!(
        (to_block - from_block + 1) as usize == num_blocks,
        "block range [{from_block}, {to_block}] doesn't match num_blocks ({num_blocks})"
    );

    let full_header_size = FIXED_HEADER + num_blocks * 4;
    anyhow::ensure!(
        all_raw.len() >= full_header_size,
        "blob payload too short for {num_blocks} block boundaries"
    );

    let mut block_boundaries = Vec::with_capacity(num_blocks);
    for i in 0..num_blocks {
        let off = FIXED_HEADER + i * 4;
        let len = u32::from_be_bytes(all_raw[off..off + 4].try_into().unwrap()) as usize;
        block_boundaries.push(len);
    }

    Ok((BlobHeader { from_block, to_block, block_boundaries }, all_raw))
}

/// Extracts the tx_data chunk for a specific block from decoded blob payload.
fn extract_block_tx_data<'a>(
    header: &BlobHeader,
    all_raw: &'a [u8],
    block_number: u64,
) -> anyhow::Result<&'a [u8]> {
    let idx = block_number.checked_sub(header.from_block).ok_or_else(|| {
        anyhow::anyhow!("block {block_number} before blob range (from={})", header.from_block)
    })? as usize;

    anyhow::ensure!(
        idx < header.block_boundaries.len(),
        "block {block_number} outside blob range [{}, {}]",
        header.from_block,
        header.to_block,
    );

    let data_offset = header.size() + header.block_boundaries[..idx].iter().sum::<usize>();
    let chunk_len = header.block_boundaries[idx];

    anyhow::ensure!(
        data_offset + chunk_len <= all_raw.len(),
        "block {block_number} tx_data exceeds blob payload"
    );

    Ok(&all_raw[data_offset..data_offset + chunk_len])
}

// ---------------------------------------------------------------------------
// Blob verification
// ---------------------------------------------------------------------------

/// Verifies all blobs against known tx_data_hashes, returns versioned hashes.
///
/// `tx_data_hashes` come from trusted sources: either the in-memory BlockStore
/// (for SubmitBatch) or signed EthExecutionResponses (for SubmitBatchFromResponses).
fn verify_blobs(blobs: &[Vec<u8>], tx_data_hashes: &[B256]) -> anyhow::Result<Vec<B256>> {
    let (header, all_raw) = decode_blob_payload(blobs)?;

    let num_blocks = header.block_boundaries.len();
    anyhow::ensure!(
        num_blocks == tx_data_hashes.len(),
        "header declares {num_blocks} blocks but {} tx_data_hashes provided",
        tx_data_hashes.len(),
    );

    for block_num in header.from_block..=header.to_block {
        let chunk = extract_block_tx_data(&header, &all_raw, block_num)?;
        let hash = B256::from_slice(&Sha256::digest(chunk));
        let idx = (block_num - header.from_block) as usize;
        anyhow::ensure!(
            hash == tx_data_hashes[idx],
            "tx_data_hash mismatch at block {block_num}: expected {}, got {hash}",
            tx_data_hashes[idx],
        );
    }

    compute_versioned_hashes(blobs)
}

// ---------------------------------------------------------------------------
// Batch signing
// ---------------------------------------------------------------------------

/// Signs batch_root and versioned_hashes into a SubmitBatchResponse.
fn sign_batch(
    batch_root: [u8; 32],
    versioned_hashes: Vec<B256>,
    signing_key: &SigningKey,
) -> SubmitBatchResponse {
    let mut hasher = Sha256::new();
    hasher.update(batch_root);
    for vh in &versioned_hashes {
        hasher.update(vh.as_slice());
    }
    let signing_payload = hasher.finalize();
    let signature: Signature = signing_key.sign(&signing_payload);

    SubmitBatchResponse {
        batch_root: batch_root.to_vec(),
        versioned_hashes,
        signature: signature.to_vec(),
    }
}

// ---------------------------------------------------------------------------
// SubmitBatch — tx_data_hashes from in-memory BlockStore
// ---------------------------------------------------------------------------

pub(crate) fn handle_submit_batch(
    from: u64,
    to: u64,
    blobs: &[Vec<u8>],
    signing_key: &SigningKey,
    store: &BlockStore,
) -> anyhow::Result<SubmitBatchResponse> {
    let leaves = store.get_leaves(from, to)?;
    let tx_data_hashes = store.get_tx_data_hashes(from, to)?;

    let batch_root = calculate_merkle_root(&leaves)?;
    let versioned_hashes = verify_blobs(blobs, &tx_data_hashes)?;
    Ok(sign_batch(batch_root, versioned_hashes, signing_key))
}

// ---------------------------------------------------------------------------
// SubmitBatchFromResponses — tx_data_hashes from signed responses
// ---------------------------------------------------------------------------

pub(crate) fn handle_submit_batch_from_responses(
    responses: &[EthExecutionResponse],
    blobs: &[Vec<u8>],
    signing_key: &SigningKey,
) -> anyhow::Result<SubmitBatchResponse> {
    let verifying_key = *signing_key.verifying_key();

    let mut leaves = Vec::with_capacity(responses.len());
    let mut tx_data_hashes = Vec::with_capacity(responses.len());

    for (i, resp) in responses.iter().enumerate() {
        // tx_data_hash is included in the signature for normal execute_block
        // responses, so we pass it as extra_hash_data to verify authenticity.
        verify_response(resp, &verifying_key).with_context(|| {
            format!("response #{i} (block {}) verification failed", resp.block_number)
        })?;
        leaves.push(leaf_from_response(resp));
        tx_data_hashes.push(resp.tx_data_hash);
    }

    let batch_root = calculate_merkle_root(&leaves)?;
    let versioned_hashes = verify_blobs(blobs, &tx_data_hashes)?;
    Ok(sign_batch(batch_root, versioned_hashes, signing_key))
}

// ---------------------------------------------------------------------------
// Block execution — shared core
// ---------------------------------------------------------------------------

struct ExecutionResult {
    block_number: u64,
    parent_hash: B256,
    block_hash: B256,
    withdrawal_hash: B256,
    deposit_hash: B256,
    tx_data_hash: B256,
}

fn run_block(
    input: EthClientExecutorInput,
    block_store: &Mutex<BlockStore>,
) -> anyhow::Result<ExecutionResult> {
    let tx_data_hash = {
        let tx_data: Vec<u8> =
            input.current_block.body.transactions.iter().flat_map(|tx| tx.encoded_2718()).collect();
        B256::from_slice(&Sha256::digest(&tx_data))
    };

    let genesis = (&input.genesis)
        .try_into()
        .map_err(|_| anyhow::anyhow!("Invalid genesis configuration"))?;
    let executor = EthClientExecutor::eth(Arc::new(genesis), input.custom_beneficiary);
    let (header, events_hash) =
        executor.execute(input).map_err(|e| anyhow::anyhow!("Block execution failed: {e:?}"))?;

    let block_hash = header.hash_slow();
    let parent_hash = header.parent_hash;
    let block_number = header.number;

    let leaf = compute_leaf(
        parent_hash.as_slice(),
        block_hash.as_slice(),
        events_hash.withdrawal_hash.as_slice(),
        events_hash.deposit_hash.as_slice(),
    );

    block_store
        .lock()
        .map_err(|e| anyhow::anyhow!("block_store mutex poisoned: {e}"))?
        .insert(block_number, BlockEntry { leaf, tx_data_hash });

    Ok(ExecutionResult {
        block_number,
        parent_hash,
        block_hash,
        withdrawal_hash: events_hash.withdrawal_hash,
        deposit_hash: events_hash.deposit_hash,
        tx_data_hash,
    })
}

fn sign_execution(
    result: &ExecutionResult,
    extra_hash_data: &[&[u8]],
    signing_key: &SigningKey,
) -> EthExecutionResponse {
    let mut hasher = Sha256::new();
    hasher.update(result.parent_hash.as_slice());
    hasher.update(result.block_hash.as_slice());
    hasher.update(result.withdrawal_hash.as_slice());
    hasher.update(result.deposit_hash.as_slice());
    for data in extra_hash_data {
        hasher.update(data);
    }
    let result_hash = hasher.finalize();

    let signature: Signature = signing_key.sign(&result_hash);

    EthExecutionResponse {
        block_number: result.block_number,
        parent_hash: result.parent_hash,
        block_hash: result.block_hash,
        withdrawal_hash: result.withdrawal_hash,
        deposit_hash: result.deposit_hash,
        tx_data_hash: result.tx_data_hash,
        result_hash: result_hash.to_vec(),
        signature: signature.to_vec(),
    }
}

// ---------------------------------------------------------------------------
// Phase 1: Normal block execution
//
// tx_data_hash IS included in the signature so that
// SubmitBatchFromResponses can trust it came from this enclave.
// ---------------------------------------------------------------------------

pub(crate) fn execute_block(
    input: EthClientExecutorInput,
    signing_key: &SigningKey,
    block_store: &Mutex<BlockStore>,
) -> anyhow::Result<EthExecutionResponse> {
    let result = run_block(input, block_store)?;
    // Include tx_data_hash in signature — needed for SubmitBatchFromResponses
    // to extract trusted tx_data_hashes from signed responses.
    Ok(sign_execution(&result, &[result.tx_data_hash.as_slice()], signing_key))
}

// ---------------------------------------------------------------------------
// Phase 1: Challenge block execution (with blob verification)
//
// tx_data_hash is NOT included in the signature — L1 doesn't know it
// and Nitro attestation guarantees the check was performed.
// ---------------------------------------------------------------------------

pub(crate) fn execute_block_challenge(
    input: EthClientExecutorInput,
    raw_blobs: &[Vec<u8>],
    signing_key: &SigningKey,
    block_store: &Mutex<BlockStore>,
) -> anyhow::Result<EthExecutionResponse> {
    let block_number = input.current_block.header.number;

    // Decode blobs and verify tx_data matches
    let (header, all_raw) = decode_blob_payload(raw_blobs)?;
    let chunk = extract_block_tx_data(&header, &all_raw, block_number)?;
    let blob_tx_data_hash = B256::from_slice(&Sha256::digest(chunk));

    // Execute block
    let result = run_block(input, block_store)?;

    anyhow::ensure!(
        result.tx_data_hash == blob_tx_data_hash,
        "tx_data mismatch for block {}: execution={}, blob={}",
        result.block_number,
        result.tx_data_hash,
        blob_tx_data_hash
    );

    // KZG versioned hashes go into the signature; tx_data_hash does NOT
    let versioned_hashes = compute_versioned_hashes(raw_blobs)?;
    let vh_slices: Vec<&[u8]> = versioned_hashes.iter().map(|vh| vh.as_slice()).collect();

    Ok(sign_execution(&result, &vh_slices, signing_key))
}

// ---------------------------------------------------------------------------
// Enclave identity & runtime
// ---------------------------------------------------------------------------

struct EnclaveIdentity {
    signing_key: SigningKey,
    public_key: Vec<u8>,
    attestation: Vec<u8>,
}

struct Enclave {
    listener: VsockListener,
}

fn send_response(channel: &mut VsockChannel, resp: &EnclaveResponse) {
    if let Err(e) = channel.send_bincode(resp) {
        eprintln!("Failed to send response to host: {e:#}");
    }
}

impl Enclave {
    fn init() -> anyhow::Result<Self> {
        let listener = VsockListener::bind(&VsockAddr::new(VMADDR_CID_ANY, VSOCK_PORT))
            .context("Failed to bind VSOCK listener")?;
        Ok(Self { listener })
    }

    fn run(self) -> ! {
        println!("Enclave listening, waiting for messages…");

        let mut identity: Option<Arc<EnclaveIdentity>> = None;
        let block_store = Arc::new(Mutex::new(BlockStore::new()));

        loop {
            let mut channel = match VsockChannel::accept(&self.listener) {
                Ok(ch) => ch,
                Err(e) => {
                    eprintln!("Failed to accept connection: {e:#}");
                    continue;
                }
            };

            let raw = match channel.receive() {
                Ok(data) => data,
                Err(e) => {
                    eprintln!("Failed to receive message: {e:#}");
                    continue;
                }
            };

            let msg: EnclaveIncoming = match bincode::deserialize(&raw) {
                Ok(m) => m,
                Err(e) => {
                    let resp = EnclaveResponse::Error(format!("Failed to deserialize: {e}"));
                    send_response(&mut channel, &resp);
                    continue;
                }
            };

            match msg {
                // ── Handshake ────────────────────────────────────
                EnclaveIncoming::Handshake { credentials } => {
                    if let Some(ref id) = identity {
                        let resp = EnclaveResponse::AlreadyInitialized {
                            public_key: id.public_key.clone(),
                            attestation: id.attestation.clone(),
                        };
                        send_response(&mut channel, &resp);
                        println!("Handshake repeated — returned existing key");
                    } else {
                        match generate_key(credentials) {
                            Ok(id) => {
                                let resp = EnclaveResponse::KeyGenerated {
                                    public_key: id.public_key.clone(),
                                    attestation: id.attestation.clone(),
                                };
                                send_response(&mut channel, &resp);
                                println!("Key generated successfully");
                                identity = Some(Arc::new(id));
                            }
                            Err(e) => {
                                let resp = EnclaveResponse::Error(format!("{e:#}"));
                                send_response(&mut channel, &resp);
                            }
                        }
                    }
                }

                // ── Phase 1: Normal block execution ──────────────
                EnclaveIncoming::ExecuteBlock { input } => {
                    let Some(ref id) = identity else {
                        let resp = EnclaveResponse::NotInitialized;
                        send_response(&mut channel, &resp);
                        continue;
                    };

                    let id = Arc::clone(id);
                    let store = Arc::clone(&block_store);

                    thread::spawn(move || {
                        let result = execute_block(input, &id.signing_key, &store);
                        let resp = match result {
                            Ok(output) => EnclaveResponse::ExecutionResult(output),
                            Err(e) => EnclaveResponse::Error(format!("{e:#}")),
                        };
                        if let Err(e) = channel.send_bincode(&resp) {
                            eprintln!("Failed to send ExecuteBlock response: {e:#}");
                        }
                    });
                }

                // ── Phase 1: Challenge block execution ───────────
                EnclaveIncoming::ExecuteBlockChallenge { input, raw_blobs } => {
                    let Some(ref id) = identity else {
                        let resp = EnclaveResponse::NotInitialized;
                        send_response(&mut channel, &resp);
                        continue;
                    };

                    let id = Arc::clone(id);
                    let store = Arc::clone(&block_store);

                    thread::spawn(move || {
                        let result =
                            execute_block_challenge(input, &raw_blobs, &id.signing_key, &store);
                        let resp = match result {
                            Ok(output) => EnclaveResponse::ExecutionResult(output),
                            Err(e) => EnclaveResponse::Error(format!("{e:#}")),
                        };
                        if let Err(e) = channel.send_bincode(&resp) {
                            eprintln!("Failed to send ExecuteBlockChallenge response: {e:#}");
                        }
                    });
                }

                // ── SubmitBatch: tx_data_hashes from in-memory store ──
                EnclaveIncoming::SubmitBatch { from, to, blobs } => {
                    let Some(ref id) = identity else {
                        let resp = EnclaveResponse::NotInitialized;
                        send_response(&mut channel, &resp);
                        continue;
                    };

                    let resp = match block_store.lock() {
                        Ok(store) => {
                            match handle_submit_batch(from, to, &blobs, &id.signing_key, &store) {
                                Ok(result) => EnclaveResponse::SubmitBatchResult(result),
                                Err(e) => EnclaveResponse::Error(format!("{e:#}")),
                            }
                        }
                        Err(e) => {
                            EnclaveResponse::Error(format!("block_store mutex poisoned: {e}"))
                        }
                    };
                    send_response(&mut channel, &resp);
                }

                // ── SubmitBatchFromResponses: tx_data_hashes from signed responses ──
                EnclaveIncoming::SubmitBatchFromResponses { responses, blobs } => {
                    let Some(ref id) = identity else {
                        let resp = EnclaveResponse::NotInitialized;
                        send_response(&mut channel, &resp);
                        continue;
                    };

                    let resp = match handle_submit_batch_from_responses(
                        &responses,
                        &blobs,
                        &id.signing_key,
                    ) {
                        Ok(result) => EnclaveResponse::SubmitBatchResult(result),
                        Err(e) => EnclaveResponse::Error(format!("{e:#}")),
                    };
                    send_response(&mut channel, &resp);
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Key generation
// ---------------------------------------------------------------------------

fn generate_key(credentials: nitro_types::AwsCredentials) -> anyhow::Result<EnclaveIdentity> {
    let kms = KmsClient::new(credentials);

    let kms_entropy = kms.generate_random().context("KMS GenerateRandom failed")?;
    let nsm_entropy = get_nsm_entropy().context("Failed to get NSM entropy")?;

    let key_bytes = derive_valid_ecdsa_key(&kms_entropy, &nsm_entropy)?;
    let signing_key = signing_key_from_bytes(&key_bytes)?;
    let public_key = encode_public_key(&signing_key);
    let attestation = create_attestation(&public_key)?;

    Ok(EnclaveIdentity { signing_key, public_key, attestation })
}

// ---------------------------------------------------------------------------
// Pure helper functions
// ---------------------------------------------------------------------------

fn signing_key_from_bytes(bytes: &[u8]) -> anyhow::Result<SigningKey> {
    let secret = SecretKey::from_bytes(bytes.into()).context("Invalid secp256k1 key bytes")?;
    Ok(SigningKey::from(secret))
}

fn encode_public_key(key: &SigningKey) -> Vec<u8> {
    key.verifying_key().to_encoded_point(false).as_bytes().to_vec()
}

fn get_nsm_entropy() -> anyhow::Result<Vec<u8>> {
    let fd = driver::nsm_init();
    let response = driver::nsm_process_request(fd, Request::GetRandom);
    driver::nsm_exit(fd);
    match response {
        Response::GetRandom { random } => Ok(random),
        _ => Err(anyhow::anyhow!("NSM GetRandom returned unexpected response")),
    }
}

fn create_attestation(public_key: &[u8]) -> anyhow::Result<Vec<u8>> {
    let fd = driver::nsm_init();
    let response = driver::nsm_process_request(
        fd,
        Request::Attestation {
            public_key: None,
            user_data: Some(ByteBuf::from(public_key.to_vec())),
            nonce: None,
        },
    );
    driver::nsm_exit(fd);
    match response {
        Response::Attestation { document } => Ok(document),
        _ => Err(anyhow::anyhow!("NSM Attestation failed")),
    }
}

fn derive_valid_ecdsa_key(data_key: &[u8], r_local: &[u8]) -> anyhow::Result<[u8; 32]> {
    let (_, hk) = Hkdf::<Sha256>::extract(Some(r_local), data_key);
    for counter in 0..=100u32 {
        let mut candidate = [0u8; 32];
        let info = format!("enclave-signing-key-v1-{counter}");
        hk.expand(info.as_bytes(), &mut candidate)
            .map_err(|_| anyhow::anyhow!("HKDF expansion failed"))?;
        if SecretKey::from_slice(&candidate).is_ok() {
            return Ok(candidate);
        }
    }
    Err(anyhow::anyhow!("Failed to derive valid key after 100 iterations"))
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

pub fn main() -> anyhow::Result<()> {
    println!("Nitro enclave starting");
    let enclave = Enclave::init().context("Enclave initialization failed")?;
    println!("Initialization complete, entering main loop");
    enclave.run();
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn canonicalize(input: &[u8]) -> anyhow::Result<Vec<u8>> {
        anyhow::ensure!(
            input.len() <= MAX_RAW_BYTES_PER_BLOB,
            "input length {} exceeds MAX_RAW_BYTES_PER_BLOB ({})",
            input.len(),
            MAX_RAW_BYTES_PER_BLOB,
        );
        if input.is_empty() {
            return Ok(Vec::new());
        }
        let chunks = (input.len() + BYTES_PER_FIELD_ELEMENT - 1) / BYTES_PER_FIELD_ELEMENT;
        let mut result = vec![0u8; chunks * 32];
        let mut inp = 0;
        let mut out = 0;
        while inp < input.len() {
            out += 1;
            let n = BYTES_PER_FIELD_ELEMENT.min(input.len() - inp);
            result[out..out + n].copy_from_slice(&input[inp..inp + n]);
            inp += n;
            out += BYTES_PER_FIELD_ELEMENT;
        }
        Ok(result)
    }

    #[test]
    fn canonicalize_decanonicalize_roundtrip() {
        let cases: &[&[u8]] = &[b"", b"hello", &[0xFFu8; 31], &[0xAB; 62], &[0x01; 100]];
        for input in cases {
            let encoded = canonicalize(input).expect("canonicalize failed");
            if input.is_empty() {
                assert!(encoded.is_empty());
                continue;
            }
            let decoded = decanonicalize(&encoded, input.len()).expect("decanonicalize failed");
            assert_eq!(&decoded, input, "roundtrip failed for input of len {}", input.len());
        }
    }

    #[test]
    fn canonicalize_rejects_oversized_input() {
        let too_big = vec![0u8; MAX_RAW_BYTES_PER_BLOB + 1];
        assert!(canonicalize(&too_big).is_err());
    }

    #[test]
    fn decanonicalize_rejects_non_canonical() {
        let mut blob = vec![0u8; 64];
        blob[0] = 0x01;
        assert!(decanonicalize(&blob, 31).is_err());
    }

    #[test]
    fn decanonicalize_rejects_truncated_blob() {
        let blob = vec![0u8; 10];
        assert!(decanonicalize(&blob, 31).is_err());
    }

    #[test]
    fn merkle_root_single_leaf() {
        let leaf = [0xAA; 32];
        let root = calculate_merkle_root(&[leaf]).unwrap();
        assert_eq!(root, leaf);
    }

    #[test]
    fn merkle_root_two_leaves() {
        let a = [0x01; 32];
        let b = [0x02; 32];
        let root = calculate_merkle_root(&[a, b]).unwrap();
        assert_eq!(root, keccak_pair(a, b));
    }

    #[test]
    fn merkle_root_odd_leaf_duplicated() {
        let a = [0x01; 32];
        let b = [0x02; 32];
        let c = [0x03; 32];
        let root = calculate_merkle_root(&[a, b, c]).unwrap();
        let expected = keccak_pair(keccak_pair(a, b), keccak_pair(c, c));
        assert_eq!(root, expected);
    }

    #[test]
    fn merkle_root_empty_rejected() {
        assert!(calculate_merkle_root(&[]).is_err());
    }

    #[test]
    fn compute_leaf_deterministic() {
        let p = [0x01; 32];
        let b = [0x02; 32];
        let w = [0x03; 32];
        let d = [0x04; 32];
        let l1 = compute_leaf(&p, &b, &w, &d);
        let l2 = compute_leaf(&p, &b, &w, &d);
        assert_eq!(l1, l2);
        let l3 = compute_leaf(&p, &b, &w, &[0x05; 32]);
        assert_ne!(l1, l3);
    }

    #[test]
    fn block_store_eviction() {
        let mut store = BlockStore::new();
        let dummy = BlockEntry { leaf: [0u8; 32], tx_data_hash: B256::ZERO };
        for i in 0..(MAX_ENTRIES as u64 + 100) {
            store.insert(i, dummy);
        }
        assert_eq!(store.entries.len(), MAX_ENTRIES);
        assert!(store.entries.get(&0).is_none());
        assert!(store.entries.get(&99).is_none());
        assert!(store.entries.get(&100).is_some());
    }

    #[test]
    fn block_store_get_range_missing_block() {
        let mut store = BlockStore::new();
        let dummy = BlockEntry { leaf: [0x01; 32], tx_data_hash: B256::ZERO };
        store.insert(1, dummy);
        store.insert(3, dummy);
        assert!(store.get_leaves(1, 3).is_err());
        assert!(store.get_tx_data_hashes(1, 3).is_err());
    }
}
