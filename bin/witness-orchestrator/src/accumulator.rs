//! Batch accumulator: collects per-block execution responses and tracks L1
//! batch lifecycle events until all conditions for `/sign-batch-root` are met.
//!
//! A batch is "ready" when:
//! 1. All blocks in `[from_block, to_block]` have execution responses
//! 2. The batch has moved to Submitted on L1 (`BatchSubmitted` event received)
//!
//! Responses are stored in a flat pool keyed by block number — blocks are
//! produced in realtime and responses typically arrive before `commitBatch`
//! is called on L1, so there is no "matching batch" yet at insertion time.

use std::{
    collections::{BTreeMap, HashMap, HashSet},
    sync::{Arc, Mutex},
};

use alloy_primitives::B256;
use tracing::{error, info, warn};

use crate::{
    db::Db,
    types::{EthExecutionResponse, SubmitBatchResponse},
};

#[derive(Debug)]
pub(crate) struct PendingBatch {
    pub batch_index: u64,
    pub from_block: u64,
    pub to_block: u64,
    pub blobs_accepted: bool,
}

#[derive(Debug, Clone)]
pub(crate) struct DispatchedBatch {
    pub batch_index: u64,
    pub from_block: u64,
    pub to_block: u64,
    pub tx_hash: B256,
    pub l1_block: u64,
    /// RBF state: nonce used to sign the pending tx. `None` for legacy
    /// (pre-migration) dispatched rows that predate RBF.
    pub nonce: Option<u64>,
    /// RBF state: last broadcast `maxFeePerGas`. `None` for legacy rows.
    pub max_fee_per_gas: Option<u128>,
    /// RBF state: last broadcast `maxPriorityFeePerGas`. `None` for legacy rows.
    pub max_priority_fee_per_gas: Option<u128>,
}

#[derive(Debug)]
pub(crate) struct BatchAccumulator {
    pub(crate) batches: BTreeMap<u64, PendingBatch>,
    responses: HashMap<u64, EthExecutionResponse>,
    /// BatchSubmitted events that arrived before the batch was registered via set_batch.
    /// Applied when the batch is later registered.
    pending_blobs_accepted: HashSet<u64>,
    db: Option<Arc<Mutex<Db>>>,
    /// In-memory cache of batch signatures: batch_index → SubmitBatchResponse.
    /// Mirrors the `batch_signatures` DB table. Eliminates sync SQL on the hot path.
    pub(crate) signatures: HashMap<u64, SubmitBatchResponse>,
    /// Batches submitted to L1 awaiting finalization.
    pub(crate) dispatched: BTreeMap<u64, DispatchedBatch>,
}

impl BatchAccumulator {
    async fn persist<F>(&self, f: F)
    where
        F: FnOnce(&mut Db) + Send + 'static,
    {
        if let Some(db) = &self.db {
            let db = Arc::clone(db);
            if let Err(e) = tokio::task::spawn_blocking(move || {
                f(&mut db.lock().unwrap_or_else(|e| e.into_inner()));
            })
            .await
            {
                warn!(err = %e, "persist: spawn_blocking failed");
            }
        }
    }

    #[cfg(test)]
    pub(crate) fn new() -> Self {
        Self {
            batches: BTreeMap::new(),
            responses: HashMap::new(),
            pending_blobs_accepted: HashSet::new(),
            db: None,
            signatures: HashMap::new(),
            dispatched: BTreeMap::new(),
        }
    }

    /// Create accumulator backed by a DB. Loads all state from DB on construction.
    pub(crate) fn with_db(db: Arc<Mutex<Db>>) -> Self {
        let guard = db.lock().unwrap_or_else(|e| e.into_inner());
        let responses: HashMap<u64, EthExecutionResponse> =
            guard.load_responses().into_iter().map(|r| (r.block_number, r)).collect();
        let batches: BTreeMap<u64, PendingBatch> =
            guard.load_batches().into_iter().map(|b| (b.batch_index, b)).collect();
        let pending_blobs_accepted: HashSet<u64> =
            guard.load_pending_blobs_accepted().into_iter().collect();
        let dispatched: BTreeMap<u64, DispatchedBatch> = guard
            .load_dispatched_batches()
            .into_iter()
            .filter_map(|(bi, fb, tb, tx_hash_bytes, l1b, nonce, mfpg, mpfpg)| {
                let tx_hash = B256::try_from(tx_hash_bytes.as_slice()).ok().or_else(|| {
                    error!(
                        batch_index = bi,
                        len = tx_hash_bytes.len(),
                        "Corrupt tx_hash in dispatched_batches — skipping"
                    );
                    None
                })?;
                Some((
                    bi,
                    DispatchedBatch {
                        batch_index: bi,
                        from_block: fb,
                        to_block: tb,
                        tx_hash,
                        l1_block: l1b,
                        nonce,
                        max_fee_per_gas: mfpg,
                        max_priority_fee_per_gas: mpfpg,
                    },
                ))
            })
            .collect();
        let mut signatures: HashMap<u64, SubmitBatchResponse> = HashMap::new();
        let mut stale_sigs: Vec<u64> = Vec::new();
        for (idx, resp) in guard.load_all_batch_signatures() {
            if batches.contains_key(&idx) || dispatched.contains_key(&idx) {
                signatures.insert(idx, resp);
            } else {
                stale_sigs.push(idx);
            }
        }
        if !stale_sigs.is_empty() {
            warn!(
                count = stale_sigs.len(),
                indexes = ?stale_sigs,
                "Startup: dropping orphan batch_signatures rows (no matching batch)"
            );
            for idx in &stale_sigs {
                guard.delete_batch_signature(*idx);
            }
        }
        drop(guard);

        Self { batches, responses, pending_blobs_accepted, db: Some(db), signatures, dispatched }
    }

    /// Register a new batch from a `BatchCommitted` event.
    ///
    /// Idempotent: a listener re-emission of the same `BatchCommitted`
    /// returns early without clobbering accumulated state (especially
    /// `blobs_accepted`). A range-mismatched re-emission is impossible by
    /// L1 contract invariant: the contract emits `BatchReverted` before
    /// any re-commit with a different range, which triggers a full DB
    /// wipe + restart via `wipe_for_revert`. A fresh process therefore
    /// never sees a range mismatch for an already-registered batch.
    pub(crate) async fn set_batch(&mut self, batch_index: u64, from_block: u64, to_block: u64) {
        if self.dispatched.contains_key(&batch_index) || self.batches.contains_key(&batch_index) {
            return;
        }

        // Consume any buffered BatchSubmitted for this batch
        let blobs_accepted = self.pending_blobs_accepted.remove(&batch_index);
        if blobs_accepted {
            self.persist(move |db| db.delete_pending_blobs_accepted(batch_index)).await;
        }

        let already = (from_block..=to_block).filter(|b| self.responses.contains_key(b)).count();
        info!(
            batch_index,
            from_block,
            to_block,
            already,
            in_flight = self.batches.len(),
            blobs_already_accepted = blobs_accepted,
            "New batch registered"
        );
        let batch = PendingBatch { batch_index, from_block, to_block, blobs_accepted };
        self.persist(move |db| {
            db.save_batch(&PendingBatch { batch_index, from_block, to_block, blobs_accepted });
        })
        .await;
        self.batches.insert(batch_index, batch);
    }

    /// Store a block execution response. O(1).
    pub(crate) async fn insert_response(&mut self, resp: EthExecutionResponse) {
        let resp_clone = resp.clone();
        self.persist(move |db| db.save_response(&resp_clone)).await;
        let block = resp.block_number;
        self.responses.insert(block, resp);
    }

    pub(crate) async fn mark_batch_submitted(&mut self, batch_index: u64) {
        if let Some(batch) = self.batches.get_mut(&batch_index) {
            batch.blobs_accepted = true;
            // DB column keeps its original name — internal persistence schema.
            self.persist(move |db| db.update_blobs_accepted(batch_index)).await;
            info!(batch_index, "Batch marked Submitted on L1");
        } else {
            self.pending_blobs_accepted.insert(batch_index);
            self.persist(move |db| db.save_pending_blobs_accepted(batch_index)).await;
            warn!(batch_index, "BatchSubmitted arrived before BatchCommitted — buffered");
        }
    }

    fn is_batch_ready(&self, batch: &PendingBatch) -> bool {
        batch.blobs_accepted &&
            (batch.from_block..=batch.to_block).all(|b| self.responses.contains_key(&b))
    }

    #[cfg(test)]
    pub(crate) fn first_ready(&self) -> Option<u64> {
        self.batches.values().find(|b| self.is_batch_ready(b)).map(|b| b.batch_index)
    }

    /// Returns the first ready batch (in BTreeMap order) that does NOT have
    /// a cached signature. Used by the eager signer.
    pub(crate) fn first_ready_unsigned(&self) -> Option<u64> {
        self.batches
            .values()
            .filter(|b| self.is_batch_ready(b))
            .find(|b| !self.signatures.contains_key(&b.batch_index))
            .map(|b| b.batch_index)
    }

    /// Returns the first batch in BTreeMap order that has a cached signature,
    /// along with the signature bytes. Used by the sequential dispatcher.
    ///
    /// Returns `None` if the first pending batch is not yet signed (strict ordering).
    pub(crate) fn first_sequential_signed(&self) -> Option<(u64, Vec<u8>)> {
        let first = self.batches.values().next()?;
        let resp = self.signatures.get(&first.batch_index)?;
        Some((first.batch_index, resp.signature.clone()))
    }

    pub(crate) fn get(&self, batch_index: u64) -> Option<&PendingBatch> {
        self.batches.get(&batch_index)
    }

    /// Returns the highest `to_block` across all pending and dispatched batches, or `None` if
    /// empty.
    #[cfg(test)]
    pub(crate) fn max_to_block(&self) -> Option<u64> {
        let pending_max = self.batches.values().map(|b| b.to_block).max();
        let dispatched_max = self.dispatched.values().map(|d| d.to_block).max();
        pending_max.max(dispatched_max)
    }

    /// Purge responses for specific blocks (key rotation recovery).
    /// Clears responses from memory + SQLite. Called on key rotation
    /// recovery (drop stale responses so they can be re-populated by freshly
    /// signed ones) and on post-sign cleanup (once a batch's signature is
    /// cached, its block responses are unreachable). Batches are preserved —
    /// only responses are removed.
    pub(crate) async fn purge_responses(&mut self, blocks: &[u64]) {
        for &block in blocks {
            self.responses.remove(&block);
        }
        let owned = blocks.to_vec();
        self.persist(move |db| db.delete_responses_batch(&owned)).await;
        info!(count = blocks.len(), "Purged responses");
    }

    /// Cache a signature in memory (called after successful signing).
    pub(crate) fn cache_signature(&mut self, batch_index: u64, resp: SubmitBatchResponse) {
        self.signatures.insert(batch_index, resp);
    }

    /// Delete a cached batch signature (e.g. after key rotation invalidation).
    pub(crate) async fn delete_batch_signature(&mut self, batch_index: u64) {
        self.signatures.remove(&batch_index);
        self.persist(move |db| db.delete_batch_signature(batch_index)).await;
    }

    /// Returns cloned responses for blocks in [from, to].
    pub(crate) fn get_responses(&self, from: u64, to: u64) -> Vec<EthExecutionResponse> {
        (from..=to).filter_map(|b| self.responses.get(&b).cloned()).collect()
    }

    /// Move a batch from pending to dispatched state, persisting initial RBF
    /// state atomically with the transition.
    /// Removes from `batches` and `signatures`, inserts into `dispatched`.
    pub(crate) async fn mark_dispatched(
        &mut self,
        batch_index: u64,
        tx_hash: B256,
        l1_block: u64,
        nonce: u64,
        max_fee_per_gas: u128,
        max_priority_fee_per_gas: u128,
    ) {
        let Some(batch) = self.batches.remove(&batch_index) else { return };
        // Keep the signature cached in-memory through the dispatched state
        // so that an `undispatch` (reorg / RBF Failed / Reverted) can restore
        // the batch to pending without needing a DB round-trip to reload it.
        // The DB row in `batch_signatures` is preserved by `move_to_dispatched`
        // and is only deleted by `finalize_dispatched_batch`.

        let dispatched = DispatchedBatch {
            batch_index,
            from_block: batch.from_block,
            to_block: batch.to_block,
            tx_hash,
            l1_block,
            nonce: Some(nonce),
            max_fee_per_gas: Some(max_fee_per_gas),
            max_priority_fee_per_gas: Some(max_priority_fee_per_gas),
        };

        let fb = batch.from_block;
        let tb = batch.to_block;
        let tx_h = tx_hash.0.to_vec();
        self.persist(move |db| {
            db.move_to_dispatched(
                batch_index,
                fb,
                tb,
                &tx_h,
                l1_block,
                nonce,
                max_fee_per_gas,
                max_priority_fee_per_gas,
            )
        })
        .await;

        self.dispatched.insert(batch_index, dispatched);
    }

    /// Mark a batch as dispatched by an EXTERNAL actor (observed via
    /// `BatchPreconfirmed` L1 event). No RBF state — we are not the submitter.
    pub(crate) async fn mark_dispatched_external(
        &mut self,
        batch_index: u64,
        tx_hash: B256,
        l1_block: u64,
    ) {
        let Some(batch) = self.batches.remove(&batch_index) else { return };
        self.signatures.remove(&batch_index);

        let dispatched = DispatchedBatch {
            batch_index,
            from_block: batch.from_block,
            to_block: batch.to_block,
            tx_hash,
            l1_block,
            nonce: None,
            max_fee_per_gas: None,
            max_priority_fee_per_gas: None,
        };

        let fb = batch.from_block;
        let tb = batch.to_block;
        let tx_h = tx_hash.0.to_vec();
        self.persist(move |db| {
            db.move_to_dispatched_external(batch_index, fb, tb, &tx_h, l1_block)
        })
        .await;

        self.dispatched.insert(batch_index, dispatched);
    }

    /// Called by the main loop after an RBF worker signals a successful
    /// rebroadcast with bumped fees. Persists new tx_hash + fees atomically
    /// and mirrors them in memory.
    pub(crate) async fn record_rbf_bump(
        &mut self,
        batch_index: u64,
        new_tx_hash: B256,
        max_fee_per_gas: u128,
        max_priority_fee_per_gas: u128,
    ) {
        if let Some(d) = self.dispatched.get_mut(&batch_index) {
            d.tx_hash = new_tx_hash;
            d.max_fee_per_gas = Some(max_fee_per_gas);
            d.max_priority_fee_per_gas = Some(max_priority_fee_per_gas);
        }
        let tx_h = new_tx_hash.0.to_vec();
        self.persist(move |db| {
            db.update_rbf_state(batch_index, &tx_h, max_fee_per_gas, max_priority_fee_per_gas)
        })
        .await;
    }

    /// Called once when the RBF worker finds a receipt for the landed tx.
    /// Updates the placeholder `l1_block` (set to 0 at dispatch time) to the
    /// actual landed L1 block number, in DB and memory.
    pub(crate) async fn record_dispatched_l1_block(&mut self, batch_index: u64, l1_block: u64) {
        if let Some(d) = self.dispatched.get_mut(&batch_index) {
            d.l1_block = l1_block;
        }
        self.persist(move |db| db.update_dispatched_l1_block(batch_index, l1_block)).await;
    }

    /// Finalize a dispatched batch: delete all associated data from DB + memory.
    pub(crate) async fn finalize_dispatched(
        &mut self,
        batch_index: u64,
    ) -> Option<DispatchedBatch> {
        let dispatched = self.dispatched.remove(&batch_index)?;
        let fb = dispatched.from_block;
        let tb = dispatched.to_block;

        self.persist(move |db| db.finalize_dispatched_batch(batch_index, fb, tb)).await;

        for b in fb..=tb {
            self.responses.remove(&b);
        }
        self.signatures.remove(&batch_index);

        Some(dispatched)
    }

    /// Move a dispatched batch back to pending (reorg / dispatch retry).
    ///
    /// Guard: rows with `nonce == None` were seeded by `mark_dispatched_external`
    /// from a `BatchPreconfirmed` L1 event (someone else preconfirmed the batch).
    /// A concurrent pre-flight Failed/Reverted on our side must NOT wipe that
    /// external state — its finalization is owned by the external submitter and
    /// the finalization ticker will clean up once the receipt lands. Only our
    /// own dispatches (nonce = Some) may be unwound here.
    pub(crate) async fn undispatch(&mut self, batch_index: u64) -> bool {
        if let Some(d) = self.dispatched.get(&batch_index) {
            if d.nonce.is_none() {
                info!(
                    batch_index,
                    "Skip undispatch: external dispatch (nonce=None) — leaving for finalization"
                );
                return false;
            }
        } else {
            return false;
        }

        let Some(dispatched) = self.dispatched.remove(&batch_index) else {
            return false;
        };

        let batch = PendingBatch {
            batch_index,
            from_block: dispatched.from_block,
            to_block: dispatched.to_block,
            blobs_accepted: true,
        };

        let fb = dispatched.from_block;
        let tb = dispatched.to_block;
        self.persist(move |db| db.undispatch_batch(batch_index, fb, tb)).await;

        self.batches.insert(batch_index, batch);
        true
    }

    /// Snapshot of dispatched batches (batch_index, tx_hash, l1_block) for
    /// off-main-loop finalization work. Clones each row so the caller can
    /// move it across a task boundary without holding a reference.
    pub(crate) fn dispatched_snapshot(&self) -> Vec<(u64, B256, u64)> {
        self.dispatched.values().map(|d| (d.batch_index, d.tx_hash, d.l1_block)).collect()
    }

    /// Check if any dispatched batches exist.
    pub(crate) fn has_dispatched(&self) -> bool {
        !self.dispatched.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::B256;

    fn mock_response(block_number: u64) -> EthExecutionResponse {
        EthExecutionResponse {
            block_number,
            leaf: [0u8; 32],
            block_hash: B256::ZERO,
            signature: [0u8; 64],
        }
    }

    #[tokio::test]
    async fn set_batch_idempotent_preserves_blobs_accepted() {
        let mut acc = BatchAccumulator::new();
        acc.set_batch(1, 100, 199).await;
        acc.mark_batch_submitted(1).await;
        assert!(acc.batches.get(&1).unwrap().blobs_accepted);

        // Re-emission of the same BatchCommitted log must NOT clear the flag.
        acc.set_batch(1, 100, 199).await;
        assert!(acc.batches.get(&1).unwrap().blobs_accepted);
    }

    #[tokio::test]
    async fn not_ready_without_blobs_accepted() {
        let mut acc = BatchAccumulator::new();
        acc.set_batch(1, 10, 12).await;
        acc.insert_response(mock_response(10)).await;
        acc.insert_response(mock_response(11)).await;
        acc.insert_response(mock_response(12)).await;

        assert!(acc.first_ready().is_none());
        acc.mark_batch_submitted(1).await;
        assert_eq!(acc.first_ready(), Some(1));
    }

    #[tokio::test]
    async fn not_ready_without_all_responses() {
        let mut acc = BatchAccumulator::new();
        acc.set_batch(1, 10, 12).await;
        acc.mark_batch_submitted(1).await;

        acc.insert_response(mock_response(10)).await;
        acc.insert_response(mock_response(11)).await;
        assert!(acc.first_ready().is_none());

        acc.insert_response(mock_response(12)).await;
        assert_eq!(acc.first_ready(), Some(1));
    }

    #[tokio::test]
    async fn concurrent_batches() {
        let mut acc = BatchAccumulator::new();
        acc.set_batch(1, 10, 11).await;
        acc.set_batch(2, 12, 13).await;

        acc.insert_response(mock_response(10)).await;
        acc.insert_response(mock_response(11)).await;
        acc.mark_batch_submitted(1).await;
        assert_eq!(acc.first_ready(), Some(1));

        acc.insert_response(mock_response(12)).await;
        acc.insert_response(mock_response(13)).await;
        acc.mark_batch_submitted(2).await;

        acc.mark_dispatched(1, B256::ZERO, 1, 0, 0, 0).await;
        acc.finalize_dispatched(1).await;
        assert_eq!(acc.first_ready(), Some(2));
    }

    #[tokio::test]
    async fn responses_before_batch_registration() {
        let mut acc = BatchAccumulator::new();

        // Normal flow: responses arrive before acceptNextBatch
        acc.insert_response(mock_response(10)).await;
        acc.insert_response(mock_response(11)).await;
        acc.insert_response(mock_response(12)).await;

        acc.set_batch(1, 10, 12).await;
        acc.mark_batch_submitted(1).await;
        assert_eq!(acc.first_ready(), Some(1));
    }

    #[tokio::test]
    async fn purge_responses_preserves_batches() {
        let mut acc = BatchAccumulator::new();
        acc.set_batch(1, 10, 12).await;
        acc.insert_response(mock_response(10)).await;
        acc.insert_response(mock_response(11)).await;
        acc.insert_response(mock_response(12)).await;
        acc.mark_batch_submitted(1).await;

        // Batch should be ready
        assert_eq!(acc.first_ready(), Some(1));

        // Purge responses for blocks 11 and 12 (key rotation)
        acc.purge_responses(&[11, 12]).await;

        // Batch is no longer ready (missing responses)
        assert!(acc.first_ready().is_none());
        // But the batch itself still exists
        assert!(acc.get(1).is_some());
        // Block 10 response is preserved
        assert!(acc.responses.contains_key(&10));
        assert!(!acc.responses.contains_key(&11));
        assert!(!acc.responses.contains_key(&12));

        // Re-insert responses — batch becomes ready again
        acc.insert_response(mock_response(11)).await;
        acc.insert_response(mock_response(12)).await;
        assert_eq!(acc.first_ready(), Some(1));
    }

    fn temp_db() -> Arc<Mutex<Db>> {
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let id = COUNTER.fetch_add(1, Ordering::Relaxed);
        let path =
            std::env::temp_dir().join(format!("orchestrator_test_{id}_{}.db", std::process::id()));
        let db = Db::open(&path).unwrap();
        Arc::new(Mutex::new(db))
    }

    #[tokio::test]
    async fn first_ready_unsigned_skips_signed() {
        let db = temp_db();
        let mut acc = BatchAccumulator::with_db(Arc::clone(&db));

        acc.set_batch(1, 10, 10).await;
        acc.set_batch(2, 11, 11).await;
        acc.insert_response(mock_response(10)).await;
        acc.insert_response(mock_response(11)).await;
        acc.mark_batch_submitted(1).await;
        acc.mark_batch_submitted(2).await;

        // Both ready, neither signed
        assert_eq!(acc.first_ready_unsigned(), Some(1));

        // Sign batch 1
        let sig_resp = crate::types::SubmitBatchResponse {
            batch_root: vec![0u8; 32],
            versioned_hashes: vec![],
            signature: vec![1, 2, 3],
        };
        acc.cache_signature(1, sig_resp.clone());

        // Now first_ready_unsigned should skip batch 1 and return batch 2
        assert_eq!(acc.first_ready_unsigned(), Some(2));

        // Sign batch 2 as well
        acc.cache_signature(2, sig_resp);

        // No unsigned batches left
        assert_eq!(acc.first_ready_unsigned(), None);
    }

    #[tokio::test]
    async fn first_sequential_signed_strict_ordering() {
        let db = temp_db();
        let mut acc = BatchAccumulator::with_db(Arc::clone(&db));

        acc.set_batch(1, 10, 10).await;
        acc.set_batch(2, 11, 11).await;
        acc.insert_response(mock_response(10)).await;
        acc.insert_response(mock_response(11)).await;
        acc.mark_batch_submitted(1).await;
        acc.mark_batch_submitted(2).await;

        // No signatures yet — returns None
        assert!(acc.first_sequential_signed().is_none());

        // Sign only batch 2 (not the first)
        let sig_resp = crate::types::SubmitBatchResponse {
            batch_root: vec![0u8; 32],
            versioned_hashes: vec![],
            signature: vec![4, 5, 6],
        };
        acc.cache_signature(2, sig_resp);

        // Batch 1 is first in BTreeMap but unsigned — returns None (strict ordering)
        assert!(acc.first_sequential_signed().is_none());

        // Sign batch 1
        let sig1 = crate::types::SubmitBatchResponse {
            batch_root: vec![0u8; 32],
            versioned_hashes: vec![],
            signature: vec![7, 8, 9],
        };
        acc.cache_signature(1, sig1);

        // Now batch 1 is first and signed — returns it
        let result = acc.first_sequential_signed();
        assert!(result.is_some());
        let (idx, sig) = result.unwrap();
        assert_eq!(idx, 1);
        assert_eq!(sig, vec![7, 8, 9]);
    }

    #[tokio::test]
    async fn mark_dispatched_removes_from_batches_adds_to_dispatched() {
        let mut acc = BatchAccumulator::new();
        acc.set_batch(1, 10, 12).await;
        acc.insert_response(mock_response(10)).await;
        acc.insert_response(mock_response(11)).await;
        acc.insert_response(mock_response(12)).await;
        acc.mark_batch_submitted(1).await;

        let tx_hash = B256::from([0xAA; 32]);
        acc.mark_dispatched(1, tx_hash, 100, 0, 0, 0).await;

        assert!(acc.get(1).is_none());
        assert!(acc.dispatched.contains_key(&1));
        let d = &acc.dispatched[&1];
        assert_eq!(d.from_block, 10);
        assert_eq!(d.to_block, 12);
        assert_eq!(d.tx_hash, tx_hash);
        assert_eq!(d.l1_block, 100);
    }

    #[tokio::test]
    async fn finalize_dispatched_cleans_up_responses() {
        let mut acc = BatchAccumulator::new();
        acc.set_batch(1, 10, 11).await;
        acc.insert_response(mock_response(10)).await;
        acc.insert_response(mock_response(11)).await;
        acc.mark_batch_submitted(1).await;

        // Also insert a response for a different batch to verify it's not removed
        acc.insert_response(mock_response(12)).await;

        acc.mark_dispatched(1, B256::from([0xBB; 32]), 50, 0, 0, 0).await;

        let dispatched = acc.finalize_dispatched(1).await.unwrap();
        assert_eq!(dispatched.batch_index, 1);
        assert!(acc.dispatched.is_empty());
        assert!(!acc.responses.contains_key(&10));
        assert!(!acc.responses.contains_key(&11));
        // Response for block 12 (different batch) should still exist
        assert!(acc.responses.contains_key(&12));
    }

    #[tokio::test]
    async fn undispatch_moves_back_to_batches() {
        let mut acc = BatchAccumulator::new();
        acc.set_batch(1, 10, 11).await;
        acc.insert_response(mock_response(10)).await;
        acc.insert_response(mock_response(11)).await;
        acc.mark_batch_submitted(1).await;

        acc.mark_dispatched(1, B256::from([0xCC; 32]), 60, 0, 0, 0).await;
        assert!(acc.get(1).is_none());

        let ok = acc.undispatch(1).await;
        assert!(ok);
        assert!(acc.dispatched.is_empty());
        let batch = acc.get(1).unwrap();
        assert_eq!(batch.from_block, 10);
        assert_eq!(batch.to_block, 11);
        assert!(batch.blobs_accepted);
    }

    #[tokio::test]
    async fn undispatch_skips_external_dispatch() {
        // Simulates the race: we signed a batch, a concurrent BatchPreconfirmed
        // live event moved it to dispatched via mark_dispatched_external
        // (nonce = None), and our in-flight pre-flight then returned Failed.
        // The Failed-branch undispatch MUST NOT wipe the external state.
        let mut acc = BatchAccumulator::new();
        acc.set_batch(1, 10, 11).await;
        acc.insert_response(mock_response(10)).await;
        acc.insert_response(mock_response(11)).await;
        acc.mark_batch_submitted(1).await;

        acc.mark_dispatched_external(1, B256::from([0xAB; 32]), 42).await;
        assert!(acc.dispatched.contains_key(&1));
        assert!(acc.get(1).is_none());

        let ok = acc.undispatch(1).await;
        assert!(!ok, "undispatch must be a no-op for external dispatch");
        assert!(acc.dispatched.contains_key(&1), "external row preserved");
        assert!(acc.get(1).is_none(), "no resurrection into pending");
    }

    #[tokio::test]
    async fn max_to_block_considers_dispatched() {
        let mut acc = BatchAccumulator::new();
        acc.set_batch(1, 10, 20).await;
        acc.insert_response(mock_response(10)).await;
        acc.mark_batch_submitted(1).await;

        assert_eq!(acc.max_to_block(), Some(20));

        acc.mark_dispatched(1, B256::from([0xDD; 32]), 70, 0, 0, 0).await;

        // After dispatch, pending is empty but dispatched has it
        assert!(acc.batches.is_empty());
        assert_eq!(acc.max_to_block(), Some(20));
    }

    #[tokio::test]
    async fn dispatched_batches_db_round_trip() {
        let db = temp_db();
        let mut acc = BatchAccumulator::with_db(Arc::clone(&db));

        acc.set_batch(1, 10, 12).await;
        acc.insert_response(mock_response(10)).await;
        acc.insert_response(mock_response(11)).await;
        acc.insert_response(mock_response(12)).await;
        acc.mark_batch_submitted(1).await;

        let tx_hash = B256::from([0xEE; 32]);
        acc.mark_dispatched(1, tx_hash, 80, 0, 0, 0).await;

        // Reload from DB
        let acc2 = BatchAccumulator::with_db(Arc::clone(&db));
        assert!(acc2.dispatched.contains_key(&1));
        let d = &acc2.dispatched[&1];
        assert_eq!(d.from_block, 10);
        assert_eq!(d.to_block, 12);
        assert_eq!(d.tx_hash, tx_hash);
        assert_eq!(d.l1_block, 80);
        // Pending batch should be gone (moved to dispatched)
        assert!(acc2.get(1).is_none());
    }

    #[tokio::test]
    async fn set_batch_same_range_on_dispatched_batch_is_noop() {
        let db = temp_db();
        let mut acc = BatchAccumulator::with_db(Arc::clone(&db));
        acc.set_batch(1, 10, 20).await;
        for b in 10..=20u64 {
            acc.insert_response(mock_response(b)).await;
        }
        acc.mark_batch_submitted(1).await;
        let tx_hash = B256::from([0xCC; 32]);
        acc.mark_dispatched(1, tx_hash, 50, 0, 0, 0).await;

        // Same range — idempotent re-emission, no state change.
        acc.set_batch(1, 10, 20).await;

        assert!(acc.dispatched.contains_key(&1));
        assert!(!acc.batches.contains_key(&1));
    }

    #[tokio::test]
    async fn startup_drops_orphan_signature_rows_keeps_valid_ones() {
        let db = temp_db();

        // Seed state directly on the DB: batch 1 has a pending row + signature
        // (valid), batch 7 has ONLY a signature row (orphan — simulates the
        // crash-mid-commit scenario where the pending row was lost).
        {
            let guard = db.lock().unwrap();
            guard.save_batch(&PendingBatch {
                batch_index: 1,
                from_block: 10,
                to_block: 15,
                blobs_accepted: true,
            });
            let sig = crate::types::SubmitBatchResponse {
                batch_root: vec![0u8; 32],
                versioned_hashes: vec![],
                signature: vec![0xAA],
            };
            guard.save_batch_signature(1, &sig);
            guard.save_batch_signature(7, &sig);
        }

        // with_db must drop the orphan sig (7) and keep the valid one (1).
        let acc = BatchAccumulator::with_db(Arc::clone(&db));

        assert!(acc.batches.contains_key(&1), "batch 1 pending row preserved");
        assert!(acc.signatures.contains_key(&1), "batch 1 signature preserved");
        assert!(!acc.signatures.contains_key(&7), "batch 7 orphan signature not loaded");

        // DB-level check: orphan row is gone; valid row remains.
        let guard = db.lock().unwrap();
        let remaining = guard.load_batch_signature_indexes();
        assert_eq!(remaining, vec![1u64]);
    }
}
