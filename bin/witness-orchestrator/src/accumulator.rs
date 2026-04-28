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
use tokio::sync::mpsc;
use tracing::{error, info, warn};

use crate::{
    db::{Db, DbCommand},
    types::{EthExecutionResponse, SubmitBatchResponse},
};

/// State carried over from a prior process lifetime, used by the dispatcher
/// worker's resume path to skip the initial broadcast (a tx with this nonce
/// is already in the mempool) and enter the bump loop directly.
#[derive(Debug, Clone, Copy)]
pub(crate) struct RbfResumeState {
    pub(crate) nonce: u64,
    pub(crate) tx_hash: B256,
    pub(crate) max_fee_per_gas: u128,
    pub(crate) max_priority_fee_per_gas: u128,
}

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
    /// In-memory cache of batch signatures: batch_index → SubmitBatchResponse.
    /// Mirrors the `batch_signatures` DB table. Eliminates sync SQL on the hot path.
    pub(crate) signatures: HashMap<u64, SubmitBatchResponse>,
    /// Batches submitted to L1 awaiting finalization.
    pub(crate) dispatched: BTreeMap<u64, DispatchedBatch>,
    /// `None` only in unit tests that assert in-memory state without
    /// touching the DB writer actor.
    db_tx: Option<mpsc::UnboundedSender<DbCommand>>,
}

impl BatchAccumulator {
    #[cfg(test)]
    pub(crate) fn new() -> Self {
        Self {
            batches: BTreeMap::new(),
            responses: HashMap::new(),
            pending_blobs_accepted: HashSet::new(),
            signatures: HashMap::new(),
            dispatched: BTreeMap::new(),
            db_tx: None,
        }
    }

    /// A closed channel means accumulator memory is ahead of SQLite —
    /// recoverable on restart but worth alerting on.
    fn send_cmd(&self, cmd: DbCommand) {
        if let Some(tx) = &self.db_tx {
            if tx.send(cmd).is_err() {
                metrics::counter!(crate::metrics::DB_WRITER_DROPPED_TOTAL).increment(1);
                error!("DB writer channel closed — accumulator mutation dropped");
            }
        }
    }

    /// Loads all state from `db` on construction. Subsequent mutations are
    /// persisted via `db_tx` automatically.
    pub(crate) fn with_db(db: Arc<Mutex<Db>>, db_tx: mpsc::UnboundedSender<DbCommand>) -> Self {
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

        Self {
            batches,
            responses,
            pending_blobs_accepted,
            signatures,
            dispatched,
            db_tx: Some(db_tx),
        }
    }

    /// Register a new batch from a `BatchCommitted` event.
    ///
    /// Idempotent: a listener re-emission of the same `BatchCommitted` is a
    /// no-op without clobbering accumulated state (especially
    /// `blobs_accepted`). A range-mismatched re-emission is impossible by
    /// L1 contract invariant: the contract emits `BatchReverted` before any
    /// re-commit with a different range, which triggers a full DB wipe +
    /// restart via `wipe_for_revert`. A fresh process therefore never sees
    /// a range mismatch for an already-registered batch.
    pub(crate) fn set_batch(&mut self, batch_index: u64, from_block: u64, to_block: u64) {
        if self.dispatched.contains_key(&batch_index) || self.batches.contains_key(&batch_index) {
            return;
        }

        let blobs_accepted = self.pending_blobs_accepted.remove(&batch_index);
        if blobs_accepted {
            self.send_cmd(DbCommand::DeletePendingBlobsAccepted(batch_index));
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
        self.send_cmd(DbCommand::SaveBatch(PendingBatch {
            batch_index,
            from_block,
            to_block,
            blobs_accepted,
        }));
        self.batches.insert(batch_index, batch);
    }

    pub(crate) fn insert_response(&mut self, resp: EthExecutionResponse) {
        let block = resp.block_number;
        self.send_cmd(DbCommand::SaveResponse(resp.clone()));
        self.responses.insert(block, resp);
    }

    /// Buffers `BatchSubmitted` events that arrive before the matching
    /// `BatchCommitted` so they can be applied once the batch registers.
    pub(crate) fn mark_batch_submitted(&mut self, batch_index: u64) {
        if let Some(batch) = self.batches.get_mut(&batch_index) {
            batch.blobs_accepted = true;
            info!(batch_index, "Batch marked Submitted on L1");
            self.send_cmd(DbCommand::UpdateBlobsAccepted(batch_index));
        } else {
            self.pending_blobs_accepted.insert(batch_index);
            warn!(batch_index, "BatchSubmitted arrived before BatchCommitted — buffered");
            self.send_cmd(DbCommand::SavePendingBlobsAccepted(batch_index));
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

    pub(crate) fn first_ready_unsigned(&self) -> Option<u64> {
        self.batches
            .values()
            .filter(|b| self.is_batch_ready(b))
            .find(|b| !self.signatures.contains_key(&b.batch_index))
            .map(|b| b.batch_index)
    }

    /// Returns `None` if the lowest-index pending batch is not yet signed:
    /// dispatch is strictly ordered.
    pub(crate) fn first_sequential_signed(&self) -> Option<(u64, Vec<u8>)> {
        let first = self.batches.values().next()?;
        let resp = self.signatures.get(&first.batch_index)?;
        Some((first.batch_index, resp.signature.clone()))
    }

    pub(crate) fn get(&self, batch_index: u64) -> Option<&PendingBatch> {
        self.batches.get(&batch_index)
    }

    #[cfg(test)]
    pub(crate) fn max_to_block(&self) -> Option<u64> {
        let pending_max = self.batches.values().map(|b| b.to_block).max();
        let dispatched_max = self.dispatched.values().map(|d| d.to_block).max();
        pending_max.max(dispatched_max)
    }

    /// Purge responses for specific blocks (key rotation recovery). Clears
    /// responses from memory and persists the deletion. Batches are
    /// preserved — only responses are removed.
    pub(crate) fn purge_responses(&mut self, blocks: &[u64]) {
        for &block in blocks {
            self.responses.remove(&block);
        }
        info!(count = blocks.len(), "Purged responses");
        self.send_cmd(DbCommand::DeleteResponsesBatch(blocks.to_vec()));
    }

    pub(crate) fn cache_signature(&mut self, batch_index: u64, resp: SubmitBatchResponse) {
        self.signatures.insert(batch_index, resp);
    }

    pub(crate) fn delete_batch_signature(&mut self, batch_index: u64) {
        self.signatures.remove(&batch_index);
        self.send_cmd(DbCommand::DeleteBatchSignature(batch_index));
    }

    pub(crate) fn get_responses(&self, from: u64, to: u64) -> Vec<EthExecutionResponse> {
        (from..=to).filter_map(|b| self.responses.get(&b).cloned()).collect()
    }

    /// The cached signature is preserved through the dispatched state so an
    /// `undispatch` (reorg / RBF Failed / Reverted) can restore the batch
    /// to pending without a DB round-trip. The `batch_signatures` row is
    /// only deleted by `FinalizeDispatchedBatch`.
    pub(crate) fn mark_dispatched(
        &mut self,
        batch_index: u64,
        tx_hash: B256,
        l1_block: u64,
        nonce: u64,
        max_fee_per_gas: u128,
        max_priority_fee_per_gas: u128,
    ) {
        let Some(batch) = self.batches.remove(&batch_index) else {
            return;
        };

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
        self.dispatched.insert(batch_index, dispatched);
        self.send_cmd(DbCommand::MoveToDispatched {
            batch_index,
            from_block: fb,
            to_block: tb,
            tx_hash: tx_h,
            l1_block,
            nonce,
            max_fee_per_gas,
            max_priority_fee_per_gas,
        });
    }

    /// External dispatcher — observed via `BatchPreconfirmed` L1 event.
    /// `nonce`/fees stay `None` because we are not the submitter, which is
    /// also the marker `undispatch` uses to skip these rows.
    pub(crate) fn mark_dispatched_external(
        &mut self,
        batch_index: u64,
        tx_hash: B256,
        l1_block: u64,
    ) {
        let Some(batch) = self.batches.remove(&batch_index) else {
            return;
        };
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
        self.dispatched.insert(batch_index, dispatched);
        self.send_cmd(DbCommand::MoveToDispatchedExternal {
            batch_index,
            from_block: fb,
            to_block: tb,
            tx_hash: tx_h,
            l1_block,
        });
    }

    /// Promote an in-flight dispatched row (`l1_block == 0`, full RBF state)
    /// to the external-dispatched shape (`l1_block = real`, `nonce`/fees
    /// cleared, cached signature dropped) when pre-flight reconciliation
    /// discovers the batch is already preconfirmed on L1. After this the row
    /// no longer matches `first_inflight_resume`, so the dispatcher stops
    /// re-picking it, and the finalization worker (which filters to
    /// `l1_block > 0`) can pick up the receipt.
    ///
    /// Returns `false` if the batch isn't currently in `dispatched`.
    pub(crate) fn promote_inflight_to_external(
        &mut self,
        batch_index: u64,
        tx_hash: B256,
        l1_block: u64,
    ) -> bool {
        let Some(d) = self.dispatched.get_mut(&batch_index) else {
            return false;
        };
        d.tx_hash = tx_hash;
        d.l1_block = l1_block;
        d.nonce = None;
        d.max_fee_per_gas = None;
        d.max_priority_fee_per_gas = None;
        let from_block = d.from_block;
        let to_block = d.to_block;
        self.signatures.remove(&batch_index);
        let tx_h = tx_hash.0.to_vec();
        self.send_cmd(DbCommand::MoveToDispatchedExternal {
            batch_index,
            from_block,
            to_block,
            tx_hash: tx_h,
            l1_block,
        });
        true
    }

    pub(crate) fn record_rbf_bump(
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
        self.send_cmd(DbCommand::UpdateRbfState {
            batch_index,
            tx_hash: tx_h,
            max_fee_per_gas,
            max_priority_fee_per_gas,
        });
    }

    /// Replaces the `l1_block == 0` placeholder set by `mark_dispatched`
    /// with the real landed block number once the receipt is observed.
    pub(crate) fn record_dispatched_l1_block(&mut self, batch_index: u64, l1_block: u64) {
        if let Some(d) = self.dispatched.get_mut(&batch_index) {
            d.l1_block = l1_block;
        }
        self.send_cmd(DbCommand::UpdateDispatchedL1Block { batch_index, l1_block });
    }

    pub(crate) fn finalize_dispatched(&mut self, batch_index: u64) -> Option<DispatchedBatch> {
        let dispatched = self.dispatched.remove(&batch_index)?;
        let fb = dispatched.from_block;
        let tb = dispatched.to_block;

        for b in fb..=tb {
            self.responses.remove(&b);
        }
        self.signatures.remove(&batch_index);

        self.send_cmd(DbCommand::FinalizeDispatchedBatch {
            batch_index,
            from_block: fb,
            to_block: tb,
        });
        Some(dispatched)
    }

    /// External dispatches (`nonce == None`) are not unwound — their
    /// finalization is owned by the external submitter and the finalization
    /// ticker cleans up once the receipt lands. Returns `true` only when
    /// our own row (`nonce == Some`) was actually moved back to pending.
    pub(crate) fn undispatch(&mut self, batch_index: u64) -> bool {
        match self.dispatched.get(&batch_index) {
            Some(d) if d.nonce.is_none() => {
                info!(
                    batch_index,
                    "Skip undispatch: external dispatch (nonce=None) — leaving for finalization"
                );
                return false;
            }
            Some(_) => {}
            None => return false,
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
        self.batches.insert(batch_index, batch);
        self.send_cmd(DbCommand::UndispatchBatch { batch_index, from_block: fb, to_block: tb });
        true
    }

    pub(crate) fn dispatched_snapshot(&self) -> Vec<(u64, B256, u64)> {
        self.dispatched.values().map(|d| (d.batch_index, d.tx_hash, d.l1_block)).collect()
    }

    /// Lets the finalization ticker discard stale observations whose
    /// snapshot `tx_hash` no longer matches the current dispatch.
    pub(crate) fn dispatched_tx_hash(&self, batch_index: u64) -> Option<B256> {
        self.dispatched.get(&batch_index).map(|d| d.tx_hash)
    }

    pub(crate) fn has_dispatched(&self) -> bool {
        !self.dispatched.is_empty()
    }

    /// Returns the dispatched row whose RBF cycle is still in flight —
    /// `l1_block == 0` placeholder plus all RBF fields populated. The "at
    /// most one fresh dispatch in flight" gate invariant guarantees there
    /// is at most one such row, so the dispatcher worker uses this on
    /// startup to resume the broadcast left behind by a prior process.
    pub(crate) fn first_inflight_resume(&self) -> Option<(u64, Vec<u8>, RbfResumeState)> {
        let (batch_index, d) = self.dispatched.iter().find(|(_, d)| {
            d.l1_block == 0 &&
                d.nonce.is_some() &&
                d.max_fee_per_gas.is_some() &&
                d.max_priority_fee_per_gas.is_some()
        })?;
        let signature = self.signatures.get(batch_index)?.signature.clone();
        let resume = RbfResumeState {
            nonce: d.nonce?,
            tx_hash: d.tx_hash,
            max_fee_per_gas: d.max_fee_per_gas?,
            max_priority_fee_per_gas: d.max_priority_fee_per_gas?,
        };
        Some((*batch_index, signature, resume))
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
        acc.set_batch(1, 100, 199);
        acc.mark_batch_submitted(1);
        assert!(acc.batches.get(&1).unwrap().blobs_accepted);

        // Re-emission of the same BatchCommitted log must NOT clear the flag.
        acc.set_batch(1, 100, 199);
        assert!(acc.batches.get(&1).unwrap().blobs_accepted);
    }

    #[tokio::test]
    async fn not_ready_without_blobs_accepted() {
        let mut acc = BatchAccumulator::new();
        acc.set_batch(1, 10, 12);
        acc.insert_response(mock_response(10));
        acc.insert_response(mock_response(11));
        acc.insert_response(mock_response(12));

        assert!(acc.first_ready().is_none());
        acc.mark_batch_submitted(1);
        assert_eq!(acc.first_ready(), Some(1));
    }

    #[tokio::test]
    async fn not_ready_without_all_responses() {
        let mut acc = BatchAccumulator::new();
        acc.set_batch(1, 10, 12);
        acc.mark_batch_submitted(1);

        acc.insert_response(mock_response(10));
        acc.insert_response(mock_response(11));
        assert!(acc.first_ready().is_none());

        acc.insert_response(mock_response(12));
        assert_eq!(acc.first_ready(), Some(1));
    }

    #[tokio::test]
    async fn concurrent_batches() {
        let mut acc = BatchAccumulator::new();
        acc.set_batch(1, 10, 11);
        acc.set_batch(2, 12, 13);

        acc.insert_response(mock_response(10));
        acc.insert_response(mock_response(11));
        acc.mark_batch_submitted(1);
        assert_eq!(acc.first_ready(), Some(1));

        acc.insert_response(mock_response(12));
        acc.insert_response(mock_response(13));
        acc.mark_batch_submitted(2);

        acc.mark_dispatched(1, B256::ZERO, 1, 0, 0, 0);
        acc.finalize_dispatched(1);
        assert_eq!(acc.first_ready(), Some(2));
    }

    #[tokio::test]
    async fn responses_before_batch_registration() {
        let mut acc = BatchAccumulator::new();

        // Normal flow: responses arrive before acceptNextBatch
        acc.insert_response(mock_response(10));
        acc.insert_response(mock_response(11));
        acc.insert_response(mock_response(12));

        acc.set_batch(1, 10, 12);
        acc.mark_batch_submitted(1);
        assert_eq!(acc.first_ready(), Some(1));
    }

    #[tokio::test]
    async fn purge_responses_preserves_batches() {
        let mut acc = BatchAccumulator::new();
        acc.set_batch(1, 10, 12);
        acc.insert_response(mock_response(10));
        acc.insert_response(mock_response(11));
        acc.insert_response(mock_response(12));
        acc.mark_batch_submitted(1);

        // Batch should be ready
        assert_eq!(acc.first_ready(), Some(1));

        // Purge responses for blocks 11 and 12 (key rotation)
        acc.purge_responses(&[11, 12]);

        // Batch is no longer ready (missing responses)
        assert!(acc.first_ready().is_none());
        // But the batch itself still exists
        assert!(acc.get(1).is_some());
        // Block 10 response is preserved
        assert!(acc.responses.contains_key(&10));
        assert!(!acc.responses.contains_key(&11));
        assert!(!acc.responses.contains_key(&12));

        // Re-insert responses — batch becomes ready again
        acc.insert_response(mock_response(11));
        acc.insert_response(mock_response(12));
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

    /// Spawn a writer actor and build an accumulator backed by it. Tests that
    /// assert on DB reloads must `drop(acc)` and `handle.await.unwrap()`
    /// before reloading so queued mutations are flushed first.
    fn accumulator_with_actor(
        db: Arc<Mutex<Db>>,
    ) -> (BatchAccumulator, tokio::task::JoinHandle<()>) {
        let (db_tx, db_rx) = mpsc::unbounded_channel();
        let acc = BatchAccumulator::with_db(Arc::clone(&db), db_tx);
        let handle = tokio::spawn(crate::db::run_db_writer(db_rx, db));
        (acc, handle)
    }

    #[tokio::test]
    async fn first_ready_unsigned_skips_signed() {
        let db = temp_db();
        let (mut acc, _handle) = accumulator_with_actor(Arc::clone(&db));

        acc.set_batch(1, 10, 10);
        acc.set_batch(2, 11, 11);
        acc.insert_response(mock_response(10));
        acc.insert_response(mock_response(11));
        acc.mark_batch_submitted(1);
        acc.mark_batch_submitted(2);

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
        let (mut acc, _handle) = accumulator_with_actor(Arc::clone(&db));

        acc.set_batch(1, 10, 10);
        acc.set_batch(2, 11, 11);
        acc.insert_response(mock_response(10));
        acc.insert_response(mock_response(11));
        acc.mark_batch_submitted(1);
        acc.mark_batch_submitted(2);

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
        acc.set_batch(1, 10, 12);
        acc.insert_response(mock_response(10));
        acc.insert_response(mock_response(11));
        acc.insert_response(mock_response(12));
        acc.mark_batch_submitted(1);

        let tx_hash = B256::from([0xAA; 32]);
        acc.mark_dispatched(1, tx_hash, 100, 0, 0, 0);

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
        acc.set_batch(1, 10, 11);
        acc.insert_response(mock_response(10));
        acc.insert_response(mock_response(11));
        acc.mark_batch_submitted(1);

        // Also insert a response for a different batch to verify it's not removed
        acc.insert_response(mock_response(12));

        acc.mark_dispatched(1, B256::from([0xBB; 32]), 50, 0, 0, 0);

        let dispatched = acc.finalize_dispatched(1).unwrap();
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
        acc.set_batch(1, 10, 11);
        acc.insert_response(mock_response(10));
        acc.insert_response(mock_response(11));
        acc.mark_batch_submitted(1);

        acc.mark_dispatched(1, B256::from([0xCC; 32]), 60, 0, 0, 0);
        assert!(acc.get(1).is_none());

        assert!(acc.undispatch(1));
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
        acc.set_batch(1, 10, 11);
        acc.insert_response(mock_response(10));
        acc.insert_response(mock_response(11));
        acc.mark_batch_submitted(1);

        acc.mark_dispatched_external(1, B256::from([0xAB; 32]), 42);
        assert!(acc.dispatched.contains_key(&1));
        assert!(acc.get(1).is_none());

        assert!(!acc.undispatch(1), "undispatch must be a no-op for external dispatch");
        assert!(acc.dispatched.contains_key(&1), "external row preserved");
        assert!(acc.get(1).is_none(), "no resurrection into pending");
    }

    #[tokio::test]
    async fn max_to_block_considers_dispatched() {
        let mut acc = BatchAccumulator::new();
        acc.set_batch(1, 10, 20);
        acc.insert_response(mock_response(10));
        acc.mark_batch_submitted(1);

        assert_eq!(acc.max_to_block(), Some(20));

        acc.mark_dispatched(1, B256::from([0xDD; 32]), 70, 0, 0, 0);

        // After dispatch, pending is empty but dispatched has it
        assert!(acc.batches.is_empty());
        assert_eq!(acc.max_to_block(), Some(20));
    }

    #[tokio::test]
    async fn dispatched_batches_db_round_trip() {
        let db = temp_db();
        let (mut acc, handle) = accumulator_with_actor(Arc::clone(&db));

        acc.set_batch(1, 10, 12);
        acc.insert_response(mock_response(10));
        acc.insert_response(mock_response(11));
        acc.insert_response(mock_response(12));
        acc.mark_batch_submitted(1);

        let tx_hash = B256::from([0xEE; 32]);
        acc.mark_dispatched(1, tx_hash, 80, 0, 0, 0);

        // Flush pending writes before reload. Dropping the accumulator
        // drops its `db_tx`; the actor then observes the channel close,
        // performs one final flush, and exits.
        drop(acc);
        handle.await.unwrap();

        // Reload from DB — fresh accumulator + actor. Discard the actor
        // immediately; this test only reads.
        let (db_tx2, _db_rx2) = mpsc::unbounded_channel();
        let acc2 = BatchAccumulator::with_db(Arc::clone(&db), db_tx2);
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
        let (mut acc, _handle) = accumulator_with_actor(Arc::clone(&db));
        acc.set_batch(1, 10, 20);
        for b in 10..=20u64 {
            acc.insert_response(mock_response(b));
        }
        acc.mark_batch_submitted(1);
        let tx_hash = B256::from([0xCC; 32]);
        acc.mark_dispatched(1, tx_hash, 50, 0, 0, 0);

        // Same range — idempotent re-emission, no state change.
        acc.set_batch(1, 10, 20);

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
        // No actor needed — test only asserts in-memory + DB state after the
        // synchronous orphan cleanup inside `with_db`.
        let (db_tx, _db_rx) = mpsc::unbounded_channel();
        let acc = BatchAccumulator::with_db(Arc::clone(&db), db_tx);

        assert!(acc.batches.contains_key(&1), "batch 1 pending row preserved");
        assert!(acc.signatures.contains_key(&1), "batch 1 signature preserved");
        assert!(!acc.signatures.contains_key(&7), "batch 7 orphan signature not loaded");

        // DB-level check: orphan row is gone; valid row remains.
        let guard = db.lock().unwrap();
        let remaining = guard.load_batch_signature_indexes();
        assert_eq!(remaining, vec![1u64]);
    }

    /// Resume scope returns the dispatched row whose RBF cycle is still in
    /// flight (`l1_block == 0`). The other row, already past initial
    /// broadcast (`l1_block != 0`), waits on finalization-check and is not
    /// returned here.
    #[tokio::test]
    async fn first_inflight_resume_returns_l1_block_zero_row() {
        let mut acc = BatchAccumulator::new();
        acc.set_batch(1, 10, 11);
        acc.set_batch(2, 12, 13);
        acc.insert_response(mock_response(10));
        acc.insert_response(mock_response(11));
        acc.insert_response(mock_response(12));
        acc.insert_response(mock_response(13));
        acc.mark_batch_submitted(1);
        acc.mark_batch_submitted(2);

        // Both signed (so the cached signature exists for the resume scan).
        let sig = crate::types::SubmitBatchResponse {
            batch_root: vec![0u8; 32],
            versioned_hashes: vec![],
            signature: vec![0xAB],
        };
        acc.cache_signature(1, sig.clone());
        acc.cache_signature(2, sig);

        // Batch 1 is "fully dispatched" with a real l1_block, batch 2 is
        // mid-RBF with the placeholder (l1_block == 0).
        acc.mark_dispatched(1, B256::from([0xAA; 32]), 100, 5, 1_000, 100);
        acc.mark_dispatched(2, B256::from([0xBB; 32]), 0, 6, 2_000, 200);

        let pick = acc.first_inflight_resume();
        assert!(pick.is_some(), "must return the in-flight (l1_block==0) row");
        let (idx, _signature, resume) = pick.unwrap();
        assert_eq!(idx, 2);
        assert_eq!(resume.nonce, 6);
        assert_eq!(resume.max_fee_per_gas, 2_000);
    }

    #[tokio::test]
    async fn promote_inflight_to_external_clears_rbf_state() {
        let mut acc = BatchAccumulator::new();
        acc.set_batch(1, 10, 11);
        acc.insert_response(mock_response(10));
        acc.insert_response(mock_response(11));
        acc.mark_batch_submitted(1);
        let sig = crate::types::SubmitBatchResponse {
            batch_root: vec![0u8; 32],
            versioned_hashes: vec![],
            signature: vec![0xAA],
        };
        acc.cache_signature(1, sig);
        // Mid-RBF row: l1_block placeholder, RBF state populated.
        acc.mark_dispatched(1, B256::from([0xAA; 32]), 0, 5, 1_000, 100);
        assert!(acc.first_inflight_resume().is_some(), "precondition: row matches resume scope");

        let external_tx = B256::from([0xBB; 32]);
        assert!(acc.promote_inflight_to_external(1, external_tx, 999));

        let d = &acc.dispatched[&1];
        assert_eq!(d.tx_hash, external_tx);
        assert_eq!(d.l1_block, 999);
        assert_eq!(d.nonce, None);
        assert_eq!(d.max_fee_per_gas, None);
        assert_eq!(d.max_priority_fee_per_gas, None);
        assert!(!acc.signatures.contains_key(&1), "signature dropped");
        assert!(
            acc.first_inflight_resume().is_none(),
            "row no longer matches resume scope after promotion"
        );
    }

    #[tokio::test]
    async fn promote_inflight_to_external_returns_false_when_not_dispatched() {
        let mut acc = BatchAccumulator::new();
        acc.set_batch(1, 10, 11);
        assert!(!acc.promote_inflight_to_external(1, B256::from([0xCC; 32]), 100));
    }

    /// All dispatched rows have a real `l1_block != 0` — they are owned by
    /// the finalization-check loop, not the resume path. `first_inflight_resume`
    /// returns `None`.
    #[tokio::test]
    async fn first_inflight_resume_none_when_all_have_real_l1_block() {
        let mut acc = BatchAccumulator::new();
        acc.set_batch(1, 10, 11);
        acc.insert_response(mock_response(10));
        acc.insert_response(mock_response(11));
        acc.mark_batch_submitted(1);
        let sig = crate::types::SubmitBatchResponse {
            batch_root: vec![0u8; 32],
            versioned_hashes: vec![],
            signature: vec![0xCC],
        };
        acc.cache_signature(1, sig);
        acc.mark_dispatched(1, B256::from([0xCC; 32]), 200, 7, 3_000, 300);

        assert!(acc.first_inflight_resume().is_none());
    }
}
