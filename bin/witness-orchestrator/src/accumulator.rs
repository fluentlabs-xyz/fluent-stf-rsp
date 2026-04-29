//! Batch accumulator: in-memory mirror of the `batches` SQLite table plus the
//! hot write-back cache for per-block `EthExecutionResponse` rows.
//!
//! Status state machine mirrors the L1 contract progression:
//!
//! ```text
//! Committed → Accepted → Sent → Preconfirmed → Finalized
//! ```
//!
//! `enclave_signed` is an orthogonal local flag — toggles when
//! `/sign-batch-root` succeeds.
//!
//! All mutating methods follow the 3-step pattern (Q1):
//!   1. acquire the mutex, compute the new state, drop the mutex,
//!   2. await `db_send_sync(...)` (DB durability — ~10 ms),
//!   3. re-acquire the mutex, apply the patch to memory.
//!
//! Step 2 is awaited **outside** the `std::sync::Mutex` guard. This preserves
//! the project-wide compile-time invariant that the guard is `!Send` and
//! therefore cannot cross an `.await` point.

use std::{
    collections::{BTreeMap, HashMap, HashSet},
    sync::{Arc, Mutex},
};

use alloy_primitives::B256;
use tokio::sync::mpsc;
use tracing::{info, warn};

use crate::{
    db::{db_send_sync, now_ts, BatchPatch, BatchRow, BatchStatus, DbCommand, SyncOp},
    types::{EthExecutionResponse, SubmitBatchResponse},
};

/// State carried over from a prior process lifetime. Used by the dispatcher's
/// resume path to skip the initial broadcast and enter the bump loop directly.
#[derive(Debug, Clone, Copy)]
pub(crate) struct RbfResumeState {
    pub(crate) nonce: u64,
    pub(crate) tx_hash: B256,
    pub(crate) max_fee_per_gas: u128,
    pub(crate) max_priority_fee_per_gas: u128,
}

#[derive(Debug)]
pub(crate) struct BatchAccumulator {
    /// Mirror of the `batches` SQLite table. Sync-flushed: every mutation
    /// persists to SQLite before the in-memory row is updated.
    pub(crate) batches: BTreeMap<u64, BatchRow>,
    /// Hot in-memory cache for per-block enclave responses. Source of truth
    /// for live state; SQLite is the async-flushed durability backstop.
    /// Crash loses the trailing un-flushed window — re-execution recovers.
    responses: HashMap<u64, EthExecutionResponse>,
    /// `BatchSubmitted` events that arrived before the matching
    /// `BatchCommitted`. Not persisted: the L1 listener replays from
    /// `l1_checkpoint` after a restart, so the events come back.
    early_blobs_in_l1: HashSet<u64>,
    /// `None` only in unit tests that assert in-memory state without
    /// touching the DB writer actor.
    db_tx: Option<mpsc::UnboundedSender<DbCommand>>,
}

impl BatchAccumulator {
    /// Bulk-load all persistent state on startup.
    pub(crate) fn with_db(
        db: Arc<Mutex<crate::db::Db>>,
        db_tx: mpsc::UnboundedSender<DbCommand>,
    ) -> Self {
        let guard = db.lock().unwrap_or_else(|e| e.into_inner());
        let batches: BTreeMap<u64, BatchRow> =
            guard.load_all_batches().into_iter().map(|b| (b.batch_index, b)).collect();
        let responses: HashMap<u64, EthExecutionResponse> =
            guard.load_responses().into_iter().map(|r| (r.block_number, r)).collect();
        drop(guard);
        Self { batches, responses, early_blobs_in_l1: HashSet::new(), db_tx: Some(db_tx) }
    }

    // ── Hot response cache (async-flushed; no .await needed) ─────────────────

    pub(crate) fn insert_response(&mut self, resp: EthExecutionResponse) {
        let block = resp.block_number;
        self.responses.insert(block, resp.clone());
        if let Some(tx) = &self.db_tx {
            if tx.send(DbCommand::Async(crate::db::AsyncOp::SaveResponse(resp))).is_err() {
                metrics::counter!(crate::metrics::DB_WRITER_DROPPED_TOTAL).increment(1);
            }
        }
    }

    pub(crate) fn purge_responses(&mut self, blocks: &[u64]) {
        for &b in blocks {
            self.responses.remove(&b);
        }
        if let Some(tx) = &self.db_tx {
            if tx
                .send(DbCommand::Async(crate::db::AsyncOp::DeleteResponsesBatch(blocks.to_vec())))
                .is_err()
            {
                metrics::counter!(crate::metrics::DB_WRITER_DROPPED_TOTAL).increment(1);
            }
        }
    }

    pub(crate) fn get_responses(&self, from: u64, to: u64) -> Vec<EthExecutionResponse> {
        (from..=to).filter_map(|b| self.responses.get(&b).cloned()).collect()
    }

    // ── Read predicates ─────────────────────────────────────────────────────

    pub(crate) fn get(&self, batch_index: u64) -> Option<&BatchRow> {
        self.batches.get(&batch_index)
    }

    /// First batch eligible for `/sign-batch-root` — `accepted` and not yet
    /// signed, with all per-block responses present.
    pub(crate) fn first_accepted_unsigned(&self) -> Option<u64> {
        self.batches
            .values()
            .find(|b| {
                b.status == BatchStatus::Accepted &&
                    !b.enclave_signed &&
                    (b.from_block..=b.to_block).all(|blk| self.responses.contains_key(&blk))
            })
            .map(|b| b.batch_index)
    }

    /// First batch eligible for dispatch: lowest-index batch with status
    /// `Accepted` AND `enclave_signed`, AND no later-indexed batch is already
    /// past the same boundary (sequential gate per L1 contract invariant).
    pub(crate) fn first_dispatchable(&self) -> Option<u64> {
        let first = self.batches.values().next()?;
        // Strict sequential: lowest-index batch must be the dispatch target.
        // If it is past Accepted (Sent / Preconfirmed / Finalized), the next
        // lowest unsent must wait until the dispatcher cycle completes.
        if first.status >= BatchStatus::Sent {
            // Find the lowest-index batch still in Committed/Accepted; the
            // sequential gate is "no gaps before it" which the L1 contract
            // emitting BatchCommitted in order already guarantees.
            return self
                .batches
                .values()
                .find(|b| b.status == BatchStatus::Accepted && b.enclave_signed)
                .map(|b| b.batch_index);
        }
        if first.status == BatchStatus::Accepted && first.enclave_signed {
            Some(first.batch_index)
        } else {
            None
        }
    }

    /// Lowest-index batch with status `Sent` and full RBF state — the
    /// dispatcher worker uses this on startup to resume a prior-process
    /// broadcast left in mempool.
    pub(crate) fn first_inflight_resume(&self) -> Option<(u64, Vec<u8>, RbfResumeState)> {
        self.batches
            .values()
            .find(|b| {
                b.status == BatchStatus::Sent &&
                    b.nonce.is_some() &&
                    b.tx_hash.is_some() &&
                    b.max_fee_per_gas.is_some() &&
                    b.max_priority_fee_per_gas.is_some() &&
                    b.signature.is_some()
            })
            .map(|b| {
                let resume = RbfResumeState {
                    nonce: b.nonce.unwrap(),
                    tx_hash: b.tx_hash.unwrap(),
                    max_fee_per_gas: b.max_fee_per_gas.unwrap(),
                    max_priority_fee_per_gas: b.max_priority_fee_per_gas.unwrap(),
                };
                (b.batch_index, b.signature.as_ref().unwrap().signature.clone(), resume)
            })
    }

    /// Snapshot of all rows whose tx is mined on L1 (status Preconfirmed)
    /// for the finalization worker to poll Ethereum chain finality.
    pub(crate) fn dispatched_for_finalization_check(&self) -> Vec<(u64, B256, u64)> {
        self.batches
            .values()
            .filter(|b| b.status == BatchStatus::Preconfirmed)
            .filter_map(|b| Some((b.batch_index, b.tx_hash?, b.l1_block?)))
            .collect()
    }

    /// `MAX(to_block)` across rows with status >= Sent; in-memory mirror of
    /// `Db::highest_dispatched_to_block`. Used by metrics / startup
    /// `orchestrator_tip` seed.
    pub(crate) fn highest_dispatched_to_block(&self) -> Option<u64> {
        self.batches.values().filter(|b| b.status >= BatchStatus::Sent).map(|b| b.to_block).max()
    }

    /// `MAX(to_block)` across finalized rows.
    pub(crate) fn highest_finalized_to_block(&self) -> Option<u64> {
        self.batches
            .values()
            .filter(|b| b.status == BatchStatus::Finalized)
            .map(|b| b.to_block)
            .max()
    }

    /// Maximum nonce across local (non-external) sent rows. Drives
    /// `NonceAllocator` floor at startup.
    pub(crate) fn stored_nonce_floor(&self) -> Option<u64> {
        self.batches.values().filter_map(|b| b.nonce).max().map(|n| n + 1)
    }

    pub(crate) fn dispatched_tx_hash(&self, batch_index: u64) -> Option<B256> {
        self.batches.get(&batch_index).and_then(|b| b.tx_hash)
    }
}

// ============================================================================
// Mutating async functions (the 3-step pattern)
// ============================================================================
//
// Each function:
//   1. locks `accumulator`, computes new state + grabs `db_tx` clone, drops lock
//   2. `db_send_sync(...).await` — durability barrier, ~10 ms
//   3. locks `accumulator` again, applies the change to memory
//
// Steps 1 and 3 are microseconds each; step 2 runs OUTSIDE the lock so other
// callers do not contend on the mutex while DB I/O is in flight.

/// Idempotent on re-emission of the same `BatchCommitted`. If
/// `early_blobs_in_l1` already contains the index, the row is created at
/// `Accepted` and the buffer entry is dropped.
pub(crate) async fn observe_committed(
    accumulator: &Arc<Mutex<BatchAccumulator>>,
    batch_index: u64,
    from_block: u64,
    to_block: u64,
) -> eyre::Result<()> {
    let (row, db_tx, drain_buffer) = {
        let acc = accumulator.lock().unwrap_or_else(|e| e.into_inner());
        if acc.batches.contains_key(&batch_index) {
            return Ok(());
        }
        let now = now_ts();
        let blobs_in_l1 = acc.early_blobs_in_l1.contains(&batch_index);
        let row = BatchRow {
            batch_index,
            from_block,
            to_block,
            status: if blobs_in_l1 { BatchStatus::Accepted } else { BatchStatus::Committed },
            enclave_signed: false,
            signature: None,
            tx_hash: None,
            nonce: None,
            max_fee_per_gas: None,
            max_priority_fee_per_gas: None,
            l1_block: None,
            committed_at: now,
            last_status_change_at: now,
        };
        let db_tx = acc.db_tx.clone().ok_or_else(|| eyre::eyre!("no db_tx"))?;
        (row, db_tx, blobs_in_l1)
    };
    db_send_sync(&db_tx, SyncOp::UpsertBatch(row.clone())).await?;
    {
        let mut acc = accumulator.lock().unwrap_or_else(|e| e.into_inner());
        if drain_buffer {
            acc.early_blobs_in_l1.remove(&batch_index);
        }
        let already =
            (row.from_block..=row.to_block).filter(|b| acc.responses.contains_key(b)).count();
        info!(
            batch_index,
            from_block = row.from_block,
            to_block = row.to_block,
            status = ?row.status,
            already,
            in_flight = acc.batches.len(),
            "New batch registered"
        );
        acc.batches.insert(row.batch_index, row);
    }
    Ok(())
}

/// `BatchSubmitted` from L1. Buffered in-memory (not persisted) if the
/// matching `BatchCommitted` hasn't arrived yet; on restart the L1 listener
/// replays from `l1_checkpoint` and re-emits the event.
pub(crate) async fn observe_submitted(
    accumulator: &Arc<Mutex<BatchAccumulator>>,
    batch_index: u64,
) -> eyre::Result<()> {
    // Pre-check: is the row present and in Committed?
    let action = {
        let mut acc = accumulator.lock().unwrap_or_else(|e| e.into_inner());
        match acc.batches.get(&batch_index).map(|b| b.status) {
            Some(BatchStatus::Committed) => Some(true),
            Some(_) => None, // already past Accepted; idempotent no-op
            None => {
                acc.early_blobs_in_l1.insert(batch_index);
                warn!(batch_index, "BatchSubmitted arrived before BatchCommitted — buffered");
                None
            }
        }
    };
    let Some(true) = action else { return Ok(()) };
    let patch = BatchPatch { status: Some(BatchStatus::Accepted), ..Default::default() };
    let db_tx = {
        let acc = accumulator.lock().unwrap_or_else(|e| e.into_inner());
        acc.db_tx.clone().ok_or_else(|| eyre::eyre!("no db_tx"))?
    };
    db_send_sync(&db_tx, SyncOp::PatchBatch { batch_index, patch: patch.clone() }).await?;
    {
        let mut acc = accumulator.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(row) = acc.batches.get_mut(&batch_index) {
            apply_patch_in_memory(row, &patch);
            info!(batch_index, "Batch marked Accepted (blobs in L1)");
        }
    }
    Ok(())
}

/// `/sign-batch-root` succeeded. Sets `enclave_signed=true` and persists the
/// signature blob. Idempotent on cached signatures from a prior attempt.
pub(crate) async fn record_enclave_signed(
    accumulator: &Arc<Mutex<BatchAccumulator>>,
    batch_index: u64,
    sig: SubmitBatchResponse,
) -> eyre::Result<()> {
    let patch =
        BatchPatch { enclave_signed: Some(true), signature: Some(Some(sig)), ..Default::default() };
    apply_patch(accumulator, batch_index, patch).await
}

/// First broadcast of `preconfirmBatch` to L1 mempool. Sets status=Sent and
/// the full RBF state.
pub(crate) async fn record_broadcast(
    accumulator: &Arc<Mutex<BatchAccumulator>>,
    batch_index: u64,
    tx_hash: B256,
    nonce: u64,
    max_fee_per_gas: u128,
    max_priority_fee_per_gas: u128,
) -> eyre::Result<()> {
    let patch = BatchPatch {
        status: Some(BatchStatus::Sent),
        tx_hash: Some(Some(tx_hash)),
        nonce: Some(Some(nonce)),
        max_fee_per_gas: Some(Some(max_fee_per_gas)),
        max_priority_fee_per_gas: Some(Some(max_priority_fee_per_gas)),
        ..Default::default()
    };
    apply_patch(accumulator, batch_index, patch).await
}

/// RBF bump rebroadcast. Overwrites tx_hash and fees; status stays at Sent.
pub(crate) async fn record_rbf_bump(
    accumulator: &Arc<Mutex<BatchAccumulator>>,
    batch_index: u64,
    tx_hash: B256,
    max_fee_per_gas: u128,
    max_priority_fee_per_gas: u128,
) -> eyre::Result<()> {
    let patch = BatchPatch {
        tx_hash: Some(Some(tx_hash)),
        max_fee_per_gas: Some(Some(max_fee_per_gas)),
        max_priority_fee_per_gas: Some(Some(max_priority_fee_per_gas)),
        ..Default::default()
    };
    apply_patch(accumulator, batch_index, patch).await
}

/// Dispatcher observed the receipt for our broadcast — records `l1_block`
/// but leaves `status=Sent`. The L1 listener owns the `Sent → Preconfirmed`
/// transition (per Q3 / Q4 decisions).
pub(crate) async fn record_receipt_observed(
    accumulator: &Arc<Mutex<BatchAccumulator>>,
    batch_index: u64,
    l1_block: u64,
) -> eyre::Result<()> {
    let patch = BatchPatch { l1_block: Some(Some(l1_block)), ..Default::default() };
    apply_patch(accumulator, batch_index, patch).await
}

/// `BatchPreconfirmed` L1 event. Three cases:
///   - row was at status `Sent` (we own the tx) → flip to Preconfirmed, overwrite l1_block (event
///     is authoritative);
///   - row was at status < Sent (external takeover) → flip to Preconfirmed, populate tx_hash +
///     l1_block, leave nonce/fees NULL (we did not submit);
///   - row was already at status Preconfirmed/Finalized → idempotent no-op;
///   - no row at all (very early external batch we never observed via BatchCommitted) → insert at
///     Preconfirmed.
pub(crate) async fn observe_preconfirmed(
    accumulator: &Arc<Mutex<BatchAccumulator>>,
    batch_index: u64,
    tx_hash: B256,
    l1_block: u64,
) -> eyre::Result<()> {
    enum Action {
        Insert(BatchRow),
        Patch(BatchPatch),
        Noop,
    }
    let (action, db_tx) = {
        let acc = accumulator.lock().unwrap_or_else(|e| e.into_inner());
        let db_tx = acc.db_tx.clone().ok_or_else(|| eyre::eyre!("no db_tx"))?;
        let action = match acc.batches.get(&batch_index) {
            Some(b) if b.status == BatchStatus::Sent => {
                // Our tx — keep RBF fields, just flip status + overwrite l1_block.
                Action::Patch(BatchPatch {
                    status: Some(BatchStatus::Preconfirmed),
                    l1_block: Some(Some(l1_block)),
                    ..Default::default()
                })
            }
            Some(b) if b.status < BatchStatus::Sent => {
                // External takeover.
                Action::Patch(BatchPatch {
                    status: Some(BatchStatus::Preconfirmed),
                    tx_hash: Some(Some(tx_hash)),
                    l1_block: Some(Some(l1_block)),
                    nonce: Some(None),
                    max_fee_per_gas: Some(None),
                    max_priority_fee_per_gas: Some(None),
                    ..Default::default()
                })
            }
            Some(_) => Action::Noop,
            None => {
                // External row we never observed through BatchCommitted.
                let now = now_ts();
                Action::Insert(BatchRow {
                    batch_index,
                    from_block: 0,
                    to_block: 0,
                    status: BatchStatus::Preconfirmed,
                    enclave_signed: false,
                    signature: None,
                    tx_hash: Some(tx_hash),
                    nonce: None,
                    max_fee_per_gas: None,
                    max_priority_fee_per_gas: None,
                    l1_block: Some(l1_block),
                    committed_at: now,
                    last_status_change_at: now,
                })
            }
        };
        (action, db_tx)
    };
    match action {
        Action::Noop => Ok(()),
        Action::Patch(patch) => {
            db_send_sync(&db_tx, SyncOp::PatchBatch { batch_index, patch: patch.clone() }).await?;
            {
                let mut acc = accumulator.lock().unwrap_or_else(|e| e.into_inner());
                if let Some(row) = acc.batches.get_mut(&batch_index) {
                    apply_patch_in_memory(row, &patch);
                }
            }
            info!(batch_index, %tx_hash, l1_block, "Batch preconfirmed on L1");
            Ok(())
        }
        Action::Insert(row) => {
            db_send_sync(&db_tx, SyncOp::UpsertBatch(row.clone())).await?;
            {
                let mut acc = accumulator.lock().unwrap_or_else(|e| e.into_inner());
                acc.batches.insert(row.batch_index, row);
            }
            info!(
                batch_index,
                %tx_hash,
                l1_block,
                "Batch preconfirmed on L1 (no prior committed observation)"
            );
            Ok(())
        }
    }
}

/// Ethereum chain-finality polling observed our preconfirmed tx in a
/// finalized L1 block. Terminal status.
pub(crate) async fn record_finalized(
    accumulator: &Arc<Mutex<BatchAccumulator>>,
    batch_index: u64,
) -> eyre::Result<()> {
    let patch = BatchPatch { status: Some(BatchStatus::Finalized), ..Default::default() };
    apply_patch(accumulator, batch_index, patch).await
}

/// Reorg recovery: a `Preconfirmed` row's L1 receipt is no longer
/// observable (`get_transaction_receipt` returned `None`), implying the
/// underlying tx fell out of the canonical chain. Rolls status back to
/// `Sent` and clears `l1_block` so the dispatcher's
/// `first_inflight_resume` re-picks the row and resumes RBF. RBF state
/// (nonce, tx_hash, fees, signature) is preserved so the rebroadcast
/// targets the same nonce. No-op when status is already past
/// `Preconfirmed` (e.g. raced with `record_finalized`) or when the row
/// was an external dispatch (`nonce.is_none()`).
pub(crate) async fn record_reorg_to_sent(
    accumulator: &Arc<Mutex<BatchAccumulator>>,
    batch_index: u64,
) -> eyre::Result<bool> {
    let (patch, db_tx) = {
        let acc = accumulator.lock().unwrap_or_else(|e| e.into_inner());
        let row = match acc.batches.get(&batch_index) {
            Some(r) => r,
            None => return Ok(false),
        };
        if row.status != BatchStatus::Preconfirmed {
            return Ok(false);
        }
        if row.nonce.is_none() {
            info!(batch_index, "Skip reorg rollback: external dispatch (nonce=None)");
            return Ok(false);
        }
        let patch = BatchPatch {
            status: Some(BatchStatus::Sent),
            l1_block: Some(None),
            ..Default::default()
        };
        let db_tx = acc.db_tx.clone().ok_or_else(|| eyre::eyre!("no db_tx"))?;
        (patch, db_tx)
    };
    db_send_sync(&db_tx, SyncOp::PatchBatch { batch_index, patch: patch.clone() }).await?;
    {
        let mut acc = accumulator.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(row) = acc.batches.get_mut(&batch_index) {
            apply_patch_in_memory(row, &patch);
        }
    }
    Ok(true)
}

/// Pre-receipt failure or REVERTED tx — roll back to `Accepted`, clear RBF
/// state. No-op for external rows (`nonce.is_none()`).
pub(crate) async fn rollback_to_accepted(
    accumulator: &Arc<Mutex<BatchAccumulator>>,
    batch_index: u64,
) -> eyre::Result<bool> {
    let (patch, db_tx) = {
        let acc = accumulator.lock().unwrap_or_else(|e| e.into_inner());
        let row = match acc.batches.get(&batch_index) {
            Some(r) => r,
            None => return Ok(false),
        };
        if row.nonce.is_none() {
            info!(batch_index, "Skip rollback: external dispatch (nonce=None)");
            return Ok(false);
        }
        if row.status != BatchStatus::Sent {
            return Ok(false);
        }
        let patch = BatchPatch {
            status: Some(BatchStatus::Accepted),
            tx_hash: Some(None),
            nonce: Some(None),
            max_fee_per_gas: Some(None),
            max_priority_fee_per_gas: Some(None),
            l1_block: Some(None),
            ..Default::default()
        };
        let db_tx = acc.db_tx.clone().ok_or_else(|| eyre::eyre!("no db_tx"))?;
        (patch, db_tx)
    };
    db_send_sync(&db_tx, SyncOp::PatchBatch { batch_index, patch: patch.clone() }).await?;
    {
        let mut acc = accumulator.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(row) = acc.batches.get_mut(&batch_index) {
            apply_patch_in_memory(row, &patch);
        }
    }
    Ok(true)
}

/// Key rotation — invalidate the existing batch signature. enclave_signed
/// flips to false, signature is cleared. Caller is expected to also
/// re-execute the affected blocks.
pub(crate) async fn invalidate_signature(
    accumulator: &Arc<Mutex<BatchAccumulator>>,
    batch_index: u64,
) -> eyre::Result<()> {
    let patch =
        BatchPatch { enclave_signed: Some(false), signature: Some(None), ..Default::default() };
    apply_patch(accumulator, batch_index, patch).await
}

// ── Internal helpers ────────────────────────────────────────────────────────

async fn apply_patch(
    accumulator: &Arc<Mutex<BatchAccumulator>>,
    batch_index: u64,
    patch: BatchPatch,
) -> eyre::Result<()> {
    let db_tx = {
        let acc = accumulator.lock().unwrap_or_else(|e| e.into_inner());
        if !acc.batches.contains_key(&batch_index) {
            warn!(batch_index, "apply_patch: no batch found — skip");
            return Ok(());
        }
        acc.db_tx.clone().ok_or_else(|| eyre::eyre!("no db_tx"))?
    };
    db_send_sync(&db_tx, SyncOp::PatchBatch { batch_index, patch: patch.clone() }).await?;
    {
        let mut acc = accumulator.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(row) = acc.batches.get_mut(&batch_index) {
            apply_patch_in_memory(row, &patch);
        }
    }
    Ok(())
}

fn apply_patch_in_memory(row: &mut BatchRow, patch: &BatchPatch) {
    if let Some(s) = patch.status {
        row.status = s;
        row.last_status_change_at = now_ts();
    }
    if let Some(b) = patch.enclave_signed {
        row.enclave_signed = b;
    }
    if let Some(ref s) = patch.signature {
        row.signature = s.clone();
    }
    if let Some(t) = patch.tx_hash {
        row.tx_hash = t;
    }
    if let Some(n) = patch.nonce {
        row.nonce = n;
    }
    if let Some(f) = patch.max_fee_per_gas {
        row.max_fee_per_gas = f;
    }
    if let Some(f) = patch.max_priority_fee_per_gas {
        row.max_priority_fee_per_gas = f;
    }
    if let Some(b) = patch.l1_block {
        row.l1_block = b;
    }
}
