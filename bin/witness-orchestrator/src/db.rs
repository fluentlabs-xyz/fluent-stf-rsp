//! SQLite persistence for orchestrator crash recovery.
//!
//! Stores `EthExecutionResponse` entries and `PendingBatch` state so the
//! orchestrator can resume without re-requesting already-computed witnesses after
//! a crash.
//!
//! Schema:
//! - `block_responses(block_number PK, response BLOB)` — serialized responses
//! - `pending_batches(batch_index PK, from_block, to_block, blobs_accepted)`
//! - `pending_blobs_accepted(batch_index PK)` — buffered pre-registration events
//! - `meta(key PK, value)` — checkpoint and other scalars
//!
//! All writes are immediately durable (WAL mode, synchronous=NORMAL).

use std::{path::Path, sync::Arc, time::Duration};

use rusqlite::{params, Connection, Result};
use tokio::{
    sync::mpsc,
    time::{interval, MissedTickBehavior},
};
use tracing::error;

use crate::{
    accumulator::PendingBatch,
    types::{EthExecutionResponse, SubmitBatchResponse},
};

pub(crate) struct Db {
    pub(crate) conn: Connection,
}

impl std::fmt::Debug for Db {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Db").finish_non_exhaustive()
    }
}

impl Db {
    /// Open or create the SQLite database at `path`.
    pub(crate) fn open(path: &Path) -> Result<Self> {
        let conn = Connection::open(path)?;
        conn.execute_batch("PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL;")?;
        conn.execute_batch(
            "
            CREATE TABLE IF NOT EXISTS block_responses (
                block_number INTEGER PRIMARY KEY,
                response     BLOB NOT NULL
            );
            CREATE TABLE IF NOT EXISTS pending_batches (
                batch_index   INTEGER PRIMARY KEY,
                from_block    INTEGER NOT NULL,
                to_block      INTEGER NOT NULL,
                blobs_accepted INTEGER NOT NULL DEFAULT 0
            );
            CREATE TABLE IF NOT EXISTS pending_blobs_accepted (
                batch_index INTEGER PRIMARY KEY
            );
            CREATE TABLE IF NOT EXISTS batch_signatures (
                batch_index INTEGER PRIMARY KEY,
                response    BLOB NOT NULL
            );
            CREATE TABLE IF NOT EXISTS dispatched_batches (
                batch_index INTEGER PRIMARY KEY,
                from_block  INTEGER NOT NULL,
                to_block    INTEGER NOT NULL,
                tx_hash     BLOB NOT NULL,
                l1_block    INTEGER NOT NULL,
                nonce       INTEGER,
                max_fee_per_gas          TEXT,
                max_priority_fee_per_gas TEXT
            );
            CREATE TABLE IF NOT EXISTS meta (
                key   TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );
        ",
        )?;

        // Migration: add RBF columns to pre-existing dispatched_batches tables.
        // SQLite has no IF NOT EXISTS for ADD COLUMN; we check PRAGMA first.
        let existing_cols: std::collections::HashSet<String> = {
            let mut stmt = conn.prepare("PRAGMA table_info(dispatched_batches)")?;
            let iter = stmt.query_map([], |row| row.get::<_, String>(1))?;
            iter.filter_map(|r| r.ok()).collect()
        };
        for (col, ddl) in [
            ("nonce", "ALTER TABLE dispatched_batches ADD COLUMN nonce INTEGER"),
            ("max_fee_per_gas", "ALTER TABLE dispatched_batches ADD COLUMN max_fee_per_gas TEXT"),
            (
                "max_priority_fee_per_gas",
                "ALTER TABLE dispatched_batches ADD COLUMN max_priority_fee_per_gas TEXT",
            ),
        ] {
            if !existing_cols.contains(col) {
                conn.execute_batch(ddl)?;
            }
        }

        Ok(Self { conn })
    }

    // ── Checkpoint ──────────────────────────────────────────────────────────

    pub(crate) fn get_checkpoint(&self) -> u64 {
        self.conn
            .query_row("SELECT value FROM meta WHERE key = 'checkpoint'", [], |row| {
                row.get::<_, String>(0)
            })
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(0)
    }

    pub(crate) fn save_checkpoint(&self, block_number: u64) {
        if let Err(e) = self.conn.execute(
            "INSERT OR REPLACE INTO meta(key, value) VALUES('checkpoint', ?1)",
            params![block_number.to_string()],
        ) {
            error!(err = %e, "Failed to persist checkpoint");
        }
    }

    // ── L1 checkpoint ────────────────────────────────────────────────────────────

    /// Last L1 block successfully polled by the L1 listener.
    /// On restart, the listener resumes from `get_l1_checkpoint().map(|b| b +
    /// 1).unwrap_or(l1_start_block)`. Returns `None` if never set — distinguishes "not
    /// persisted" from "persisted block 0".
    pub(crate) fn get_l1_checkpoint(&self) -> Option<u64> {
        self.conn
            .query_row("SELECT value FROM meta WHERE key = 'l1_checkpoint'", [], |row| {
                row.get::<_, String>(0)
            })
            .ok()
            .and_then(|s| s.parse().ok())
    }

    pub(crate) fn save_l1_checkpoint(&self, block_number: u64) {
        if let Err(e) = self.conn.execute(
            "INSERT OR REPLACE INTO meta(key, value) VALUES('l1_checkpoint', ?1)",
            params![block_number.to_string()],
        ) {
            error!(err = %e, "Failed to persist l1_checkpoint");
        }
    }

    // ── Pending start batch id (BatchReverted recovery) ─────────────────────────
    //
    // On `BatchReverted`, the orchestrator wipes its DB and persists the
    // reverted batch index here. The startup path prefers this over the
    // `L1_START_BATCH_ID` env var so the next restart resolves the L2
    // checkpoint from the reverted batch, not the stale env value.

    pub(crate) fn get_start_batch_id(&self) -> Option<u64> {
        self.conn
            .query_row("SELECT value FROM meta WHERE key = 'start_batch_id'", [], |row| {
                row.get::<_, String>(0)
            })
            .ok()
            .and_then(|s| s.parse().ok())
    }

    pub(crate) fn clear_start_batch_id(&self) {
        if let Err(e) = self.conn.execute("DELETE FROM meta WHERE key = 'start_batch_id'", []) {
            error!(err = %e, "Failed to clear start_batch_id");
        }
    }

    /// Atomically wipe all orchestrator state and persist the recovery
    /// anchors for the next startup: `start_batch_id` (reverted batch index)
    /// and `l1_checkpoint` (L1 block of the `BatchReverted` event).
    ///
    /// Wipes every data table — `block_responses`, `pending_batches`,
    /// `pending_blobs_accepted`, `batch_signatures`, `dispatched_batches`,
    /// and the entire `meta` table — before writing the two new meta rows.
    pub(crate) fn wipe_for_revert(&mut self, start_batch_id: u64, l1_block: u64) {
        let tx = match self.conn.transaction() {
            Ok(tx) => tx,
            Err(e) => {
                error!(err = %e, "wipe_for_revert: begin tx failed");
                return;
            }
        };
        let res = tx
            .execute_batch(
                "DELETE FROM block_responses;
                 DELETE FROM pending_batches;
                 DELETE FROM pending_blobs_accepted;
                 DELETE FROM batch_signatures;
                 DELETE FROM dispatched_batches;
                 DELETE FROM meta;",
            )
            .and_then(|()| {
                tx.execute(
                    "INSERT INTO meta(key, value) VALUES('start_batch_id', ?1)",
                    params![start_batch_id.to_string()],
                )
                .map(|_| ())
            })
            .and_then(|()| {
                tx.execute(
                    "INSERT INTO meta(key, value) VALUES('l1_checkpoint', ?1)",
                    params![l1_block.to_string()],
                )
                .map(|_| ())
            });
        match res {
            Ok(()) => {
                if let Err(e) = tx.commit() {
                    error!(err = %e, "wipe_for_revert: commit failed");
                }
            }
            Err(e) => {
                error!(err = %e, "wipe_for_revert: statement failed — rolling back");
            }
        }
    }

    // ── Last batch end ────────────────────────────────────────────────────────────

    /// to_block of the last successfully preconfirmed batch.
    /// Used to recover `next_batch_from_block` on restart when pending_batches is empty.
    /// Returns None if no batch has ever been preconfirmed.
    pub(crate) fn get_last_batch_end(&self) -> Option<u64> {
        self.conn
            .query_row("SELECT value FROM meta WHERE key = 'last_batch_end'", [], |row| {
                row.get::<_, String>(0)
            })
            .ok()
            .and_then(|s| s.parse().ok())
    }

    pub(crate) fn save_last_batch_end(&self, block_number: u64) {
        if let Err(e) = self.conn.execute(
            "INSERT OR REPLACE INTO meta(key, value) VALUES('last_batch_end', ?1)",
            params![block_number.to_string()],
        ) {
            error!(err = %e, "Failed to persist last_batch_end");
        }
    }

    // ── Responses ───────────────────────────────────────────────────────────

    /// Delete many responses in a single transaction so bulk purges (e.g. key
    /// rotation) don't serialize N individual writes.
    pub(crate) fn delete_responses_batch(&mut self, blocks: &[u64]) {
        let tx = match self.conn.transaction() {
            Ok(t) => t,
            Err(e) => {
                error!(err = %e, "delete_responses_batch: begin transaction failed");
                return;
            }
        };
        for &block in blocks {
            if let Err(e) =
                tx.execute("DELETE FROM block_responses WHERE block_number = ?1", params![block])
            {
                error!(err = %e, block_number = block, "delete_responses_batch: row delete failed");
            }
        }
        if let Err(e) = tx.commit() {
            error!(err = %e, "delete_responses_batch: commit failed");
        }
    }

    pub(crate) fn load_responses(&self) -> Vec<EthExecutionResponse> {
        let mut stmt =
            match self.conn.prepare("SELECT response FROM block_responses ORDER BY block_number") {
                Ok(s) => s,
                Err(e) => {
                    error!(err = %e, "load_responses prepare failed");
                    return vec![];
                }
            };
        let blobs: Vec<Vec<u8>> = stmt
            .query_map([], |row| row.get(0))
            .map(|rows| rows.filter_map(|r| r.ok()).collect())
            .unwrap_or_default();
        blobs.into_iter().filter_map(|b| bincode::deserialize(&b).ok()).collect()
    }

    pub(crate) fn get_all_response_block_numbers(&self) -> Vec<u64> {
        let mut stmt = match self
            .conn
            .prepare("SELECT block_number FROM block_responses ORDER BY block_number")
        {
            Ok(s) => s,
            Err(_) => return vec![],
        };
        stmt.query_map([], |row| row.get::<_, i64>(0))
            .map(|rows| rows.filter_map(|r| r.ok()).map(|n| n as u64).collect())
            .unwrap_or_default()
    }

    // ── Batches ─────────────────────────────────────────────────────────────

    #[cfg(test)]
    pub(crate) fn save_batch(&self, batch: &PendingBatch) {
        if let Err(e) = self.conn.execute(
            "INSERT OR REPLACE INTO pending_batches(batch_index, from_block, to_block, blobs_accepted)
             VALUES(?1, ?2, ?3, ?4)",
            params![batch.batch_index, batch.from_block, batch.to_block, batch.blobs_accepted as i64],
        ) {
            error!(err = %e, batch_index = batch.batch_index, "Failed to persist batch");
        }
    }

    pub(crate) fn load_batches(&self) -> Vec<PendingBatch> {
        let mut stmt = match self.conn.prepare(
            "SELECT batch_index, from_block, to_block, blobs_accepted FROM pending_batches ORDER BY batch_index",
        ) {
            Ok(s) => s,
            Err(e) => {
                error!(err = %e, "Failed to prepare load_batches");
                return vec![];
            }
        };
        stmt.query_map([], |row| {
            Ok(PendingBatch {
                batch_index: row.get::<_, i64>(0)? as u64,
                from_block: row.get::<_, i64>(1)? as u64,
                to_block: row.get::<_, i64>(2)? as u64,
                blobs_accepted: row.get::<_, i64>(3)? != 0,
            })
        })
        .map(|rows| rows.filter_map(|r| r.ok()).collect())
        .unwrap_or_default()
    }

    // ── Batch signatures ─────────────────────────────────────────────────────

    #[cfg(test)]
    pub(crate) fn save_batch_signature(&self, batch_index: u64, resp: &SubmitBatchResponse) {
        let blob = match bincode::serialize(resp) {
            Ok(b) => b,
            Err(e) => {
                error!(err = %e, batch_index, "Failed to serialize SubmitBatchResponse");
                return;
            }
        };
        if let Err(e) = self.conn.execute(
            "INSERT OR REPLACE INTO batch_signatures(batch_index, response) VALUES(?1, ?2)",
            params![batch_index, blob],
        ) {
            error!(err = %e, batch_index, "Failed to persist batch signature");
        }
    }

    pub(crate) fn get_batch_signature(&self, batch_index: u64) -> Option<SubmitBatchResponse> {
        let blob: Vec<u8> = self
            .conn
            .query_row(
                "SELECT response FROM batch_signatures WHERE batch_index = ?1",
                params![batch_index],
                |row| row.get(0),
            )
            .ok()?;
        bincode::deserialize(&blob).ok()
    }

    pub(crate) fn delete_batch_signature(&self, batch_index: u64) {
        if let Err(e) = self
            .conn
            .execute("DELETE FROM batch_signatures WHERE batch_index = ?1", params![batch_index])
        {
            error!(err = %e, batch_index, "Failed to delete batch signature");
        }
    }

    /// Return every `batch_index` currently present in `batch_signatures`.
    /// Used at startup to detect orphan signature rows (rows whose matching
    /// `pending_batches` / `dispatched_batches` row was lost to a mid-commit
    /// crash).
    pub(crate) fn load_batch_signature_indexes(&self) -> Vec<u64> {
        let mut stmt = match self.conn.prepare("SELECT batch_index FROM batch_signatures") {
            Ok(s) => s,
            Err(e) => {
                error!(err = %e, "Failed to prepare batch_signatures index scan");
                return Vec::new();
            }
        };
        let iter = match stmt.query_map([], |row| row.get::<_, u64>(0)) {
            Ok(i) => i,
            Err(e) => {
                error!(err = %e, "Failed to query batch_signatures rows");
                return Vec::new();
            }
        };
        iter.collect::<Result<Vec<_>>>().unwrap_or_else(|e| {
            error!(err = %e, "Failed to read batch_signatures rows");
            Vec::new()
        })
    }

    /// Load every `(batch_index, SubmitBatchResponse)` row from
    /// `batch_signatures` in a single query. Used at startup to rebuild the
    /// in-memory signature map.
    pub(crate) fn load_all_batch_signatures(&self) -> Vec<(u64, SubmitBatchResponse)> {
        let mut stmt = match self.conn.prepare("SELECT batch_index, response FROM batch_signatures")
        {
            Ok(s) => s,
            Err(e) => {
                error!(err = %e, "Failed to prepare batch_signatures scan");
                return Vec::new();
            }
        };
        let iter = match stmt.query_map([], |row| {
            let idx: u64 = row.get(0)?;
            let blob: Vec<u8> = row.get(1)?;
            Ok((idx, blob))
        }) {
            Ok(i) => i,
            Err(e) => {
                error!(err = %e, "Failed to query batch_signatures rows");
                return Vec::new();
            }
        };
        let mut out = Vec::new();
        for row in iter {
            match row {
                Ok((idx, blob)) => match bincode::deserialize::<SubmitBatchResponse>(&blob) {
                    Ok(resp) => out.push((idx, resp)),
                    Err(e) => {
                        error!(err = %e, batch_index = idx, "Failed to deserialize batch signature");
                    }
                },
                Err(e) => {
                    error!(err = %e, "Failed to read batch_signatures row");
                }
            }
        }
        out
    }

    // ── Pending blobs accepted ───────────────────────────────────────────────

    pub(crate) fn load_pending_blobs_accepted(&self) -> Vec<u64> {
        let mut stmt = match self.conn.prepare("SELECT batch_index FROM pending_blobs_accepted") {
            Ok(s) => s,
            Err(_) => return vec![],
        };
        stmt.query_map([], |row| row.get::<_, i64>(0))
            .map(|rows| rows.filter_map(|r| r.ok()).map(|n| n as u64).collect())
            .unwrap_or_default()
    }

    // ── Dispatched batches ──────────────────────────────────────────────────

    /// Atomically move a batch from pending to dispatched, persisting initial
    /// RBF state (nonce + fees) alongside the transition.
    /// Single transaction: DELETE from pending + INSERT into dispatched.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn move_to_dispatched(
        &mut self,
        batch_index: u64,
        from_block: u64,
        to_block: u64,
        tx_hash: &[u8],
        l1_block: u64,
        nonce: u64,
        max_fee_per_gas: u128,
        max_priority_fee_per_gas: u128,
    ) {
        let tx = match self.conn.transaction() {
            Ok(tx) => tx,
            Err(e) => {
                error!(err = %e, batch_index, "Failed to begin move_to_dispatched tx");
                return;
            }
        };
        let ok = tx
            .execute("DELETE FROM pending_batches WHERE batch_index = ?1", params![batch_index])
            .and_then(|_| {
                tx.execute(
                    "INSERT OR REPLACE INTO dispatched_batches(
                batch_index, from_block, to_block, tx_hash, l1_block,
                nonce, max_fee_per_gas, max_priority_fee_per_gas
             ) VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                    params![
                        batch_index,
                        from_block,
                        to_block,
                        tx_hash,
                        l1_block,
                        nonce,
                        max_fee_per_gas.to_string(),
                        max_priority_fee_per_gas.to_string(),
                    ],
                )
            });
        match ok {
            Ok(_) => {
                if let Err(e) = tx.commit() {
                    error!(err = %e, batch_index, "Failed to commit move_to_dispatched");
                }
            }
            Err(e) => {
                error!(err = %e, batch_index, "Failed to move batch to dispatched — rolling back");
            }
        }
    }

    /// Atomically move a batch from pending to dispatched WITHOUT RBF state.
    /// Used for externally-preconfirmed batches (observed via L1 event) where
    /// we are not the submitter and therefore have no local nonce or fees.
    /// Single transaction: DELETE from pending + INSERT into dispatched with
    /// NULL RBF columns.
    pub(crate) fn move_to_dispatched_external(
        &mut self,
        batch_index: u64,
        from_block: u64,
        to_block: u64,
        tx_hash: &[u8],
        l1_block: u64,
    ) {
        let tx = match self.conn.transaction() {
            Ok(tx) => tx,
            Err(e) => {
                error!(err = %e, batch_index, "Failed to begin move_to_dispatched_external tx");
                return;
            }
        };
        let ok = tx.execute(
            "DELETE FROM pending_batches WHERE batch_index = ?1",
            params![batch_index],
        ).and_then(|_| tx.execute(
            "INSERT OR REPLACE INTO dispatched_batches(batch_index, from_block, to_block, tx_hash, l1_block)
             VALUES(?1, ?2, ?3, ?4, ?5)",
            params![batch_index, from_block, to_block, tx_hash, l1_block],
        ));
        match ok {
            Ok(_) => {
                if let Err(e) = tx.commit() {
                    error!(err = %e, batch_index, "Failed to commit move_to_dispatched_external");
                }
            }
            Err(e) => {
                error!(err = %e, batch_index, "Failed to move external batch to dispatched — rolling back");
            }
        }
    }

    /// Atomically clean up a finalized dispatched batch.
    /// Single transaction: DELETE dispatched + DELETE responses + DELETE signature.
    pub(crate) fn finalize_dispatched_batch(
        &mut self,
        batch_index: u64,
        from_block: u64,
        to_block: u64,
    ) {
        let tx = match self.conn.transaction() {
            Ok(tx) => tx,
            Err(e) => {
                error!(err = %e, batch_index, "Failed to begin finalize tx");
                return;
            }
        };
        let ok = tx
            .execute("DELETE FROM dispatched_batches WHERE batch_index = ?1", params![batch_index])
            .and_then(|_| {
                tx.execute(
                    "DELETE FROM block_responses WHERE block_number BETWEEN ?1 AND ?2",
                    params![from_block, to_block],
                )
            })
            .and_then(|_| {
                tx.execute(
                    "DELETE FROM batch_signatures WHERE batch_index = ?1",
                    params![batch_index],
                )
            });
        match ok {
            Ok(_) => {
                if let Err(e) = tx.commit() {
                    error!(err = %e, batch_index, "Failed to commit finalize_dispatched_batch");
                }
            }
            Err(e) => {
                error!(err = %e, batch_index, "Failed to finalize dispatched batch — rolling back");
            }
        }
    }

    /// Move a dispatched batch back to pending (reorg recovery).
    /// Single transaction: DELETE from dispatched + INSERT into pending.
    pub(crate) fn undispatch_batch(&mut self, batch_index: u64, from_block: u64, to_block: u64) {
        let tx = match self.conn.transaction() {
            Ok(tx) => tx,
            Err(e) => {
                error!(err = %e, batch_index, "Failed to begin undispatch tx");
                return;
            }
        };
        let ok = tx.execute(
            "DELETE FROM dispatched_batches WHERE batch_index = ?1",
            params![batch_index],
        ).and_then(|_| tx.execute(
            "INSERT OR REPLACE INTO pending_batches(batch_index, from_block, to_block, blobs_accepted)
             VALUES(?1, ?2, ?3, 1)",
            params![batch_index, from_block, to_block],
        ));
        match ok {
            Ok(_) => {
                if let Err(e) = tx.commit() {
                    error!(err = %e, batch_index, "Failed to commit undispatch_batch");
                }
            }
            Err(e) => {
                error!(err = %e, batch_index, "Failed to undispatch batch — rolling back");
            }
        }
    }

    /// Returns per-row: (batch_index, from_block, to_block, tx_hash, l1_block,
    /// nonce, max_fee_per_gas, max_priority_fee_per_gas). The last three are
    /// `Option` because legacy rows (pre-migration) have NULL in those columns.
    #[allow(clippy::type_complexity)]
    pub(crate) fn load_dispatched_batches(
        &self,
    ) -> Vec<(u64, u64, u64, Vec<u8>, u64, Option<u64>, Option<u128>, Option<u128>)> {
        let mut stmt = match self.conn.prepare(
            "SELECT batch_index, from_block, to_block, tx_hash, l1_block,
                    nonce, max_fee_per_gas, max_priority_fee_per_gas
             FROM dispatched_batches ORDER BY batch_index",
        ) {
            Ok(s) => s,
            Err(e) => {
                error!(err = %e, "Failed to prepare load_dispatched_batches");
                return vec![];
            }
        };
        stmt.query_map([], |row| {
            Ok((
                row.get::<_, i64>(0)? as u64,
                row.get::<_, i64>(1)? as u64,
                row.get::<_, i64>(2)? as u64,
                row.get::<_, Vec<u8>>(3)?,
                row.get::<_, i64>(4)? as u64,
                row.get::<_, Option<i64>>(5)?.map(|n| n as u64),
                row.get::<_, Option<String>>(6)?.and_then(|s| s.parse::<u128>().ok()),
                row.get::<_, Option<String>>(7)?.and_then(|s| s.parse::<u128>().ok()),
            ))
        })
        .map(|rows| rows.filter_map(|r| r.ok()).collect())
        .unwrap_or_default()
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// DB writer actor
// ═══════════════════════════════════════════════════════════════════════════
//
// All mutating SQLite operations route through an `mpsc::UnboundedSender<DbCommand>`
// into a single background task that batches per-row writes into one
// transaction per flush (size threshold OR timer tick) — collapsing N fsyncs
// into one. Atomic multi-statement commands drain the per-row buffer first,
// then run as their own dedicated transaction, preserving both atomicity and
// FIFO ordering with preceding per-row writes.
//
// Readers (`get_*`, `load_*`) stay synchronous on the same `Arc<Mutex<Db>>`
// the actor owns — startup reads happen before the actor runs; the lone
// runtime read (`get_batch_signature` in `sign_batch_io`) serializes on the
// Mutex with the actor.

#[allow(clippy::large_enum_variant)]
pub(crate) enum DbCommand {
    // Per-row (coalesced into one batched transaction on flush)
    SaveResponse(EthExecutionResponse),
    SaveCheckpoint(u64),
    SaveL1Checkpoint(u64),
    SaveLastBatchEnd(u64),
    SaveBatch(PendingBatch),
    UpdateBlobsAccepted(u64),
    SavePendingBlobsAccepted(u64),
    DeletePendingBlobsAccepted(u64),
    SaveBatchSignature {
        batch_index: u64,
        resp: SubmitBatchResponse,
    },
    DeleteBatchSignature(u64),
    UpdateRbfState {
        batch_index: u64,
        tx_hash: Vec<u8>,
        max_fee_per_gas: u128,
        max_priority_fee_per_gas: u128,
    },
    UpdateDispatchedL1Block {
        batch_index: u64,
        l1_block: u64,
    },

    // Atomic multi-statement (dedicated transaction; buffer flushed first)
    DeleteResponsesBatch(Vec<u64>),
    MoveToDispatched {
        batch_index: u64,
        from_block: u64,
        to_block: u64,
        tx_hash: Vec<u8>,
        l1_block: u64,
        nonce: u64,
        max_fee_per_gas: u128,
        max_priority_fee_per_gas: u128,
    },
    MoveToDispatchedExternal {
        batch_index: u64,
        from_block: u64,
        to_block: u64,
        tx_hash: Vec<u8>,
        l1_block: u64,
    },
    FinalizeDispatchedBatch {
        batch_index: u64,
        from_block: u64,
        to_block: u64,
    },
    UndispatchBatch {
        batch_index: u64,
        from_block: u64,
        to_block: u64,
    },
    WipeForRevert {
        start_batch_id: u64,
        l1_block: u64,
    },
}

impl DbCommand {
    fn is_atomic(&self) -> bool {
        matches!(
            self,
            DbCommand::DeleteResponsesBatch(_) |
                DbCommand::MoveToDispatched { .. } |
                DbCommand::MoveToDispatchedExternal { .. } |
                DbCommand::FinalizeDispatchedBatch { .. } |
                DbCommand::UndispatchBatch { .. } |
                DbCommand::WipeForRevert { .. }
        )
    }
}

/// Per-row flush threshold. Sized to cover a whole L2 batch (≤ ~10 k blocks)
/// in a handful of flushes while keeping buffered memory bounded.
const DB_BUFFER_FLUSH_SIZE: usize = 1000;

/// Timer-driven flush cadence. Short enough for live ops visibility; long
/// enough to amortize fsyncs across many per-row commands during bursts.
const DB_BUFFER_FLUSH_INTERVAL: Duration = Duration::from_millis(100);

/// Drain `rx` until the sender is dropped, applying commands to the DB.
/// Per-row commands coalesce into one transaction per flush; atomic multi-
/// statement commands flush any pending buffer first and then run as their
/// own transaction. On sender close, performs one final flush and exits.
pub(crate) async fn run_db_writer(
    mut rx: mpsc::UnboundedReceiver<DbCommand>,
    db: Arc<std::sync::Mutex<Db>>,
) {
    tracing::info!("DB writer actor started");
    let mut buffer: Vec<DbCommand> = Vec::with_capacity(DB_BUFFER_FLUSH_SIZE);
    let mut ticker = interval(DB_BUFFER_FLUSH_INTERVAL);
    ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);

    loop {
        tokio::select! {
            biased;
            maybe_cmd = rx.recv() => {
                match maybe_cmd {
                    Some(cmd) if cmd.is_atomic() => {
                        flush_per_row_buffer(&db, &mut buffer);
                        run_atomic_command(&db, cmd);
                    }
                    Some(cmd) => {
                        buffer.push(cmd);
                        if buffer.len() >= DB_BUFFER_FLUSH_SIZE {
                            flush_per_row_buffer(&db, &mut buffer);
                        }
                    }
                    None => {
                        flush_per_row_buffer(&db, &mut buffer);
                        break;
                    }
                }
            }
            _ = ticker.tick() => {
                if !buffer.is_empty() {
                    flush_per_row_buffer(&db, &mut buffer);
                }
            }
        }
    }
    tracing::info!("DB writer actor exited");
}

fn flush_per_row_buffer(db: &Arc<std::sync::Mutex<Db>>, buffer: &mut Vec<DbCommand>) {
    if buffer.is_empty() {
        return;
    }
    let drained: Vec<DbCommand> = std::mem::take(buffer);
    let count = drained.len();
    let mut guard = db.lock().unwrap_or_else(|e| e.into_inner());
    let tx = match guard.conn.transaction() {
        Ok(t) => t,
        Err(e) => {
            error!(err = %e, count, "db writer: begin tx failed — batch dropped");
            return;
        }
    };
    for cmd in drained {
        apply_per_row_in_tx(&tx, cmd);
    }
    if let Err(e) = tx.commit() {
        error!(err = %e, count, "db writer: commit failed — batch lost");
    }
}

fn apply_per_row_in_tx(tx: &rusqlite::Transaction<'_>, cmd: DbCommand) {
    match cmd {
        DbCommand::SaveResponse(resp) => {
            let blob = match bincode::serialize(&resp) {
                Ok(b) => b,
                Err(e) => {
                    error!(err = %e, "save_response: serialize failed");
                    return;
                }
            };
            if let Err(e) = tx.execute(
                "INSERT OR REPLACE INTO block_responses(block_number, response) VALUES(?1, ?2)",
                params![resp.block_number, blob],
            ) {
                error!(err = %e, block_number = resp.block_number, "save_response in batch");
            }
        }
        DbCommand::SaveCheckpoint(cp) => {
            if let Err(e) = tx.execute(
                "INSERT OR REPLACE INTO meta(key, value) VALUES('checkpoint', ?1)",
                params![cp.to_string()],
            ) {
                error!(err = %e, cp, "save_checkpoint in batch");
            }
        }
        DbCommand::SaveL1Checkpoint(cp) => {
            if let Err(e) = tx.execute(
                "INSERT OR REPLACE INTO meta(key, value) VALUES('l1_checkpoint', ?1)",
                params![cp.to_string()],
            ) {
                error!(err = %e, cp, "save_l1_checkpoint in batch");
            }
        }
        DbCommand::SaveLastBatchEnd(b) => {
            if let Err(e) = tx.execute(
                "INSERT OR REPLACE INTO meta(key, value) VALUES('last_batch_end', ?1)",
                params![b.to_string()],
            ) {
                error!(err = %e, block = b, "save_last_batch_end in batch");
            }
        }
        DbCommand::SaveBatch(batch) => {
            if let Err(e) = tx.execute(
                "INSERT OR REPLACE INTO pending_batches(batch_index, from_block, to_block, blobs_accepted) VALUES(?1, ?2, ?3, ?4)",
                params![batch.batch_index, batch.from_block, batch.to_block, batch.blobs_accepted as i64],
            ) {
                error!(err = %e, batch_index = batch.batch_index, "save_batch in batch");
            }
        }
        DbCommand::UpdateBlobsAccepted(batch_index) => {
            if let Err(e) = tx.execute(
                "UPDATE pending_batches SET blobs_accepted = 1 WHERE batch_index = ?1",
                params![batch_index],
            ) {
                error!(err = %e, batch_index, "update_blobs_accepted in batch");
            }
        }
        DbCommand::SavePendingBlobsAccepted(batch_index) => {
            if let Err(e) = tx.execute(
                "INSERT OR IGNORE INTO pending_blobs_accepted(batch_index) VALUES(?1)",
                params![batch_index],
            ) {
                error!(err = %e, batch_index, "save_pending_blobs_accepted in batch");
            }
        }
        DbCommand::DeletePendingBlobsAccepted(batch_index) => {
            if let Err(e) = tx.execute(
                "DELETE FROM pending_blobs_accepted WHERE batch_index = ?1",
                params![batch_index],
            ) {
                error!(err = %e, batch_index, "delete_pending_blobs_accepted in batch");
            }
        }
        DbCommand::SaveBatchSignature { batch_index, resp } => {
            let blob = match bincode::serialize(&resp) {
                Ok(b) => b,
                Err(e) => {
                    error!(err = %e, batch_index, "save_batch_signature: serialize failed");
                    return;
                }
            };
            if let Err(e) = tx.execute(
                "INSERT OR REPLACE INTO batch_signatures(batch_index, response) VALUES(?1, ?2)",
                params![batch_index, blob],
            ) {
                error!(err = %e, batch_index, "save_batch_signature in batch");
            }
        }
        DbCommand::DeleteBatchSignature(batch_index) => {
            if let Err(e) = tx.execute(
                "DELETE FROM batch_signatures WHERE batch_index = ?1",
                params![batch_index],
            ) {
                error!(err = %e, batch_index, "delete_batch_signature in batch");
            }
        }
        DbCommand::UpdateRbfState {
            batch_index,
            tx_hash,
            max_fee_per_gas,
            max_priority_fee_per_gas,
        } => {
            if let Err(e) = tx.execute(
                "UPDATE dispatched_batches SET tx_hash = ?2, max_fee_per_gas = ?3, max_priority_fee_per_gas = ?4 WHERE batch_index = ?1",
                params![batch_index, tx_hash, max_fee_per_gas.to_string(), max_priority_fee_per_gas.to_string()],
            ) {
                error!(err = %e, batch_index, "update_rbf_state in batch");
            }
        }
        DbCommand::UpdateDispatchedL1Block { batch_index, l1_block } => {
            if let Err(e) = tx.execute(
                "UPDATE dispatched_batches SET l1_block = ?2 WHERE batch_index = ?1",
                params![batch_index, l1_block],
            ) {
                error!(err = %e, batch_index, "update_dispatched_l1_block in batch");
            }
        }
        _ => unreachable!("atomic command reached per-row apply"),
    }
}

fn run_atomic_command(db: &Arc<std::sync::Mutex<Db>>, cmd: DbCommand) {
    let mut guard = db.lock().unwrap_or_else(|e| e.into_inner());
    match cmd {
        DbCommand::DeleteResponsesBatch(blocks) => guard.delete_responses_batch(&blocks),
        DbCommand::MoveToDispatched {
            batch_index,
            from_block,
            to_block,
            tx_hash,
            l1_block,
            nonce,
            max_fee_per_gas,
            max_priority_fee_per_gas,
        } => guard.move_to_dispatched(
            batch_index,
            from_block,
            to_block,
            &tx_hash,
            l1_block,
            nonce,
            max_fee_per_gas,
            max_priority_fee_per_gas,
        ),
        DbCommand::MoveToDispatchedExternal {
            batch_index,
            from_block,
            to_block,
            tx_hash,
            l1_block,
        } => {
            guard.move_to_dispatched_external(batch_index, from_block, to_block, &tx_hash, l1_block)
        }
        DbCommand::FinalizeDispatchedBatch { batch_index, from_block, to_block } => {
            guard.finalize_dispatched_batch(batch_index, from_block, to_block)
        }
        DbCommand::UndispatchBatch { batch_index, from_block, to_block } => {
            guard.undispatch_batch(batch_index, from_block, to_block)
        }
        DbCommand::WipeForRevert { start_batch_id, l1_block } => {
            guard.wipe_for_revert(start_batch_id, l1_block)
        }
        _ => unreachable!("non-atomic command reached atomic handler"),
    }
}
