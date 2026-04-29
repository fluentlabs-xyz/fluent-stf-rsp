//! SQLite persistence for orchestrator crash recovery.
//!
//! Single source of truth for batch lifecycle state: every batch has one row
//! in the `batches` table whose `status` field tracks the canonical L1
//! contract progression (`committed → accepted → sent → preconfirmed →
//! finalized`). An orthogonal `enclave_signed` flag records the local
//! milestone of `/sign-batch-root` succeeding.
//!
//! `block_responses` is the durability backstop for the in-memory hot cache
//! held by `BatchAccumulator.responses` — async-batched writes amortize
//! fsyncs; on crash we lose the trailing un-flushed window and recover by
//! re-execution.
//!
//! `meta` carries the two non-derivable scalars: `l1_checkpoint` (listener
//! resume point) and `start_batch_id` (BatchReverted recovery anchor).
//!
//! All writes go through the actor in `run_db_writer`. Async per-row writes
//! coalesce into one transaction per flush; sync writes run as their own
//! dedicated transaction with an awaited oneshot ack so the caller observes
//! durability before proceeding.

use std::{path::Path, sync::Arc, time::Duration};

use alloy_primitives::B256;
use rusqlite::{params, Connection, OptionalExtension, Result};
use tokio::{
    sync::{mpsc, oneshot},
    time::{interval, MissedTickBehavior},
};
use tracing::error;

use crate::types::{EthExecutionResponse, SubmitBatchResponse};

// ============================================================================
// Status enum
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) enum BatchStatus {
    Committed = 0,
    Accepted = 1,
    Sent = 2,
    Preconfirmed = 3,
    Finalized = 4,
}

impl BatchStatus {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Committed => "committed",
            Self::Accepted => "accepted",
            Self::Sent => "sent",
            Self::Preconfirmed => "preconfirmed",
            Self::Finalized => "finalized",
        }
    }

    pub(crate) fn from_db(s: &str) -> Option<Self> {
        match s {
            "committed" => Some(Self::Committed),
            "accepted" => Some(Self::Accepted),
            "sent" => Some(Self::Sent),
            "preconfirmed" => Some(Self::Preconfirmed),
            "finalized" => Some(Self::Finalized),
            _ => None,
        }
    }
}

// ============================================================================
// Batch row + patch
// ============================================================================

#[derive(Debug, Clone)]
pub(crate) struct BatchRow {
    pub batch_index: u64,
    pub from_block: u64,
    pub to_block: u64,
    pub status: BatchStatus,
    pub enclave_signed: bool,
    pub signature: Option<SubmitBatchResponse>,
    pub tx_hash: Option<B256>,
    pub nonce: Option<u64>,
    pub max_fee_per_gas: Option<u128>,
    pub max_priority_fee_per_gas: Option<u128>,
    pub l1_block: Option<u64>,
    pub committed_at: u64,
    pub last_status_change_at: u64,
}

/// Sparse update — only fields the caller wants to change.
/// `None` → leave unchanged. `Some(None)` → set the column to NULL.
#[derive(Debug, Clone, Default)]
pub(crate) struct BatchPatch {
    pub status: Option<BatchStatus>,
    pub enclave_signed: Option<bool>,
    pub signature: Option<Option<SubmitBatchResponse>>,
    pub tx_hash: Option<Option<B256>>,
    pub nonce: Option<Option<u64>>,
    pub max_fee_per_gas: Option<Option<u128>>,
    pub max_priority_fee_per_gas: Option<Option<u128>>,
    pub l1_block: Option<Option<u64>>,
}

// ============================================================================
// Challenge enums + row + patch
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum ChallengeKind {
    Block,
    BatchRoot,
}

impl ChallengeKind {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Block => "block",
            Self::BatchRoot => "batch_root",
        }
    }

    pub(crate) fn from_db(s: &str) -> Option<Self> {
        match s {
            "block" => Some(Self::Block),
            "batch_root" => Some(Self::BatchRoot),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) enum ChallengeStatus {
    Received = 0,
    Sp1Proving = 1,
    Sp1Proved = 2,
    Dispatched = 3,
    Resolved = 4,
}

impl ChallengeStatus {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Received => "received",
            Self::Sp1Proving => "sp1_proving",
            Self::Sp1Proved => "sp1_proved",
            Self::Dispatched => "dispatched",
            Self::Resolved => "resolved",
        }
    }

    pub(crate) fn from_db(s: &str) -> Option<Self> {
        match s {
            "received" => Some(Self::Received),
            "sp1_proving" => Some(Self::Sp1Proving),
            "sp1_proved" => Some(Self::Sp1Proved),
            "dispatched" => Some(Self::Dispatched),
            "resolved" => Some(Self::Resolved),
            _ => None,
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) struct ChallengeRow {
    pub challenge_id: i64,
    pub kind: ChallengeKind,
    pub batch_index: u64,
    pub commitment: Option<B256>,
    pub status: ChallengeStatus,
    pub deadline: u64,
    pub sp1_request_id: Option<B256>,
    pub sp1_proof_bytes: Option<Vec<u8>>,
    pub tx_hash: Option<B256>,
    pub nonce: Option<u64>,
    pub max_fee_per_gas: Option<u128>,
    pub max_priority_fee_per_gas: Option<u128>,
    pub l1_block: Option<u64>,
    pub committed_at: u64,
    pub last_status_change_at: u64,
}

#[derive(Debug, Clone, Default)]
pub(crate) struct ChallengePatch {
    pub status: Option<ChallengeStatus>,
    pub sp1_request_id: Option<Option<B256>>,
    pub sp1_proof_bytes: Option<Option<Vec<u8>>>,
    pub tx_hash: Option<Option<B256>>,
    pub nonce: Option<Option<u64>>,
    pub max_fee_per_gas: Option<Option<u128>>,
    pub max_priority_fee_per_gas: Option<Option<u128>>,
    pub l1_block: Option<Option<u64>>,
}

// ============================================================================
// Db handle
// ============================================================================

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
            CREATE TABLE IF NOT EXISTS batches (
                batch_index              INTEGER PRIMARY KEY,
                from_block               INTEGER NOT NULL,
                to_block                 INTEGER NOT NULL,
                status                   TEXT    NOT NULL,
                enclave_signed           INTEGER NOT NULL DEFAULT 0,
                signature                BLOB,
                tx_hash                  BLOB,
                nonce                    INTEGER,
                max_fee_per_gas          TEXT,
                max_priority_fee_per_gas TEXT,
                l1_block                 INTEGER,
                committed_at             INTEGER NOT NULL,
                last_status_change_at    INTEGER NOT NULL,
                CHECK (status IN ('committed','accepted','sent','preconfirmed','finalized'))
            );
            CREATE INDEX IF NOT EXISTS batches_status_idx ON batches(status);

            CREATE TABLE IF NOT EXISTS block_responses (
                block_number INTEGER PRIMARY KEY,
                response     BLOB    NOT NULL
            );

            CREATE TABLE IF NOT EXISTS meta (
                key   TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS challenges (
                challenge_id              INTEGER PRIMARY KEY AUTOINCREMENT,
                kind                      TEXT    NOT NULL,
                batch_index               INTEGER NOT NULL,
                commitment                BLOB,
                status                    TEXT    NOT NULL,
                deadline                  INTEGER NOT NULL,
                sp1_request_id            BLOB,
                sp1_proof_bytes           BLOB,
                tx_hash                   BLOB,
                nonce                     INTEGER,
                max_fee_per_gas           TEXT,
                max_priority_fee_per_gas  TEXT,
                l1_block                  INTEGER,
                committed_at              INTEGER NOT NULL,
                last_status_change_at     INTEGER NOT NULL,
                CHECK (kind IN ('block','batch_root')),
                CHECK (status IN ('received','sp1_proving','sp1_proved','dispatched','resolved')),
                CHECK (kind = 'batch_root' OR commitment IS NOT NULL)
            );
            CREATE UNIQUE INDEX IF NOT EXISTS challenges_block_uniq
                ON challenges(kind, batch_index, commitment)
                WHERE kind = 'block';
            CREATE UNIQUE INDEX IF NOT EXISTS challenges_batch_root_uniq
                ON challenges(kind, batch_index)
                WHERE kind = 'batch_root';
            CREATE INDEX IF NOT EXISTS challenges_active_idx
                ON challenges(status, l1_block, committed_at);
            ",
        )?;
        Ok(Self { conn })
    }

    // ── Meta scalars ──────────────────────────────────────────────────────────

    pub(crate) fn get_l1_checkpoint(&self) -> Option<u64> {
        self.conn
            .query_row("SELECT value FROM meta WHERE key = 'l1_checkpoint'", [], |row| {
                row.get::<_, String>(0)
            })
            .optional()
            .ok()
            .flatten()
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

    pub(crate) fn get_start_batch_id(&self) -> Option<u64> {
        self.conn
            .query_row("SELECT value FROM meta WHERE key = 'start_batch_id'", [], |row| {
                row.get::<_, String>(0)
            })
            .optional()
            .ok()
            .flatten()
            .and_then(|s| s.parse().ok())
    }

    pub(crate) fn clear_start_batch_id(&self) {
        if let Err(e) = self.conn.execute("DELETE FROM meta WHERE key = 'start_batch_id'", []) {
            error!(err = %e, "Failed to clear start_batch_id");
        }
    }

    // ── Derived scalars (computed from batches) ───────────────────────────────

    /// `MAX(to_block)` across rows whose status is at least `Sent`.
    /// Drives the L2 driver checkpoint upper bound on startup.
    pub(crate) fn highest_dispatched_to_block(&self) -> Option<u64> {
        self.conn
            .query_row(
                "SELECT MAX(to_block) FROM batches \
                 WHERE status IN ('sent','preconfirmed','finalized')",
                [],
                |row| row.get::<_, Option<i64>>(0),
            )
            .ok()
            .flatten()
            .map(|v| v as u64)
    }

    /// First missing block in any unsent batch — drives startup checkpoint
    /// adjustment. Returns `(batch_index, gap_block)` for the lowest-index
    /// batch with any block in `from_block..=to_block` absent from
    /// `block_responses`. `None` means every unsent batch is fully covered.
    pub(crate) fn earliest_unsent_with_gap(&self) -> Option<(u64, u64)> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT batch_index, from_block, to_block FROM batches \
                 WHERE status NOT IN ('sent','preconfirmed','finalized') \
                 ORDER BY batch_index",
            )
            .ok()?;
        let rows: Vec<(u64, u64, u64)> = stmt
            .query_map([], |row| {
                Ok((
                    row.get::<_, i64>(0)? as u64,
                    row.get::<_, i64>(1)? as u64,
                    row.get::<_, i64>(2)? as u64,
                ))
            })
            .ok()?
            .filter_map(|r| r.ok())
            .collect();
        for (batch_index, from_block, to_block) in rows {
            for b in from_block..=to_block {
                let exists: bool = self
                    .conn
                    .query_row(
                        "SELECT 1 FROM block_responses WHERE block_number = ?1",
                        params![b as i64],
                        |_| Ok(true),
                    )
                    .optional()
                    .unwrap_or(None)
                    .unwrap_or(false);
                if !exists {
                    return Some((batch_index, b));
                }
            }
        }
        None
    }

    // ── Batch table ──────────────────────────────────────────────────────────

    pub(crate) fn upsert_batch(&self, row: &BatchRow) -> Result<()> {
        let sig_blob = row.signature.as_ref().map(bincode::serialize).transpose().map_err(|e| {
            rusqlite::Error::ToSqlConversionFailure(Box::new(std::io::Error::other(format!(
                "serialize SubmitBatchResponse: {e}"
            ))))
        })?;
        self.conn.execute(
            "INSERT OR REPLACE INTO batches (\
                batch_index, from_block, to_block, status, enclave_signed, \
                signature, tx_hash, nonce, max_fee_per_gas, max_priority_fee_per_gas, \
                l1_block, committed_at, last_status_change_at\
             ) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13)",
            params![
                row.batch_index as i64,
                row.from_block as i64,
                row.to_block as i64,
                row.status.as_str(),
                row.enclave_signed as i64,
                sig_blob,
                row.tx_hash.as_ref().map(|h| h.0.to_vec()),
                row.nonce.map(|n| n as i64),
                row.max_fee_per_gas.map(|n| n.to_string()),
                row.max_priority_fee_per_gas.map(|n| n.to_string()),
                row.l1_block.map(|n| n as i64),
                row.committed_at as i64,
                row.last_status_change_at as i64,
            ],
        )?;
        Ok(())
    }

    pub(crate) fn patch_batch(&self, batch_index: u64, patch: &BatchPatch) -> Result<()> {
        let mut sets: Vec<&'static str> = Vec::new();
        let mut binds: Vec<Box<dyn rusqlite::ToSql>> = Vec::new();

        if let Some(s) = patch.status {
            sets.push("status = ?");
            binds.push(Box::new(s.as_str().to_string()));
            sets.push("last_status_change_at = ?");
            binds.push(Box::new(now_ts() as i64));
        }
        if let Some(b) = patch.enclave_signed {
            sets.push("enclave_signed = ?");
            binds.push(Box::new(b as i64));
        }
        if let Some(ref sig_opt) = patch.signature {
            let sig_blob = sig_opt.as_ref().map(bincode::serialize).transpose().map_err(|e| {
                rusqlite::Error::ToSqlConversionFailure(Box::new(std::io::Error::other(format!(
                    "serialize signature: {e}"
                ))))
            })?;
            sets.push("signature = ?");
            binds.push(Box::new(sig_blob));
        }
        if let Some(tx) = patch.tx_hash {
            sets.push("tx_hash = ?");
            binds.push(Box::new(tx.map(|h| h.0.to_vec())));
        }
        if let Some(n) = patch.nonce {
            sets.push("nonce = ?");
            binds.push(Box::new(n.map(|v| v as i64)));
        }
        if let Some(f) = patch.max_fee_per_gas {
            sets.push("max_fee_per_gas = ?");
            binds.push(Box::new(f.map(|v| v.to_string())));
        }
        if let Some(f) = patch.max_priority_fee_per_gas {
            sets.push("max_priority_fee_per_gas = ?");
            binds.push(Box::new(f.map(|v| v.to_string())));
        }
        if let Some(b) = patch.l1_block {
            sets.push("l1_block = ?");
            binds.push(Box::new(b.map(|v| v as i64)));
        }
        if sets.is_empty() {
            return Ok(());
        }

        let sql = format!("UPDATE batches SET {} WHERE batch_index = ?", sets.join(", "));
        binds.push(Box::new(batch_index as i64));
        let bind_refs: Vec<&dyn rusqlite::ToSql> = binds.iter().map(|b| b.as_ref()).collect();
        self.conn.execute(&sql, &bind_refs[..])?;
        Ok(())
    }

    pub(crate) fn load_all_batches(&self) -> Vec<BatchRow> {
        let mut stmt = match self.conn.prepare(
            "SELECT batch_index, from_block, to_block, status, enclave_signed, \
                    signature, tx_hash, nonce, max_fee_per_gas, max_priority_fee_per_gas, \
                    l1_block, committed_at, last_status_change_at \
             FROM batches ORDER BY batch_index",
        ) {
            Ok(s) => s,
            Err(e) => {
                error!(err = %e, "load_all_batches prepare failed");
                return vec![];
            }
        };
        stmt.query_map([], row_to_batch_row)
            .map(|iter| iter.filter_map(|r| r.ok()).collect())
            .unwrap_or_default()
    }

    // ── block_responses ──────────────────────────────────────────────────────

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
            .map(|iter| iter.filter_map(|r| r.ok()).collect())
            .unwrap_or_default();
        blobs.into_iter().filter_map(|b| bincode::deserialize(&b).ok()).collect()
    }

    // ── Challenges table ─────────────────────────────────────────────────────

    /// `INSERT OR IGNORE` — idempotent on listener replay. Per-kind
    /// uniqueness is enforced by the partial unique indexes.
    pub(crate) fn insert_challenge(&self, row: &ChallengeRow) -> Result<()> {
        self.conn.execute(
            "INSERT OR IGNORE INTO challenges (\
                kind, batch_index, commitment, status, deadline, \
                sp1_request_id, sp1_proof_bytes, \
                tx_hash, nonce, max_fee_per_gas, max_priority_fee_per_gas, \
                l1_block, committed_at, last_status_change_at\
             ) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14)",
            params![
                row.kind.as_str(),
                row.batch_index as i64,
                row.commitment.as_ref().map(|h| h.0.to_vec()),
                row.status.as_str(),
                row.deadline as i64,
                row.sp1_request_id.as_ref().map(|h| h.0.to_vec()),
                row.sp1_proof_bytes.as_ref(),
                row.tx_hash.as_ref().map(|h| h.0.to_vec()),
                row.nonce.map(|n| n as i64),
                row.max_fee_per_gas.map(|n| n.to_string()),
                row.max_priority_fee_per_gas.map(|n| n.to_string()),
                row.l1_block.map(|n| n as i64),
                row.committed_at as i64,
                row.last_status_change_at as i64,
            ],
        )?;
        Ok(())
    }

    pub(crate) fn patch_challenge(&self, challenge_id: i64, patch: &ChallengePatch) -> Result<()> {
        let mut sets: Vec<&'static str> = Vec::new();
        let mut binds: Vec<Box<dyn rusqlite::ToSql>> = Vec::new();

        if let Some(s) = patch.status {
            sets.push("status = ?");
            binds.push(Box::new(s.as_str().to_string()));
            sets.push("last_status_change_at = ?");
            binds.push(Box::new(now_ts() as i64));
        }
        if let Some(ref id) = patch.sp1_request_id {
            sets.push("sp1_request_id = ?");
            binds.push(Box::new(id.as_ref().map(|h| h.0.to_vec())));
        }
        if let Some(ref bytes) = patch.sp1_proof_bytes {
            sets.push("sp1_proof_bytes = ?");
            binds.push(Box::new(bytes.clone()));
        }
        if let Some(tx) = patch.tx_hash {
            sets.push("tx_hash = ?");
            binds.push(Box::new(tx.map(|h| h.0.to_vec())));
        }
        if let Some(n) = patch.nonce {
            sets.push("nonce = ?");
            binds.push(Box::new(n.map(|v| v as i64)));
        }
        if let Some(f) = patch.max_fee_per_gas {
            sets.push("max_fee_per_gas = ?");
            binds.push(Box::new(f.map(|v| v.to_string())));
        }
        if let Some(f) = patch.max_priority_fee_per_gas {
            sets.push("max_priority_fee_per_gas = ?");
            binds.push(Box::new(f.map(|v| v.to_string())));
        }
        if let Some(b) = patch.l1_block {
            sets.push("l1_block = ?");
            binds.push(Box::new(b.map(|v| v as i64)));
        }
        if sets.is_empty() {
            return Ok(());
        }

        let sql = format!("UPDATE challenges SET {} WHERE challenge_id = ?", sets.join(", "));
        binds.push(Box::new(challenge_id));
        let bind_refs: Vec<&dyn rusqlite::ToSql> = binds.iter().map(|b| b.as_ref()).collect();
        self.conn.execute(&sql, &bind_refs[..])?;
        Ok(())
    }

    /// Worker gate: pick the next row to drive forward.
    pub(crate) fn find_active_challenge(&self) -> Option<ChallengeRow> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT challenge_id, kind, batch_index, commitment, status, deadline, \
                        sp1_request_id, sp1_proof_bytes, tx_hash, nonce, \
                        max_fee_per_gas, max_priority_fee_per_gas, l1_block, \
                        committed_at, last_status_change_at \
                 FROM challenges \
                 WHERE status = 'received' \
                    OR status = 'sp1_proving' \
                    OR status = 'sp1_proved' \
                    OR (status = 'dispatched' AND l1_block IS NULL) \
                 ORDER BY committed_at ASC \
                 LIMIT 1",
            )
            .ok()?;
        stmt.query_row([], row_to_challenge_row).optional().ok().flatten()
    }

    pub(crate) fn find_challenge_by_id(&self, challenge_id: i64) -> Option<ChallengeRow> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT challenge_id, kind, batch_index, commitment, status, deadline, \
                        sp1_request_id, sp1_proof_bytes, tx_hash, nonce, \
                        max_fee_per_gas, max_priority_fee_per_gas, l1_block, \
                        committed_at, last_status_change_at \
                 FROM challenges WHERE challenge_id = ?1",
            )
            .ok()?;
        stmt.query_row(params![challenge_id], row_to_challenge_row).optional().ok().flatten()
    }

    /// Lookup for `ChallengeResolved` / `BatchRootChallengeResolved` event
    /// idempotency. For `Block` kind, `commitment` is required and matches
    /// exactly; for `BatchRoot` kind, `commitment` is ignored.
    pub(crate) fn find_challenge_by_event(
        &self,
        kind: ChallengeKind,
        batch_index: u64,
        commitment: Option<B256>,
    ) -> Option<ChallengeRow> {
        match kind {
            ChallengeKind::Block => {
                let c = commitment?;
                let mut stmt = self
                    .conn
                    .prepare(
                        "SELECT challenge_id, kind, batch_index, commitment, status, deadline, \
                                sp1_request_id, sp1_proof_bytes, tx_hash, nonce, \
                                max_fee_per_gas, max_priority_fee_per_gas, l1_block, \
                                committed_at, last_status_change_at \
                         FROM challenges \
                         WHERE kind = 'block' AND batch_index = ?1 AND commitment = ?2",
                    )
                    .ok()?;
                stmt.query_row(params![batch_index as i64, c.0.to_vec()], row_to_challenge_row)
                    .optional()
                    .ok()
                    .flatten()
            }
            ChallengeKind::BatchRoot => {
                let mut stmt = self
                    .conn
                    .prepare(
                        "SELECT challenge_id, kind, batch_index, commitment, status, deadline, \
                                sp1_request_id, sp1_proof_bytes, tx_hash, nonce, \
                                max_fee_per_gas, max_priority_fee_per_gas, l1_block, \
                                committed_at, last_status_change_at \
                         FROM challenges \
                         WHERE kind = 'batch_root' AND batch_index = ?1",
                    )
                    .ok()?;
                stmt.query_row(params![batch_index as i64], row_to_challenge_row)
                    .optional()
                    .ok()
                    .flatten()
            }
        }
    }

    /// Snapshot of dispatched rows whose receipt the finalization worker
    /// must reconcile against L1 (for reorg detection).
    pub(crate) fn dispatched_challenges_with_l1_block(&self) -> Vec<(i64, B256, u64)> {
        let mut stmt = match self.conn.prepare(
            "SELECT challenge_id, tx_hash, l1_block FROM challenges \
             WHERE status = 'dispatched' AND tx_hash IS NOT NULL AND l1_block IS NOT NULL",
        ) {
            Ok(s) => s,
            Err(e) => {
                error!(err = %e, "dispatched_challenges_with_l1_block prepare failed");
                return vec![];
            }
        };
        stmt.query_map([], |row| {
            let id: i64 = row.get(0)?;
            let tx_blob: Vec<u8> = row.get(1)?;
            let l1_block: i64 = row.get(2)?;
            let tx_hash = B256::try_from(tx_blob.as_slice()).map_err(|e| {
                rusqlite::Error::FromSqlConversionFailure(
                    1,
                    rusqlite::types::Type::Blob,
                    Box::new(std::io::Error::other(format!("tx_hash B256: {e}"))),
                )
            })?;
            Ok((id, tx_hash, l1_block as u64))
        })
        .map(|iter| iter.filter_map(|r| r.ok()).collect())
        .unwrap_or_default()
    }

    // ── BatchReverted recovery ───────────────────────────────────────────────

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
                "DELETE FROM batches; \
                 DELETE FROM block_responses; \
                 DELETE FROM challenges; \
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
}

fn row_to_batch_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<BatchRow> {
    let status_str: String = row.get(3)?;
    let status = BatchStatus::from_db(&status_str).ok_or_else(|| {
        rusqlite::Error::FromSqlConversionFailure(
            3,
            rusqlite::types::Type::Text,
            Box::new(std::io::Error::other(format!("unknown batch status: {status_str}"))),
        )
    })?;
    let enclave_signed: i64 = row.get(4)?;
    let signature_blob: Option<Vec<u8>> = row.get(5)?;
    let signature = signature_blob
        .map(|b| bincode::deserialize::<SubmitBatchResponse>(&b))
        .transpose()
        .map_err(|e| {
            rusqlite::Error::FromSqlConversionFailure(
                5,
                rusqlite::types::Type::Blob,
                Box::new(std::io::Error::other(format!("deserialize signature: {e}"))),
            )
        })?;
    let tx_hash_blob: Option<Vec<u8>> = row.get(6)?;
    let tx_hash = tx_hash_blob
        .map(|b| {
            B256::try_from(b.as_slice()).map_err(|e| {
                rusqlite::Error::FromSqlConversionFailure(
                    6,
                    rusqlite::types::Type::Blob,
                    Box::new(std::io::Error::other(format!("tx_hash B256: {e}"))),
                )
            })
        })
        .transpose()?;
    let nonce: Option<i64> = row.get(7)?;
    let max_fee: Option<String> = row.get(8)?;
    let max_priority: Option<String> = row.get(9)?;
    let l1_block: Option<i64> = row.get(10)?;
    let committed_at: i64 = row.get(11)?;
    let last_status_change_at: i64 = row.get(12)?;
    Ok(BatchRow {
        batch_index: row.get::<_, i64>(0)? as u64,
        from_block: row.get::<_, i64>(1)? as u64,
        to_block: row.get::<_, i64>(2)? as u64,
        status,
        enclave_signed: enclave_signed != 0,
        signature,
        tx_hash,
        nonce: nonce.map(|n| n as u64),
        max_fee_per_gas: max_fee.and_then(|s| s.parse::<u128>().ok()),
        max_priority_fee_per_gas: max_priority.and_then(|s| s.parse::<u128>().ok()),
        l1_block: l1_block.map(|v| v as u64),
        committed_at: committed_at as u64,
        last_status_change_at: last_status_change_at as u64,
    })
}

fn row_to_challenge_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<ChallengeRow> {
    let kind_str: String = row.get(1)?;
    let kind = ChallengeKind::from_db(&kind_str).ok_or_else(|| {
        rusqlite::Error::FromSqlConversionFailure(
            1,
            rusqlite::types::Type::Text,
            Box::new(std::io::Error::other(format!("unknown challenge kind: {kind_str}"))),
        )
    })?;
    let commitment_blob: Option<Vec<u8>> = row.get(3)?;
    let commitment = commitment_blob
        .map(|b| {
            B256::try_from(b.as_slice()).map_err(|e| {
                rusqlite::Error::FromSqlConversionFailure(
                    3,
                    rusqlite::types::Type::Blob,
                    Box::new(std::io::Error::other(format!("commitment B256: {e}"))),
                )
            })
        })
        .transpose()?;
    let status_str: String = row.get(4)?;
    let status = ChallengeStatus::from_db(&status_str).ok_or_else(|| {
        rusqlite::Error::FromSqlConversionFailure(
            4,
            rusqlite::types::Type::Text,
            Box::new(std::io::Error::other(format!("unknown challenge status: {status_str}"))),
        )
    })?;
    let deadline: i64 = row.get(5)?;
    let sp1_request_blob: Option<Vec<u8>> = row.get(6)?;
    let sp1_request_id = sp1_request_blob
        .map(|b| {
            B256::try_from(b.as_slice()).map_err(|e| {
                rusqlite::Error::FromSqlConversionFailure(
                    6,
                    rusqlite::types::Type::Blob,
                    Box::new(std::io::Error::other(format!("sp1_request_id B256: {e}"))),
                )
            })
        })
        .transpose()?;
    let sp1_proof_bytes: Option<Vec<u8>> = row.get(7)?;
    let tx_hash_blob: Option<Vec<u8>> = row.get(8)?;
    let tx_hash = tx_hash_blob
        .map(|b| {
            B256::try_from(b.as_slice()).map_err(|e| {
                rusqlite::Error::FromSqlConversionFailure(
                    8,
                    rusqlite::types::Type::Blob,
                    Box::new(std::io::Error::other(format!("tx_hash B256: {e}"))),
                )
            })
        })
        .transpose()?;
    let nonce: Option<i64> = row.get(9)?;
    let max_fee: Option<String> = row.get(10)?;
    let max_priority: Option<String> = row.get(11)?;
    let l1_block: Option<i64> = row.get(12)?;
    let committed_at: i64 = row.get(13)?;
    let last_status_change_at: i64 = row.get(14)?;
    Ok(ChallengeRow {
        challenge_id: row.get::<_, i64>(0)?,
        kind,
        batch_index: row.get::<_, i64>(2)? as u64,
        commitment,
        status,
        deadline: deadline as u64,
        sp1_request_id,
        sp1_proof_bytes,
        tx_hash,
        nonce: nonce.map(|n| n as u64),
        max_fee_per_gas: max_fee.and_then(|s| s.parse::<u128>().ok()),
        max_priority_fee_per_gas: max_priority.and_then(|s| s.parse::<u128>().ok()),
        l1_block: l1_block.map(|v| v as u64),
        committed_at: committed_at as u64,
        last_status_change_at: last_status_change_at as u64,
    })
}

pub(crate) fn now_ts() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

// ============================================================================
// DbCommand actor
// ============================================================================
//
// Async per-row writes coalesce into one transaction per flush (size threshold
// or 100 ms timer). Sync writes flush the per-row buffer first, run as their
// own dedicated transaction, then signal a oneshot so the caller observes
// durability. Caller-side helper: `db_send_sync(...).await`.

pub(crate) enum DbCommand {
    Async(AsyncOp),
    Sync(SyncOp, oneshot::Sender<()>),
}

#[allow(clippy::large_enum_variant)]
pub(crate) enum AsyncOp {
    SaveResponse(EthExecutionResponse),
    DeleteResponsesBatch(Vec<u64>),
    SaveL1Checkpoint(u64),
}

#[allow(clippy::large_enum_variant)]
pub(crate) enum SyncOp {
    UpsertBatch(BatchRow),
    PatchBatch { batch_index: u64, patch: BatchPatch },
    WipeForRevert { start_batch_id: u64, l1_block: u64 },
    InsertChallenge(ChallengeRow),
    PatchChallenge { challenge_id: i64, patch: ChallengePatch },
}

const DB_BUFFER_FLUSH_SIZE: usize = 1000;
const DB_BUFFER_FLUSH_INTERVAL: Duration = Duration::from_millis(100);

pub(crate) async fn run_db_writer(
    mut rx: mpsc::UnboundedReceiver<DbCommand>,
    db: Arc<std::sync::Mutex<Db>>,
) {
    tracing::info!("DB writer actor started");
    let mut buffer: Vec<AsyncOp> = Vec::with_capacity(DB_BUFFER_FLUSH_SIZE);
    let mut ticker = interval(DB_BUFFER_FLUSH_INTERVAL);
    ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);

    loop {
        tokio::select! {
            biased;
            maybe_cmd = rx.recv() => {
                match maybe_cmd {
                    Some(DbCommand::Sync(op, ack)) => {
                        flush_async_buffer(&db, &mut buffer);
                        run_sync_op(&db, op);
                        let _ = ack.send(());
                    }
                    Some(DbCommand::Async(op)) => {
                        buffer.push(op);
                        if buffer.len() >= DB_BUFFER_FLUSH_SIZE {
                            flush_async_buffer(&db, &mut buffer);
                        }
                    }
                    None => {
                        flush_async_buffer(&db, &mut buffer);
                        break;
                    }
                }
            }
            _ = ticker.tick() => {
                if !buffer.is_empty() {
                    flush_async_buffer(&db, &mut buffer);
                }
            }
        }
    }
    tracing::info!("DB writer actor exited");
}

fn flush_async_buffer(db: &Arc<std::sync::Mutex<Db>>, buffer: &mut Vec<AsyncOp>) {
    if buffer.is_empty() {
        return;
    }
    let drained: Vec<AsyncOp> = std::mem::take(buffer);
    let count = drained.len();
    let mut guard = db.lock().unwrap_or_else(|e| e.into_inner());
    let tx = match guard.conn.transaction() {
        Ok(t) => t,
        Err(e) => {
            error!(err = %e, count, "db writer: begin tx failed — batch dropped");
            return;
        }
    };
    for op in drained {
        apply_async_op(&tx, op);
    }
    if let Err(e) = tx.commit() {
        error!(err = %e, count, "db writer: commit failed — batch lost");
    }
}

fn apply_async_op(tx: &rusqlite::Transaction<'_>, op: AsyncOp) {
    match op {
        AsyncOp::SaveResponse(resp) => {
            let blob = match bincode::serialize(&resp) {
                Ok(b) => b,
                Err(e) => {
                    error!(err = %e, "save_response: serialize failed");
                    return;
                }
            };
            if let Err(e) = tx.execute(
                "INSERT OR REPLACE INTO block_responses(block_number, response) VALUES(?1, ?2)",
                params![resp.block_number as i64, blob],
            ) {
                error!(err = %e, block_number = resp.block_number, "save_response in batch");
            }
        }
        AsyncOp::DeleteResponsesBatch(blocks) => {
            for block in blocks {
                if let Err(e) = tx.execute(
                    "DELETE FROM block_responses WHERE block_number = ?1",
                    params![block as i64],
                ) {
                    error!(err = %e, block_number = block, "delete_responses_batch row");
                }
            }
        }
        AsyncOp::SaveL1Checkpoint(cp) => {
            if let Err(e) = tx.execute(
                "INSERT OR REPLACE INTO meta(key, value) VALUES('l1_checkpoint', ?1)",
                params![cp.to_string()],
            ) {
                error!(err = %e, cp, "save_l1_checkpoint in batch");
            }
        }
    }
}

fn run_sync_op(db: &Arc<std::sync::Mutex<Db>>, op: SyncOp) {
    let mut guard = db.lock().unwrap_or_else(|e| e.into_inner());
    match op {
        SyncOp::UpsertBatch(row) => {
            if let Err(e) = guard.upsert_batch(&row) {
                error!(err = %e, batch_index = row.batch_index, "upsert_batch failed");
            }
        }
        SyncOp::PatchBatch { batch_index, patch } => {
            if let Err(e) = guard.patch_batch(batch_index, &patch) {
                error!(err = %e, batch_index, "patch_batch failed");
            }
        }
        SyncOp::WipeForRevert { start_batch_id, l1_block } => {
            guard.wipe_for_revert(start_batch_id, l1_block);
        }
        SyncOp::InsertChallenge(row) => {
            if let Err(e) = guard.insert_challenge(&row) {
                error!(err = %e, batch_index = row.batch_index, "insert_challenge failed");
            }
        }
        SyncOp::PatchChallenge { challenge_id, patch } => {
            if let Err(e) = guard.patch_challenge(challenge_id, &patch) {
                error!(err = %e, challenge_id, "patch_challenge failed");
            }
        }
    }
}

/// Send a sync write through the actor and await its ack.
/// Caller observes durability (one fsync) before returning.
pub(crate) async fn db_send_sync(
    db_tx: &mpsc::UnboundedSender<DbCommand>,
    op: SyncOp,
) -> eyre::Result<()> {
    let (ack_tx, ack_rx) = oneshot::channel();
    db_tx.send(DbCommand::Sync(op, ack_tx)).map_err(|_| eyre::eyre!("db writer channel closed"))?;
    ack_rx.await.map_err(|_| eyre::eyre!("db writer dropped ack"))?;
    Ok(())
}
