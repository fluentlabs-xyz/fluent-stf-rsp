//! Cold-only witness persistence backed by `redb`.
//!
//! Used by the embedded forward-driver to durably store witnesses for
//! re-execution lookups (enclave key rotation) and to survive orchestrator
//! restarts. Zstd-compressed, byte-capped, block-window retention.

#![allow(clippy::result_large_err)]

use std::path::PathBuf;
use std::sync::Arc;

use redb::{Database, ReadableTable, TableDefinition};
use tracing::{error, info, warn};

use crate::types::ProveRequest;

const COLD_TABLE: TableDefinition<'_, u64, &[u8]> = TableDefinition::new("cold_witnesses");
const META_TABLE: TableDefinition<'_, &str, u64> = TableDefinition::new("cold_meta");
const TOTAL_BYTES_KEY: &str = "total_bytes";

pub struct WitnessHub {
    db: Arc<Database>,
    max_cold_bytes: u64,
    retention_blocks: u64,
}

impl std::fmt::Debug for WitnessHub {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WitnessHub").finish_non_exhaustive()
    }
}

impl WitnessHub {
    /// Open or create a cold witness database at `cold_file`.
    ///
    /// `retention_blocks` defines the window of retained blocks. On every
    /// successful `push(N)`, entries with `block_number < N - retention_blocks`
    /// are removed in the same write transaction. `retention_blocks == 0`
    /// disables retention (archive mode).
    pub fn new(cold_file: PathBuf, max_cold_bytes: u64, retention_blocks: u64) -> Self {
        if let Some(parent) = cold_file.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent)
                    .expect("failed to create cold witness parent directory");
            }
        }
        let db = Database::create(&cold_file)
            .unwrap_or_else(|e| panic!("failed to open cold redb at {cold_file:?}: {e}"));

        // Ensure both tables exist on a fresh file.
        {
            let write_txn = db.begin_write().expect("begin_write on fresh cold db");
            write_txn.open_table(COLD_TABLE).expect("open COLD_TABLE");
            write_txn.open_table(META_TABLE).expect("open META_TABLE");
            write_txn.commit().expect("commit fresh cold schema");
        }

        Self { db: Arc::new(db), max_cold_bytes, retention_blocks }
    }

    /// Persist a witness payload for `block_number`. Returns only after the
    /// `redb` commit (fsync) — await is the backpressure signal. Any failure
    /// is a hard error so the driver can refuse to advance past an
    /// unpersisted block (A2 atomicity invariant).
    pub async fn push(&self, block_number: u64, payload: &[u8]) -> eyre::Result<()> {
        let db = Arc::clone(&self.db);
        let max_cold_bytes = self.max_cold_bytes;
        let retention_blocks = self.retention_blocks;
        let payload = payload.to_vec();

        let join = tokio::task::spawn_blocking(move || -> eyre::Result<()> {
            let compressed = zstd::encode_all(payload.as_slice(), 3)
                .map_err(|e| eyre::eyre!("zstd encode: {e}"))?;
            commit_one_blocking(&db, block_number, compressed, max_cold_bytes, retention_blocks)
                .map_err(|e| eyre::eyre!("commit_one: {e}"))
        })
        .await;

        match join {
            Ok(Ok(())) => Ok(()),
            Ok(Err(e)) => {
                error!(block_number, err = %e, "Cold: witness commit failed");
                Err(e)
            }
            Err(e) => {
                error!(block_number, err = %e, "Cold: spawn_blocking join failed");
                Err(eyre::eyre!("spawn_blocking join: {e}"))
            }
        }
    }

    /// Highest block number currently in the cold store. Under window retention
    /// the newest row is never evicted, so `table.last()` is the resume point.
    pub fn last_committed_block(&self) -> eyre::Result<Option<u64>> {
        let read_txn = self.db.begin_read()?;
        let table = read_txn.open_table(COLD_TABLE)?;
        let last = table.last()?.map(|(k, _)| k.value());
        Ok(last)
    }

    /// Look up a single witness by block number. Returns `None` if missing
    /// or on decode failure.
    pub async fn get_witness(&self, block_number: u64) -> Option<ProveRequest> {
        let db = Arc::clone(&self.db);

        tokio::task::spawn_blocking(move || -> Option<ProveRequest> {
            let read_txn = db.begin_read().ok()?;
            let table = read_txn.open_table(COLD_TABLE).ok()?;
            let compressed = table.get(block_number).ok()??.value().to_vec();
            let payload = zstd::decode_all(compressed.as_slice()).ok()?;
            Some(ProveRequest { block_number, payload })
        })
        .await
        .ok()?
    }
}

/// Commit a single `(block_number, compressed)` entry in one write txn:
/// insert, prune stale entries below the retention window, update
/// `total_bytes`, log a warning if the size cap is exceeded.
fn commit_one_blocking(
    db: &Database,
    block_number: u64,
    compressed: Vec<u8>,
    max_cold_bytes: u64,
    retention_blocks: u64,
) -> Result<(), redb::Error> {
    let write_txn = db.begin_write()?;
    {
        let mut cold = write_txn.open_table(COLD_TABLE)?;
        let mut meta = write_txn.open_table(META_TABLE)?;

        let compressed_len = compressed.len() as u64;
        // Replacing an existing entry must update `total_bytes` by net delta,
        // not by addition — otherwise retries / replays inflate the counter.
        let prior_len: u64 = cold.get(block_number)?.map(|v| v.value().len() as u64).unwrap_or(0);
        cold.insert(block_number, compressed.as_slice())?;

        let mut total_bytes =
            read_total_bytes(&meta)?.saturating_sub(prior_len).saturating_add(compressed_len);

        // Retention: drop every entry with key < block_number - retention_blocks
        // in the same write txn. `retention_blocks == 0` → archive mode, no-op.
        if retention_blocks > 0 {
            let cutoff = block_number.saturating_sub(retention_blocks);
            if cutoff > 0 {
                let stale: Vec<(u64, u64)> = cold
                    .range(..cutoff)?
                    .filter_map(|r| r.ok().map(|(k, v)| (k.value(), v.value().len() as u64)))
                    .collect();
                for (k, size) in &stale {
                    cold.remove(*k)?;
                    total_bytes = total_bytes.saturating_sub(*size);
                }
                if !stale.is_empty() {
                    info!(block_number, cutoff, pruned = stale.len(), "Cold: retention prune");
                }
            }
        }

        meta.insert(TOTAL_BYTES_KEY, total_bytes)?;

        if total_bytes > max_cold_bytes {
            warn!(
                block_number,
                total_bytes,
                max_cold_bytes,
                retention_blocks,
                "Cold store exceeds size cap — lower WITNESS_RETENTION_BLOCKS or raise MAX_COLD_BYTES"
            );
        }
    }
    write_txn.commit()?;
    info!(block_number, "Cold: committed");
    Ok(())
}

fn read_total_bytes(meta: &redb::Table<'_, &str, u64>) -> Result<u64, redb::Error> {
    Ok(meta.get(TOTAL_BYTES_KEY)?.map(|v| v.value()).unwrap_or(0))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn unique_cold_file(tag: &str) -> PathBuf {
        use std::time::{SystemTime, UNIX_EPOCH};
        let nanos = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
        let base = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../target/witness_hub_tests");
        let dir = base.join(format!("{tag}_{nanos}"));
        std::fs::create_dir_all(&dir).unwrap();
        dir.join("cold.redb")
    }

    #[tokio::test]
    async fn push_get_roundtrip() {
        let file = unique_cold_file("roundtrip");
        let hub = WitnessHub::new(file.clone(), 10 * 1024 * 1024, 0);

        hub.push(42, &vec![7u8; 1024]).await.unwrap();

        let got = hub.get_witness(42).await.expect("block 42");
        assert_eq!(got.block_number, 42);
        assert_eq!(got.payload.len(), 1024);
        assert_eq!(got.payload[0], 7u8);

        drop(hub);
        let _ = std::fs::remove_file(&file);
    }

    #[tokio::test]
    async fn push_overwrite_preserves_total_bytes() {
        let file = unique_cold_file("overwrite");
        let hub = WitnessHub::new(file.clone(), 10 * 1024 * 1024, 0);

        hub.push(1, &vec![7u8; 100_000]).await.unwrap();
        let total1 = {
            let txn = hub.db.begin_read().unwrap();
            txn.open_table(META_TABLE).unwrap().get(TOTAL_BYTES_KEY).unwrap().unwrap().value()
        };

        hub.push(1, &vec![9u8; 100_000]).await.unwrap();
        let total2 = {
            let txn = hub.db.begin_read().unwrap();
            txn.open_table(META_TABLE).unwrap().get(TOTAL_BYTES_KEY).unwrap().unwrap().value()
        };

        // Same block_number, same compressed size — total must not double.
        assert_eq!(total1, total2);

        drop(hub);
        let _ = std::fs::remove_file(&file);
    }

    #[tokio::test]
    async fn last_committed_block_tracks_highest_push() {
        let file = unique_cold_file("last_committed");
        let hub = WitnessHub::new(file.clone(), 10 * 1024 * 1024, 0);

        assert_eq!(hub.last_committed_block().unwrap(), None);

        hub.push(10, &vec![1u8; 1024]).await.unwrap();
        assert_eq!(hub.last_committed_block().unwrap(), Some(10));

        hub.push(20, &vec![2u8; 1024]).await.unwrap();
        assert_eq!(hub.last_committed_block().unwrap(), Some(20));

        drop(hub);
        let _ = std::fs::remove_file(&file);
    }

    #[tokio::test]
    async fn survives_hub_drop_and_reopen() {
        let file = unique_cold_file("reopen");
        {
            let hub = WitnessHub::new(file.clone(), 10 * 1024 * 1024, 0);
            for i in 1..=5u64 {
                hub.push(i, &vec![i as u8; 300 * 1024]).await.unwrap();
            }
        }

        let hub = WitnessHub::new(file.clone(), 10 * 1024 * 1024, 0);
        let got = hub.get_witness(3).await.expect("block 3 in cold");
        assert_eq!(got.payload.len(), 300 * 1024);
        assert_eq!(got.payload[0], 3u8);

        drop(hub);
        let _ = std::fs::remove_file(&file);
    }

    #[tokio::test]
    async fn push_prunes_blocks_below_retention_window() {
        let file = unique_cold_file("retention");
        // retention = 3: push(N) removes entries with key < N - 3.
        let hub = WitnessHub::new(file.clone(), 10 * 1024 * 1024, 3);

        for i in 1..=10u64 {
            hub.push(i, &vec![i as u8; 1024]).await.unwrap();
        }

        let read_txn = hub.db.begin_read().unwrap();
        let table = read_txn.open_table(COLD_TABLE).unwrap();
        // After push(10), cutoff = 7 → blocks 1..=6 gone, 7..=10 stay.
        for i in 1..=6u64 {
            assert!(table.get(i).unwrap().is_none(), "block {i} must be pruned");
        }
        for i in 7..=10u64 {
            assert!(table.get(i).unwrap().is_some(), "block {i} must remain");
        }

        drop(read_txn);
        drop(hub);
        let _ = std::fs::remove_file(&file);
    }

    #[tokio::test]
    async fn retention_zero_keeps_all() {
        let file = unique_cold_file("archive");
        let hub = WitnessHub::new(file.clone(), 10 * 1024 * 1024, 0);

        for i in 1..=20u64 {
            hub.push(i, &vec![i as u8; 256]).await.unwrap();
        }

        let read_txn = hub.db.begin_read().unwrap();
        let table = read_txn.open_table(COLD_TABLE).unwrap();
        for i in 1..=20u64 {
            assert!(table.get(i).unwrap().is_some(), "archive mode must keep block {i}");
        }

        drop(read_txn);
        drop(hub);
        let _ = std::fs::remove_file(&file);
    }

    #[tokio::test]
    async fn push_prune_updates_total_bytes() {
        let file = unique_cold_file("prune_meta");
        let hub = WitnessHub::new(file.clone(), 10 * 1024 * 1024, 3);

        for i in 1..=10u64 {
            hub.push(i, &vec![i as u8; 300 * 1024]).await.unwrap();
        }

        let read_txn = hub.db.begin_read().unwrap();
        let table = read_txn.open_table(COLD_TABLE).unwrap();
        let meta = read_txn.open_table(META_TABLE).unwrap();
        let sum: u64 =
            table.iter().unwrap().filter_map(|r| r.ok().map(|(_, v)| v.value().len() as u64)).sum();
        let total = meta.get(TOTAL_BYTES_KEY).unwrap().unwrap().value();
        assert_eq!(sum, total, "meta[total_bytes] must equal sum of remaining value lengths");

        drop(read_txn);
        drop(hub);
        let _ = std::fs::remove_file(&file);
    }
}
