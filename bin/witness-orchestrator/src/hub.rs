//! Cold-only witness persistence backed by `redb`.
//!
//! Used by the embedded forward-driver to durably store witnesses for
//! re-execution lookups (enclave key rotation) and to survive orchestrator
//! restarts. Zstd-compressed, byte-capped, explicit range acknowledgement.

#![allow(clippy::result_large_err)]

use std::path::PathBuf;
use std::sync::Arc;

use redb::{Database, ReadableTable, TableDefinition};
use tracing::{error, info, warn};

use crate::types::ProveRequest;

const COLD_TABLE: TableDefinition<'_, u64, &[u8]> = TableDefinition::new("cold_witnesses");
const META_TABLE: TableDefinition<'_, &str, u64> = TableDefinition::new("cold_meta");
const TOTAL_BYTES_KEY: &str = "total_bytes";
/// Highest `block_number` ever durably committed to the cold store. Written
/// on every successful commit in `commit_one_blocking` and **never** cleared
/// or decremented by `acknowledge_range` / eviction. This is the driver's
/// resume-point source of truth: `max(COLD_TABLE key)` is unsafe because
/// `acknowledge_range` deletes acknowledged rows in steady state.
const LAST_COMMITTED_KEY: &str = "last_committed_block";

pub(crate) struct WitnessHub {
    db: Arc<Database>,
    max_cold_bytes: u64,
}

impl std::fmt::Debug for WitnessHub {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WitnessHub").finish_non_exhaustive()
    }
}

impl WitnessHub {
    /// Open or create a cold witness database at `cold_file`.
    pub(crate) fn new(cold_file: PathBuf, max_cold_bytes: u64) -> Self {
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

        Self { db: Arc::new(db), max_cold_bytes }
    }

    /// Persist a witness payload for `block_number`. Returns only after the
    /// `redb` commit (fsync) — await is the backpressure signal. Any failure
    /// is now a hard error so the driver can refuse to advance past an
    /// unpersisted block (A2 atomicity invariant).
    pub(crate) async fn push(&self, block_number: u64, payload: &[u8]) -> eyre::Result<()> {
        let db = Arc::clone(&self.db);
        let max_cold_bytes = self.max_cold_bytes;
        let payload = payload.to_vec();

        let join = tokio::task::spawn_blocking(move || -> eyre::Result<()> {
            let compressed = zstd::encode_all(payload.as_slice(), 3)
                .map_err(|e| eyre::eyre!("zstd encode: {e}"))?;
            commit_one_blocking(&db, block_number, compressed, max_cold_bytes)
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

    /// Highest `block_number` ever durably committed to the cold store.
    /// Unlike `max(COLD_TABLE key)`, this is **monotonic**: it is written
    /// on every commit and never decremented by `acknowledge_range` or
    /// eviction. It is the driver's resume-point source of truth.
    pub(crate) fn last_committed_block(&self) -> eyre::Result<Option<u64>> {
        let read_txn = self.db.begin_read()?;
        let meta = read_txn.open_table(META_TABLE)?;
        Ok(meta.get(LAST_COMMITTED_KEY)?.map(|v| v.value()))
    }

    /// Look up a single witness by block number. Returns `None` if missing
    /// or on decode failure.
    pub(crate) async fn get_witness(&self, block_number: u64) -> Option<ProveRequest> {
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

    /// Delete all cold-tier entries in `[from_block, to_block]`.
    pub(crate) async fn acknowledge_range(&self, from_block: u64, to_block: u64) {
        let db = Arc::clone(&self.db);
        let from = from_block;
        let to = to_block.saturating_add(1);

        let join = tokio::task::spawn_blocking(move || -> Result<u64, redb::Error> {
            let write_txn = db.begin_write()?;
            let freed = {
                let mut cold_table = write_txn.open_table(COLD_TABLE)?;
                let mut meta = write_txn.open_table(META_TABLE)?;

                let keys: Vec<(u64, u64)> = cold_table
                    .range(from..to)?
                    .filter_map(|r| r.ok().map(|(k, v)| (k.value(), v.value().len() as u64)))
                    .collect();
                let mut freed: u64 = 0;
                for (k, size) in &keys {
                    cold_table.remove(*k)?;
                    freed = freed.saturating_add(*size);
                }
                let new_total = read_total_bytes(&meta)?.saturating_sub(freed);
                meta.insert(TOTAL_BYTES_KEY, new_total)?;
                freed
            };
            write_txn.commit()?;
            Ok(freed)
        })
        .await;

        match join {
            Ok(Ok(_)) => info!(from_block, to_block, "Cold witnesses acknowledged"),
            Ok(Err(e)) => warn!(err = %e, "Cold: acknowledge commit failed"),
            Err(e) => warn!(err = %e, "Cold: acknowledge spawn_blocking failed"),
        }
    }
}

/// Commit a single `(block_number, compressed)` entry in one write txn:
/// insert, update `total_bytes`, log a warning if the size cap is exceeded.
///
/// Eviction is **not** performed here — un-acknowledged witnesses may still
/// be needed for re-execution after enclave key rotation. Only
/// [`WitnessHub::acknowledge_range`] (called after successful batch signing)
/// removes cold-store entries. If `total_bytes` exceeds the cap, the operator
/// should investigate why signing is falling behind or increase the limit.
fn commit_one_blocking(
    db: &Database,
    block_number: u64,
    compressed: Vec<u8>,
    max_cold_bytes: u64,
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
        let new_total =
            read_total_bytes(&meta)?.saturating_sub(prior_len).saturating_add(compressed_len);
        meta.insert(TOTAL_BYTES_KEY, new_total)?;
        // Monotonic resume point — never cleared or decremented.
        let prev_committed: u64 = meta.get(LAST_COMMITTED_KEY)?.map(|v| v.value()).unwrap_or(0);
        if block_number > prev_committed {
            meta.insert(LAST_COMMITTED_KEY, block_number)?;
        }

        if new_total > max_cold_bytes {
            warn!(
                block_number,
                total_bytes = new_total,
                max_cold_bytes,
                "Cold store exceeds size cap — signing pipeline may be falling behind"
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
        let hub = WitnessHub::new(file.clone(), 10 * 1024 * 1024);

        hub.push(42, &vec![7u8; 1024]).await.unwrap();

        let got = hub.get_witness(42).await.expect("block 42");
        assert_eq!(got.block_number, 42);
        assert_eq!(got.payload.len(), 1024);
        assert_eq!(got.payload[0], 7u8);

        drop(hub);
        let _ = std::fs::remove_file(&file);
    }

    #[tokio::test]
    async fn acknowledge_range_deletes_and_updates_meta() {
        let file = unique_cold_file("ack_range");
        let hub = WitnessHub::new(file.clone(), 10 * 1024 * 1024);

        for i in 1..=10u64 {
            hub.push(i, &vec![i as u8; 300 * 1024]).await.unwrap();
        }
        hub.acknowledge_range(1, 3).await;

        let read_txn = hub.db.begin_read().unwrap();
        let table = read_txn.open_table(COLD_TABLE).unwrap();
        let meta = read_txn.open_table(META_TABLE).unwrap();

        let sum: u64 =
            table.iter().unwrap().filter_map(|r| r.ok().map(|(_, v)| v.value().len() as u64)).sum();
        let total = meta.get(TOTAL_BYTES_KEY).unwrap().unwrap().value();
        assert_eq!(sum, total, "meta[total_bytes] must equal sum of value lengths");

        // Blocks 1..=3 are gone, 4..=10 remain.
        assert!(table.get(1u64).unwrap().is_none());
        assert!(table.get(3u64).unwrap().is_none());
        assert!(table.get(4u64).unwrap().is_some());

        drop(read_txn);
        drop(hub);
        let _ = std::fs::remove_file(&file);
    }

    #[tokio::test]
    async fn push_overwrite_preserves_total_bytes() {
        let file = unique_cold_file("overwrite");
        let hub = WitnessHub::new(file.clone(), 10 * 1024 * 1024);

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
        let hub = WitnessHub::new(file.clone(), 10 * 1024 * 1024);

        assert_eq!(hub.last_committed_block().unwrap(), None);

        hub.push(10, &vec![1u8; 1024]).await.unwrap();
        assert_eq!(hub.last_committed_block().unwrap(), Some(10));

        hub.push(20, &vec![2u8; 1024]).await.unwrap();
        assert_eq!(hub.last_committed_block().unwrap(), Some(20));

        // acknowledge_range must NOT decrement LAST_COMMITTED_KEY
        hub.acknowledge_range(10, 20).await;
        assert_eq!(hub.last_committed_block().unwrap(), Some(20));

        drop(hub);
        let _ = std::fs::remove_file(&file);
    }

    #[tokio::test]
    async fn survives_hub_drop_and_reopen() {
        let file = unique_cold_file("reopen");
        {
            let hub = WitnessHub::new(file.clone(), 10 * 1024 * 1024);
            for i in 1..=5u64 {
                hub.push(i, &vec![i as u8; 300 * 1024]).await.unwrap();
            }
        }

        let hub = WitnessHub::new(file.clone(), 10 * 1024 * 1024);
        let got = hub.get_witness(3).await.expect("block 3 in cold");
        assert_eq!(got.payload.len(), 300 * 1024);
        assert_eq!(got.payload[0], 3u8);

        drop(hub);
        let _ = std::fs::remove_file(&file);
    }
}
