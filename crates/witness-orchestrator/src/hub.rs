//! In-process witness hub: byte-bounded ring buffer + broadcast fan-out.
//!
//! The ExEx pushes witnesses via [`WitnessHub::push`]. The gRPC server reads
//! them via [`WitnessHub::subscribe`] (live stream) and
//! [`WitnessHub::snapshot_from`] (replay on reconnect).
//!
//! ## Memory model
//!
//! Each `ProveRequest` is wrapped in `Arc`. The ring buffer and broadcast
//! channel hold `Arc` clones pointing to the same allocation — witness data
//! is never duplicated.
//!
//! ## Cold tier
//!
//! Entries evicted from the hot ring (or oversized payloads that bypass it)
//! are persisted in a single `redb` file. A write transaction wraps each
//! put/delete so `meta[total_bytes] == sum(cold_witnesses values)` holds
//! by construction. Backfill mode amortizes fsync by batching.

#![allow(clippy::result_large_err)]

use std::collections::VecDeque;
use std::path::PathBuf;
use std::sync::{Arc, Mutex as StdMutex};

use redb::{Database, ReadableTable, TableDefinition};
use tokio::sync::{broadcast, RwLock};
use tracing::{error, info, warn};

use crate::types::{ProveRequest, SharedProveRequest};

/// Broadcast channel capacity for live subscribers.
const BROADCAST_CAPACITY: usize = 1024;

/// Cold witnesses: key = block number, value = zstd(level=3, bincode(payload)).
const COLD_TABLE: TableDefinition<'_, u64, &[u8]> = TableDefinition::new("cold_witnesses");
/// Meta table for counters. Single known key today: `TOTAL_BYTES_KEY`.
const META_TABLE: TableDefinition<'_, &str, u64> = TableDefinition::new("cold_meta");
const TOTAL_BYTES_KEY: &str = "total_bytes";

/// How many entries `new_for_backfill` buffers before committing a batch.
/// One fsync per 64 puts — big backfill speed-up. Crash window is bounded
/// by this constant; backfill is re-runnable so the loss is acceptable.
const BACKFILL_BATCH_SIZE: usize = 64;

/// Pending backfill batch: compressed `(block_number, bytes)` entries
/// awaiting a commit. Shared between concurrent `write_entry` calls on
/// the blocking pool.
type BackfillBatch = Arc<StdMutex<Vec<(u64, Vec<u8>)>>>;

/// Default age (in blocks) after which cold-tier entries are evicted in
/// live mode. 48 h at 1 block/sec. Backfill mode disables this.
const DEFAULT_MAX_COLD_AGE: u64 = 60 * 60 * 48;

struct ColdTier {
    db: Arc<Database>,
    max_cold_bytes: u64,
    max_age: Option<u64>,
    /// `None` in live mode (per-entry commit). `Some(..)` in backfill mode —
    /// holds compressed entries until `BACKFILL_BATCH_SIZE` is reached or
    /// the hub is dropped.
    batch: Option<BackfillBatch>,
}

impl Drop for ColdTier {
    fn drop(&mut self) {
        let Some(batch) = self.batch.as_ref() else { return };
        let mut guard = batch.lock().unwrap_or_else(|e| e.into_inner());
        if guard.is_empty() {
            return;
        }
        let entries = std::mem::take(&mut *guard);
        drop(guard);
        if let Err(e) =
            commit_batch_blocking(&self.db, entries, self.max_cold_bytes, self.max_age, None)
        {
            error!(err = %e, "Cold: final batch flush failed on Drop");
        }
    }
}

impl ColdTier {
    async fn write_entry(&self, req: SharedProveRequest) -> Result<(), String> {
        let db = Arc::clone(&self.db);
        let max_cold_bytes = self.max_cold_bytes;
        let max_age = self.max_age;
        let batch = self.batch.clone();
        let block_number = req.block_number;
        let payload = req.payload.clone();

        let join = tokio::task::spawn_blocking(move || -> Result<(), String> {
            let compressed =
                zstd::encode_all(payload.as_slice(), 3).map_err(|e| format!("zstd encode: {e}"))?;

            match batch {
                None => commit_one_blocking(&db, block_number, compressed, max_cold_bytes, max_age)
                    .map_err(|e| format!("commit_one: {e}")),
                Some(batch) => {
                    let mut guard = batch.lock().unwrap_or_else(|e| e.into_inner());
                    guard.push((block_number, compressed));
                    if guard.len() >= BACKFILL_BATCH_SIZE {
                        let drained = std::mem::take(&mut *guard);
                        drop(guard);
                        commit_batch_blocking(
                            &db,
                            drained,
                            max_cold_bytes,
                            max_age,
                            Some(block_number),
                        )
                        .map_err(|e| format!("commit_batch: {e}"))?;
                    }
                    Ok(())
                }
            }
        })
        .await;

        match join {
            Ok(res) => res,
            Err(e) => Err(format!("spawn_blocking join: {e}")),
        }
    }
}

/// Commit a single `(block_number, compressed)` entry in one write txn:
/// insert, update `total_bytes`, run size + age eviction.
fn commit_one_blocking(
    db: &Database,
    block_number: u64,
    compressed: Vec<u8>,
    max_cold_bytes: u64,
    max_age: Option<u64>,
) -> Result<(), redb::Error> {
    let write_txn = db.begin_write()?;
    {
        let mut cold = write_txn.open_table(COLD_TABLE)?;
        let mut meta = write_txn.open_table(META_TABLE)?;

        let compressed_len = compressed.len() as u64;
        cold.insert(block_number, compressed.as_slice())?;
        let new_total = read_total_bytes(&meta)?.saturating_add(compressed_len);
        meta.insert(TOTAL_BYTES_KEY, new_total)?;

        while read_total_bytes(&meta)? > max_cold_bytes {
            if !evict_oldest(&mut cold, &mut meta)? {
                break;
            }
        }

        if let Some(max_age) = max_age {
            loop {
                let Some((oldest_block, _)) = peek_oldest(&cold)? else { break };
                if block_number.saturating_sub(oldest_block) < max_age {
                    break;
                }
                if !evict_oldest(&mut cold, &mut meta)? {
                    break;
                }
            }
        }
    }
    write_txn.commit()?;
    info!(block_number, "Cold: committed");
    Ok(())
}

/// Commit up to `BACKFILL_BATCH_SIZE` entries in a single write txn.
/// `newest_block` is the "now" for age eviction; pass `None` on the final
/// shutdown flush (age eviction is skipped).
fn commit_batch_blocking(
    db: &Database,
    entries: Vec<(u64, Vec<u8>)>,
    max_cold_bytes: u64,
    max_age: Option<u64>,
    newest_block: Option<u64>,
) -> Result<(), redb::Error> {
    if entries.is_empty() {
        return Ok(());
    }
    let len = entries.len();
    let write_txn = db.begin_write()?;
    {
        let mut cold = write_txn.open_table(COLD_TABLE)?;
        let mut meta = write_txn.open_table(META_TABLE)?;

        let mut added: u64 = 0;
        for (block_number, compressed) in &entries {
            cold.insert(*block_number, compressed.as_slice())?;
            added = added.saturating_add(compressed.len() as u64);
        }
        let new_total = read_total_bytes(&meta)?.saturating_add(added);
        meta.insert(TOTAL_BYTES_KEY, new_total)?;

        while read_total_bytes(&meta)? > max_cold_bytes {
            if !evict_oldest(&mut cold, &mut meta)? {
                break;
            }
        }

        if let (Some(max_age), Some(newest)) = (max_age, newest_block) {
            loop {
                let Some((oldest_block, _)) = peek_oldest(&cold)? else { break };
                if newest.saturating_sub(oldest_block) < max_age {
                    break;
                }
                if !evict_oldest(&mut cold, &mut meta)? {
                    break;
                }
            }
        }
    }
    write_txn.commit()?;
    info!(batch = len, "Cold: batch committed");
    Ok(())
}

fn read_total_bytes(meta: &redb::Table<'_, &str, u64>) -> Result<u64, redb::Error> {
    Ok(meta.get(TOTAL_BYTES_KEY)?.map(|v| v.value()).unwrap_or(0))
}

fn peek_oldest(cold: &redb::Table<'_, u64, &[u8]>) -> Result<Option<(u64, u64)>, redb::Error> {
    let mut iter = cold.iter()?;
    match iter.next() {
        Some(Ok((k, v))) => Ok(Some((k.value(), v.value().len() as u64))),
        Some(Err(e)) => Err(e.into()),
        None => Ok(None),
    }
}

fn evict_oldest(
    cold: &mut redb::Table<'_, u64, &[u8]>,
    meta: &mut redb::Table<'_, &str, u64>,
) -> Result<bool, redb::Error> {
    let oldest = peek_oldest(cold)?;
    let Some((oldest_block, size)) = oldest else { return Ok(false) };
    cold.remove(oldest_block)?;
    let new_total = read_total_bytes(meta)?.saturating_sub(size);
    meta.insert(TOTAL_BYTES_KEY, new_total)?;
    info!(oldest_block, freed_bytes = size, "Cold: evicted");
    Ok(true)
}

/// Central witness distribution point.
///
/// Shared via `Arc` between the ExEx (writer) and gRPC server (reader).
pub struct WitnessHub {
    tx: broadcast::Sender<SharedProveRequest>,
    buffer: RwLock<RingBuffer>,
    cold: Option<ColdTier>,
}

impl std::fmt::Debug for WitnessHub {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WitnessHub").finish_non_exhaustive()
    }
}

/// Byte-bounded ring buffer for witness replay.
struct RingBuffer {
    entries: VecDeque<SharedProveRequest>,
    total_bytes: usize,
    max_bytes: usize,
}

impl RingBuffer {
    fn new(max_bytes: usize) -> Self {
        Self { entries: VecDeque::new(), total_bytes: 0, max_bytes }
    }

    fn push(&mut self, req: SharedProveRequest) -> Vec<SharedProveRequest> {
        let entry_bytes = req.payload.len();
        let mut evicted = Vec::new();

        while self.total_bytes + entry_bytes > self.max_bytes {
            match self.entries.pop_front() {
                Some(e) => {
                    self.total_bytes -= e.payload.len();
                    evicted.push(e);
                }
                None => break,
            }
        }

        self.total_bytes += entry_bytes;
        self.entries.push_back(req);
        evicted
    }

    fn snapshot_from(&self, from_block: u64) -> Vec<SharedProveRequest> {
        self.entries.iter().filter(|r| r.block_number >= from_block).cloned().collect()
    }

    fn oldest_block(&self) -> Option<u64> {
        self.entries.front().map(|r| r.block_number)
    }

    fn stats(&self) -> (usize, usize) {
        (self.entries.len(), self.total_bytes)
    }
}

impl WitnessHub {
    /// Create a new hub with a byte-bounded hot ring buffer and optional cold tier.
    /// `cold_file` is the path to the `.redb` database file.
    pub fn new(max_bytes: usize, cold_file: Option<PathBuf>, max_cold_bytes: u64) -> Self {
        Self::new_inner(max_bytes, cold_file, max_cold_bytes, Some(DEFAULT_MAX_COLD_AGE), false)
    }

    /// Create a new hub configured for one-shot backfill:
    /// - no age-based eviction,
    /// - hot ring sized to 1 byte so every push spills straight to cold,
    /// - commits batched in groups of `BACKFILL_BATCH_SIZE` for fsync amortization.
    pub fn new_for_backfill(cold_file: PathBuf, max_cold_bytes: u64) -> Self {
        Self::new_inner(1, Some(cold_file), max_cold_bytes, None, true)
    }

    fn new_inner(
        max_bytes: usize,
        cold_file: Option<PathBuf>,
        max_cold_bytes: u64,
        max_age: Option<u64>,
        batch_mode: bool,
    ) -> Self {
        let (tx, _) = broadcast::channel(BROADCAST_CAPACITY);

        let cold = cold_file.map(|path| {
            if let Some(parent) = path.parent() {
                if !parent.as_os_str().is_empty() {
                    std::fs::create_dir_all(parent)
                        .expect("failed to create cold witness parent directory");
                }
            }
            let db = Database::create(&path)
                .unwrap_or_else(|e| panic!("failed to open cold redb at {path:?}: {e}"));

            // Ensure both tables exist on a fresh file.
            {
                let write_txn = db.begin_write().expect("begin_write on fresh cold db");
                write_txn.open_table(COLD_TABLE).expect("open COLD_TABLE");
                write_txn.open_table(META_TABLE).expect("open META_TABLE");
                write_txn.commit().expect("commit fresh cold schema");
            }

            ColdTier {
                db: Arc::new(db),
                max_cold_bytes,
                max_age,
                batch: batch_mode
                    .then(|| Arc::new(StdMutex::new(Vec::with_capacity(BACKFILL_BATCH_SIZE)))),
            }
        });

        Self { tx, buffer: RwLock::new(RingBuffer::new(max_bytes)), cold }
    }

    /// Push a new witness into the buffer and broadcast it to live subscribers.
    ///
    /// Returns only after the cold commit (if any) has completed. The await
    /// is the backpressure signal — callers automatically throttle to the
    /// cold tier's fsync rate.
    pub async fn push(&self, req: Arc<ProveRequest>) {
        let payload_bytes = req.payload.len();
        let block_number = req.block_number;

        let oversized = payload_bytes > self.buffer.read().await.max_bytes;

        if oversized {
            warn!(
                block_number,
                payload_bytes, "Oversized witness — bypassing ring buffer, sending to cold tier"
            );
            if let Some(cold) = &self.cold {
                if let Err(e) = cold.write_entry(Arc::clone(&req)).await {
                    error!(block_number, err = %e, "Cold: oversized witness commit failed");
                }
            }
            let _ = self.tx.send(req);
            return;
        }

        let evicted = {
            let mut buf = self.buffer.write().await;
            let evicted = buf.push(Arc::clone(&req));
            let (entries, total) = buf.stats();
            info!(
                block_number,
                payload_bytes,
                buffer_entries = entries,
                buffer_bytes = total,
                "Witness buffered"
            );
            evicted
        };

        if let Some(cold) = &self.cold {
            for entry in evicted {
                let ev_block = entry.block_number;
                if let Err(e) = cold.write_entry(entry).await {
                    error!(block_number = ev_block, err = %e, "Cold: evicted witness commit failed");
                }
            }
        }

        let _ = self.tx.send(req);
    }

    /// Subscribe to live witness broadcasts.
    pub fn subscribe(&self) -> broadcast::Receiver<SharedProveRequest> {
        self.tx.subscribe()
    }

    /// Return all buffered witnesses with `block_number >= from_block`.
    pub async fn snapshot_from(&self, from_block: u64) -> Vec<SharedProveRequest> {
        let buf = self.buffer.read().await;
        buf.snapshot_from(from_block)
    }

    /// Returns the block number of the oldest entry in the hot buffer, if any.
    pub async fn oldest_buffered_block(&self) -> Option<u64> {
        self.buffer.read().await.oldest_block()
    }

    /// Returns sorted block numbers in `[from, to)` that have cold-tier entries.
    pub fn cold_blocks_in_range(&self, from: u64, to: u64) -> Vec<u64> {
        let Some(cold) = &self.cold else { return vec![] };
        let Ok(read_txn) = cold.db.begin_read() else { return vec![] };
        let Ok(table) = read_txn.open_table(COLD_TABLE) else { return vec![] };
        let Ok(iter) = table.range(from..to) else { return vec![] };
        iter.filter_map(|r| r.ok().map(|(k, _)| k.value())).collect()
    }

    /// Read one cold-tier entry. Returns None if not found or decode fails.
    pub async fn read_cold_block(&self, block_number: u64) -> Option<SharedProveRequest> {
        let cold = self.cold.as_ref()?;
        let db = Arc::clone(&cold.db);

        tokio::task::spawn_blocking(move || -> Option<SharedProveRequest> {
            let read_txn = db.begin_read().ok()?;
            let table = read_txn.open_table(COLD_TABLE).ok()?;
            let compressed = table.get(block_number).ok()??.value().to_vec();
            let payload = zstd::decode_all(compressed.as_slice()).ok()?;
            Some(Arc::new(ProveRequest { block_number, payload }))
        })
        .await
        .ok()?
    }

    /// Get a single block witness from hot buffer by block number.
    pub async fn get_block(&self, block_number: u64) -> Option<SharedProveRequest> {
        let buf = self.buffer.read().await;
        buf.entries.iter().find(|r| r.block_number == block_number).cloned()
    }

    /// Get a single witness by block number: tries hot buffer first, then cold tier.
    pub async fn get_witness(&self, block_number: u64) -> Option<SharedProveRequest> {
        if let Some(req) = self.get_block(block_number).await {
            return Some(req);
        }
        self.read_cold_block(block_number).await
    }

    /// Deletes cold-tier entries for blocks in `[from_block, to_block]`.
    pub async fn acknowledge_range(&self, from_block: u64, to_block: u64) {
        self.delete_cold_range(from_block, to_block.saturating_add(1)).await;
        info!(from_block, to_block, "Cold witnesses acknowledged (range)");
    }

    /// Deletes all cold-tier entries with block_number <= up_to_block.
    pub async fn acknowledge(&self, up_to_block: u64) {
        self.delete_cold_range(0, up_to_block.saturating_add(1)).await;
        info!(up_to_block, "Cold witnesses acknowledged");
    }

    /// One-shot delete of all entries in `[from, to)` inside a single write txn.
    async fn delete_cold_range(&self, from: u64, to: u64) {
        let Some(cold) = &self.cold else { return };
        let db = Arc::clone(&cold.db);
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
            Ok(Ok(_)) => {}
            Ok(Err(e)) => warn!(err = %e, "Cold: acknowledge commit failed"),
            Err(e) => warn!(err = %e, "Cold: acknowledge spawn_blocking failed"),
        }
    }
}

impl Default for WitnessHub {
    fn default() -> Self {
        Self::new(1024 * 1024 * 1024, None, 10 * 1024 * 1024 * 1024)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_MAX_BYTES: usize = 1024 * 1024 * 1024;

    fn make_req(block_number: u64, size: usize) -> Arc<ProveRequest> {
        Arc::new(ProveRequest { block_number, payload: vec![0u8; size] })
    }

    #[test]
    fn evicts_by_bytes() {
        let mut buf = RingBuffer::new(TEST_MAX_BYTES);
        let chunk = TEST_MAX_BYTES / 4;
        for i in 0..4 {
            let _ = buf.push(make_req(i, chunk));
        }
        assert_eq!(buf.entries.len(), 4);
        assert_eq!(buf.total_bytes, chunk * 4);

        let _ = buf.push(make_req(4, chunk));
        assert!(buf.total_bytes <= TEST_MAX_BYTES);
        assert!(buf.entries.iter().all(|r| r.block_number != 0));
    }

    #[test]
    fn snapshot_from_filters() {
        let mut buf = RingBuffer::new(TEST_MAX_BYTES);
        for i in 10..15 {
            let _ = buf.push(make_req(i, 100));
        }

        let snap = buf.snapshot_from(12);
        let numbers: Vec<u64> = snap.iter().map(|r| r.block_number).collect();
        assert_eq!(numbers, vec![12, 13, 14]);
    }

    fn unique_cold_file(tag: &str) -> PathBuf {
        use std::time::{SystemTime, UNIX_EPOCH};
        let nanos = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
        // Use target/ instead of /tmp so tests work in sandboxes with
        // tiny tmpfs quotas.
        let base = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../target/witness_hub_tests");
        let dir = base.join(format!("{tag}_{nanos}"));
        std::fs::create_dir_all(&dir).unwrap();
        dir.join("cold.redb")
    }

    /// After a sequence of oversized pushes and a range ack, the `total_bytes`
    /// meta entry must match the sum of value lengths in the cold table.
    #[tokio::test]
    async fn cold_meta_matches_sum_of_values() {
        let file = unique_cold_file("meta_matches");
        let hub = WitnessHub::new(256 * 1024, Some(file.clone()), 10 * 1024 * 1024);

        for i in 1..=10u64 {
            hub.push(Arc::new(ProveRequest {
                block_number: i,
                payload: vec![i as u8; 300 * 1024],
            }))
            .await;
        }
        hub.acknowledge_range(1, 3).await;

        let cold = hub.cold.as_ref().unwrap();
        let read_txn = cold.db.begin_read().unwrap();
        let table = read_txn.open_table(COLD_TABLE).unwrap();
        let meta = read_txn.open_table(META_TABLE).unwrap();

        let sum: u64 =
            table.iter().unwrap().filter_map(|r| r.ok().map(|(_, v)| v.value().len() as u64)).sum();
        let total = meta.get(TOTAL_BYTES_KEY).unwrap().unwrap().value();
        assert_eq!(sum, total, "meta[total_bytes] must equal sum of value lengths");

        drop(read_txn);
        drop(hub);
        let _ = std::fs::remove_file(&file);
    }

    #[tokio::test]
    async fn oversized_witness_bypasses_hot_buffer() {
        let file = unique_cold_file("oversized");
        let hub = WitnessHub::new(64 * 1024, Some(file.clone()), 10 * 1024 * 1024);

        for i in 1..=3u64 {
            hub.push(Arc::new(ProveRequest { block_number: i, payload: vec![0u8; 10 * 1024] }))
                .await;
        }
        assert_eq!(hub.buffer.read().await.entries.len(), 3);

        hub.push(Arc::new(ProveRequest { block_number: 100, payload: vec![7u8; 128 * 1024] }))
            .await;

        let buf = hub.buffer.read().await;
        assert_eq!(buf.entries.len(), 3);
        assert!(buf.entries.iter().all(|r| r.block_number != 100));
        drop(buf);

        // Sync commit → block is visible immediately, no polling needed.
        let cold_blocks = hub.cold_blocks_in_range(0, u64::MAX);
        assert_eq!(cold_blocks, vec![100]);

        drop(hub);
        let _ = std::fs::remove_file(&file);
    }

    /// Backfill hubs disable age eviction and batch commits — drop the hub
    /// to force the final flush, then re-open and verify both blocks persist.
    #[tokio::test]
    async fn cold_tier_no_age_eviction_when_disabled() {
        let file = unique_cold_file("no_age_evict");
        {
            let hub = WitnessHub::new_for_backfill(file.clone(), 10 * 1024 * 1024);
            hub.push(Arc::new(ProveRequest { block_number: 1, payload: vec![1u8; 1024] })).await;
            hub.push(Arc::new(ProveRequest {
                block_number: DEFAULT_MAX_COLD_AGE + 2,
                payload: vec![2u8; 1024],
            }))
            .await;
            // hub drops here → ColdTier::Drop flushes the trailing batch.
        }

        let hub = WitnessHub::new_for_backfill(file.clone(), 10 * 1024 * 1024);
        let blocks = hub.cold_blocks_in_range(0, u64::MAX);
        assert!(blocks.contains(&1), "block 1 must not be age-evicted");
        assert!(blocks.contains(&(DEFAULT_MAX_COLD_AGE + 2)));

        drop(hub);
        let _ = std::fs::remove_file(&file);
    }

    /// Durability end-to-end: write, drop, reopen, range scan, single read.
    #[tokio::test]
    async fn cold_survives_hub_drop_and_reopen() {
        let file = unique_cold_file("reopen");
        {
            let hub = WitnessHub::new(256 * 1024, Some(file.clone()), 10 * 1024 * 1024);
            for i in 1..=5u64 {
                hub.push(Arc::new(ProveRequest {
                    block_number: i,
                    payload: vec![i as u8; 300 * 1024],
                }))
                .await;
            }
        }

        let hub = WitnessHub::new(256 * 1024, Some(file.clone()), 10 * 1024 * 1024);
        let blocks = hub.cold_blocks_in_range(0, u64::MAX);
        assert_eq!(blocks, vec![1, 2, 3, 4, 5]);

        let got = hub.read_cold_block(3).await.expect("block 3 in cold");
        assert_eq!(got.payload.len(), 300 * 1024);
        assert_eq!(got.payload[0], 3u8);

        drop(hub);
        let _ = std::fs::remove_file(&file);
    }
}
