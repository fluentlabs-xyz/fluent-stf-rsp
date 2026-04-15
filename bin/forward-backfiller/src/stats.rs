//! Pipeline statistics: per-block samples, 10s heartbeat,
//! end-of-run summary. No external histogram crate — `Vec<u64>` +
//! sort is simpler than hdrhistogram and fast enough at O(n log n)
//! on ≤100k samples.
//!
//! Extended from `bin/mdbx-witness-backfiller/src/stats.rs` with
//! per-phase fields for the forward-sync loop: `fetch_ms`, `trie_ms`,
//! `save_ms`, `witness_ms`.

use std::time::{Duration, Instant};

use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tracing::info;

const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(10);

#[derive(Debug, Clone, Copy)]
pub(crate) struct BlockStats {
    pub block_number: u64,
    pub total_ms: u64,
    pub fetch_ms: u64,
    pub execute_ms: u64,
    pub trie_ms: u64,
    pub save_ms: u64,
    pub witness_ms: u64,
    pub serialize_ms: u64,
    pub push_ms: u64,
    pub payload_bytes: u64,
}

#[derive(Debug, Default)]
struct Accum {
    totals: Vec<u64>,
    fetches: Vec<u64>,
    executes: Vec<u64>,
    tries: Vec<u64>,
    saves: Vec<u64>,
    witnesses: Vec<u64>,
    serializes: Vec<u64>,
    pushes: Vec<u64>,
    total_bytes: u64,
    done: u64,
}

impl Accum {
    fn record(&mut self, s: BlockStats) {
        let _ = s.block_number;
        self.totals.push(s.total_ms);
        self.fetches.push(s.fetch_ms);
        self.executes.push(s.execute_ms);
        self.tries.push(s.trie_ms);
        self.saves.push(s.save_ms);
        self.witnesses.push(s.witness_ms);
        self.serializes.push(s.serialize_ms);
        self.pushes.push(s.push_ms);
        self.total_bytes += s.payload_bytes;
        self.done += 1;
    }
}

fn percentile(samples: &mut [u64], p: f64) -> u64 {
    if samples.is_empty() {
        return 0;
    }
    samples.sort_unstable();
    let idx = ((samples.len() as f64 - 1.0) * p).round() as usize;
    samples[idx]
}

#[derive(Debug, Clone)]
pub(crate) struct Summary {
    pub succeeded: u64,
    pub failed: u64,
    pub wall: Duration,
    pub total_bytes: u64,
    pub total_p50: u64,
    pub total_p95: u64,
    pub total_p99: u64,
    pub fetch_p50: u64,
    pub execute_p50: u64,
    pub trie_p50: u64,
    pub save_p50: u64,
    pub witness_p50: u64,
    pub serialize_p50: u64,
    pub push_p50: u64,
}

impl Summary {
    pub(crate) fn log(&self) {
        info!(
            succeeded = self.succeeded,
            failed = self.failed,
            wall_secs = self.wall.as_secs(),
            total_bytes = self.total_bytes,
            total_p50 = self.total_p50,
            total_p95 = self.total_p95,
            total_p99 = self.total_p99,
            fetch_p50 = self.fetch_p50,
            execute_p50 = self.execute_p50,
            trie_p50 = self.trie_p50,
            save_p50 = self.save_p50,
            witness_p50 = self.witness_p50,
            serialize_p50 = self.serialize_p50,
            push_p50 = self.push_p50,
            "forward-backfill summary"
        );
    }
}

pub(crate) struct StatsHandle {
    pub tx: mpsc::UnboundedSender<BlockStats>,
    pub join: JoinHandle<Summary>,
}

/// Spawn the stats task. Drop all `tx` clones to signal end — task
/// drains remaining samples and returns the final [`Summary`].
pub(crate) fn spawn(total_planned: u64) -> StatsHandle {
    let (tx, mut rx) = mpsc::unbounded_channel::<BlockStats>();
    let start = Instant::now();
    let join = tokio::spawn(async move {
        let mut acc = Accum::default();
        let mut ticker = tokio::time::interval(HEARTBEAT_INTERVAL);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        // First tick fires immediately — skip it so the first heartbeat
        // shows at T+10s rather than T+0s.
        ticker.tick().await;

        loop {
            tokio::select! {
                maybe = rx.recv() => {
                    match maybe {
                        Some(s) => acc.record(s),
                        None => break,
                    }
                }
                _ = ticker.tick() => {
                    heartbeat(&acc, total_planned, start.elapsed());
                }
            }
        }

        let wall = start.elapsed();
        Summary {
            succeeded: acc.done,
            failed: 0,
            wall,
            total_bytes: acc.total_bytes,
            total_p50: percentile(&mut acc.totals.clone(), 0.50),
            total_p95: percentile(&mut acc.totals.clone(), 0.95),
            total_p99: percentile(&mut acc.totals.clone(), 0.99),
            fetch_p50: percentile(&mut acc.fetches.clone(), 0.50),
            execute_p50: percentile(&mut acc.executes.clone(), 0.50),
            trie_p50: percentile(&mut acc.tries.clone(), 0.50),
            save_p50: percentile(&mut acc.saves.clone(), 0.50),
            witness_p50: percentile(&mut acc.witnesses.clone(), 0.50),
            serialize_p50: percentile(&mut acc.serializes.clone(), 0.50),
            push_p50: percentile(&mut acc.pushes.clone(), 0.50),
        }
    });
    StatsHandle { tx, join }
}

fn heartbeat(acc: &Accum, total: u64, elapsed: Duration) {
    let done = acc.done;
    let pct = if total == 0 { 0.0 } else { (done as f64 / total as f64) * 100.0 };
    let rate = if elapsed.as_secs() > 0 { done as f64 / elapsed.as_secs() as f64 } else { 0.0 };
    let remaining = total.saturating_sub(done);
    let eta_secs = if rate > 0.0 { (remaining as f64 / rate) as u64 } else { 0 };

    let p50 = |samples: &Vec<u64>| {
        let mut v = samples.clone();
        percentile(&mut v, 0.50)
    };
    let mut totals = acc.totals.clone();
    let total_p95 = percentile(&mut totals, 0.95);

    info!(
        done,
        total,
        pct = format!("{pct:.1}%"),
        rate_bps = format!("{rate:.2}"),
        eta_secs,
        total_p50_ms = p50(&acc.totals),
        total_p95_ms = total_p95,
        fetch_p50_ms = p50(&acc.fetches),
        execute_p50_ms = p50(&acc.executes),
        trie_p50_ms = p50(&acc.tries),
        save_p50_ms = p50(&acc.saves),
        witness_p50_ms = p50(&acc.witnesses),
        serialize_p50_ms = p50(&acc.serializes),
        push_p50_ms = p50(&acc.pushes),
        bytes_written = acc.total_bytes,
        "progress"
    );
}
