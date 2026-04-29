//! Hot per-block-response cache. Source of truth for live response state;
//! `block_responses` SQLite table is the async-flushed durability backstop.
//! Crash loses the trailing un-flushed window; restart re-executes via
//! `Db::missing_blocks_for_unsent_batches` priority replay.
//!
//! All other batch state (the `batches` table) lives only in SQLite.
//! Workers query it directly each tick — see the predicate methods on `Db`.

use std::{collections::HashMap, sync::Arc};

use tokio::sync::mpsc;

use crate::{
    db::{AsyncOp, DbCommand},
    types::EthExecutionResponse,
};

#[derive(Debug)]
pub(crate) struct ResponseCache {
    responses: HashMap<u64, EthExecutionResponse>,
    db_tx: Option<mpsc::UnboundedSender<DbCommand>>,
}

impl ResponseCache {
    /// Bulk-load responses persisted in `block_responses` on startup.
    pub(crate) fn with_db(
        db: Arc<std::sync::Mutex<crate::db::Db>>,
        db_tx: mpsc::UnboundedSender<DbCommand>,
    ) -> Self {
        let guard = db.lock().unwrap_or_else(|e| e.into_inner());
        let responses: HashMap<u64, EthExecutionResponse> =
            guard.load_responses().into_iter().map(|r| (r.block_number, r)).collect();
        drop(guard);
        Self { responses, db_tx: Some(db_tx) }
    }

    pub(crate) fn contains(&self, block: u64) -> bool {
        self.responses.contains_key(&block)
    }

    pub(crate) fn get_range(&self, from: u64, to: u64) -> Vec<EthExecutionResponse> {
        (from..=to).filter_map(|b| self.responses.get(&b).cloned()).collect()
    }

    pub(crate) fn insert(&mut self, resp: EthExecutionResponse) {
        let block = resp.block_number;
        self.responses.insert(block, resp.clone());
        if let Some(tx) = &self.db_tx {
            if tx.send(DbCommand::Async(AsyncOp::SaveResponse(resp))).is_err() {
                metrics::counter!(crate::metrics::DB_WRITER_DROPPED_TOTAL).increment(1);
            }
        }
    }

    pub(crate) fn purge(&mut self, blocks: &[u64]) {
        for &b in blocks {
            self.responses.remove(&b);
        }
        if let Some(tx) = &self.db_tx {
            if tx.send(DbCommand::Async(AsyncOp::DeleteResponsesBatch(blocks.to_vec()))).is_err() {
                metrics::counter!(crate::metrics::DB_WRITER_DROPPED_TOTAL).increment(1);
            }
        }
    }
}
