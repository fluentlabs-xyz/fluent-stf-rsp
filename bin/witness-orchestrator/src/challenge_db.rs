//! L1-event-driven DB writes for the challenge state machine. Called
//! from `handle_l1_event`; the active worker in `challenge_resolver`
//! drives rows forward from there.

use std::sync::Arc;

use alloy_primitives::{Address, B256};
use alloy_provider::Provider;
use l1_rollup_client::get_block_challenge_deadline;
use tokio::sync::mpsc;

use crate::db::{
    db_send_sync, now_ts, ChallengeKind, ChallengePatch, ChallengeRow, ChallengeStatus, Db,
    DbCommand, SyncOp,
};

pub(crate) async fn observe_block_challenged(
    db_tx: &mpsc::UnboundedSender<DbCommand>,
    l1_provider: &impl Provider,
    contract_addr: Address,
    batch_index: u64,
    commitment: B256,
) -> eyre::Result<()> {
    let deadline = get_block_challenge_deadline(l1_provider, contract_addr, commitment).await?;
    let now = now_ts();
    let row = ChallengeRow {
        challenge_id: 0,
        kind: ChallengeKind::Block,
        batch_index,
        commitment: Some(commitment),
        status: ChallengeStatus::Received,
        deadline,
        sp1_request_id: None,
        sp1_proof_bytes: None,
        tx_hash: None,
        nonce: None,
        max_fee_per_gas: None,
        max_priority_fee_per_gas: None,
        l1_block: None,
        committed_at: now,
        last_status_change_at: now,
    };
    db_send_sync(db_tx, SyncOp::InsertChallenge(row)).await
}

pub(crate) async fn observe_batch_root_challenged(
    db_tx: &mpsc::UnboundedSender<DbCommand>,
    batch_index: u64,
) -> eyre::Result<()> {
    let now = now_ts();
    let row = ChallengeRow {
        challenge_id: 0,
        kind: ChallengeKind::BatchRoot,
        batch_index,
        commitment: None,
        status: ChallengeStatus::Received,
        // No per-record deadline — batch-root disputes are bounded by the
        // rollup-level halt rather than a window on the row.
        deadline: u64::MAX,
        sp1_request_id: None,
        sp1_proof_bytes: None,
        tx_hash: None,
        nonce: None,
        max_fee_per_gas: None,
        max_priority_fee_per_gas: None,
        l1_block: None,
        committed_at: now,
        last_status_change_at: now,
    };
    db_send_sync(db_tx, SyncOp::InsertChallenge(row)).await
}

pub(crate) async fn observe_resolved(
    db: &Arc<std::sync::Mutex<Db>>,
    db_tx: &mpsc::UnboundedSender<DbCommand>,
    kind: ChallengeKind,
    batch_index: u64,
    commitment: Option<B256>,
) -> eyre::Result<()> {
    let row = {
        let guard = db.lock().unwrap_or_else(|e| e.into_inner());
        guard.find_challenge_by_event(kind, batch_index, commitment)
    };
    let Some(row) = row else { return Ok(()) };
    if row.status == ChallengeStatus::Resolved {
        return Ok(());
    }
    let patch = ChallengePatch { status: Some(ChallengeStatus::Resolved), ..Default::default() };
    db_send_sync(db_tx, SyncOp::PatchChallenge { challenge_id: row.challenge_id, patch }).await
}
