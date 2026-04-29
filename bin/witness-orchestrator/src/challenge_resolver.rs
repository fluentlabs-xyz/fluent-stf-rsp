//! Persistent challenge resolver: a single worker drives every challenge
//! row through the DB-backed status machine
//! (`received → sp1_proving → sp1_proved → dispatched → resolved`).
//!
//! - **Block-level** challenges: delegate SP1 Groth16 proof generation to the proxy
//!   `/challenge/sp1/{request,status}` API; build a merkle inclusion proof from L2 RPC data; submit
//!   `resolveBlockChallenge`.
//! - **Batch-root** challenges: reconstruct the merkle root locally from L2 RPC headers + receipts
//!   (no SP1); submit `resolveBatchRootChallenge`.
//!
//! Single-worker: one challenge in flight at a time. State is durable in
//! the `challenges` SQLite table — restart resumes from the persisted
//! status without re-issuing SP1 work or re-broadcasting in-flight resolve
//! txs.

use std::{sync::Arc, time::Duration};

use alloy_primitives::{Bytes, FixedBytes, B256, U256};
use alloy_provider::Provider;
use alloy_rpc_types::TransactionReceipt;
use fluent_stf_primitives::{
    BRIDGE_ADDRESS, BRIDGE_DEPOSIT_TOPIC, BRIDGE_ROLLBACK_TOPIC, BRIDGE_WITHDRAWAL_TOPIC,
    LEGACY_BRIDGE_WITHDRAWAL_TOPIC,
};
use l1_rollup_client::{
    build_resolve_batch_root_challenge_tx, build_resolve_block_challenge_tx, fetch_batch_range,
    L2BlockHeader, MerkleProof, RollupTxTemplate,
};
use rsp_host_executor::events_hash::{
    calculate_deposit_hash, calculate_withdrawal_root, count_deposits,
};
use serde::{Deserialize, Serialize};
use tokio::time::MissedTickBehavior;
use tracing::{info, warn};

use crate::{
    db::{db_send_sync, ChallengeKind, ChallengePatch, ChallengeRow, ChallengeStatus, SyncOp},
    orchestrator::{DispatchBackoff, OrchestratorShared, RevertKind},
    rbf::{run_generic, RbfObserver},
};

/// Polling interval for `/challenge/sp1/status`.
const SP1_STATUS_POLL_INTERVAL: Duration = Duration::from_secs(15);

/// Active worker tick.
const WORKER_TICK: Duration = Duration::from_secs(1);

// ============================================================================
// Worker entry point
// ============================================================================

pub(crate) async fn run(shared: Arc<OrchestratorShared>) {
    info!("challenge_resolver started");
    let mut tick = tokio::time::interval(WORKER_TICK);
    tick.set_missed_tick_behavior(MissedTickBehavior::Skip);
    let mut backoff = DispatchBackoff::default();

    loop {
        tokio::select! {
            biased;
            _ = shared.shutdown.cancelled() => break,
            _ = tick.tick() => {}
        }

        let row = {
            let guard = shared.db.lock().unwrap_or_else(|e| e.into_inner());
            guard.find_active_challenge()
        };
        let Some(row) = row else { continue };

        // Deadline visibility: log + metric, but the operator decides what
        // to do — we do not auto-abort (per the no-`aborted` decision).
        if row.deadline != u64::MAX {
            if let Ok(current_l1_block) = shared.config.l1_provider.get_block_number().await {
                if current_l1_block > row.deadline {
                    metrics::counter!(
                        "orchestrator_challenge_deadline_expired_total",
                        "kind" => row.kind.as_str(),
                    )
                    .increment(1);
                    warn!(
                        challenge_id = row.challenge_id,
                        deadline = row.deadline,
                        current_l1_block,
                        "challenge deadline expired"
                    );
                }
            }
        }

        match row.status {
            ChallengeStatus::Received => handle_received(&shared, &row, &mut backoff).await,
            ChallengeStatus::Sp1Proving => handle_sp1_proving(&shared, &row).await,
            ChallengeStatus::Sp1Proved => handle_sp1_proved(&shared, &row, &mut backoff).await,
            ChallengeStatus::Dispatched => {
                handle_dispatched_resume(&shared, &row, &mut backoff).await;
            }
            ChallengeStatus::Resolved => {
                // Filtered by `find_active_challenge`; defensive log.
                warn!(challenge_id = row.challenge_id, "active gate returned resolved row");
            }
        }
    }
    info!("challenge_resolver exiting");
}

// ============================================================================
// Status-specific handlers
// ============================================================================

async fn handle_received(
    shared: &OrchestratorShared,
    row: &ChallengeRow,
    backoff: &mut DispatchBackoff,
) {
    match row.kind {
        ChallengeKind::Block => {
            // Block-kind: ask the proxy to produce an SP1 proof; status
            // moves to `sp1_proving` only after we have a request_id.
            let target_block_number = match resolve_block_target(shared, row).await {
                Some(n) => n,
                None => return,
            };
            match post_sp1_request(
                &shared.config.http_client,
                &shared.config.proxy_url,
                &shared.config.api_key,
                target_block_number,
                row.batch_index,
            )
            .await
            {
                Ok(request_id) => {
                    let patch = ChallengePatch {
                        status: Some(ChallengeStatus::Sp1Proving),
                        sp1_request_id: Some(Some(request_id)),
                        ..Default::default()
                    };
                    persist_patch(shared, row.challenge_id, patch).await;
                    info!(
                        challenge_id = row.challenge_id,
                        batch_index = row.batch_index,
                        target_block_number,
                        %request_id,
                        "SP1 proof requested via proxy"
                    );
                }
                Err(e) => {
                    warn!(
                        challenge_id = row.challenge_id,
                        err = %e,
                        "post_sp1_request failed"
                    );
                }
            }
        }
        ChallengeKind::BatchRoot => {
            // Batch-root: no SP1 round-trip — build calldata + broadcast.
            run_resolve_lifecycle(shared, row, backoff).await;
        }
    }
}

async fn handle_sp1_proving(shared: &OrchestratorShared, row: &ChallengeRow) {
    let request_id = match row.sp1_request_id {
        Some(id) => id,
        None => {
            warn!(
                challenge_id = row.challenge_id,
                "sp1_proving without sp1_request_id — rolling back to received"
            );
            let patch =
                ChallengePatch { status: Some(ChallengeStatus::Received), ..Default::default() };
            persist_patch(shared, row.challenge_id, patch).await;
            return;
        }
    };
    match poll_sp1_status(
        &shared.config.http_client,
        &shared.config.proxy_url,
        &shared.config.api_key,
        request_id,
    )
    .await
    {
        Ok(Sp1StatusOutcome::Ready(proof_bytes)) => {
            let patch = ChallengePatch {
                status: Some(ChallengeStatus::Sp1Proved),
                sp1_proof_bytes: Some(Some(proof_bytes)),
                ..Default::default()
            };
            persist_patch(shared, row.challenge_id, patch).await;
            info!(challenge_id = row.challenge_id, "SP1 proof ready");
        }
        Ok(Sp1StatusOutcome::Pending) => {}
        Err(Sp1StatusError::Lost) => {
            metrics::counter!(
                "orchestrator_challenge_sp1_request_lost_total",
                "kind" => row.kind.as_str(),
            )
            .increment(1);
            warn!(
                challenge_id = row.challenge_id,
                %request_id,
                "SP1 request lost (proxy 404) — clearing request_id and re-issuing"
            );
            let patch = ChallengePatch {
                status: Some(ChallengeStatus::Received),
                sp1_request_id: Some(None),
                ..Default::default()
            };
            persist_patch(shared, row.challenge_id, patch).await;
        }
        Err(Sp1StatusError::Other(e)) => {
            warn!(
                challenge_id = row.challenge_id,
                err = %e,
                "poll_sp1_status failed — retrying next tick"
            );
        }
    }
}

async fn handle_sp1_proved(
    shared: &OrchestratorShared,
    row: &ChallengeRow,
    backoff: &mut DispatchBackoff,
) {
    run_resolve_lifecycle(shared, row, backoff).await;
}

async fn handle_dispatched_resume(
    shared: &OrchestratorShared,
    row: &ChallengeRow,
    backoff: &mut DispatchBackoff,
) {
    let resume = match (row.nonce, row.tx_hash, row.max_fee_per_gas, row.max_priority_fee_per_gas) {
        (Some(n), Some(h), Some(fee), Some(tip)) => ResumeState {
            nonce: n,
            tx_hash: h,
            max_fee_per_gas: fee,
            max_priority_fee_per_gas: tip,
        },
        _ => {
            // RBF state torn — restart from scratch (a fresh nonce, fees).
            run_resolve_lifecycle(shared, row, backoff).await;
            return;
        }
    };
    let template = match build_resolve_template(shared, row, resume.nonce).await {
        Ok(t) => t,
        Err(e) => {
            warn!(
                challenge_id = row.challenge_id,
                err = %e,
                "build_resolve_template (resume) failed"
            );
            return;
        }
    };
    let observer = ResolveObserver {
        shared,
        challenge_id: row.challenge_id,
        kind: row.kind,
        nonce: resume.nonce,
        batch_index: row.batch_index,
    };
    run_generic(
        shared,
        row.batch_index,
        &template,
        resume.nonce,
        Some(crate::accumulator::RbfResumeState {
            nonce: resume.nonce,
            tx_hash: resume.tx_hash,
            max_fee_per_gas: resume.max_fee_per_gas,
            max_priority_fee_per_gas: resume.max_priority_fee_per_gas,
        }),
        resume.max_fee_per_gas,
        resume.max_priority_fee_per_gas,
        &observer,
        backoff,
    )
    .await;
}

#[derive(Debug, Clone, Copy)]
struct ResumeState {
    nonce: u64,
    tx_hash: B256,
    max_fee_per_gas: u128,
    max_priority_fee_per_gas: u128,
}

/// Allocate a fresh nonce, build the calldata, estimate fees, and run the
/// shared RBF lifecycle from a clean start.
async fn run_resolve_lifecycle(
    shared: &OrchestratorShared,
    row: &ChallengeRow,
    backoff: &mut DispatchBackoff,
) {
    let nonce = shared.nonce_allocator.allocate();
    let template = match build_resolve_template(shared, row, nonce).await {
        Ok(t) => t,
        Err(e) => {
            warn!(
                challenge_id = row.challenge_id,
                err = %e,
                "build_resolve_template failed"
            );
            shared.nonce_allocator.release(nonce);
            return;
        }
    };
    let cap = shared.config.rbf_max_fee_per_gas_wei;
    let est = match shared.config.l1_provider.estimate_eip1559_fees().await {
        Ok(e) => e,
        Err(e) => {
            warn!(
                challenge_id = row.challenge_id,
                err = %e,
                "estimate_eip1559_fees failed"
            );
            shared.nonce_allocator.release(nonce);
            return;
        }
    };
    let mut fee = est.max_fee_per_gas;
    let mut tip = est.max_priority_fee_per_gas;
    if fee >= cap {
        fee = cap;
        if tip > cap {
            tip = cap;
        }
        warn!(
            challenge_id = row.challenge_id,
            kind = row.kind.as_str(),
            max_fee_cap = cap,
            "resolve initial fee at/above cap"
        );
    }
    let observer = ResolveObserver {
        shared,
        challenge_id: row.challenge_id,
        kind: row.kind,
        nonce,
        batch_index: row.batch_index,
    };
    run_generic(shared, row.batch_index, &template, nonce, None, fee, tip, &observer, backoff)
        .await;
}

/// Per-kind dispatcher: builds either a `resolveBlockChallenge` or a
/// `resolveBatchRootChallenge` template.
async fn build_resolve_template(
    shared: &OrchestratorShared,
    row: &ChallengeRow,
    nonce: u64,
) -> eyre::Result<RollupTxTemplate> {
    match row.kind {
        ChallengeKind::Block => build_block_resolve_template(shared, row, nonce).await,
        ChallengeKind::BatchRoot => build_batch_root_resolve_template(shared, row, nonce).await,
    }
}

async fn build_block_resolve_template(
    shared: &OrchestratorShared,
    row: &ChallengeRow,
    nonce: u64,
) -> eyre::Result<RollupTxTemplate> {
    let cfg = &shared.config;
    let commitment =
        row.commitment.ok_or_else(|| eyre::eyre!("block challenge row missing commitment"))?;
    let sp1_proof = row
        .sp1_proof_bytes
        .clone()
        .ok_or_else(|| eyre::eyre!("block challenge row missing sp1_proof_bytes"))?;

    let (from_block, to_block) = fetch_batch_range(
        &cfg.l1_read_provider,
        &cfg.l2_provider,
        cfg.l1_rollup_addr,
        row.batch_index,
        cfg.l1_deploy_block,
    )
    .await?;

    let (headers, leaves, target_idx) =
        collect_headers_with_target(&cfg.l2_provider, from_block, to_block, Some(commitment))
            .await
            .ok_or_else(|| eyre::eyre!("collect_headers_with_target failed"))?;

    let idx = target_idx.ok_or_else(|| {
        eyre::eyre!("no matching leaf in batch {} for commitment {commitment}", row.batch_index)
    })?;

    let (proof_nonce, proof_bytes) = batch_merkle::build_merkle_proof(&leaves, idx);
    let merkle_proof =
        MerkleProof { nonce: U256::from(proof_nonce), proof: Bytes::from(proof_bytes) };

    build_resolve_block_challenge_tx(
        &cfg.l1_provider,
        cfg.l1_rollup_addr,
        row.batch_index,
        headers[idx].clone(),
        merkle_proof,
        sp1_proof,
        cfg.l1_signer_address,
        nonce,
    )
    .await
}

async fn build_batch_root_resolve_template(
    shared: &OrchestratorShared,
    row: &ChallengeRow,
    nonce: u64,
) -> eyre::Result<RollupTxTemplate> {
    let cfg = &shared.config;
    if row.batch_index == 0 {
        return Err(eyre::eyre!("batch 0 is genesis — cannot resolve batch-root challenge"));
    }

    let (from_block, to_block) = fetch_batch_range(
        &cfg.l1_read_provider,
        &cfg.l2_provider,
        cfg.l1_rollup_addr,
        row.batch_index,
        cfg.l1_deploy_block,
    )
    .await?;
    let (prev_from, prev_to) = fetch_batch_range(
        &cfg.l1_read_provider,
        &cfg.l2_provider,
        cfg.l1_rollup_addr,
        row.batch_index - 1,
        cfg.l1_deploy_block,
    )
    .await?;

    let (headers, _leaves, _) =
        collect_headers_with_target(&cfg.l2_provider, from_block, to_block, None)
            .await
            .ok_or_else(|| eyre::eyre!("collect_headers_with_target (current) failed"))?;
    let (prev_headers, prev_leaves, _) =
        collect_headers_with_target(&cfg.l2_provider, prev_from, prev_to, None)
            .await
            .ok_or_else(|| eyre::eyre!("collect_headers_with_target (previous) failed"))?;

    let prev_last_idx = prev_headers.len() - 1;
    let last_block_header_in_previous_batch = prev_headers[prev_last_idx].clone();
    let (proof_nonce, proof_bytes) = batch_merkle::build_merkle_proof(&prev_leaves, prev_last_idx);
    let last_block_proof =
        MerkleProof { nonce: U256::from(proof_nonce), proof: Bytes::from(proof_bytes) };

    build_resolve_batch_root_challenge_tx(
        &cfg.l1_provider,
        cfg.l1_rollup_addr,
        row.batch_index,
        last_block_header_in_previous_batch,
        headers,
        last_block_proof,
        cfg.l1_signer_address,
        nonce,
    )
    .await
}

/// Resolve the L2 block number that backs the disputed commitment by
/// scanning the batch's blocks. Returns `None` on RPC failure or absent
/// match (caller logs and waits for the next tick).
async fn resolve_block_target(shared: &OrchestratorShared, row: &ChallengeRow) -> Option<u64> {
    let cfg = &shared.config;
    let commitment = match row.commitment {
        Some(c) => c,
        None => {
            warn!(challenge_id = row.challenge_id, "block challenge row missing commitment");
            return None;
        }
    };
    let (from_block, to_block) = match fetch_batch_range(
        &cfg.l1_read_provider,
        &cfg.l2_provider,
        cfg.l1_rollup_addr,
        row.batch_index,
        cfg.l1_deploy_block,
    )
    .await
    {
        Ok(r) => r,
        Err(e) => {
            warn!(
                challenge_id = row.challenge_id,
                err = %e,
                "fetch_batch_range failed"
            );
            return None;
        }
    };
    let (_, _leaves, target_idx) =
        collect_headers_with_target(&cfg.l2_provider, from_block, to_block, Some(commitment))
            .await?;
    let idx = target_idx?;
    Some(from_block + idx as u64)
}

async fn persist_patch(shared: &OrchestratorShared, challenge_id: i64, patch: ChallengePatch) {
    if let Err(e) =
        db_send_sync(&shared.db_tx, SyncOp::PatchChallenge { challenge_id, patch }).await
    {
        tracing::error!(challenge_id, err = %e, "persist_patch (challenge) failed");
    }
}

// ============================================================================
// Header construction (RPC + receipts → L2BlockHeader)
// ============================================================================

/// Walk `[from_block, to_block]`, build an `L2BlockHeader` per block from
/// L2 RPC, and compute the merkle leaf. If `target_commitment` is set,
/// returns the index of the matching leaf.
async fn collect_headers_with_target(
    l2_provider: &alloy_provider::RootProvider,
    from_block: u64,
    to_block: u64,
    target_commitment: Option<B256>,
) -> Option<(Vec<L2BlockHeader>, Vec<B256>, Option<usize>)> {
    let count = (to_block - from_block + 1) as usize;
    let mut headers: Vec<L2BlockHeader> = Vec::with_capacity(count);
    let mut leaves: Vec<B256> = Vec::with_capacity(count);
    let mut target_idx: Option<usize> = None;
    for (i, block_number) in (from_block..=to_block).enumerate() {
        let header = match build_l2_block_header(l2_provider, block_number).await {
            Ok(h) => h,
            Err(e) => {
                warn!(block_number, err = %e, "failed to build L2BlockHeader");
                return None;
            }
        };
        let leaf = batch_merkle::compute_leaf(
            header.previousBlockHash,
            header.blockHash,
            header.withdrawalRoot,
            header.depositRoot,
        );
        if let Some(c) = target_commitment {
            if leaf == c {
                target_idx = Some(i);
            }
        }
        headers.push(header);
        leaves.push(leaf);
    }
    Some((headers, leaves, target_idx))
}

async fn build_l2_block_header(
    l2_provider: &alloy_provider::RootProvider,
    block_number: u64,
) -> eyre::Result<L2BlockHeader> {
    let block = l2_provider
        .get_block_by_number(block_number.into())
        .await
        .map_err(|e| eyre::eyre!("get_block_by_number({block_number}) failed: {e}"))?
        .ok_or_else(|| eyre::eyre!("block {block_number} not found on L2"))?;

    let receipts: Vec<TransactionReceipt> = l2_provider
        .get_block_receipts(block_number.into())
        .await
        .map_err(|e| eyre::eyre!("get_block_receipts({block_number}) failed: {e}"))?
        .unwrap_or_default();

    let withdrawal_root = calculate_withdrawal_root(
        &receipts,
        BRIDGE_ADDRESS,
        BRIDGE_WITHDRAWAL_TOPIC,
        LEGACY_BRIDGE_WITHDRAWAL_TOPIC,
        BRIDGE_ROLLBACK_TOPIC,
    );
    let deposit_root = calculate_deposit_hash(&receipts, BRIDGE_ADDRESS, BRIDGE_DEPOSIT_TOPIC);
    let deposit_count = count_deposits(&receipts, BRIDGE_ADDRESS, BRIDGE_DEPOSIT_TOPIC);

    Ok(L2BlockHeader {
        previousBlockHash: block.header.parent_hash,
        blockHash: block.header.hash,
        withdrawalRoot: withdrawal_root,
        depositRoot: deposit_root,
        depositCount: deposit_count,
    })
}

// ============================================================================
// Proxy SP1 round-trip
// ============================================================================

#[derive(Serialize)]
struct Sp1RequestBody {
    block_number: u64,
    batch_index: u64,
}

#[derive(Serialize)]
struct Sp1StatusBody {
    request_id: B256,
}

#[derive(Deserialize)]
struct Sp1RequestResponse {
    request_id: B256,
}

#[derive(Deserialize)]
struct Sp1ProofResponse {
    #[allow(dead_code)]
    vk_hash: FixedBytes<32>,
    #[allow(dead_code)]
    public_values: Vec<u8>,
    proof_bytes: Vec<u8>,
}

enum Sp1StatusOutcome {
    Ready(Vec<u8>),
    Pending,
}

enum Sp1StatusError {
    /// Proxy returned 404 — the request was lost (e.g. proxy DB wipe).
    /// Caller re-issues by clearing `sp1_request_id`.
    Lost,
    Other(eyre::Report),
}

async fn post_sp1_request(
    http_client: &reqwest::Client,
    proxy_url: &str,
    api_key: &str,
    block_number: u64,
    batch_index: u64,
) -> eyre::Result<B256> {
    let resp = http_client
        .post(format!("{proxy_url}/challenge/sp1/request"))
        .header("x-api-key", api_key)
        .json(&Sp1RequestBody { block_number, batch_index })
        .send()
        .await
        .map_err(|e| eyre::eyre!("/challenge/sp1/request POST failed: {e}"))?;

    let status = resp.status();
    if !status.is_success() {
        let body = resp.text().await.unwrap_or_default();
        return Err(eyre::eyre!("/challenge/sp1/request returned {status}: {body}"));
    }
    let body: Sp1RequestResponse =
        resp.json().await.map_err(|e| eyre::eyre!("decode /challenge/sp1/request body: {e}"))?;
    Ok(body.request_id)
}

async fn poll_sp1_status(
    http_client: &reqwest::Client,
    proxy_url: &str,
    api_key: &str,
    request_id: B256,
) -> Result<Sp1StatusOutcome, Sp1StatusError> {
    // Pace successive polls inside a single tick. The active worker re-enters
    // this function on its 1s tick; this short sleep prevents the unlikely
    // case of double-polling from back-to-back ticks.
    tokio::time::sleep(SP1_STATUS_POLL_INTERVAL).await;

    let resp = http_client
        .post(format!("{proxy_url}/challenge/sp1/status"))
        .header("x-api-key", api_key)
        .json(&Sp1StatusBody { request_id })
        .send()
        .await
        .map_err(|e| {
            Sp1StatusError::Other(eyre::eyre!("/challenge/sp1/status POST failed: {e}"))
        })?;

    match resp.status().as_u16() {
        200 => {
            let proof: Sp1ProofResponse = resp
                .json()
                .await
                .map_err(|e| Sp1StatusError::Other(eyre::eyre!("decode proof body: {e}")))?;
            Ok(Sp1StatusOutcome::Ready(proof.proof_bytes))
        }
        202 => Ok(Sp1StatusOutcome::Pending),
        404 => Err(Sp1StatusError::Lost),
        other => {
            let body = resp.text().await.unwrap_or_default();
            Err(Sp1StatusError::Other(eyre::eyre!(
                "/challenge/sp1/status returned {other}: {body}"
            )))
        }
    }
}

// ============================================================================
// Stateful RbfObserver — mirrors PreconfirmObserver
// ============================================================================

pub(crate) struct ResolveObserver<'a> {
    shared: &'a OrchestratorShared,
    challenge_id: i64,
    kind: ChallengeKind,
    nonce: u64,
    batch_index: u64,
}

#[async_trait::async_trait]
impl RbfObserver for ResolveObserver<'_> {
    async fn on_first_broadcast(&self, hash: B256, fee: u128, tip: u128) {
        info!(
            kind = self.kind.as_str(),
            challenge_id = self.challenge_id,
            batch_index = self.batch_index,
            %hash,
            max_fee_per_gas = fee,
            max_priority_fee_per_gas = tip,
            "resolve broadcast (initial)"
        );
        let patch = ChallengePatch {
            status: Some(ChallengeStatus::Dispatched),
            tx_hash: Some(Some(hash)),
            nonce: Some(Some(self.nonce)),
            max_fee_per_gas: Some(Some(fee)),
            max_priority_fee_per_gas: Some(Some(tip)),
            ..Default::default()
        };
        persist_patch(self.shared, self.challenge_id, patch).await;
        crate::metrics::counter_resolve_dispatched(metric_kind_label(self.kind));
    }

    async fn on_rebroadcast(&self, hash: B256, fee: u128, tip: u128) {
        info!(
            kind = self.kind.as_str(),
            challenge_id = self.challenge_id,
            batch_index = self.batch_index,
            %hash,
            max_fee_per_gas = fee,
            max_priority_fee_per_gas = tip,
            "resolve RBF rebroadcast"
        );
        let patch = ChallengePatch {
            tx_hash: Some(Some(hash)),
            max_fee_per_gas: Some(Some(fee)),
            max_priority_fee_per_gas: Some(Some(tip)),
            ..Default::default()
        };
        persist_patch(self.shared, self.challenge_id, patch).await;
    }

    async fn on_submitted(&self, hash: B256, l1_block: u64) {
        info!(
            kind = self.kind.as_str(),
            challenge_id = self.challenge_id,
            batch_index = self.batch_index,
            %hash,
            l1_block,
            "resolve confirmed on L1"
        );
        let patch = ChallengePatch { l1_block: Some(Some(l1_block)), ..Default::default() };
        persist_patch(self.shared, self.challenge_id, patch).await;
        crate::metrics::counter_resolve_submitted(metric_kind_label(self.kind));
    }

    async fn on_reverted(&self, hash: B256, kind: RevertKind) {
        warn!(
            tx_kind = self.kind.as_str(),
            challenge_id = self.challenge_id,
            batch_index = self.batch_index,
            %hash,
            ?kind,
            "resolve REVERTED on L1 — alert + retry"
        );
        crate::metrics::counter_resolve_rejected(metric_kind_label(self.kind));
        // Clear RBF state so the worker re-broadcasts on its next tick.
        // Status stays `Dispatched` with `l1_block IS NULL`.
        let patch = ChallengePatch {
            tx_hash: Some(None),
            nonce: Some(None),
            max_fee_per_gas: Some(None),
            max_priority_fee_per_gas: Some(None),
            ..Default::default()
        };
        persist_patch(self.shared, self.challenge_id, patch).await;
    }

    async fn on_pre_receipt_failure(&self, reason: &'static str) {
        warn!(
            kind = self.kind.as_str(),
            challenge_id = self.challenge_id,
            batch_index = self.batch_index,
            reason,
            "resolve pre-receipt failure — alert + retry"
        );
        crate::metrics::counter_resolve_pre_receipt_failure(metric_kind_label(self.kind));
        let patch = ChallengePatch {
            tx_hash: Some(None),
            nonce: Some(None),
            max_fee_per_gas: Some(None),
            max_priority_fee_per_gas: Some(None),
            ..Default::default()
        };
        persist_patch(self.shared, self.challenge_id, patch).await;
    }

    async fn should_abort(&self) -> bool {
        let row = {
            let guard = self.shared.db.lock().unwrap_or_else(|e| e.into_inner());
            guard.find_challenge_by_id(self.challenge_id)
        };
        match row {
            Some(r) => r.status == ChallengeStatus::Resolved,
            None => true,
        }
    }
}

fn metric_kind_label(kind: ChallengeKind) -> &'static str {
    match kind {
        ChallengeKind::Block => "resolve_block_challenge",
        ChallengeKind::BatchRoot => "resolve_batch_root_challenge",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Pure-Rust mirror of `MerkleTree.verifyMerkleProof` from the
    /// rollup contract. `nonce` is the leaf index; `proof` is a packed
    /// sequence of 32-byte sibling hashes from leaf to root.
    fn verify_merkle_proof(root: B256, leaf: B256, mut nonce: u64, proof: &[u8]) -> bool {
        if !proof.len().is_multiple_of(32) {
            return false;
        }
        let mut hash = leaf;
        for chunk in proof.chunks_exact(32) {
            let sibling = B256::from_slice(chunk);
            hash = if nonce.is_multiple_of(2) {
                batch_merkle::keccak_pair(hash, sibling)
            } else {
                batch_merkle::keccak_pair(sibling, hash)
            };
            nonce /= 2;
        }
        hash == root
    }

    /// End-to-end mirror of `Rollup.resolveBatchRootChallenge`'s
    /// validation against real Fluent testnet data for batch 877. Runs
    /// the four checks the contract performs that depend on real chain
    /// state:
    ///
    /// 1. Local merkle root over `blockHeaders[]` equals on-chain `batchRoot`.
    /// 2. Sequential chain linkage within the batch (`blockHeaders[i].blockHash ==
    ///    blockHeaders[i+1].previousBlockHash`).
    /// 3. Cross-batch chain linkage (`lastBlockHeaderInPreviousBatch.blockHash ==
    ///    blockHeaders[0].previousBlockHash`).
    /// 4. Merkle inclusion proof of `lastBlockHeaderInPreviousBatch`'s commitment against the
    ///    previous batch's `batchRoot` at index `previousBatchNumberOfBlocks - 1`.
    #[tokio::test]
    #[ignore = "requires INTEGRATION_L2_RPC_URL; hits real L2 RPC for ~2k blocks"]
    async fn real_batch_877_resolve_validation() {
        const BATCH_877_FROM: u64 = 25_448_823;
        const BATCH_877_TO: u64 = 25_449_846;
        const BATCH_877_ROOT: B256 = alloy_primitives::b256!(
            "0x385f55c1589c3cd05c0f9b2360870c5aa818384d2bfbb990491c6acc34a4c1c4"
        );

        const BATCH_876_FROM: u64 = 25_447_799;
        const BATCH_876_TO: u64 = 25_448_822;
        const BATCH_876_ROOT: B256 = alloy_primitives::b256!(
            "0x0631672b00a8e80b9750db0b89a32cd4eb58929fd9fb196666f1e637e5ac0020"
        );

        let rpc_url = std::env::var("INTEGRATION_L2_RPC_URL")
            .expect("INTEGRATION_L2_RPC_URL must be set to run this integration test");
        let url: url::Url = rpc_url.parse().expect("INTEGRATION_L2_RPC_URL is not a valid URL");
        let l2: alloy_provider::RootProvider =
            rsp_provider::create_provider(url).expect("failed to build L2 provider");

        let (headers_877, leaves_877, _) =
            collect_headers_with_target(&l2, BATCH_877_FROM, BATCH_877_TO, None)
                .await
                .expect("collect_headers_with_target(877) failed");
        assert_eq!(
            leaves_877.len() as u64,
            BATCH_877_TO - BATCH_877_FROM + 1,
            "batch 877 leaf count != range"
        );

        let local_root_877 = batch_merkle::calculate_merkle_root(&leaves_877);
        assert_eq!(local_root_877, BATCH_877_ROOT, "batch 877 local root != on-chain batchRoot");

        for i in 0..headers_877.len() - 1 {
            assert_eq!(
                headers_877[i].blockHash,
                headers_877[i + 1].previousBlockHash,
                "batch 877 chain break between local index {i} and {}",
                i + 1
            );
        }

        let (headers_876, leaves_876, _) =
            collect_headers_with_target(&l2, BATCH_876_FROM, BATCH_876_TO, None)
                .await
                .expect("collect_headers_with_target(876) failed");
        let last_idx_876 = leaves_876.len() - 1;
        let last_header_876 = &headers_876[last_idx_876];

        assert_eq!(
            last_header_876.blockHash, headers_877[0].previousBlockHash,
            "cross-batch chain break: last(876).blockHash != first(877).previousBlockHash"
        );

        let last_leaf_876 = leaves_876[last_idx_876];
        let (nonce, proof_bytes) = batch_merkle::build_merkle_proof(&leaves_876, last_idx_876);
        assert!(
            verify_merkle_proof(BATCH_876_ROOT, last_leaf_876, nonce, &proof_bytes),
            "merkle inclusion proof for last leaf of batch 876 failed against on-chain root"
        );

        println!(
            "✓ batch 877 resolve calldata validates: root={local_root_877}, chain linkage OK, cross-batch link OK, last-leaf-of-876 inclusion proof OK"
        );
    }
}
