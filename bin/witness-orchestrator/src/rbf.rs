//! Drives a single batch's `preconfirmBatch` tx through pre-flight
//! reconciliation, broadcast, fee-bump rebroadcast, and receipt observation.
//!
//! Layout:
//! - [`run`] — entry point called by the dispatcher worker.
//! - [`preflight`] — on-chain status check that decides whether to broadcast.
//! - [`build_template`] / [`initial_fees`] — set up nonce, calldata, EIP-1559 fees for the first
//!   iteration of the bump loop.
//! - [`bump_loop`] — broadcast → sleep+poll → bump → broadcast cycle.
//! - [`try_broadcast`] / [`poll_for_terminal`] — extracted phases of the loop.
//! - [`handle_submitted`] / [`handle_reverted`] / [`handle_failed_then_undispatch`] — terminal
//!   outcome handlers, used by both the loop and `preflight`.

use alloy_eips::BlockNumberOrTag;
use alloy_primitives::B256;
use alloy_provider::Provider;
use l1_rollup_client::{
    batch_status, broadcast_preconfirm, build_preconfirm_tx, find_batch_preconfirm_event,
    get_batch_on_chain, is_nonce_too_low_error, PreconfirmTxTemplate,
};
use tracing::{error, info, warn};

use crate::{
    accumulator::RbfResumeState,
    orchestrator::{
        bump_fees, classify_revert, DispatchBackoff, OrchestratorShared, RevertKind,
        STUCK_AT_CAP_TIMEOUT,
    },
};

pub(crate) async fn run(
    shared: &OrchestratorShared,
    batch_index: u64,
    signature: Vec<u8>,
    resume: Option<RbfResumeState>,
    backoff: &mut DispatchBackoff,
) {
    if !preflight(shared, batch_index, backoff).await {
        return;
    }

    let nonce = match &resume {
        Some(r) => r.nonce,
        None => shared.nonce_allocator.allocate(),
    };
    let is_resume = resume.is_some();

    let Some(template) =
        build_template(shared, batch_index, signature, nonce, is_resume, backoff).await
    else {
        return;
    };

    let Some((fee, tip)) = initial_fees(shared, batch_index, resume.as_ref(), nonce, backoff).await
    else {
        return;
    };

    bump_loop(shared, batch_index, &template, nonce, resume, fee, tip, backoff).await;
}

/// `false` means the caller should return — `preflight` already applied
/// any backoff or recorded the external dispatch.
async fn preflight(
    shared: &OrchestratorShared,
    batch_index: u64,
    backoff: &mut DispatchBackoff,
) -> bool {
    let provider = &shared.config.l1_provider;
    let contract = shared.config.l1_rollup_addr;
    let cancel = &shared.shutdown;

    let on_chain = tokio::select! {
        _ = cancel.cancelled() => return false,
        res = get_batch_on_chain(provider, contract, batch_index) => match res {
            Ok(v) => v,
            Err(e) => {
                warn!(batch_index, err = %e, "pre-flight getBatch failed");
                backoff.apply("pre-flight RPC failed");
                return false;
            }
        },
    };

    match on_chain.status {
        batch_status::SUBMITTED => true,
        batch_status::PRECONFIRMED | batch_status::CHALLENGED | batch_status::FINALIZED => {
            handle_already_preconfirmed(shared, batch_index, on_chain.accepted_at_block, backoff)
                .await;
            false
        }
        batch_status::NONE | batch_status::COMMITTED => {
            warn!(
                batch_index,
                status = on_chain.status,
                "pre-flight: batch not yet Submitted on L1 — backing off"
            );
            handle_failed_then_undispatch(shared, batch_index, backoff, "pre-flight not submitted")
                .await;
            false
        }
        other => {
            warn!(
                batch_index,
                status = other,
                "pre-flight: unexpected on-chain batch status — backing off"
            );
            handle_failed_then_undispatch(
                shared,
                batch_index,
                backoff,
                "pre-flight unexpected status",
            )
            .await;
            false
        }
    }
}

/// The batch is already past `Submitted` on L1. If the corresponding
/// `BatchPreconfirmed` event is finalized we record the external dispatch;
/// otherwise we back off — the event may still land in the unfinalized
/// window, and broadcasting now would revert with `InvalidBatchStatus`.
async fn handle_already_preconfirmed(
    shared: &OrchestratorShared,
    batch_index: u64,
    accepted_at_block: u64,
    backoff: &mut DispatchBackoff,
) {
    let provider = &shared.config.l1_provider;
    let contract = shared.config.l1_rollup_addr;
    let cancel = &shared.shutdown;

    let finalized_block = tokio::select! {
        _ = cancel.cancelled() => return,
        res = provider.get_block_by_number(BlockNumberOrTag::Finalized) => match res {
            Ok(v) => v,
            Err(e) => {
                warn!(batch_index, err = %e, "get_block(Finalized) failed");
                backoff.apply("pre-flight finalized fetch failed");
                return;
            }
        },
    };
    let Some(finalized_block) = finalized_block else {
        warn!(batch_index, "L1 RPC returned no finalized block — chain not progressing?");
        backoff.apply("L1 finalized head missing");
        return;
    };
    let finalized_head = finalized_block.header.number;
    if accepted_at_block > finalized_head {
        warn!(
            batch_index,
            accepted_at_block,
            finalized_head,
            "pre-flight: batch commit still unfinalized on L1 — backing off"
        );
        handle_failed_then_undispatch(shared, batch_index, backoff, "pre-flight unfinalized").await;
        return;
    }

    let info = tokio::select! {
        _ = cancel.cancelled() => return,
        res = find_batch_preconfirm_event(
            provider, contract, batch_index, accepted_at_block, finalized_head,
        ) => match res {
            Ok(v) => v,
            Err(e) => {
                warn!(batch_index, err = %e, "find_batch_preconfirm_event failed");
                backoff.apply("pre-flight event scan failed");
                return;
            }
        },
    };
    let Some(info) = info else {
        // Either Challenged-from-Submitted (no preceding `BatchPreconfirmed`
        // ever existed) or the event is still in the unfinalized window.
        warn!(batch_index, "pre-flight: no finalized BatchPreconfirmed event — backing off");
        handle_failed_then_undispatch(shared, batch_index, backoff, "pre-flight no event").await;
        return;
    };

    info!(
        batch_index,
        tx_hash = %info.tx_hash,
        l1_block = info.l1_block,
        "pre-flight: batch already preconfirmed on L1 — recording external dispatch"
    );
    {
        let mut acc = shared.accumulator.lock().unwrap_or_else(|e| e.into_inner());
        // If the row is already in `dispatched` (resume hit), the in-flight
        // RBF state must be promoted in place — otherwise the row keeps
        // `l1_block == 0` and `first_inflight_resume` re-picks it forever
        // because `mark_dispatched_external` only acts on `batches`.
        if acc.dispatched.contains_key(&batch_index) {
            acc.promote_inflight_to_external(batch_index, info.tx_hash, info.l1_block);
        } else {
            acc.mark_dispatched_external(batch_index, info.tx_hash, info.l1_block);
        }
        if let Some(batch) = acc.dispatched.get(&batch_index) {
            crate::metrics::set_last_batch_dispatched(
                batch_index,
                batch.from_block,
                batch.to_block,
            );
        }
    }
    backoff.reset();
}

async fn build_template(
    shared: &OrchestratorShared,
    batch_index: u64,
    signature: Vec<u8>,
    nonce: u64,
    is_resume: bool,
    backoff: &mut DispatchBackoff,
) -> Option<PreconfirmTxTemplate> {
    let provider = &shared.config.l1_provider;
    let contract = shared.config.l1_rollup_addr;
    let verifier = shared.config.nitro_verifier_addr;
    let signer_addr = shared.config.l1_signer_address;
    let cancel = &shared.shutdown;

    tokio::select! {
        _ = cancel.cancelled() => {
            if !is_resume {
                shared.nonce_allocator.release(nonce);
            }
            None
        }
        res = build_preconfirm_tx(
            provider, contract, verifier, batch_index, signature, signer_addr, nonce,
        ) => match res {
            Ok(t) => Some(t),
            Err(e) => {
                if !is_resume {
                    shared.nonce_allocator.release(nonce);
                }
                warn!(batch_index, err = %e, "build_preconfirm_tx failed");
                backoff.apply("build_preconfirm_tx failed");
                None
            }
        }
    }
}

/// Resume reuses the persisted RBF state; fresh dispatches estimate
/// EIP-1559 fees and clamp at the configured cap.
async fn initial_fees(
    shared: &OrchestratorShared,
    batch_index: u64,
    resume: Option<&RbfResumeState>,
    nonce: u64,
    backoff: &mut DispatchBackoff,
) -> Option<(u128, u128)> {
    if let Some(r) = resume {
        return Some((r.max_fee_per_gas, r.max_priority_fee_per_gas));
    }

    let provider = &shared.config.l1_provider;
    let cancel = &shared.shutdown;
    let max_fee_cap = shared.config.rbf_max_fee_per_gas_wei;

    let est = tokio::select! {
        _ = cancel.cancelled() => {
            shared.nonce_allocator.release(nonce);
            return None;
        }
        res = provider.estimate_eip1559_fees() => match res {
            Ok(v) => v,
            Err(e) => {
                shared.nonce_allocator.release(nonce);
                warn!(batch_index, err = %e, "estimate_eip1559_fees failed");
                backoff.apply("estimate_eip1559_fees failed");
                return None;
            }
        }
    };

    let mut fee = est.max_fee_per_gas;
    let mut tip = est.max_priority_fee_per_gas;
    if fee >= max_fee_cap {
        fee = max_fee_cap;
        if tip > max_fee_cap {
            tip = max_fee_cap;
        }
        warn!(batch_index, max_fee_cap, "RBF: initial fee at/above cap — clamping and proceeding");
    }
    Some((fee, tip))
}

#[allow(clippy::too_many_arguments)]
async fn bump_loop(
    shared: &OrchestratorShared,
    batch_index: u64,
    template: &PreconfirmTxTemplate,
    nonce: u64,
    resume: Option<RbfResumeState>,
    initial_fee: u128,
    initial_tip: u128,
    backoff: &mut DispatchBackoff,
) {
    let max_fee_cap = shared.config.rbf_max_fee_per_gas_wei;
    let bump_percent = shared.config.rbf_bump_percent;

    let mut max_fee_per_gas = initial_fee;
    let mut max_priority_fee_per_gas = initial_tip;
    let mut current_hash: Option<B256> = resume.as_ref().map(|r| r.tx_hash);
    // The resume path inherits an in-mempool tx from a prior process;
    // skip the first broadcast so we do not get an "already known" reject.
    let mut just_resumed = resume.is_some();
    let mut at_cap_logged = max_fee_per_gas >= max_fee_cap;
    let mut stuck_at_cap_since: Option<tokio::time::Instant> =
        at_cap_logged.then(tokio::time::Instant::now);

    loop {
        if !just_resumed {
            match try_broadcast(
                shared,
                batch_index,
                template,
                max_fee_per_gas,
                max_priority_fee_per_gas,
                current_hash,
                nonce,
                backoff,
            )
            .await
            {
                BroadcastResult::Continue { hash } => current_hash = Some(hash),
                BroadcastResult::Done => return,
            }
        }
        just_resumed = false;

        let observed_hash = current_hash.expect("post-broadcast => current_hash set");
        match poll_for_terminal(shared, batch_index, template, observed_hash, backoff).await {
            PollResult::Done => return,
            PollResult::NotMined => {}
        }

        if let Some(since) = stuck_at_cap_since {
            let elapsed = since.elapsed();
            if elapsed >= STUCK_AT_CAP_TIMEOUT {
                metrics::counter!(
                    crate::metrics::L1_BROADCAST_FAILURES_TOTAL,
                    "kind" => "stuck_at_cap",
                )
                .increment(1);
                warn!(
                    batch_index,
                    elapsed_secs = elapsed.as_secs(),
                    stuck_at_cap_timeout_secs = STUCK_AT_CAP_TIMEOUT.as_secs(),
                    "RBF: stuck at fee cap past timeout — giving up so dispatcher can retry"
                );
                handle_failed_then_undispatch(shared, batch_index, backoff, "stuck-at-cap timeout")
                    .await;
                return;
            }
        }

        let (new_fee, new_tip, clamped) =
            bump_fees(max_fee_per_gas, max_priority_fee_per_gas, bump_percent, max_fee_cap);
        max_fee_per_gas = new_fee;
        max_priority_fee_per_gas = new_tip;

        if clamped {
            stuck_at_cap_since.get_or_insert_with(tokio::time::Instant::now);
            if !at_cap_logged {
                error!(
                    batch_index,
                    max_fee_cap,
                    "RBF fee cap reached — operator attention required; dispatcher continues \
                     rebroadcasting at cap"
                );
                at_cap_logged = true;
            }
        }
    }
}

enum BroadcastResult {
    /// Caller should poll `hash` for a receipt.
    Continue { hash: B256 },
    /// Function reached a terminal state (cancel, initial-broadcast failure,
    /// or fast-fail terminal); caller returns.
    Done,
}

#[allow(clippy::too_many_arguments)]
async fn try_broadcast(
    shared: &OrchestratorShared,
    batch_index: u64,
    template: &PreconfirmTxTemplate,
    max_fee_per_gas: u128,
    max_priority_fee_per_gas: u128,
    current_hash: Option<B256>,
    nonce: u64,
    backoff: &mut DispatchBackoff,
) -> BroadcastResult {
    let provider = &shared.config.l1_provider;
    let signer = shared.config.l1_signer.as_ref();
    let cancel = &shared.shutdown;
    let was_first = current_hash.is_none();

    let res = tokio::select! {
        _ = cancel.cancelled() => {
            if was_first {
                shared.nonce_allocator.release(nonce);
            }
            info!(batch_index, "RBF dispatch cancelled (shutdown)");
            return BroadcastResult::Done;
        }
        res = broadcast_preconfirm(
            provider,
            signer,
            template,
            max_fee_per_gas,
            max_priority_fee_per_gas,
        ) => res,
    };

    match res {
        Ok(new_hash) => {
            persist_broadcast(
                shared,
                batch_index,
                template,
                new_hash,
                max_fee_per_gas,
                max_priority_fee_per_gas,
                was_first,
                backoff,
            );
            BroadcastResult::Continue { hash: new_hash }
        }
        Err(e) => {
            handle_broadcast_error(shared, batch_index, template, e, current_hash, nonce, backoff)
                .await
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn persist_broadcast(
    shared: &OrchestratorShared,
    batch_index: u64,
    template: &PreconfirmTxTemplate,
    new_hash: B256,
    max_fee_per_gas: u128,
    max_priority_fee_per_gas: u128,
    was_first: bool,
    backoff: &mut DispatchBackoff,
) {
    if was_first {
        info!(
            batch_index,
            nonce = template.nonce,
            %new_hash,
            max_fee_per_gas,
            max_priority_fee_per_gas,
            "preconfirmBatch tx broadcast (initial)"
        );
        // Update the dispatched gauge under the same lock as
        // `mark_dispatched` so the metric reflects the moment of broadcast
        // rather than the eventual receipt landing — otherwise the bump
        // cycle leaves a visible gap on the dashboard.
        backoff.reset();
        let mut acc = shared.accumulator.lock().unwrap_or_else(|e| e.into_inner());
        acc.mark_dispatched(
            batch_index,
            new_hash,
            0,
            template.nonce,
            max_fee_per_gas,
            max_priority_fee_per_gas,
        );
        if let Some(batch) = acc.dispatched.get(&batch_index) {
            crate::metrics::set_last_batch_dispatched(
                batch_index,
                batch.from_block,
                batch.to_block,
            );
        }
    } else {
        info!(
            batch_index,
            %new_hash,
            max_fee_per_gas,
            max_priority_fee_per_gas,
            "RBF bump rebroadcast"
        );
        let mut acc = shared.accumulator.lock().unwrap_or_else(|e| e.into_inner());
        acc.record_rbf_bump(batch_index, new_hash, max_fee_per_gas, max_priority_fee_per_gas);
    }
}

async fn handle_broadcast_error(
    shared: &OrchestratorShared,
    batch_index: u64,
    template: &PreconfirmTxTemplate,
    err: eyre::Report,
    current_hash: Option<B256>,
    nonce: u64,
    backoff: &mut DispatchBackoff,
) -> BroadcastResult {
    let msg = err.to_string();
    metrics::counter!(
        crate::metrics::L1_BROADCAST_FAILURES_TOTAL,
        "kind" => crate::metrics::broadcast_failure_kind(&msg),
    )
    .increment(1);

    let Some(prior) = current_hash else {
        // Initial broadcast `nonce-too-low` means a tx at this nonce already
        // exists on-chain; resyncing the allocator preserves it (so the next
        // pre-flight surfaces `AlreadyPreconfirmed` if it was ours).
        // Releasing here would hand the same nonce out again and create
        // duplicates.
        if is_nonce_too_low_error(&msg) {
            if let Err(sync_err) = shared
                .nonce_allocator
                .resync(&shared.config.l1_provider, shared.config.l1_signer_address)
                .await
            {
                warn!(batch_index, err = %sync_err, "NonceAllocator resync after nonce-too-low failed");
            }
        } else {
            shared.nonce_allocator.release(nonce);
        }
        warn!(batch_index, err = %msg, "initial broadcast failed");
        backoff.apply("initial broadcast failed");
        return BroadcastResult::Done;
    };

    // Bump-time `nonce-too-low` almost always means the prior broadcast
    // won the slot. Poll immediately so we do not wait a full bump
    // interval to notice.
    if is_nonce_too_low_error(&msg) {
        return bump_nonce_too_low_fastfail(shared, batch_index, template, prior, backoff).await;
    }

    warn!(batch_index, err = %msg, "RBF: bump broadcast failed — retrying next interval");
    BroadcastResult::Continue { hash: prior }
}

async fn bump_nonce_too_low_fastfail(
    shared: &OrchestratorShared,
    batch_index: u64,
    template: &PreconfirmTxTemplate,
    prior: B256,
    backoff: &mut DispatchBackoff,
) -> BroadcastResult {
    let provider = &shared.config.l1_provider;
    match provider.get_transaction_receipt(prior).await {
        Ok(Some(receipt)) => {
            crate::metrics::observe_dispatch_cost(&receipt);
            let Some(l1_block) = receipt.block_number else {
                warn!(
                    batch_index,
                    prior_hash = %prior,
                    "RBF: nonce-too-low + receipt without block_number — retry"
                );
                return BroadcastResult::Continue { hash: prior };
            };
            if receipt.status() {
                handle_submitted(shared, batch_index, prior, l1_block, backoff).await;
                return BroadcastResult::Done;
            }
            let kind = classify_revert(receipt.gas_used, template.gas_limit);
            warn!(
                batch_index,
                prior_hash = %prior,
                l1_block,
                ?kind,
                gas_used = receipt.gas_used,
                gas_limit = template.gas_limit,
                "RBF: nonce-too-low fallback found REVERTED receipt"
            );
            handle_reverted(shared, batch_index, prior, kind, backoff).await;
            BroadcastResult::Done
        }
        Ok(None) | Err(_) => {
            warn!(
                batch_index,
                prior_hash = %prior,
                "RBF: nonce advanced but latest hash has no receipt — failing"
            );
            handle_failed_then_undispatch(
                shared,
                batch_index,
                backoff,
                "nonce advanced, no receipt",
            )
            .await;
            BroadcastResult::Done
        }
    }
}

enum PollResult {
    Done,
    NotMined,
}

/// Sleep + check external takeover + poll receipt. Stays in the inner loop
/// on transient RPC quirks (`block_number == None`, RPC errors) so the fee
/// is not bumped for those cases.
async fn poll_for_terminal(
    shared: &OrchestratorShared,
    batch_index: u64,
    template: &PreconfirmTxTemplate,
    observed_hash: B256,
    backoff: &mut DispatchBackoff,
) -> PollResult {
    let cancel = &shared.shutdown;
    let bump_interval = shared.config.rbf_bump_interval;
    let provider = &shared.config.l1_provider;

    loop {
        tokio::select! {
            biased;
            _ = cancel.cancelled() => {
                info!(batch_index, "RBF dispatch cancelled (shutdown)");
                return PollResult::Done;
            }
            _ = tokio::time::sleep(bump_interval) => {}
        }

        // External-takeover guard: a `BatchPreconfirmed` L1 event sets
        // `nonce → None` via `mark_dispatched_external`. The external
        // submitter owns the row; we must not call `record_rbf_bump` or
        // `undispatch` on it.
        let nonce_present = {
            let acc = shared.accumulator.lock().unwrap_or_else(|e| e.into_inner());
            acc.dispatched.get(&batch_index).map(|d| d.nonce.is_some())
        };
        match nonce_present {
            Some(true) => {}
            Some(false) => {
                info!(
                    batch_index,
                    "RBF: external takeover detected (nonce=None) — exiting bump loop"
                );
                return PollResult::Done;
            }
            None => {
                // Row vanished — finalization-check finalized it, or a
                // resume race never inserted it. Nothing to bump.
                return PollResult::Done;
            }
        }

        match provider.get_transaction_receipt(observed_hash).await {
            Ok(Some(receipt)) => {
                crate::metrics::observe_dispatch_cost(&receipt);
                let Some(l1_block) = receipt.block_number else {
                    warn!(
                        batch_index,
                        current_hash = %observed_hash,
                        "Receipt present but block_number is None — retrying next interval"
                    );
                    continue;
                };
                if !receipt.status() {
                    let kind = classify_revert(receipt.gas_used, template.gas_limit);
                    warn!(
                        batch_index,
                        current_hash = %observed_hash,
                        l1_block,
                        ?kind,
                        gas_used = receipt.gas_used,
                        gas_limit = template.gas_limit,
                        "preconfirmBatch REVERTED on L1"
                    );
                    handle_reverted(shared, batch_index, observed_hash, kind, backoff).await;
                    return PollResult::Done;
                }
                info!(
                    batch_index,
                    current_hash = %observed_hash,
                    l1_block,
                    "preconfirmBatch confirmed on L1"
                );
                handle_submitted(shared, batch_index, observed_hash, l1_block, backoff).await;
                return PollResult::Done;
            }
            Ok(None) => return PollResult::NotMined,
            Err(e) => {
                warn!(
                    batch_index,
                    current_hash = %observed_hash,
                    err = %e,
                    "get_transaction_receipt failed — retrying next interval"
                );
                continue;
            }
        }
    }
}

async fn handle_submitted(
    shared: &OrchestratorShared,
    batch_index: u64,
    tx_hash: B256,
    l1_block: u64,
    backoff: &mut DispatchBackoff,
) {
    backoff.reset();
    {
        let mut acc = shared.accumulator.lock().unwrap_or_else(|e| e.into_inner());
        acc.record_dispatched_l1_block(batch_index, l1_block);
    }
    info!(batch_index, %tx_hash, l1_block, "Batch submitted to L1 — awaiting finalization");
}

async fn handle_reverted(
    shared: &OrchestratorShared,
    batch_index: u64,
    tx_hash: B256,
    kind: RevertKind,
    backoff: &mut DispatchBackoff,
) {
    metrics::counter!(
        crate::metrics::L1_DISPATCH_REJECTED_TOTAL,
        "kind" => crate::metrics::revert_kind_label(kind),
    )
    .increment(1);
    error!(batch_index, %tx_hash, ?kind, "preconfirmBatch REVERTED on L1 — undispatching");
    {
        let mut acc = shared.accumulator.lock().unwrap_or_else(|e| e.into_inner());
        acc.undispatch(batch_index);
    }
    match kind {
        // OOG retries immediately: the next attempt rebuilds the template,
        // which re-runs `estimate_gas` and applies the +20% buffer fresh.
        RevertKind::Oog => {}
        RevertKind::Logic => backoff.apply("Dispatch reverted (logic)"),
    }
}

async fn handle_failed_then_undispatch(
    shared: &OrchestratorShared,
    batch_index: u64,
    backoff: &mut DispatchBackoff,
    reason: &'static str,
) {
    {
        let mut acc = shared.accumulator.lock().unwrap_or_else(|e| e.into_inner());
        acc.undispatch(batch_index);
    }
    backoff.apply(reason);
}
