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
    batch_status, broadcast_rollup_tx, build_preconfirm_tx, find_batch_preconfirm_event,
    get_batch_on_chain, is_nonce_too_low_error, RollupTxTemplate,
};
use tracing::{error, info, warn};

use async_trait::async_trait;

use crate::{
    accumulator::{self, RbfResumeState},
    db::BatchStatus,
    orchestrator::{
        classify_revert, DispatchBackoff, OrchestratorShared, RevertKind, STUCK_AT_CAP_TIMEOUT,
    },
};

/// State-mutation hooks for the RBF lifecycle. Implemented by the
/// preconfirm dispatcher (mutates the `batches` table via accumulator
/// helpers) and the challenge resolver (no persistent state — pure no-ops +
/// log). Methods are `async fn` because mutations route through the
/// sync-write actor (`db_send_sync`) and await durability.
#[async_trait]
pub(crate) trait RbfObserver: Send + Sync {
    /// First successful broadcast. Records `status=Sent` + RBF state.
    async fn on_first_broadcast(&self, hash: B256, fee: u128, tip: u128);
    /// RBF bump rebroadcast. Overwrites tx_hash + fees; status stays Sent.
    async fn on_rebroadcast(&self, hash: B256, fee: u128, tip: u128);
    /// Receipt observed with status=1. Records `l1_block`; the L1 listener
    /// owns the `Sent → Preconfirmed` transition.
    async fn on_submitted(&self, hash: B256, l1_block: u64);
    /// Receipt observed with status=0. Rolls back to `Accepted`.
    async fn on_reverted(&self, hash: B256, kind: RevertKind);
    /// Pre-receipt hard fail (initial broadcast error, stuck-at-cap,
    /// nonce advanced without receipt).
    async fn on_pre_receipt_failure(&self, reason: &'static str);
    /// Polled between bump cycles. Return `true` to abandon the bump
    /// loop silently — used to detect external takeover where another
    /// dispatcher won the slot.
    async fn should_abort(&self) -> bool;
}

/// Preconfirm-path observer: routes state mutations through
/// `BatchAccumulator` (dispatched-row bookkeeping, RBF-bump record).
pub(crate) struct PreconfirmObserver<'a> {
    shared: &'a OrchestratorShared,
    batch_index: u64,
    nonce: u64,
}

impl<'a> PreconfirmObserver<'a> {
    pub(crate) fn new(shared: &'a OrchestratorShared, batch_index: u64, nonce: u64) -> Self {
        Self { shared, batch_index, nonce }
    }
}

#[async_trait]
impl RbfObserver for PreconfirmObserver<'_> {
    async fn on_first_broadcast(&self, hash: B256, fee: u128, tip: u128) {
        info!(
            batch_index = self.batch_index,
            nonce = self.nonce,
            %hash,
            max_fee_per_gas = fee,
            max_priority_fee_per_gas = tip,
            "preconfirmBatch tx broadcast (initial)"
        );
        if let Err(e) = accumulator::record_broadcast(
            &self.shared.accumulator,
            self.batch_index,
            hash,
            self.nonce,
            fee,
            tip,
        )
        .await
        {
            error!(batch_index = self.batch_index, err = %e, "record_broadcast failed");
            return;
        }
        let acc = self.shared.accumulator.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(batch) = acc.get(self.batch_index) {
            crate::metrics::set_last_batch_dispatched(
                self.batch_index,
                batch.from_block,
                batch.to_block,
            );
        }
    }

    async fn on_rebroadcast(&self, hash: B256, fee: u128, tip: u128) {
        info!(
            batch_index = self.batch_index,
            %hash,
            max_fee_per_gas = fee,
            max_priority_fee_per_gas = tip,
            "RBF bump rebroadcast"
        );
        if let Err(e) =
            accumulator::record_rbf_bump(&self.shared.accumulator, self.batch_index, hash, fee, tip)
                .await
        {
            error!(batch_index = self.batch_index, err = %e, "record_rbf_bump failed");
        }
    }

    async fn on_submitted(&self, hash: B256, l1_block: u64) {
        // Record the L1 block of the receipt; status stays `Sent`. The L1
        // listener owns the `Sent → Preconfirmed` transition (Q3/Q4).
        if let Err(e) = accumulator::record_receipt_observed(
            &self.shared.accumulator,
            self.batch_index,
            l1_block,
        )
        .await
        {
            error!(batch_index = self.batch_index, err = %e, "record_receipt_observed failed");
        }
        info!(
            batch_index = self.batch_index,
            %hash,
            l1_block,
            "Batch submitted to L1 — awaiting BatchPreconfirmed event"
        );
    }

    async fn on_reverted(&self, hash: B256, kind: RevertKind) {
        error!(
            batch_index = self.batch_index,
            %hash,
            ?kind,
            "preconfirmBatch REVERTED on L1 — rolling back to Accepted"
        );
        if let Err(e) =
            accumulator::rollback_to_accepted(&self.shared.accumulator, self.batch_index).await
        {
            error!(batch_index = self.batch_index, err = %e, "rollback_to_accepted failed");
        }
    }

    async fn on_pre_receipt_failure(&self, _reason: &'static str) {
        if let Err(e) =
            accumulator::rollback_to_accepted(&self.shared.accumulator, self.batch_index).await
        {
            error!(batch_index = self.batch_index, err = %e, "rollback_to_accepted failed");
        }
    }

    async fn should_abort(&self) -> bool {
        // External-takeover guard: a `BatchPreconfirmed` L1 event flips the
        // row's status to `Preconfirmed` (and clears nonce for external).
        // If our row is no longer at `Sent` someone else won the slot — exit
        // the bump loop without further mutations.
        let acc = self.shared.accumulator.lock().unwrap_or_else(|e| e.into_inner());
        match acc.get(self.batch_index).map(|b| (b.status, b.nonce.is_some())) {
            Some((BatchStatus::Sent, true)) => false,
            Some((BatchStatus::Sent, false)) => {
                info!(
                    batch_index = self.batch_index,
                    "RBF: external takeover detected (nonce=None) — exiting bump loop"
                );
                true
            }
            Some((status, _)) if status > BatchStatus::Sent => {
                info!(
                    batch_index = self.batch_index,
                    ?status,
                    "RBF: status moved past Sent — exiting bump loop"
                );
                true
            }
            _ => true,
        }
    }
}

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

    let observer = PreconfirmObserver::new(shared, batch_index, nonce);
    run_generic(shared, batch_index, &template, nonce, resume, fee, tip, &observer, backoff).await;
}

/// RBF bump-and-poll lifecycle. State mutations are delegated to
/// `observer`; caller is responsible for pre-flight checks + template
/// construction, and `nonce` must already be allocated from
/// `shared.nonce_allocator`.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn run_generic(
    shared: &OrchestratorShared,
    batch_index: u64,
    template: &RollupTxTemplate,
    nonce: u64,
    resume: Option<RbfResumeState>,
    initial_fee: u128,
    initial_tip: u128,
    observer: &dyn RbfObserver,
    backoff: &mut DispatchBackoff,
) {
    bump_loop(
        shared,
        batch_index,
        template,
        nonce,
        resume,
        initial_fee,
        initial_tip,
        observer,
        backoff,
    )
    .await;
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
            handle_failed_then_undispatch_preflight(
                shared,
                batch_index,
                backoff,
                "pre-flight not submitted",
            )
            .await;
            false
        }
        other => {
            warn!(
                batch_index,
                status = other,
                "pre-flight: unexpected on-chain batch status — backing off"
            );
            handle_failed_then_undispatch_preflight(
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
        handle_failed_then_undispatch_preflight(
            shared,
            batch_index,
            backoff,
            "pre-flight unfinalized",
        )
        .await;
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
        handle_failed_then_undispatch_preflight(
            shared,
            batch_index,
            backoff,
            "pre-flight no event",
        )
        .await;
        return;
    };

    info!(
        batch_index,
        tx_hash = %info.tx_hash,
        l1_block = info.l1_block,
        "pre-flight: batch already preconfirmed on L1 — recording preconfirmation"
    );
    if let Err(e) = accumulator::observe_preconfirmed(
        &shared.accumulator,
        batch_index,
        info.tx_hash,
        info.l1_block,
    )
    .await
    {
        warn!(batch_index, err = %e, "observe_preconfirmed failed");
        backoff.apply("observe_preconfirmed failed");
        return;
    }
    {
        let acc = shared.accumulator.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(batch) = acc.get(batch_index) {
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
) -> Option<RollupTxTemplate> {
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
    template: &RollupTxTemplate,
    nonce: u64,
    resume: Option<RbfResumeState>,
    initial_fee: u128,
    initial_tip: u128,
    observer: &dyn RbfObserver,
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
                observer,
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
        match poll_for_terminal(shared, batch_index, template, observed_hash, observer, backoff)
            .await
        {
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
                handle_failed_then_undispatch(observer, backoff, "stuck-at-cap timeout").await;
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
    template: &RollupTxTemplate,
    max_fee_per_gas: u128,
    max_priority_fee_per_gas: u128,
    current_hash: Option<B256>,
    nonce: u64,
    observer: &dyn RbfObserver,
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
        res = broadcast_rollup_tx(
            provider,
            signer,
            template,
            max_fee_per_gas,
            max_priority_fee_per_gas,
        ) => res,
    };

    match res {
        Ok(new_hash) => {
            if was_first {
                backoff.reset();
                observer
                    .on_first_broadcast(new_hash, max_fee_per_gas, max_priority_fee_per_gas)
                    .await;
            } else {
                observer.on_rebroadcast(new_hash, max_fee_per_gas, max_priority_fee_per_gas).await;
            }
            BroadcastResult::Continue { hash: new_hash }
        }
        Err(e) => {
            handle_broadcast_error(
                shared,
                batch_index,
                template,
                e,
                current_hash,
                nonce,
                observer,
                backoff,
            )
            .await
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn handle_broadcast_error(
    shared: &OrchestratorShared,
    batch_index: u64,
    template: &RollupTxTemplate,
    err: eyre::Report,
    current_hash: Option<B256>,
    nonce: u64,
    observer: &dyn RbfObserver,
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
        return bump_nonce_too_low_fastfail(shared, batch_index, template, prior, observer, backoff)
            .await;
    }

    warn!(batch_index, err = %msg, "RBF: bump broadcast failed — retrying next interval");
    BroadcastResult::Continue { hash: prior }
}

async fn bump_nonce_too_low_fastfail(
    shared: &OrchestratorShared,
    batch_index: u64,
    template: &RollupTxTemplate,
    prior: B256,
    observer: &dyn RbfObserver,
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
                handle_submitted(observer, prior, l1_block, backoff).await;
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
            handle_reverted(observer, prior, kind, backoff).await;
            BroadcastResult::Done
        }
        Ok(None) | Err(_) => {
            warn!(
                batch_index,
                prior_hash = %prior,
                "RBF: nonce advanced but latest hash has no receipt — failing"
            );
            handle_failed_then_undispatch(observer, backoff, "nonce advanced, no receipt").await;
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
    template: &RollupTxTemplate,
    observed_hash: B256,
    observer: &dyn RbfObserver,
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

        if observer.should_abort().await {
            return PollResult::Done;
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
                    handle_reverted(observer, observed_hash, kind, backoff).await;
                    return PollResult::Done;
                }
                info!(
                    batch_index,
                    current_hash = %observed_hash,
                    l1_block,
                    "preconfirmBatch confirmed on L1"
                );
                handle_submitted(observer, observed_hash, l1_block, backoff).await;
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
    observer: &dyn RbfObserver,
    tx_hash: B256,
    l1_block: u64,
    backoff: &mut DispatchBackoff,
) {
    backoff.reset();
    observer.on_submitted(tx_hash, l1_block).await;
}

async fn handle_reverted(
    observer: &dyn RbfObserver,
    tx_hash: B256,
    kind: RevertKind,
    backoff: &mut DispatchBackoff,
) {
    metrics::counter!(
        crate::metrics::L1_DISPATCH_REJECTED_TOTAL,
        "kind" => crate::metrics::revert_kind_label(kind),
    )
    .increment(1);
    observer.on_reverted(tx_hash, kind).await;
    match kind {
        // OOG retries immediately: the next attempt rebuilds the template,
        // which re-runs `estimate_gas` and applies the +20% buffer fresh.
        RevertKind::Oog => {}
        RevertKind::Logic => backoff.apply("Dispatch reverted (logic)"),
    }
}

async fn handle_failed_then_undispatch(
    observer: &dyn RbfObserver,
    backoff: &mut DispatchBackoff,
    reason: &'static str,
) {
    observer.on_pre_receipt_failure(reason).await;
    backoff.apply(reason);
}

/// Preflight-time fail path: preconfirm-specific. Runs before any
/// `RbfObserver` exists, so it touches the accumulator directly.
async fn handle_failed_then_undispatch_preflight(
    shared: &OrchestratorShared,
    batch_index: u64,
    backoff: &mut DispatchBackoff,
    reason: &'static str,
) {
    if let Err(e) = accumulator::rollback_to_accepted(&shared.accumulator, batch_index).await {
        warn!(batch_index, err = %e, "preflight rollback failed");
    }
    backoff.apply(reason);
}

/// `tip <= max_fee` is the EIP-1559 invariant; the third return value is
/// the `clamped` flag indicating the post-bump fee reached `cap`.
pub(crate) fn bump_fees(
    max_fee: u128,
    tip: u128,
    bump_percent: u32,
    cap: u128,
) -> (u128, u128, bool) {
    let factor = 100u128 + bump_percent as u128;
    let new_fee = max_fee.saturating_mul(factor) / 100;
    let new_tip = tip.saturating_mul(factor) / 100;
    let clamped = new_fee >= cap;
    let new_fee = new_fee.min(cap);
    let new_tip = new_tip.min(new_fee);
    (new_fee, new_tip, clamped)
}
