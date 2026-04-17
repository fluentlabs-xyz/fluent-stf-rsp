//! Writable `ProviderFactory` open path and the tip-following forward-sync
//! driver loop. Re-executes Fluent L2 blocks, builds witnesses, and emits
//! `ProveRequest`s into the orchestrator channel.

use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};

use alloy_eips::BlockNumberOrTag;
use alloy_network::Ethereum;
use alloy_provider::{Provider, RootProvider};
use alloy_rpc_client::BatchRequest;
use eyre::eyre;
use futures::stream::StreamExt;
use reth_chain_state::{ComputedTrieData, ExecutedBlock};
use reth_chainspec::ChainSpec;
use reth_db::mdbx::DatabaseArguments;
use reth_db::{init_db, ClientVersion, DatabaseEnv};
use reth_db_common::init::init_genesis;
use reth_evm::execute::{BasicBlockExecutor, BlockExecutionOutput, Executor};
use reth_node_types::NodeTypesWithDBAdapter;
use reth_primitives_traits::Block as _;
use reth_provider::providers::{
    BlockchainProvider, NodeTypesForProvider, ProviderFactory, RocksDBProvider, StaticFileProvider,
};
use reth_provider::static_file::StaticFileSegment;
use reth_provider::{
    BlockBodyIndicesProvider, BlockNumReader, DatabaseProviderFactory, HeaderProvider,
    SaveBlocksMode, StaticFileProviderFactory, StaticFileWriter,
};
use reth_prune::Pruner;
use reth_prune_types::MINIMUM_UNWIND_SAFE_DISTANCE;
use reth_revm::database::StateProviderDatabase;
use reth_trie::{HashedPostState, KeccakKeyHasher};
use rsp_client_executor::evm::FluentEvmConfig;
use rsp_client_executor::IntoPrimitives;
use rsp_host_executor::EthHostExecutor;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use tracing::{error, info, warn};

use crate::hub::WitnessHub;
use crate::types::ProveRequest;

use super::node_types::FluentMdbxNode;

/// Concrete node type used by the driver. `ProviderFactory` requires
/// `NodeTypesWithDB`, which the adapter supplies by bolting `DatabaseEnv`
/// onto our bare `NodeTypes` binding.
type DriverNode = NodeTypesWithDBAdapter<FluentMdbxNode, DatabaseEnv>;

/// Concrete pruner type: built via `PrunerBuilder::build_with_provider_factory`
/// against the driver's `ProviderFactory`.
pub(crate) type DriverPruner = Pruner<
    <ProviderFactory<DriverNode> as DatabaseProviderFactory>::ProviderRW,
    ProviderFactory<DriverNode>,
>;

/// Idle poll interval — how long to sleep when remote tip has not advanced.
const IDLE_POLL_INTERVAL: Duration = Duration::from_secs(2);

/// Backoff after a transient RPC error before retrying tip lookup.
const RPC_ERROR_BACKOFF: Duration = Duration::from_secs(5);

/// Number of blocks per JSON-RPC batch during the commit-only catch-up path.
/// One HTTP POST carries `CATCHUP_BATCH_SIZE` `eth_getBlockByNumber` calls,
/// cutting per-block HTTP overhead and reducing load on the remote node.
const CATCHUP_BATCH_SIZE: u64 = 64;

/// Number of batch fetches kept in flight. With `CATCHUP_BATCH_SIZE = 64`
/// and `CATCHUP_BATCH_PIPELINE = 2` the driver prefetches up to 128 blocks
/// ahead while `commit_phase` drains them sequentially.
const CATCHUP_BATCH_PIPELINE: usize = 2;

/// Open a writable `ProviderFactory<N>` against a fresh or existing
/// reth datadir. Layout: `<datadir>/{db,static_files,rocksdb}`.
pub(crate) fn open_writable_factory<N>(
    datadir: &Path,
    chain_spec: Arc<ChainSpec>,
    mdbx_max_size: u64,
    runtime: reth_tasks::Runtime,
) -> eyre::Result<ProviderFactory<NodeTypesWithDBAdapter<N, DatabaseEnv>>>
where
    N: NodeTypesForProvider<
        ChainSpec = ChainSpec,
        Primitives = reth_ethereum_primitives::EthPrimitives,
    >,
{
    std::fs::create_dir_all(datadir)?;
    let db_path = datadir.join("db");
    let sf_path = datadir.join("static_files");
    let rocks_path = datadir.join("rocksdb");

    std::fs::create_dir_all(&db_path)?;
    std::fs::create_dir_all(&sf_path)?;
    std::fs::create_dir_all(&rocks_path)?;

    let db_args = DatabaseArguments::new(ClientVersion::default())
        .with_geometry_max_size(Some(mdbx_max_size as usize));

    let db = init_db(&db_path, db_args).map_err(|e| eyre!("init_db: {e}"))?;

    let sf = StaticFileProvider::<N::Primitives>::read_write(&sf_path)
        .map_err(|e| eyre!("static_file_provider rw: {e}"))?;

    let rocks = RocksDBProvider::builder(&rocks_path)
        .with_default_tables()
        .build()
        .map_err(|e| eyre!("rocksdb_provider build: {e}"))?;

    let factory = ProviderFactory::<NodeTypesWithDBAdapter<N, DatabaseEnv>>::new(
        db, chain_spec, sf, rocks, runtime,
    )
    .map_err(|e| eyre!("provider_factory: {e}"))?;

    heal_static_files_if_needed(&factory)?;

    Ok(factory)
}

/// Self-heal static_files that got ahead of the MDBX tip.
///
/// reth's `save_blocks` is not atomic between static-file commits and
/// the MDBX commit: if the process dies (SIGKILL, OOM, power loss, panic)
/// between them, the static_files `.conf` tail pointer moves forward
/// while MDBX stays at the previous tip. On next open, the static-file
/// provider insists on the next append being `static_tip + 1`, but
/// `save_blocks` would hand it `mdbx_tip + 1` → "expected block N but
/// got N-1".
///
/// Fix: on startup, if any of Headers / Transactions / Receipts segments
/// point to a block above the MDBX tip, queue a prune back to MDBX tip
/// and commit. Next `save_blocks` then resumes cleanly.
fn heal_static_files_if_needed<N>(
    factory: &ProviderFactory<NodeTypesWithDBAdapter<N, DatabaseEnv>>,
) -> eyre::Result<()>
where
    N: NodeTypesForProvider<
        ChainSpec = ChainSpec,
        Primitives = reth_ethereum_primitives::EthPrimitives,
    >,
{
    let mdbx_tip = factory.best_block_number().map_err(|e| eyre!("best_block_number: {e}"))?;
    if mdbx_tip == 0 {
        // Pre-genesis: leave initialization to `init_genesis`.
        return Ok(());
    }

    let sf = factory.static_file_provider();

    let headers_tip = sf.get_highest_static_file_block(StaticFileSegment::Headers).unwrap_or(0);
    let txs_tip = sf.get_highest_static_file_block(StaticFileSegment::Transactions).unwrap_or(0);
    let receipts_tip = sf.get_highest_static_file_block(StaticFileSegment::Receipts).unwrap_or(0);

    if headers_tip <= mdbx_tip && txs_tip <= mdbx_tip && receipts_tip <= mdbx_tip {
        return Ok(());
    }

    warn!(
        mdbx_tip,
        headers_tip,
        txs_tip,
        receipts_tip,
        "static_files ahead of MDBX tip — healing (previous run likely killed \
         between save_blocks and MDBX commit)"
    );

    if headers_tip > mdbx_tip {
        let to_delete = headers_tip - mdbx_tip;
        let mut w = sf
            .get_writer(mdbx_tip, StaticFileSegment::Headers)
            .map_err(|e| eyre!("heal: headers writer: {e}"))?;
        w.prune_headers(to_delete).map_err(|e| eyre!("heal: prune_headers: {e}"))?;
        w.commit().map_err(|e| eyre!("heal: headers commit: {e}"))?;
    }

    if txs_tip > mdbx_tip || receipts_tip > mdbx_tip {
        let last_tx_at_tip = {
            let db_provider = factory
                .database_provider_ro()
                .map_err(|e| eyre!("heal: database_provider_ro: {e}"))?;
            let body = db_provider
                .block_body_indices(mdbx_tip)
                .map_err(|e| eyre!("heal: block_body_indices({mdbx_tip}): {e}"))?
                .ok_or_else(|| eyre!("heal: no block_body_indices for MDBX tip {mdbx_tip}"))?;
            body.last_tx_num()
        };

        if txs_tip > mdbx_tip {
            let highest_static_tx =
                sf.get_highest_static_file_tx(StaticFileSegment::Transactions).unwrap_or(0);
            let to_delete = highest_static_tx.saturating_sub(last_tx_at_tip);
            if to_delete > 0 {
                let mut w = sf
                    .get_writer(mdbx_tip, StaticFileSegment::Transactions)
                    .map_err(|e| eyre!("heal: txs writer: {e}"))?;
                w.prune_transactions(to_delete, mdbx_tip)
                    .map_err(|e| eyre!("heal: prune_transactions: {e}"))?;
                w.commit().map_err(|e| eyre!("heal: txs commit: {e}"))?;
            }
        }

        if receipts_tip > mdbx_tip {
            let highest_static_rx =
                sf.get_highest_static_file_tx(StaticFileSegment::Receipts).unwrap_or(0);
            let to_delete = highest_static_rx.saturating_sub(last_tx_at_tip);
            if to_delete > 0 {
                let mut w = sf
                    .get_writer(mdbx_tip, StaticFileSegment::Receipts)
                    .map_err(|e| eyre!("heal: receipts writer: {e}"))?;
                w.prune_receipts(to_delete, mdbx_tip)
                    .map_err(|e| eyre!("heal: prune_receipts: {e}"))?;
                w.commit().map_err(|e| eyre!("heal: receipts commit: {e}"))?;
            }
        }
    }

    // Refresh the in-memory segment index so subsequent readers see the
    // truncated state.
    sf.initialize_index().map_err(|e| eyre!("heal: initialize_index: {e}"))?;

    info!(mdbx_tip, "heal: static_files truncated to MDBX tip");
    Ok(())
}

/// Initialise genesis on an empty datadir; no-op if already populated.
fn ensure_genesis_initialized(factory: &ProviderFactory<DriverNode>) -> eyre::Result<()> {
    let tip = factory.best_block_number().map_err(|e| eyre!("best_block_number: {e}"))?;
    if tip > 0 {
        info!(tip, "datadir already initialized, resuming");
        return Ok(());
    }
    let genesis_hash = init_genesis(factory).map_err(|e| eyre!("init_genesis: {e}"))?;
    info!(?genesis_hash, "genesis initialized");
    Ok(())
}

pub(crate) struct DriverConfig {
    pub factory: ProviderFactory<DriverNode>,
    pub rpc: RootProvider<Ethereum>,
    pub host_executor: Arc<EthHostExecutor>,
    pub hub: Arc<WitnessHub>,
    pub prove_tx: mpsc::Sender<ProveRequest>,
    pub chain_spec: Arc<ChainSpec>,
    /// Optional reth pruner. When `Some`, invoked after every successful
    /// block commit — the pruner itself throttles via its `block_interval`.
    pub pruner: Option<DriverPruner>,
    /// First block that requires a full witness. Blocks below this threshold
    /// are commit-only (MDBX sync without witness/cold-store/ProveRequest).
    /// Set to 0 to witness every block (default when L1_START_BATCH_ID is unset).
    pub witness_from_block: u64,
    /// Pipeline-confirmed watermark from the orchestrator's SQLite store.
    /// The driver's resume cursor is `max(orchestrator_checkpoint + 1, witness_from_block)`.
    pub orchestrator_checkpoint: u64,
}

/// A block fetched from RPC together with the time it took to pull.
struct FetchedBlock {
    block_number: u64,
    alloy_block: alloy_rpc_types::Block,
    fetch_ms: u64,
}

/// Commit-phase output — everything the witness phase needs plus the
/// pre-witness per-phase timings.
struct WitnessJob {
    block_number: u64,
    prim_block: reth_ethereum_primitives::Block,
    parent_state_root: alloy_primitives::B256,
    fetch_ms: u64,
    execute_ms: u64,
    trie_ms: u64,
    save_ms: u64,
    t_total_start: Instant,
}

/// Drive the forward sync loop forever. Returns when `shutdown` fires or
/// the orchestrator channel closes; propagates fatal commit/witness errors.
pub(crate) async fn run(cfg: DriverConfig, shutdown: CancellationToken) -> eyre::Result<()> {
    ensure_genesis_initialized(&cfg.factory)?;
    let mut pruner = cfg.pruner;

    // Invariant: every block MDBX-committed by the driver WITH a witness must
    // also have been cold-store-committed. Commit-only blocks (below
    // witness_from_block) do not push to cold store — this is expected.
    // If `cold_last < mdbx_tip` AND `mdbx_tip >= witness_from_block`, a previous
    // run crashed between MDBX commit and the post-commit cold push for a
    // witness block. When MDBX is still catching up below witness_from_block,
    // cold_last trailing mdbx_tip is the normal commit-only state.
    let witness_from_block = cfg.witness_from_block;
    let mdbx_tip = cfg.factory.best_block_number().map_err(|e| eyre!("best_block_number: {e}"))?;
    let cold_last =
        cfg.hub.last_committed_block().map_err(|e| eyre!("hub.last_committed_block: {e}"))?;
    // `None` means a fresh cold store (or first run with cold-store enabled).
    // Intentionally NOT an error: allows migrating an existing MDBX datadir
    // to the new cold-store system — the first N blocks simply won't be in
    // cold storage, which is acceptable since they've already been processed.
    if let Some(cl) = cold_last {
        if mdbx_tip >= witness_from_block && cl < mdbx_tip {
            return Err(eyre!(
                "cold store last_committed_block {cl} is behind MDBX tip {mdbx_tip} — \
                 previous run committed to MDBX without persisting to the cold store. \
                 Restore the cold store from backup, or roll back the MDBX datadir \
                 to the matching block, before resuming."
            ));
        }
    }
    let start_tip = mdbx_tip;

    // Startup safety: if PRUNE_FULL is on and the tip is far past
    // witness_from_block, the history needed to re-witness blocks
    // [witness_from_block..start_tip] may already have been pruned.
    if pruner.is_some()
        && witness_from_block <= start_tip
        && start_tip - witness_from_block > MINIMUM_UNWIND_SAFE_DISTANCE
    {
        return Err(eyre!(
            "PRUNE_FULL=true but mdbx_tip ({start_tip}) is {} blocks past \
             witness_from_block ({witness_from_block}) — account_history/storage_history \
             needed to re-witness blocks [{witness_from_block}..{start_tip}] may already \
             have been pruned (MINIMUM_UNWIND_SAFE_DISTANCE = {}). Either disable \
             PRUNE_FULL, or restore from a snapshot whose mdbx_tip is within {} blocks \
             of witness_from_block.",
            start_tip - witness_from_block,
            MINIMUM_UNWIND_SAFE_DISTANCE,
            MINIMUM_UNWIND_SAFE_DISTANCE,
        ));
    }

    // Resume cursor: max of pipeline-confirmed checkpoint and first
    // witness-required block, clamped to `start_tip + 1` so the driver never
    // skips past its own MDBX tip. When MDBX is behind `witness_from_block`
    // (e.g. first run with a high L1_START_BATCH_ID against a fresh datadir),
    // the clamp routes blocks [start_tip+1 .. witness_from_block-1] through
    // the commit-only fast path below instead of the full-witness path, which
    // would otherwise fail with StateAtBlockNotAvailable on the parent lookup.
    let mut next = (cfg.orchestrator_checkpoint + 1).max(witness_from_block).min(start_tip + 1);
    info!(
        mdbx_tip = start_tip,
        cold_last = ?cold_last,
        orchestrator_checkpoint = cfg.orchestrator_checkpoint,
        witness_from_block,
        next,
        "Forward driver ready"
    );

    loop {
        if shutdown.is_cancelled() {
            info!("Shutdown requested — driver exiting");
            return Ok(());
        }

        let remote_tip = match cfg.rpc.get_block_number().await {
            Ok(t) => t,
            Err(e) => {
                warn!(err = %e, "rpc get_block_number failed — backing off");
                tokio::select! {
                    _ = shutdown.cancelled() => return Ok(()),
                    _ = tokio::time::sleep(RPC_ERROR_BACKOFF) => continue,
                }
            }
        };

        // Re-witness range [next..=start_tip] is locally bounded; if remote
        // is somehow behind start_tip we still want to drain it. Idle-wait
        // only fires when both are exhausted.
        let upper_inclusive = remote_tip.max(start_tip);
        if next > upper_inclusive {
            tokio::select! {
                _ = shutdown.cancelled() => return Ok(()),
                _ = tokio::time::sleep(IDLE_POLL_INTERVAL) => continue,
            }
        }

        while next <= upper_inclusive {
            if shutdown.is_cancelled() {
                info!("Shutdown requested mid-range — driver exiting");
                return Ok(());
            }

            let block_number = next;

            // ── Already-committed re-witness paths (block_number <= start_tip) ──
            if block_number <= start_tip {
                if block_number < witness_from_block {
                    // Below witness threshold: already committed, no witness needed.
                    next = block_number + 1;
                    continue;
                }

                let permit = tokio::select! {
                    biased;
                    _ = shutdown.cancelled() => {
                        info!("Shutdown requested while waiting for capacity — driver exiting");
                        return Ok(());
                    }
                    result = cfg.prove_tx.reserve() => match result {
                        Ok(p) => p,
                        Err(_) => {
                            info!("Orchestrator channel closed — driver exiting");
                            return Ok(());
                        }
                    },
                };

                let fetched = match fetch_block(&cfg.rpc, block_number).await {
                    Ok(f) => f,
                    Err(e) => {
                        warn!(block_number, err = %e, "fetch_block failed during re-witness — retrying");
                        tokio::select! {
                            _ = shutdown.cancelled() => return Ok(()),
                            _ = tokio::time::sleep(RPC_ERROR_BACKOFF) => {}
                        }
                        break;
                    }
                };

                let payload =
                    rewitness_phase(fetched, cfg.factory.clone(), Arc::clone(&cfg.host_executor))
                        .await?;

                cfg.hub.push(block_number, &payload).await?;
                permit.send(ProveRequest { block_number, payload });

                // Pruner is skipped here — nothing was committed, so there
                // is nothing new to prune. Re-running pruner on old tips
                // would just churn without purpose.

                next = block_number + 1;
                continue;
            }

            // ── block_number > start_tip — fresh tip-following paths ──

            // Commit-only fast path (catch-up before first batch).
            //
            // Commit phase must run sequentially — `state_root_with_updates`
            // at block N reads state written by block N-1. Fetching, however,
            // is network-bound and batchable: we pipeline N JSON-RPC batches
            // (each `CATCHUP_BATCH_SIZE` blocks) so network RTT and HTTP
            // overhead are amortized across many blocks and hidden behind
            // the CPU-bound commit work.
            if block_number < witness_from_block {
                let catchup_upper = upper_inclusive.min(witness_from_block - 1);

                // Chunk [block_number ..= catchup_upper] into batches of up
                // to CATCHUP_BATCH_SIZE blocks.
                let mut ranges: Vec<(u64, u64)> = Vec::new();
                {
                    let mut s = block_number;
                    while s <= catchup_upper {
                        let e = s.saturating_add(CATCHUP_BATCH_SIZE - 1).min(catchup_upper);
                        ranges.push((s, e));
                        s = e + 1;
                    }
                }

                let rpc = cfg.rpc.clone();
                let mut batch_stream = futures::stream::iter(ranges)
                    .map(move |(s, e)| {
                        let rpc = rpc.clone();
                        async move { (s, e, fetch_batch(&rpc, s, e).await) }
                    })
                    .buffered(CATCHUP_BATCH_PIPELINE);

                let mut fetch_failed = false;
                loop {
                    let (s, e, fetch_result) = tokio::select! {
                        biased;
                        _ = shutdown.cancelled() => {
                            info!("Shutdown requested mid-catch-up — driver exiting");
                            return Ok(());
                        }
                        item = batch_stream.next() => match item {
                            Some(x) => x,
                            None => break,
                        }
                    };

                    let fetched_batch = match fetch_result {
                        Ok(v) => v,
                        Err(err) => {
                            warn!(
                                range_start = s,
                                range_end = e,
                                err = %err,
                                "fetch_batch failed — retrying range"
                            );
                            tokio::select! {
                                _ = shutdown.cancelled() => return Ok(()),
                                _ = tokio::time::sleep(RPC_ERROR_BACKOFF) => {}
                            }
                            fetch_failed = true;
                            break;
                        }
                    };

                    for fetched in fetched_batch {
                        if shutdown.is_cancelled() {
                            info!("Shutdown requested mid-catch-up — driver exiting");
                            return Ok(());
                        }
                        let bn = fetched.block_number;

                        let factory_clone = cfg.factory.clone();
                        let chain_spec_clone = Arc::clone(&cfg.chain_spec);
                        tokio::task::spawn_blocking(move || {
                            commit_phase(&factory_clone, &chain_spec_clone, fetched)
                        })
                        .await
                        .map_err(|e| eyre!("commit_phase join: {e}"))??;

                        if bn.is_multiple_of(1000) {
                            info!(
                                block_number = bn,
                                witness_from_block, "Catch-up: committed block (no witness)"
                            );
                        }
                        if bn + 1 == witness_from_block {
                            info!(
                                block_number = bn,
                                witness_from_block,
                                "Catch-up complete — switching to full witness mode"
                            );
                        }

                        // Pruner still runs during catch-up.
                        if let Some(p) = pruner.take() {
                            if p.is_pruning_needed(bn) {
                                let res = tokio::task::spawn_blocking(move || {
                                    let mut p = p;
                                    let out = p.run(bn);
                                    (p, out)
                                })
                                .await;
                                match res {
                                    Ok((returned, Ok(out))) => {
                                        info!(block_number = bn, ?out, "Pruner run");
                                        pruner = Some(returned);
                                    }
                                    Ok((returned, Err(e))) => {
                                        warn!(block_number = bn, err = %e, "Pruner run failed");
                                        pruner = Some(returned);
                                    }
                                    Err(e) => {
                                        error!(
                                            block_number = bn,
                                            err = %e,
                                            "Pruner join failed — pruning disabled for this run, restart to restore"
                                        );
                                    }
                                }
                            } else {
                                pruner = Some(p);
                            }
                        }

                        next = bn + 1;
                    }
                }

                if fetch_failed {
                    break;
                }
                continue;
            }

            // ── Full witness path (existing behavior) ──────────────────

            // Reserve a channel slot BEFORE doing any heavy work. This is
            // the pull-based backpressure point: the driver idles here until
            // the orchestrator (and its workers) have capacity, so we never
            // waste CPU/IO on fetch → commit → witness → cold-store when
            // the execution pipeline is saturated.
            let permit = tokio::select! {
                biased;
                _ = shutdown.cancelled() => {
                    info!("Shutdown requested while waiting for capacity — driver exiting");
                    return Ok(());
                }
                result = cfg.prove_tx.reserve() => match result {
                    Ok(p) => p,
                    Err(_) => {
                        info!("Orchestrator channel closed — driver exiting");
                        return Ok(());
                    }
                },
            };

            let fetched = match fetch_block(&cfg.rpc, block_number).await {
                Ok(f) => f,
                Err(e) => {
                    warn!(block_number, err = %e, "fetch_block failed — retrying range");
                    tokio::select! {
                        _ = shutdown.cancelled() => return Ok(()),
                        _ = tokio::time::sleep(RPC_ERROR_BACKOFF) => {}
                    }
                    break;
                }
            };

            // Wrap commit_phase in spawn_blocking — it does heavy sync
            // MDBX + static_files work that must not stall the async runtime.
            let factory_clone = cfg.factory.clone();
            let chain_spec_clone = Arc::clone(&cfg.chain_spec);
            let job = tokio::task::spawn_blocking(move || {
                commit_phase(&factory_clone, &chain_spec_clone, fetched)
            })
            .await
            .map_err(|e| eyre!("commit_phase join: {e}"))??;
            let payload =
                witness_phase(job, cfg.factory.clone(), Arc::clone(&cfg.host_executor)).await?;

            // Cold store is fsynced before prove_tx send; on failure the
            // driver exits rather than advancing `next`. On restart the
            // `cold_last < mdbx_tip` guard above triggers and fails loudly.
            cfg.hub.push(block_number, &payload).await?;

            permit.send(ProveRequest { block_number, payload });

            // Pruner::run does a lot of sync disk work; thread ownership
            // across a spawn_blocking so we don't hold &mut across await
            // and don't stall the async runtime.
            if let Some(p) = pruner.take() {
                if p.is_pruning_needed(block_number) {
                    let res = tokio::task::spawn_blocking(move || {
                        let mut p = p;
                        let out = p.run(block_number);
                        (p, out)
                    })
                    .await;
                    match res {
                        Ok((returned, Ok(out))) => {
                            info!(block_number, ?out, "Pruner run");
                            pruner = Some(returned);
                        }
                        Ok((returned, Err(e))) => {
                            warn!(block_number, err = %e, "Pruner run failed");
                            pruner = Some(returned);
                        }
                        Err(e) => {
                            error!(
                                block_number,
                                err = %e,
                                "Pruner join failed — pruning disabled for this run, restart to restore"
                            );
                        }
                    }
                } else {
                    pruner = Some(p);
                }
            }

            next = block_number + 1;
        }
    }
}

async fn fetch_block(
    rpc: &RootProvider<Ethereum>,
    block_number: u64,
) -> eyre::Result<FetchedBlock> {
    let t_fetch = Instant::now();
    let alloy_block = rpc
        .get_block_by_number(block_number.into())
        .full()
        .await
        .map_err(|e| eyre!("rpc get_block({block_number}): {e}"))?
        .ok_or_else(|| eyre!("rpc returned no block for {block_number}"))?;
    Ok(FetchedBlock { block_number, alloy_block, fetch_ms: t_fetch.elapsed().as_millis() as u64 })
}

/// Fetch `[start ..= end_inclusive]` as a single JSON-RPC batch request —
/// one HTTP POST carrying N `eth_getBlockByNumber` calls, whose responses
/// are multiplexed back through per-call waiters.
///
/// All-or-nothing: if the batch send fails or any waiter returns an error
/// or `null`, the whole call errors out. Callers retry the entire range
/// after a backoff, matching the previous `fetch_block` semantics.
async fn fetch_batch(
    rpc: &RootProvider<Ethereum>,
    start: u64,
    end_inclusive: u64,
) -> eyre::Result<Vec<FetchedBlock>> {
    debug_assert!(start <= end_inclusive);
    let t_fetch = Instant::now();
    let mut batch = BatchRequest::new(rpc.client());

    let mut waiters = Vec::with_capacity((end_inclusive - start + 1) as usize);
    for bn in start..=end_inclusive {
        let waiter = batch
            .add_call::<_, Option<alloy_rpc_types::Block>>(
                "eth_getBlockByNumber",
                &(BlockNumberOrTag::Number(bn), true),
            )
            .map_err(|e| eyre!("rpc batch add_call block {bn}: {e}"))?;
        waiters.push((bn, waiter));
    }

    batch.send().await.map_err(|e| eyre!("rpc batch send [{start}..={end_inclusive}]: {e}"))?;

    let total_ms = t_fetch.elapsed().as_millis() as u64;
    let per_block_ms = total_ms / (end_inclusive - start + 1);

    let mut results = Vec::with_capacity(waiters.len());
    for (bn, waiter) in waiters {
        let block = waiter
            .await
            .map_err(|e| eyre!("rpc batch get_block({bn}): {e}"))?
            .ok_or_else(|| eyre!("rpc returned no block for {bn}"))?;
        results.push(FetchedBlock { block_number: bn, alloy_block: block, fetch_ms: per_block_ms });
    }

    Ok(results)
}

/// Commit phase: alloy → primitive → execute → trie → save_blocks(Full) → commit.
fn commit_phase(
    factory: &ProviderFactory<DriverNode>,
    chain_spec: &Arc<ChainSpec>,
    fetched: FetchedBlock,
) -> eyre::Result<WitnessJob> {
    let FetchedBlock { block_number, alloy_block, fetch_ms } = fetched;
    let t_total_start = Instant::now();

    let prim_block =
        <reth_ethereum_primitives::EthPrimitives as IntoPrimitives<Ethereum>>::into_primitive_block(
            alloy_block,
        );
    let recovered = prim_block
        .clone()
        .try_into_recovered()
        .map_err(|_| eyre!("recover_senders failed for block {block_number}"))?;

    let t_exec = Instant::now();
    let state_provider = factory.history_by_block_number(block_number - 1)?;
    let db = StateProviderDatabase::new(&state_provider);
    let evm_config = FluentEvmConfig::new_with_default_factory(chain_spec.clone());
    let executor = BasicBlockExecutor::new(evm_config, db);
    let exec_output: BlockExecutionOutput<_> =
        executor.execute(&recovered).map_err(|e| eyre!("execute: {e}"))?;
    let execute_ms = t_exec.elapsed().as_millis() as u64;

    let t_trie = Instant::now();
    let hashed_state =
        HashedPostState::from_bundle_state::<KeccakKeyHasher>(exec_output.state.state());
    let (state_root, trie_updates) = state_provider
        .state_root_with_updates(hashed_state.clone())
        .map_err(|e| eyre!("state_root_with_updates: {e}"))?;

    if state_root != recovered.header().state_root {
        eyre::bail!(
            "state_root mismatch at block {block_number}: computed {state_root:?}, header {:?}",
            recovered.header().state_root,
        );
    }
    let trie_ms = t_trie.elapsed().as_millis() as u64;

    drop(state_provider);
    let hashed_sorted = hashed_state.into_sorted();
    let trie_updates_sorted = trie_updates.into_sorted();
    let trie_data = ComputedTrieData {
        hashed_state: Arc::new(hashed_sorted),
        trie_updates: Arc::new(trie_updates_sorted),
        anchored_trie_input: None,
    };
    let executed = ExecutedBlock::new(Arc::new(recovered), Arc::new(exec_output), trie_data);

    let t_save = Instant::now();
    let provider_rw = factory.provider_rw()?;
    provider_rw
        .save_blocks(vec![executed], SaveBlocksMode::Full)
        .map_err(|e| eyre!("save_blocks: {e}"))?;
    provider_rw.commit().map_err(|e| eyre!("commit: {e}"))?;
    let save_ms = t_save.elapsed().as_millis() as u64;

    let parent_state_root = factory
        .header_by_number(block_number - 1)?
        .ok_or_else(|| eyre!("missing header N-1 after commit"))?
        .state_root;

    Ok(WitnessJob {
        block_number,
        prim_block,
        parent_state_root,
        fetch_ms,
        execute_ms,
        trie_ms,
        save_ms,
        t_total_start,
    })
}

/// Witness phase: execute_exex_with_block + bincode (on blocking pool).
/// Returns the serialized payload, leaving storage/channel side-effects to
/// the caller.
async fn witness_phase(
    job: WitnessJob,
    factory: ProviderFactory<DriverNode>,
    host_executor: Arc<EthHostExecutor>,
) -> eyre::Result<Vec<u8>> {
    let WitnessJob {
        block_number,
        prim_block,
        parent_state_root,
        fetch_ms,
        execute_ms,
        trie_ms,
        save_ms,
        t_total_start,
    } = job;

    let t_witness = Instant::now();
    // execute_exex_with_block walks tries and runs EVM — heavy sync work;
    // push it onto the blocking pool so the async runtime stays responsive.
    let input = tokio::task::spawn_blocking(move || -> eyre::Result<_> {
        let read_view =
            BlockchainProvider::new(factory).map_err(|e| eyre!("BlockchainProvider::new: {e}"))?;
        host_executor
            .execute_exex_with_block(prim_block, parent_state_root, read_view, None)
            .map_err(|e| eyre!("execute_exex_with_block: {e}"))
    })
    .await
    .map_err(|e| eyre!("witness_phase join: {e}"))??;
    let witness_ms = t_witness.elapsed().as_millis() as u64;

    let t_ser = Instant::now();
    let payload = match tokio::task::spawn_blocking(move || bincode::serialize(&input)).await {
        Ok(Ok(bytes)) => bytes,
        Ok(Err(e)) => {
            error!(block_number, err = %e, "bincode serialize failed");
            return Err(eyre!("bincode: {e}"));
        }
        Err(e) => {
            error!(block_number, err = %e, "serialize task panicked");
            return Err(eyre!("serialize task: {e}"));
        }
    };
    let serialize_ms = t_ser.elapsed().as_millis() as u64;
    let payload_bytes = payload.len() as u64;

    let total_ms = t_total_start.elapsed().as_millis() as u64;
    info!(
        block_number,
        total_ms,
        fetch_ms,
        execute_ms,
        trie_ms,
        save_ms,
        witness_ms,
        serialize_ms,
        payload_bytes,
        "Block witness built"
    );

    Ok(payload)
}

/// Re-witness phase: regenerate the witness for a block already in MDBX.
/// Reads parent state root from MDBX, runs `execute_exex_with_block` against
/// the existing state, and serializes. Does NOT commit — the block is already
/// present.
async fn rewitness_phase(
    fetched: FetchedBlock,
    factory: ProviderFactory<DriverNode>,
    host_executor: Arc<EthHostExecutor>,
) -> eyre::Result<Vec<u8>> {
    let FetchedBlock { block_number, alloy_block, fetch_ms } = fetched;
    let t_total_start = Instant::now();

    let prim_block =
        <reth_ethereum_primitives::EthPrimitives as IntoPrimitives<Ethereum>>::into_primitive_block(
            alloy_block,
        );

    let parent_state_root = factory
        .header_by_number(block_number - 1)
        .map_err(|e| eyre!("header_by_number({}): {e}", block_number - 1))?
        .ok_or_else(|| eyre!("missing header N-1 during re-witness of block {block_number}"))?
        .state_root;

    let t_witness = Instant::now();
    let input = tokio::task::spawn_blocking(move || -> eyre::Result<_> {
        let read_view =
            BlockchainProvider::new(factory).map_err(|e| eyre!("BlockchainProvider::new: {e}"))?;
        host_executor
            .execute_exex_with_block(prim_block, parent_state_root, read_view, None)
            .map_err(|e| eyre!("execute_exex_with_block (rewitness): {e}"))
    })
    .await
    .map_err(|e| eyre!("rewitness_phase join: {e}"))??;
    let witness_ms = t_witness.elapsed().as_millis() as u64;

    let t_ser = Instant::now();
    let payload = match tokio::task::spawn_blocking(move || bincode::serialize(&input)).await {
        Ok(Ok(bytes)) => bytes,
        Ok(Err(e)) => {
            error!(block_number, err = %e, "bincode serialize failed (rewitness)");
            return Err(eyre!("bincode: {e}"));
        }
        Err(e) => {
            error!(block_number, err = %e, "serialize task panicked (rewitness)");
            return Err(eyre!("serialize task: {e}"));
        }
    };
    let serialize_ms = t_ser.elapsed().as_millis() as u64;

    info!(
        block_number,
        total_ms = t_total_start.elapsed().as_millis() as u64,
        fetch_ms,
        witness_ms,
        serialize_ms,
        payload_bytes = payload.len() as u64,
        "Block re-witness built"
    );

    Ok(payload)
}
