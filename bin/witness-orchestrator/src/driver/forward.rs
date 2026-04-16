//! Writable `ProviderFactory` open path and the tip-following forward-sync
//! driver loop. Re-executes Fluent L2 blocks, builds witnesses, and emits
//! `ProveRequest`s into the orchestrator channel.

use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};

use alloy_network::Ethereum;
use alloy_provider::{Provider, RootProvider};
use eyre::eyre;
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
use reth_provider::{BlockNumReader, DatabaseProviderFactory, HeaderProvider, SaveBlocksMode};
use reth_prune::Pruner;
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
    Ok(factory)
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

    // Invariant: every block MDBX-committed by the driver must also have
    // been cold-store-committed. If `cold_last < mdbx_tip`, a previous run
    // crashed (or errored) between MDBX commit and the post-commit cold
    // push — exactly the A2 data-loss window. Refuse to start so the
    // operator has to roll back or restore.
    let mdbx_tip = cfg.factory.best_block_number().map_err(|e| eyre!("best_block_number: {e}"))?;
    let cold_last =
        cfg.hub.last_committed_block().map_err(|e| eyre!("hub.last_committed_block: {e}"))?;
    // `None` means a fresh cold store (or first run with cold-store enabled).
    // Intentionally NOT an error: allows migrating an existing MDBX datadir
    // to the new cold-store system — the first N blocks simply won't be in
    // cold storage, which is acceptable since they've already been processed.
    if let Some(cl) = cold_last {
        if cl < mdbx_tip {
            return Err(eyre!(
                "cold store last_committed_block {cl} is behind MDBX tip {mdbx_tip} — \
                 previous run committed to MDBX without persisting to the cold store. \
                 Restore the cold store from backup, or roll back the MDBX datadir \
                 to the matching block, before resuming."
            ));
        }
    }
    let start_tip = mdbx_tip;
    let mut next = start_tip + 1;
    info!(mdbx_tip, cold_last = ?cold_last, next, "Forward driver ready");

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

        if remote_tip < next {
            tokio::select! {
                _ = shutdown.cancelled() => return Ok(()),
                _ = tokio::time::sleep(IDLE_POLL_INTERVAL) => continue,
            }
        }

        while next <= remote_tip {
            if shutdown.is_cancelled() {
                info!("Shutdown requested mid-range — driver exiting");
                return Ok(());
            }

            let block_number = next;

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
