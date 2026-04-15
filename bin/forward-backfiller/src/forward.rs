//! Writable `ProviderFactory` open path and the per-block forward-sync
//! driver loop. Everything reth write-side lives here.

use std::path::Path;
use std::sync::Arc;
use std::time::Instant;

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
use reth_provider::{BlockNumReader, HeaderProvider, SaveBlocksMode};
use reth_revm::database::StateProviderDatabase;
use reth_trie::{HashedPostState, KeccakKeyHasher};
use rsp_client_executor::evm::FluentEvmConfig;
use rsp_client_executor::IntoPrimitives;
use rsp_host_executor::EthHostExecutor;
use tracing::info;
use witness_orchestrator::hub::WitnessHub;
use witness_orchestrator::types::ProveRequest;

use crate::node_types::FluentMdbxNode;
use crate::stats;

/// Concrete node type used by the driver. `ProviderFactory` requires
/// `NodeTypesWithDB`, which the adapter supplies by bolting `DatabaseEnv`
/// onto our bare `NodeTypes` binding.
pub(crate) type DriverNode = NodeTypesWithDBAdapter<FluentMdbxNode, DatabaseEnv>;

/// Open a writable `ProviderFactory<N>` against a fresh or existing
/// reth datadir. Layout matches the standard `mdbx-witness-backfiller`
/// convention: `<datadir>/{db,static_files,rocksdb}`.
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
pub(crate) fn ensure_genesis_initialized(
    factory: &ProviderFactory<DriverNode>,
) -> eyre::Result<()> {
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
    pub(crate) factory: ProviderFactory<DriverNode>,
    pub(crate) rpc: RootProvider<Ethereum>,
    pub(crate) host_executor: Arc<EthHostExecutor>,
    pub(crate) hub: Arc<WitnessHub>,
    pub(crate) chain_spec: Arc<ChainSpec>,
    pub(crate) from: u64,
    pub(crate) to: u64,
    pub(crate) rpc_concurrency: usize,
    pub(crate) witness_concurrency: usize,
    pub(crate) dry_run: bool,
}

/// A block fetched from RPC together with the time it took to pull.
struct FetchedBlock {
    block_number: u64,
    alloy_block: alloy_rpc_types::Block,
    fetch_ms: u64,
}

/// Commit-phase output — everything the witness phase needs plus the
/// pre-witness per-phase timings, forwarded into the final `BlockStats`.
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

pub(crate) struct ForwardDriver {
    cfg: DriverConfig,
}

impl ForwardDriver {
    pub(crate) fn new(cfg: DriverConfig) -> Self {
        Self { cfg }
    }

    pub(crate) async fn run(self) -> eyre::Result<()> {
        let planned = self.cfg.to - self.cfg.from + 1;
        let stats = stats::spawn(planned);

        // Ensure we're starting at tip+1.
        let tip = self.cfg.factory.best_block_number()?;
        if tip + 1 != self.cfg.from {
            eyre::bail!(
                "expected tip+1 == from_block (tip={tip}, from={}); datadir not at the right height",
                self.cfg.from
            );
        }

        // Prefetch window: `rpc_concurrency` in-flight `get_block_by_number`
        // calls. `buffered` preserves input order, so blocks arrive at the
        // consumer in strictly ascending order.
        use futures::stream::{self, FuturesUnordered, StreamExt};
        let rpc = self.cfg.rpc.clone();
        let mut fetch_stream = stream::iter(self.cfg.from..=self.cfg.to)
            .map(move |block_number| {
                let rpc = rpc.clone();
                async move {
                    let t_fetch = Instant::now();
                    let alloy_block = rpc
                        .get_block_by_number(block_number.into())
                        .full()
                        .await
                        .map_err(|e| eyre!("rpc get_block({block_number}): {e}"))?
                        .ok_or_else(|| eyre!("rpc returned no block for {block_number}"))?;
                    Ok::<FetchedBlock, eyre::Report>(FetchedBlock {
                        block_number,
                        alloy_block,
                        fetch_ms: t_fetch.elapsed().as_millis() as u64,
                    })
                }
            })
            .buffered(self.cfg.rpc_concurrency.max(1));

        // Witness concurrency: at most `witness_concurrency` in-flight
        // `witness_phase` tasks. `acquire_owned` on the semaphore holds
        // `commit_phase` in pause when witness falls behind — natural
        // backpressure, no hand-rolled book-keeping.
        let witness_sem =
            Arc::new(tokio::sync::Semaphore::new(self.cfg.witness_concurrency.max(1)));
        let mut in_flight: FuturesUnordered<tokio::task::JoinHandle<eyre::Result<()>>> =
            FuturesUnordered::new();

        loop {
            tokio::select! {
                biased;
                // Drain completed witness tasks eagerly so errors surface fast.
                Some(done) = in_flight.next(), if !in_flight.is_empty() => {
                    done.map_err(|e| eyre!("witness task join: {e}"))??;
                }
                maybe = fetch_stream.next() => {
                    let Some(fetched) = maybe else { break };
                    let fetched = fetched?;

                    // Commit phase — strictly serial, on the dispatcher task.
                    let job = commit_phase(&self.cfg.factory, &self.cfg.chain_spec, fetched)?;

                    // Admission control for the witness phase.
                    let permit = Arc::clone(&witness_sem)
                        .acquire_owned()
                        .await
                        .map_err(|e| eyre!("semaphore closed: {e}"))?;

                    let fut = witness_phase(
                        job,
                        self.cfg.factory.clone(),
                        Arc::clone(&self.cfg.host_executor),
                        Arc::clone(&self.cfg.hub),
                        stats.tx.clone(),
                        permit,
                        self.cfg.dry_run,
                    );
                    in_flight.push(tokio::spawn(fut));
                }
            }
        }

        // Drain remaining witness tasks.
        while let Some(done) = in_flight.next().await {
            done.map_err(|e| eyre!("witness task join: {e}"))??;
        }

        drop(stats.tx);
        let summary = stats.join.await.map_err(|e| eyre!("stats join: {e}"))?;
        summary.log();

        Ok(())
    }
}

/// Commit phase: alloy → primitive → execute → trie → save_blocks(Full) → commit.
/// Runs strictly sequentially on the dispatcher task.
fn commit_phase(
    factory: &ProviderFactory<DriverNode>,
    chain_spec: &Arc<ChainSpec>,
    fetched: FetchedBlock,
) -> eyre::Result<WitnessJob> {
    let FetchedBlock { block_number, alloy_block, fetch_ms } = fetched;
    let t_total_start = Instant::now();

    // Convert alloy -> reth primitive block -> recovered.
    let prim_block =
        <reth_ethereum_primitives::EthPrimitives as IntoPrimitives<Ethereum>>::into_primitive_block(
            alloy_block,
        );
    let recovered = prim_block
        .clone()
        .try_into_recovered()
        .map_err(|_| eyre!("recover_senders failed for block {block_number}"))?;

    // Execute against state @ N-1 (which is tip; shortcuts to
    // LatestStateProvider inside reth).
    let t_exec = Instant::now();
    let state_provider = factory.history_by_block_number(block_number - 1)?;
    let db = StateProviderDatabase::new(&state_provider);
    let evm_config = FluentEvmConfig::new_with_default_factory(chain_spec.clone());
    let executor = BasicBlockExecutor::new(evm_config, db);
    let exec_output: BlockExecutionOutput<_> =
        executor.execute(&recovered).map_err(|e| eyre!("execute: {e}"))?;
    let execute_ms = t_exec.elapsed().as_millis() as u64;

    // Compute (state_root, trie_updates) for save_blocks(Full).
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

    // Assemble ExecutedBlock + save_blocks(Full) + commit.
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

    // After commit, tip == block_number → header_by_number(N-1) always satisfied.
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

/// Witness phase: execute_exex_with_block + bincode (on blocking pool) +
/// hub.push + stats. Runs concurrently — up to `witness_concurrency`
/// instances via the semaphore held in `_permit`.
async fn witness_phase(
    job: WitnessJob,
    factory: ProviderFactory<DriverNode>,
    host_executor: Arc<EthHostExecutor>,
    hub: Arc<WitnessHub>,
    stats_tx: tokio::sync::mpsc::UnboundedSender<stats::BlockStats>,
    _permit: tokio::sync::OwnedSemaphorePermit,
    dry_run: bool,
) -> eyre::Result<()> {
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
    let read_view =
        BlockchainProvider::new(factory).map_err(|e| eyre!("BlockchainProvider::new: {e}"))?;
    let input = host_executor
        .execute_exex_with_block(prim_block, parent_state_root, read_view, None)
        .map_err(|e| eyre!("execute_exex_with_block: {e}"))?;
    let witness_ms = t_witness.elapsed().as_millis() as u64;

    let (serialize_ms, push_ms, payload_bytes) = if dry_run {
        drop(input);
        (0u64, 0u64, 0u64)
    } else {
        let t_ser = Instant::now();
        let payload = tokio::task::spawn_blocking(move || bincode::serialize(&input))
            .await
            .map_err(|e| eyre!("serialize task panicked: {e}"))?
            .map_err(|e| eyre!("bincode: {e}"))?;
        let serialize_ms = t_ser.elapsed().as_millis() as u64;
        let payload_bytes = payload.len() as u64;

        let t_push = Instant::now();
        hub.push(Arc::new(ProveRequest { block_number, payload })).await;
        let push_ms = t_push.elapsed().as_millis() as u64;
        (serialize_ms, push_ms, payload_bytes)
    };

    let total_ms = t_total_start.elapsed().as_millis() as u64;
    let _ = stats_tx.send(stats::BlockStats {
        block_number,
        total_ms,
        fetch_ms,
        execute_ms,
        trie_ms,
        save_ms,
        witness_ms,
        serialize_ms,
        push_ms,
        payload_bytes,
    });
    Ok(())
}
