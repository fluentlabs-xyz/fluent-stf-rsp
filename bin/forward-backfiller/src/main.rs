//! Forward-sync witness backfiller.
//!
//! Starts from an EMPTY reth datadir, calls init_genesis, then walks
//! blocks [from..=to] by fetching each via RPC, executing it, committing
//! state to MDBX via save_blocks(Full), and building a witness via
//! execute_exex_with_block against the freshly-committed tip.

#![cfg_attr(not(test), warn(unused_crate_dependencies))]

mod forward;
mod node_types;
mod stats;

use std::path::PathBuf;
use std::sync::Arc;

use alloy_network::Ethereum;
use alloy_provider::RootProvider;
use clap::Parser;
use eyre::eyre;
use tokio::runtime::Handle;
use tracing::info;
use tracing_subscriber::{filter::EnvFilter, fmt, prelude::*};

use fluent_stf_primitives::fluent_chainspec;
use reth_chainspec::ChainSpec;
use reth_tasks::Runtime;
use rsp_host_executor::EthHostExecutor;
use rsp_provider::create_provider;
use witness_orchestrator::hub::WitnessHub;

use crate::forward::{DriverConfig, ForwardDriver};
use crate::node_types::FluentMdbxNode;

#[derive(Parser, Debug)]
#[command(
    name = "forward-backfiller",
    about = "Forward-drive MDBX + build witnesses from an RPC endpoint"
)]
struct Args {
    /// Fluent RPC URL (archival node required).
    #[arg(long, env = "FLUENT_RPC_URL")]
    rpc_url: url::Url,

    /// Reth datadir. If empty, init_genesis runs and processing starts at 1.
    /// Otherwise processing resumes at `best_block_number + 1`.
    #[arg(long)]
    datadir: PathBuf,

    /// Cold witness database file (redb). Created if missing.
    #[arg(long)]
    cold_file: PathBuf,

    /// Last block to process (inclusive).
    #[arg(long)]
    to_block: u64,

    /// Cold-tier byte cap. Default 1 TiB.
    #[arg(long, default_value_t = 1024u64 * 1024 * 1024 * 1024)]
    max_cold_bytes: u64,

    /// MDBX geometry max size in bytes. Default 256 GiB.
    #[arg(long, default_value_t = 256u64 * 1024 * 1024 * 1024)]
    mdbx_max_size: u64,

    /// Max in-flight RPC `get_block_by_number` prefetches. Default 8.
    #[arg(long, default_value_t = 8)]
    rpc_concurrency: usize,

    /// Max in-flight witness build + serialize tasks. Default 2.
    #[arg(long, default_value_t = 2)]
    witness_concurrency: usize,

    /// Dry-run: build ClientExecutorInput but skip serialize + hub.push.
    #[arg(long, default_value_t = false)]
    dry_run: bool,
}

#[tokio::main(flavor = "multi_thread")]
async fn main() -> eyre::Result<()> {
    if std::env::var("RUST_LOG").is_err() {
        std::env::set_var("RUST_LOG", "info");
    }
    tracing_subscriber::registry().with(fmt::layer()).with(EnvFilter::from_default_env()).init();

    let args = Args::parse();

    let chain_spec: Arc<ChainSpec> = Arc::new(fluent_chainspec());

    // RPC
    let rpc: RootProvider<Ethereum> = create_provider(args.rpc_url.clone());
    info!(rpc = %args.rpc_url, "rpc provider ready");

    // Writable factory (single-writer path — plan §5a).
    let runtime = Runtime::with_existing_handle(Handle::current())
        .map_err(|e| eyre!("reth_tasks::Runtime: {e}"))?;
    let factory = forward::open_writable_factory::<FluentMdbxNode>(
        &args.datadir,
        chain_spec.clone(),
        args.mdbx_max_size,
        runtime,
    )?;

    // Initialize genesis on empty datadir; otherwise resume from tip+1.
    forward::ensure_genesis_initialized(&factory)?;

    let tip = {
        use reth_provider::BlockNumReader;
        factory.best_block_number().map_err(|e| eyre!("best_block_number: {e}"))?
    };
    let from_block = tip + 1;
    info!(best_block_number = tip, from_block, to_block = args.to_block, "datadir ready");

    if args.to_block < from_block {
        eyre::bail!("--to-block ({}) < resume point ({from_block}); nothing to do", args.to_block);
    }

    let host_executor = Arc::new(EthHostExecutor::eth(chain_spec.clone(), None));
    let hub = Arc::new(WitnessHub::new_for_backfill(args.cold_file.clone(), args.max_cold_bytes));

    let driver = ForwardDriver::new(DriverConfig {
        factory,
        rpc,
        host_executor,
        hub,
        chain_spec,
        from: from_block,
        to: args.to_block,
        rpc_concurrency: args.rpc_concurrency,
        witness_concurrency: args.witness_concurrency,
        dry_run: args.dry_run,
    });

    driver.run().await?;
    Ok(())
}
