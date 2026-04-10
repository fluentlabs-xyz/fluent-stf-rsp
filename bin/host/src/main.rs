#![cfg_attr(not(test), warn(unused_crate_dependencies))]

use std::sync::Arc;

use clap::Parser;
use rsp_host_executor::{create_eth_block_execution_strategy_factory, EthExecutorComponents};
use rsp_provider::create_provider;
use tracing_subscriber::{
    filter::EnvFilter, fmt, prelude::__tracing_subscriber_SubscriberExt, util::SubscriberInitExt,
};

#[cfg(feature = "sp1")]
mod execute;

#[cfg(feature = "sp1")]
use execute::PersistExecutionReport;

#[cfg(feature = "sp1")]
use rsp_host_executor::{build_executor, BlockExecutor};

mod cli;
use cli::HostArgs;

#[tokio::main]
async fn main() -> eyre::Result<()> {
    // Initialize the environment variables.
    dotenv::dotenv().ok();

    if std::env::var("RUST_LOG").is_err() {
        std::env::set_var("RUST_LOG", "info");
    }

    // Initialize the logger.
    tracing_subscriber::registry()
        .with(fmt::layer())
        .with(
            EnvFilter::from_default_env()
                .add_directive("sp1_core_machine=warn".parse().unwrap())
                .add_directive("sp1_core_executor::executor=warn".parse().unwrap())
                .add_directive("sp1_prover=warn".parse().unwrap()),
        )
        .init();

    // Parse the command line arguments.
    let args = HostArgs::parse();
    let block_number = args.block_number;
    let config = args.as_config().await?;

    let block_execution_strategy_factory =
        create_eth_block_execution_strategy_factory(config.custom_beneficiary);

    let provider = config.rpc_url.as_ref().map(|url| create_provider(url.clone()));

    #[cfg(all(feature = "sp1", feature = "nitro"))]
    compile_error!("Features `sp1` and `nitro` are mutually exclusive");

    #[cfg(feature = "sp1")]
    {
        use sp1_sdk::{env::EnvProver, include_elf};

        let report_path = args.report_path.clone();
        let persist_execution_report = PersistExecutionReport::new(
            config.chain.id(),
            report_path,
            args.precompile_tracking,
            args.opcode_tracking,
        );

        let prover_client = Arc::new(EnvProver::new().await);

        let executor = build_executor::<EthExecutorComponents<_, EnvProver>, _>(
            include_elf!("rsp-client").to_vec(),
            provider,
            block_execution_strategy_factory,
            prover_client,
            persist_execution_report,
            config,
        )
        .await?;
        executor.execute(block_number).await?;
    }

    #[cfg(feature = "nitro")]
    {
        use rsp_host_executor::{build_executor_with_nitro, BlockExecutor};
        use std::path::PathBuf;

        let client_path = if let Ok(client_path) = std::env::var("NITRO_CLIENT") {
            client_path
        } else {
            "./bin/client/target/x86_64-unknown-linux-musl/release/rsp-client".to_string()
        };

        let executor = build_executor_with_nitro::<EthExecutorComponents<()>, _>(
            PathBuf::from(client_path),
            provider,
            block_execution_strategy_factory,
            Arc::new(()),
            (),
            config,
        )
        .await?;

        executor.execute(block_number).await?;
    }

    #[cfg(not(any(feature = "sp1", feature = "nitro")))]
    return Err(eyre::eyre!("No features of proving engine enable"));

    Ok(())
}
