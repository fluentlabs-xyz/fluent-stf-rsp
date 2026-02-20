#![cfg_attr(not(test), warn(unused_crate_dependencies))]

use alloy_provider::RootProvider;
use clap::Parser;
use execute::PersistExecutionReport;
#[cfg(feature = "sp1")]
use rsp_host_executor::build_executor;
#[cfg(feature = "nitro")]
use rsp_host_executor::build_executor_with_nitro;
use rsp_host_executor::create_eth_block_execution_strategy_factory;
#[cfg(feature = "sp1")]
use rsp_host_executor::{BlockExecutor, EthExecutorComponents};
use rsp_provider::create_provider;
use sp1_sdk::EnvProver;
use std::sync::Arc;
use tracing_subscriber::{
    filter::EnvFilter, fmt, prelude::__tracing_subscriber_SubscriberExt, util::SubscriberInitExt,
};

mod execute;

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
    let report_path = args.report_path.clone();
    let config = args.as_config().await?;
    let persist_execution_report = PersistExecutionReport::new(
        config.chain.id(),
        report_path,
        args.precompile_tracking,
        args.opcode_tracking,
    );

    let prover_client = Arc::new(EnvProver::new());

    let block_execution_strategy_factory =
        create_eth_block_execution_strategy_factory(&config.genesis, config.custom_beneficiary);
    let provider: Option<RootProvider> =
        config.rpc_url.as_ref().map(|url| create_provider(url.clone()));

    #[cfg(all(feature = "sp1", feature = "nitro"))]
    compile_error!("Features `sp1` and `nitro` are mutually exclusive");

    #[cfg(feature = "sp1")]
    {
        use sp1_sdk::include_elf;

        let executor = build_executor::<EthExecutorComponents<_>, _>(
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
        use std::path::PathBuf;
        let client_path = if let Ok(client_path) = std::env::var("NITRO_CLIENT") {
            client_path
        } else {
            "./bin/client/target/x86_64-unknown-linux-musl/release/rsp-client".to_string()
        };

        let executor = build_executor_with_nitro::<EthExecutorComponents<_>, _>(
            PathBuf::from(client_path),
            provider,
            block_execution_strategy_factory,
            prover_client,
            persist_execution_report,
            config,
        )
        .await?;

        executor.execute(block_number).await?;
    }

    #[cfg(not(any(feature = "sp1", feature = "nitro")))]
    return Err(eyre::eyre!("No features of proving engine enable"));

    Ok(())
}
