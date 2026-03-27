//! Deploy MockRollup on Anvil and write its address to a file and stdout.
//!
//! Environment variables:
//! - `ANVIL_URL`    — Anvil RPC URL (default: `http://localhost:8546`)
//! - `OUTPUT_FILE`  — Optional path to write the deployed address to

use alloy_provider::RootProvider;
use e2e_tests::mock_l1;
use eyre::Result;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();

    let anvil_url: url::Url =
        std::env::var("ANVIL_URL").unwrap_or_else(|_| "http://localhost:8546".into()).parse()?;

    let provider: RootProvider =
        RootProvider::new(alloy_rpc_client::RpcClient::new_http(anvil_url));

    let addr = mock_l1::deploy_mock_rollup(&provider).await?;
    println!("{addr}");

    if let Ok(output_file) = std::env::var("OUTPUT_FILE") {
        std::fs::write(&output_file, addr.to_string())?;
        tracing::info!(%output_file, "Address written to file");
    }

    Ok(())
}
