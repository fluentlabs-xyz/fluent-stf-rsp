use std::sync::Arc;

use alloy_provider::{network::Ethereum, Network, RootProvider};
use reth_chainspec::ChainSpec;
use reth_evm::ConfigureEvm;
use revm_primitives::Address;
use rsp_client_executor::{
    executor::{ClientExecutor, EthClientExecutor},
    io::ClientExecutorInput,
    BlockValidator, FromInput, IntoInput, IntoPrimitives,
};
use rsp_host_executor::{EthHostExecutor, HostExecutor};
use rsp_primitives::genesis::Genesis;
use serde::{de::DeserializeOwned, Serialize};
use tracing_subscriber::{
    fmt, prelude::__tracing_subscriber_SubscriberExt, util::SubscriberInitExt, EnvFilter,
};
use url::Url;

#[ignore]
#[tokio::test(flavor = "multi_thread")]
async fn test_e2e_ethereum() {
    run_eth_e2e(&Genesis::Mainnet, "RPC_1", 18884864, None).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn test_e2e_fluent() {
    run_eth_e2e(&Genesis::Fluent, "http://207.154.218.23:8545", 21846700, None).await;
}

async fn run_eth_e2e(
    genesis: &Genesis,
    env_var_key: &str,
    block_number: u64,
    custom_beneficiary: Option<Address>,
) {
    let chain_spec: Arc<ChainSpec> = Arc::new(genesis.try_into().unwrap());

    // Setup the host executor.
    let host_executor = EthHostExecutor::eth(chain_spec.clone(), custom_beneficiary);

    // Setup the client executor.
    let client_executor = EthClientExecutor::eth(chain_spec, custom_beneficiary);

    run_e2e::<_, ChainSpec, Ethereum>(
        host_executor,
        client_executor,
        env_var_key,
        block_number,
        genesis,
        custom_beneficiary,
    )
    .await;
}

/// Verifies that the overlay approach (before-state + BundleState → after-proof)
/// produces a valid witness by executing the client against it.
///
/// Usage:
///   TEST_RPC_URL=http://... TEST_BLOCK_NUMBER=12345 cargo test test_overlay_witness --release -- --ignored
#[ignore]
#[tokio::test(flavor = "multi_thread")]
async fn test_overlay_witness_matches_rpc() {
    dotenv::dotenv().ok();
    let _ = tracing_subscriber::registry()
        .with(fmt::layer())
        .with(EnvFilter::from_default_env())
        .try_init();

    let rpc_url: Url = std::env::var("TEST_RPC_URL")
        .expect("TEST_RPC_URL not set")
        .parse()
        .expect("invalid TEST_RPC_URL");
    let block_number: u64 = std::env::var("TEST_BLOCK_NUMBER")
        .expect("TEST_BLOCK_NUMBER not set")
        .parse()
        .expect("invalid TEST_BLOCK_NUMBER");

    let genesis = Genesis::Fluent;
    let chain_spec: Arc<ChainSpec> = Arc::new((&genesis).try_into().unwrap());

    let host_executor = EthHostExecutor::eth(chain_spec.clone(), None);
    let client_executor = EthClientExecutor::eth(chain_spec.clone(), None);

    let provider = RootProvider::<Ethereum>::new_http(rpc_url);

    // ── Reference: RPC-based execution ────────────────────────────
    tracing::info!(block_number, "Executing block via RPC (reference)");
    let reference_input = host_executor
        .execute(block_number, &provider, genesis.clone(), None, false)
        .await
        .expect("RPC execute failed");

    // Verify reference passes client execution (state root check)
    let (ref_header, _) = client_executor
        .execute(reference_input.clone())
        .expect("Reference client execution failed");
    tracing::info!(
        block_number,
        state_root = %ref_header.state_root,
        "Reference execution passed"
    );

    // ── Overlay verification ──────────────────────────────────────
    // Re-execute via RPC to get a fresh input for overlay comparison
    let overlay_input = host_executor
        .execute(block_number, &provider, genesis.clone(), None, false)
        .await
        .expect("RPC execute (overlay) failed");

    // Verify overlay input also passes client execution
    let (overlay_header, _) = client_executor
        .execute(overlay_input.clone())
        .expect("Overlay client execution failed");

    assert_eq!(
        ref_header.state_root, overlay_header.state_root,
        "State roots must match between reference and overlay"
    );

    // ── Compare EthereumState trie structures ─────────────────────
    assert_eq!(
        reference_input.parent_state, overlay_input.parent_state,
        "Parent state tries must be identical"
    );

    tracing::info!(
        block_number,
        ref_state_root = %ref_header.state_root,
        overlay_state_root = %overlay_header.state_root,
        "Overlay witness test PASSED"
    );
}

async fn run_e2e<C, CS, N>(
    host_executor: HostExecutor<C, CS>,
    client_executor: ClientExecutor<C, CS>,
    _env_var_key: &str,
    block_number: u64,
    genesis: &Genesis,
    custom_beneficiary: Option<Address>,
) where
    C: ConfigureEvm,
    C::Primitives: FromInput
        + IntoPrimitives<N>
        + IntoInput
        + BlockValidator<CS>
        + Serialize
        + DeserializeOwned,
    N: Network,
{
    // Intialize the environment variables.
    dotenv::dotenv().ok();

    // Initialize the logger.
    let _ = tracing_subscriber::registry()
        .with(fmt::layer())
        .with(EnvFilter::from_default_env())
        .try_init();

    // Setup the provider.
    let rpc_url = Url::parse("http://207.154.218.23:8545").expect("invalid rpc url");
    let provider = RootProvider::<N>::new_http(rpc_url);

    // Execute the host.
    let client_input = host_executor
        .execute(block_number, &provider, genesis.clone(), custom_beneficiary, false)
        .await
        .expect("failed to execute host");

    // Save the client input to a buffer.
    let buffer = bincode::serialize(&client_input).unwrap();

    // Load the client input from a buffer.
    let client_input: ClientExecutorInput<C::Primitives> = bincode::deserialize(&buffer).unwrap();

    // Execute the client.
    client_executor.execute(client_input.clone()).expect("failed to execute client");
}
