//! NitroVerifier contract bindings. Lives in `l1-rollup-client` for the
//! same reason the Rollup bindings do — it is read by the orchestrator and
//! proxy at L1 boundaries — but its `sol!` block is kept separate because
//! it targets a different deployed contract.

use alloy_primitives::{Address, Bytes};
use alloy_provider::Provider;
use alloy_rpc_types::TransactionRequest;
use alloy_sol_types::{sol, SolCall};
use eyre::{eyre, Result};

sol! {
    /// NitroVerifier view function (auto-generated getter for mapping).
    function verifiedPubkeys(address) external view returns (bool);
}

/// Check if an enclave address is registered in NitroVerifier.
pub async fn is_key_registered(
    provider: &impl Provider,
    nitro_verifier_addr: Address,
    enclave_address: Address,
) -> Result<bool> {
    let call = verifiedPubkeysCall(enclave_address);
    let tx = TransactionRequest {
        to: Some(nitro_verifier_addr.into()),
        input: Bytes::from(call.abi_encode()).into(),
        ..Default::default()
    };
    let result = provider.call(tx).await.map_err(|e| eyre!("verifiedPubkeys call failed: {e}"))?;
    let registered = verifiedPubkeysCall::abi_decode_returns(&result)
        .map_err(|e| eyre!("Failed to decode verifiedPubkeys result: {e}"))?;
    Ok(registered)
}
