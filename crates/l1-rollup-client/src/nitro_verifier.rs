//! NitroVerifier contract bindings. Lives in `l1-rollup-client` for the
//! same reason the Rollup bindings do — it is read by the orchestrator and
//! proxy at L1 boundaries — but its `sol!` block is kept separate because
//! it targets a different deployed contract.

use alloy_primitives::{Address, Bytes, B256};
use alloy_provider::Provider;
use alloy_rpc_types::TransactionRequest;
use alloy_sol_types::{sol, SolCall};
use eyre::{eyre, Result};
use tracing::info;

sol! {
    /// NitroVerifier view function (auto-generated getter for mapping).
    function verifiedPubkeys(address) external view returns (bool);

    /// NitroVerifier entrypoint for attestation submission. `attestationTime`
    /// must match the uint64 committed inside the SP1 proof and fall within
    /// the contract's freshness window.
    function verifyAttestation(
        address expectedPubkey,
        uint64 attestationTime,
        bytes calldata proofBytes
    ) external;
}

/// Length of the SP1 public-values blob committed by `nitro-validator`:
/// `abi.encode(address, uint64)` = two 32-byte words.
pub const ATTESTATION_PUBLIC_VALUES_LEN: usize = 64;

/// Decode `abi.encode(address, uint64)` public values committed by the
/// `nitro-validator` guest into `(enclave_address, attestation_time_sec)`.
pub fn decode_public_values(public_values: &[u8]) -> Result<(Address, u64)> {
    if public_values.len() != ATTESTATION_PUBLIC_VALUES_LEN {
        return Err(eyre!(
            "unexpected attestation public values length: got {}, want {}",
            public_values.len(),
            ATTESTATION_PUBLIC_VALUES_LEN
        ));
    }
    // Word 0: left-padded address (first 12 bytes are zero, last 20 are the address).
    // Word 1: left-padded uint64 (first 24 bytes are zero, last 8 are the timestamp BE).
    let address = Address::from_slice(&public_values[12..32]);
    let timestamp_bytes: [u8; 8] = public_values[56..64].try_into().expect("slice len checked");
    let timestamp_sec = u64::from_be_bytes(timestamp_bytes);
    Ok((address, timestamp_sec))
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

/// Submit a `verifyAttestation(address,uint64,bytes)` transaction to the
/// NitroVerifier contract and wait for the receipt.
///
/// `provider` must already be wallet-wrapped (i.e. capable of signing
/// transactions) — this crate intentionally does not depend on signer types.
/// `expected_pubkey` and `attestation_time` MUST match the values committed
/// inside `proof_bytes`, otherwise the on-chain `verifyProof` will revert.
pub async fn submit_attestation(
    provider: &impl Provider,
    nitro_verifier_addr: Address,
    expected_pubkey: Address,
    attestation_time: u64,
    proof_bytes: Bytes,
) -> Result<B256> {
    let call = verifyAttestationCall {
        expectedPubkey: expected_pubkey,
        attestationTime: attestation_time,
        proofBytes: proof_bytes,
    };

    let tx = TransactionRequest {
        to: Some(nitro_verifier_addr.into()),
        input: Bytes::from(call.abi_encode()).into(),
        ..Default::default()
    };

    info!(
        contract = %nitro_verifier_addr,
        address = %expected_pubkey,
        attestation_time,
        "Submitting verifyAttestation tx to L1..."
    );

    let pending = provider
        .send_transaction(tx)
        .await
        .map_err(|e| eyre!("Failed to send verifyAttestation tx: {e}"))?;

    let receipt =
        pending.get_receipt().await.map_err(|e| eyre!("verifyAttestation tx failed: {e}"))?;

    if !receipt.status() {
        return Err(eyre!(
            "verifyAttestation tx reverted (tx_hash: {})",
            receipt.transaction_hash
        ));
    }

    info!(
        tx_hash = %receipt.transaction_hash,
        "Attestation verified on L1 successfully"
    );

    Ok(receipt.transaction_hash)
}
