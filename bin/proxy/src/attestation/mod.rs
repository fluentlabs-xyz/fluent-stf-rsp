//! Attestation proving via SP1 network + L1 verification.
//!
//! Gated behind `prove-key-attestation` feature.

use std::sync::Arc;

use alloy_network::EthereumWallet;
use alloy_primitives::{Address, Bytes};
use alloy_provider::{Provider, ProviderBuilder, RootProvider};
use alloy_signer_local::PrivateKeySigner;
use alloy_sol_types::{sol, SolCall};
use eyre::{eyre, Result};
use revm_primitives::hex;
use sp1_sdk::{
    network::{prover::NetworkProver, NetworkMode},
    Elf, HashableKey, ProveRequest, Prover, ProverClient, ProvingKey, SP1ProvingKey, SP1Stdin,
};
use tracing::info;
use url::Url;

mod prepare;

const ROOT_CERT_DER: &[u8] = include_bytes!("../../../aws-nitro-validator/root.der");

sol! {
    function verifyAttestation(address expectedPubkey, bytes calldata proofBytes) external;
}

/// Configuration for attestation proving + L1 submission.
pub(crate) struct AttestationConfig {
    pub prover: Arc<NetworkProver>,
    pub pk: Arc<SP1ProvingKey>,
    pub l1_provider: RootProvider,
    pub l1_signer: PrivateKeySigner,
    pub nitro_verifier_addr: Address,
}

impl AttestationConfig {
    pub async fn from_env() -> Result<Self> {
        let elf_path = std::env::var("NITRO_VALIDATOR_ELF_PATH")
            .map_err(|_| eyre!("NITRO_VALIDATOR_ELF_PATH not set"))?;
        let elf_bytes = std::fs::read(&elf_path)
            .map_err(|e| eyre!("Failed to read nitro validator ELF {elf_path}: {e}"))?;
        let elf = Elf::from(elf_bytes);

        let client = ProverClient::builder()
            .network_for(NetworkMode::Mainnet)
            .build()
            .await;
        let pk = client.setup(elf).await
            .map_err(|e| eyre!("Failed to setup nitro validator proving key: {e}"))?;

        info!(
            vk_hash = %hex::encode(pk.verifying_key().hash_bytes()),
            "Nitro validator SP1 prover initialised"
        );

        let l1_rpc = std::env::var("L1_RPC_URL")
            .map_err(|_| eyre!("L1_RPC_URL not set"))?;
        let l1_url = Url::parse(&l1_rpc)?;
        let l1_provider: RootProvider = rsp_provider::create_provider(l1_url);

        let key_hex = std::env::var("L1_SUBMITTER_KEY")
            .map_err(|_| eyre!("L1_SUBMITTER_KEY not set"))?;
        let l1_signer: PrivateKeySigner = key_hex.parse()
            .map_err(|e| eyre!("Invalid L1_SUBMITTER_KEY: {e}"))?;

        let addr_str = std::env::var("NITRO_VERIFIER_ADDR")
            .map_err(|_| eyre!("NITRO_VERIFIER_ADDR not set"))?;
        let nitro_verifier_addr: Address = addr_str.parse()
            .map_err(|e| eyre!("Invalid NITRO_VERIFIER_ADDR: {e}"))?;

        Ok(Self {
            prover: Arc::new(client),
            pk: Arc::new(pk),
            l1_provider,
            l1_signer,
            nitro_verifier_addr,
        })
    }
}

/// Prove attestation via SP1 network and submit to L1 NitroVerifier.
pub(crate) async fn prove_and_submit(
    config: &AttestationConfig,
    public_key: &[u8],
    attestation: &[u8],
) -> Result<()> {
    info!("Preparing attestation proof — this may take several minutes");

    // 1. Parse attestation into guest input
    let guest_input = prepare::prepare_guest_input(attestation, ROOT_CERT_DER)
        .map_err(|e| eyre!("Failed to prepare guest input: {e}"))?;

    // 2. Submit proof to SP1 network and wait
    let mut stdin = SP1Stdin::new();
    stdin.write(&guest_input);

    info!("Submitting attestation proof to SP1 network...");
    let request_id = config.prover
        .prove(config.pk.as_ref(), stdin)
        .groth16()
        .request()
        .await
        .map_err(|e| eyre!("SP1 attestation proof request failed: {e}"))?;

    info!(request_id = %hex::encode(request_id), "Attestation proof submitted, waiting for result...");

    let proof = config.prover
        .wait_proof(request_id, None, None)
        .await
        .map_err(|e| eyre!("SP1 attestation proof failed: {e}"))?;

    info!("Attestation proof generated successfully");

    // 3. Derive Ethereum address from 65-byte uncompressed pubkey
    let address = pubkey_to_address(public_key)?;
    info!(address = %address, "Derived Ethereum address from enclave pubkey");

    // 4. Get proof bytes
    let proof_bytes = proof.bytes();

    // 5. Call NitroVerifier.verifyAttestation(address, proofBytes) on L1
    let call = verifyAttestationCall {
        expectedPubkey: address,
        proofBytes: Bytes::from(proof_bytes),
    };

    let wallet = EthereumWallet::from(config.l1_signer.clone());
    let provider = ProviderBuilder::new()
        .wallet(wallet)
        .connect_provider(config.l1_provider.clone());

    let tx = alloy_rpc_types::TransactionRequest {
        to: Some(config.nitro_verifier_addr.into()),
        input: Bytes::from(call.abi_encode()).into(),
        ..Default::default()
    };

    info!(
        contract = %config.nitro_verifier_addr,
        address = %address,
        "Submitting verifyAttestation tx to L1..."
    );

    let pending = provider.send_transaction(tx.clone()).await
        .map_err(|e| eyre!("Failed to send verifyAttestation tx: {e}"))?;

    let receipt = pending.get_receipt().await
        .map_err(|e| eyre!("verifyAttestation tx failed: {e}"))?;

    info!(
        tx_hash = %receipt.transaction_hash,
        "Attestation verified on L1 successfully"
    );

    Ok(())
}

/// Derive Ethereum address from 65-byte uncompressed secp256k1 public key.
fn pubkey_to_address(pubkey: &[u8]) -> Result<Address> {
    if pubkey.len() != 65 || pubkey[0] != 0x04 {
        return Err(eyre!("Invalid uncompressed pubkey: len={}, first=0x{:02x}",
            pubkey.len(), pubkey.first().copied().unwrap_or(0)));
    }
    let hash = alloy_primitives::keccak256(&pubkey[1..]);
    Ok(Address::from_slice(&hash[12..]))
}
