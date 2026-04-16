use std::sync::Arc;

use alloy_network::EthereumWallet;
use alloy_primitives::Address;
use alloy_provider::{ProviderBuilder, RootProvider};
use alloy_signer_local::PrivateKeySigner;
use eyre::{eyre, Result};
use l1_rollup_client::nitro_verifier;
use revm_primitives::{hex, B256};
use sp1_sdk::{
    network::{prover::NetworkProver, NetworkMode},
    Elf, HashableKey, ProveRequest, Prover, ProverClient, ProvingKey, SP1ProvingKey, SP1Stdin,
};
use tracing::info;
use url::Url;

use super::{prepare, ROOT_CERT_DER};

/// Configuration for attestation proving + L1 submission.
#[derive(Clone)]
pub(crate) struct AttestationConfig {
    pub prover: Arc<NetworkProver>,
    pub pk: Arc<SP1ProvingKey>,
    pub l1_provider: RootProvider,
    pub l1_signer: PrivateKeySigner,
    pub nitro_verifier_addr: Address,
}

impl AttestationConfig {
    pub(crate) async fn from_env() -> Result<Self> {
        let elf_path = std::env::var("NITRO_VALIDATOR_ELF_PATH")
            .map_err(|_| eyre!("NITRO_VALIDATOR_ELF_PATH not set"))?;
        let elf_bytes = std::fs::read(&elf_path)
            .map_err(|e| eyre!("Failed to read nitro validator ELF {elf_path}: {e}"))?;
        let elf = Elf::from(elf_bytes);

        let client = ProverClient::builder().network_for(NetworkMode::Mainnet).build().await;
        let pk = client
            .setup(elf)
            .await
            .map_err(|e| eyre!("Failed to setup nitro validator proving key: {e}"))?;

        info!(
            vk_hash = %hex::encode(pk.verifying_key().hash_bytes()),
            "Nitro validator SP1 prover initialised"
        );

        let l1_rpc = std::env::var("L1_RPC_URL").map_err(|_| eyre!("L1_RPC_URL not set"))?;
        let l1_url = Url::parse(&l1_rpc)?;
        let l1_provider: RootProvider = rsp_provider::create_provider(l1_url);

        let key_hex =
            std::env::var("L1_SUBMITTER_KEY").map_err(|_| eyre!("L1_SUBMITTER_KEY not set"))?;
        let l1_signer: PrivateKeySigner =
            key_hex.parse().map_err(|e| eyre!("Invalid L1_SUBMITTER_KEY: {e}"))?;

        Ok(Self {
            prover: Arc::new(client),
            pk: Arc::new(pk),
            l1_provider,
            l1_signer,
            nitro_verifier_addr: fluent_stf_primitives::NITRO_VERIFIER_ADDR,
        })
    }
}

// ---------------------------------------------------------------------------
// Request-id persistence
// ---------------------------------------------------------------------------

fn request_id_path() -> String {
    crate::enclave::storage_path("ATTESTATION_REQUEST_ID_STORAGE", "./attestation_request_id.hex")
}

fn save_request_id(id: B256) -> Result<()> {
    let path = request_id_path();
    if let Some(parent) = std::path::Path::new(&path).parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(&path, hex::encode(id)).map_err(|e| eyre!("Failed to write request_id: {e}"))
}

pub(crate) fn load_request_id() -> Option<B256> {
    let path = request_id_path();
    let hex_str = std::fs::read_to_string(&path).ok()?;
    let bytes = hex::decode(hex_str.trim()).ok()?;
    B256::try_from(bytes.as_slice()).ok()
}

pub(crate) fn delete_request_id() {
    let _ = std::fs::remove_file(request_id_path());
}

// ---------------------------------------------------------------------------
// Proving flow
// ---------------------------------------------------------------------------

/// Submit attestation proof to SP1 network, wait for result, submit to L1.
///
/// If `attestation_request_id.hex` exists on disk, resumes the existing
/// proof request instead of submitting a new one.
pub(crate) async fn prove_and_submit(
    config: &AttestationConfig,
    public_key: &[u8],
    attestation: &[u8],
) -> Result<()> {
    let request_id = match load_request_id() {
        Some(saved_id) => {
            info!(request_id = %hex::encode(saved_id), "Resuming pending attestation proof");
            saved_id
        }
        None => {
            let guest_input = prepare::prepare_guest_input(attestation, ROOT_CERT_DER)
                .map_err(|e| eyre!("Failed to prepare guest input: {e}"))?;

            let mut stdin = SP1Stdin::new();
            stdin.write(&guest_input);

            info!("Submitting attestation proof to SP1 network...");
            let id = config
                .prover
                .prove(config.pk.as_ref(), stdin)
                .groth16()
                .request()
                .await
                .map_err(|e| eyre!("SP1 attestation proof request failed: {e}"))?;

            save_request_id(id)?;
            info!(request_id = %hex::encode(id), "Attestation proof submitted");
            id
        }
    };

    info!(request_id = %hex::encode(request_id), "Waiting for attestation proof...");
    let proof = config
        .prover
        .wait_proof(request_id, None, None)
        .await
        .map_err(|e| eyre!("SP1 attestation proof failed: {e}"))?;

    info!("Attestation proof ready, submitting to L1");
    submit_proof_to_l1(config, public_key, &proof).await?;
    delete_request_id();
    Ok(())
}

// ---------------------------------------------------------------------------
// L1 submission
// ---------------------------------------------------------------------------

async fn submit_proof_to_l1(
    config: &AttestationConfig,
    public_key: &[u8],
    proof: &sp1_sdk::SP1ProofWithPublicValues,
) -> Result<()> {
    let local_address = pubkey_to_address(public_key)?;

    let (committed_address, attestation_time) =
        nitro_verifier::decode_public_values(proof.public_values.as_slice())
            .map_err(|e| eyre!("Failed to decode attestation public values: {e}"))?;

    if committed_address != local_address {
        return Err(eyre!(
            "Committed enclave address mismatch: proof={committed_address}, local={local_address}"
        ));
    }

    info!(
        address = %local_address,
        attestation_time,
        "Submitting attestation proof to L1"
    );

    let proof_bytes = proof.bytes();

    let wallet = EthereumWallet::from(config.l1_signer.clone());
    let provider =
        ProviderBuilder::new().wallet(wallet).connect_provider(config.l1_provider.clone());

    nitro_verifier::submit_attestation(
        &provider,
        config.nitro_verifier_addr,
        local_address,
        attestation_time,
        proof_bytes.into(),
    )
    .await?;

    Ok(())
}

/// Derive Ethereum address from 65-byte uncompressed secp256k1 public key.
pub(crate) fn pubkey_to_address(pubkey: &[u8]) -> Result<Address> {
    if pubkey.len() != 65 || pubkey[0] != 0x04 {
        return Err(eyre!(
            "Invalid uncompressed pubkey: len={}, first=0x{:02x}",
            pubkey.len(),
            pubkey.first().copied().unwrap_or(0)
        ));
    }
    let hash = alloy_primitives::keccak256(&pubkey[1..]);
    Ok(Address::from_slice(&hash[12..]))
}
