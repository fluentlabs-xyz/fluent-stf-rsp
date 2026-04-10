use std::sync::Arc;

use alloy_network::EthereumWallet;
use alloy_primitives::{Address, Bytes};
use alloy_provider::{Provider, ProviderBuilder, RootProvider};
use alloy_signer_local::PrivateKeySigner;
use alloy_sol_types::{sol, SolCall};
use eyre::{eyre, Result};
use revm_primitives::{hex, B256};
use sp1_sdk::{
    network::{prover::NetworkProver, NetworkMode},
    Elf, HashableKey, ProveRequest, Prover, ProverClient, ProvingKey, SP1ProvingKey, SP1Stdin,
};
use tracing::info;
use url::Url;

use super::{prepare, ROOT_CERT_DER};

sol! {
    function verifyAttestation(address expectedPubkey, bytes calldata proofBytes) external;
}

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
    pub async fn from_env() -> Result<Self> {
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

        let addr_str = std::env::var("NITRO_VERIFIER_ADDR")
            .map_err(|_| eyre!("NITRO_VERIFIER_ADDR not set"))?;
        let nitro_verifier_addr: Address =
            addr_str.parse().map_err(|e| eyre!("Invalid NITRO_VERIFIER_ADDR: {e}"))?;

        Ok(Self {
            prover: Arc::new(client),
            pk: Arc::new(pk),
            l1_provider,
            l1_signer,
            nitro_verifier_addr,
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

#[cfg(feature = "prove-key-attestation")]
fn load_request_id() -> Option<B256> {
    let path = request_id_path();
    let hex_str = std::fs::read_to_string(&path).ok()?;
    let bytes = hex::decode(hex_str.trim()).ok()?;
    B256::try_from(bytes.as_slice()).ok()
}

fn delete_request_id() {
    let _ = std::fs::remove_file(request_id_path());
}

/// Delete any saved request_id. Called when a new enclave key is generated
/// to prevent `prove_and_submit` from picking up a stale proof for a
/// previous key.
pub(crate) fn delete_stale_request_id() {
    delete_request_id();
}

/// Submit new attestation proof request to SP1. Returns request_id.
/// Saves request_id to disk for resilience.
async fn submit_attestation_proof(config: &AttestationConfig, attestation: &[u8]) -> Result<B256> {
    let guest_input = prepare::prepare_guest_input(attestation, ROOT_CERT_DER)
        .map_err(|e| eyre!("Failed to prepare guest input: {e}"))?;

    let mut stdin = SP1Stdin::new();
    stdin.write(&guest_input);

    info!("Submitting attestation proof to SP1 network...");
    let request_id = config
        .prover
        .prove(config.pk.as_ref(), stdin)
        .groth16()
        .request()
        .await
        .map_err(|e| eyre!("SP1 attestation proof request failed: {e}"))?;

    save_request_id(request_id)?;
    info!(request_id = %hex::encode(request_id), "Attestation proof submitted, request_id saved");

    Ok(request_id)
}

/// Wait for an existing proof and submit to L1. Deletes request_id file on success.
async fn wait_and_submit_to_l1(
    config: &AttestationConfig,
    request_id: B256,
    public_key: &[u8],
) -> Result<()> {
    info!(request_id = %hex::encode(request_id), "Waiting for attestation proof...");

    let proof = config
        .prover
        .wait_proof(request_id, None, None)
        .await
        .map_err(|e| eyre!("SP1 attestation proof failed: {e}"))?;

    info!("Attestation proof generated successfully");
    submit_proof_to_l1(config, public_key, &proof).await?;
    delete_request_id();
    Ok(())
}

/// Check proof status by request_id. Returns (status_string, proof_ready).
/// If proof is ready, submits to L1 and deletes request_id file.
async fn check_and_maybe_submit(
    config: &AttestationConfig,
    request_id: B256,
    public_key: &[u8],
) -> Result<(String, bool)> {
    let (status, maybe_proof) = config
        .prover
        .get_proof_status(request_id)
        .await
        .map_err(|e| eyre!("Failed to get proof status: {e}"))?;

    let status_str = format!("{status:?}");

    match maybe_proof {
        Some(proof) => {
            info!(request_id = %hex::encode(request_id), "Attestation proof ready, submitting to L1");
            submit_proof_to_l1(config, public_key, &proof).await?;
            delete_request_id();
            Ok((status_str, true))
        }
        None => {
            info!(request_id = %hex::encode(request_id), ?status, "Attestation proof still pending");
            Ok((status_str, false))
        }
    }
}

/// Extract proof bytes and submit verifyAttestation tx to L1.
async fn submit_proof_to_l1(
    config: &AttestationConfig,
    public_key: &[u8],
    proof: &sp1_sdk::SP1ProofWithPublicValues,
) -> Result<()> {
    let address = pubkey_to_address(public_key)?;
    info!(address = %address, "Derived Ethereum address from enclave pubkey");

    let proof_bytes = proof.bytes();

    let call =
        verifyAttestationCall { expectedPubkey: address, proofBytes: Bytes::from(proof_bytes) };

    let wallet = EthereumWallet::from(config.l1_signer.clone());
    let provider =
        ProviderBuilder::new().wallet(wallet).connect_provider(config.l1_provider.clone());

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

    let pending = provider
        .send_transaction(tx)
        .await
        .map_err(|e| eyre!("Failed to send verifyAttestation tx: {e}"))?;

    let receipt =
        pending.get_receipt().await.map_err(|e| eyre!("verifyAttestation tx failed: {e}"))?;

    if !receipt.status() {
        return Err(eyre!("verifyAttestation tx reverted (tx_hash: {})", receipt.transaction_hash));
    }

    info!(
        tx_hash = %receipt.transaction_hash,
        "Attestation verified on L1 successfully"
    );

    Ok(())
}

/// Resilient prove_and_submit: checks for existing request_id before submitting new.
#[cfg(feature = "prove-key-attestation")]
pub(crate) async fn prove_and_submit(
    config: &AttestationConfig,
    public_key: &[u8],
    attestation: &[u8],
) -> Result<()> {
    info!("Preparing attestation proof — this may take several minutes");

    if let Some(saved_id) = load_request_id() {
        info!(request_id = %hex::encode(saved_id), "Found saved attestation request_id, checking status...");

        match check_and_maybe_submit(config, saved_id, public_key).await {
            Ok((_status, true)) => return Ok(()),
            Ok((status, false)) => {
                info!(request_id = %hex::encode(saved_id), %status, "Saved proof still in progress, waiting...");
                wait_and_submit_to_l1(config, saved_id, public_key).await?;
                return Ok(());
            }
            Err(e) => {
                info!(request_id = %hex::encode(saved_id), %e, "Saved request_id invalid or expired, submitting new");
                delete_request_id();
            }
        }
    }

    let request_id = submit_attestation_proof(config, attestation).await?;
    wait_and_submit_to_l1(config, request_id, public_key).await?;
    Ok(())
}

/// Result of a retry-attestation call.
pub(crate) struct RetryResult {
    pub request_id: Option<B256>,
    pub status: String,
}

/// Retry attestation: either submit new proof or check status of existing one.
/// When submitting new proof, spawns a background task for wait+L1.
pub(crate) async fn retry(
    config: &AttestationConfig,
    public_key: &[u8],
    attestation: &[u8],
    existing_request_id: Option<B256>,
) -> Result<RetryResult> {
    match existing_request_id {
        Some(rid) => {
            let (status, proof_ready) = check_and_maybe_submit(config, rid, public_key).await?;

            Ok(RetryResult {
                request_id: Some(rid),
                status: if proof_ready { "proof_submitted_to_l1".to_string() } else { status },
            })
        }
        None => {
            let request_id = submit_attestation_proof(config, attestation).await?;

            let pk = public_key.to_vec();
            let cfg = config.clone();
            tokio::spawn(async move {
                if let Err(e) = wait_and_submit_to_l1(&cfg, request_id, &pk).await {
                    tracing::error!(%e, "Background attestation L1 submission failed");
                }
            });

            Ok(RetryResult { request_id: Some(request_id), status: "proof_requested".to_string() })
        }
    }
}

/// Derive Ethereum address from 65-byte uncompressed secp256k1 public key.
fn pubkey_to_address(pubkey: &[u8]) -> Result<Address> {
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
