//! Attestation validation and proving.
//!
//! - Guest input preparation and local SP1 execution: always available
//! - Network proving + L1 submission: gated behind `prove-key-attestation` feature

pub(crate) mod prepare;

pub(crate) const ROOT_CERT_DER: &[u8] = include_bytes!("../../../aws-nitro-validator/root.der");

#[cfg(feature = "prove-key-attestation")]
mod network;

#[cfg(feature = "prove-key-attestation")]
pub(crate) use network::*;

/// Run local SP1 execute to validate the attestation document.
/// Logs errors and returns on failure so the proxy continues.
#[cfg(not(feature = "prove-key-attestation"))]
pub(crate) async fn execute_local(attestation: &[u8]) {
    use sp1_sdk::Prover as _;
    use tracing::info;

    let elf_path = match std::env::var("NITRO_VALIDATOR_ELF_PATH") {
        Ok(p) => p,
        Err(_) => {
            tracing::error!(
                "NITRO_VALIDATOR_ELF_PATH not set — skipping local attestation validation"
            );
            return;
        }
    };

    let elf_bytes = match std::fs::read(&elf_path) {
        Ok(b) => b,
        Err(e) => {
            tracing::error!(%e, elf_path, "Failed to read nitro validator ELF — skipping local attestation validation");
            return;
        }
    };

    let guest_input = match prepare::prepare_guest_input(attestation, ROOT_CERT_DER) {
        Ok(input) => input,
        Err(e) => {
            tracing::error!(%e, "Failed to prepare attestation guest input");
            return;
        }
    };

    let mut stdin = sp1_sdk::SP1Stdin::new();
    stdin.write(&guest_input);

    let client = sp1_sdk::ProverClient::builder().cpu().build().await;
    match client.execute(sp1_sdk::Elf::from(elf_bytes), stdin).await {
        Ok((_public_values, report)) => {
            info!(
                total_instructions = report.total_instruction_count(),
                "Local SP1 attestation validation succeeded"
            );
        }
        Err(e) => {
            tracing::error!(?e, "Local SP1 attestation validation failed");
        }
    }
}
