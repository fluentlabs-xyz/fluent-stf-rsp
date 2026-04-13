//! Attestation validation and proving.
//!
//! - Guest input preparation and local SP1 execution: always available
//! - Network proving + L1 submission: gated behind `prove-key-attestation` feature

pub(crate) mod prepare;

pub(crate) const ROOT_CERT_DER: &[u8] = include_bytes!("../../../aws-nitro-validator/root.der");

mod network;

pub(crate) use network::*;

/// Run local SP1 execute to validate the attestation document.
/// Logs errors and returns on failure so the proxy continues.
#[cfg(any(not(feature = "prove-key-attestation"), test))]
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
        Ok((public_values, report)) => {
            let hex_encoded = revm_primitives::hex::encode(public_values.as_slice());
            info!(
                total_instructions = report.total_instruction_count(),
                committed_hex = %hex_encoded,
                "Local SP1 attestation validation succeeded"
            );
        }
        Err(e) => {
            tracing::error!(?e, "Local SP1 attestation validation failed");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ATTESTATION_BYTES: &[u8] = include_bytes!("../../../../attestation.bin");

    #[test]
    fn test_prepare_guest_input() {
        let result = prepare::prepare_guest_input(ATTESTATION_BYTES, ROOT_CERT_DER);
        assert!(result.is_ok(), "prepare_guest_input failed: {:?}", result.err());

        let input = result.unwrap();
        println!("pcr0 (len={}): {:?}", input.pcr0.len(), input.pcr0);
        println!(
            "cose_signature (len={}): {:?}",
            input.cose_signature.len(),
            &input.cose_signature[..8]
        );
        println!("user_data (len={}): {:?}", input.user_data.len(), &input.user_data[..4]);
        assert!(!input.chain.is_empty(), "certificate chain should not be empty");
        assert!(!input.sig_structure.is_empty(), "sig_structure should not be empty");
        assert!(!input.user_data.is_empty(), "user_data should not be empty");
    }

    /// Debug: parse CBOR directly to inspect PCRs map
    #[test]
    fn test_debug_pcrs_from_cbor() {
        use serde_bytes::ByteBuf;

        let (_protected, _unprotected, payload, _signature):
            (ByteBuf, ciborium::Value, ByteBuf, ByteBuf) =
            ciborium::from_reader(ATTESTATION_BYTES).unwrap();
        let payload = &payload[..];

        // Parse as raw ciborium::Value to see what PCRs looks like
        let raw: ciborium::Value = ciborium::from_reader(payload).unwrap();
        if let ciborium::Value::Map(entries) = &raw {
            for (k, v) in entries {
                if let ciborium::Value::Text(key) = k {
                    if key == "pcrs" {
                        println!("pcrs raw CBOR value: {:?}", v);
                    }
                }
            }
        }
    }

    #[tokio::test]
    async fn test_execute_local() {
        let manifest_dir = env!("CARGO_MANIFEST_DIR");
        let elf_path = format!("{}/../../nitro-validator.elf", manifest_dir);

        assert!(
            std::path::Path::new(&elf_path).exists(),
            "nitro-validator.elf not found at {elf_path}"
        );

        std::env::set_var("NITRO_VALIDATOR_ELF_PATH", &elf_path);
        execute_local(ATTESTATION_BYTES).await;
    }
}
