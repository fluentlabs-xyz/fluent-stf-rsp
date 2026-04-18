//! Attestation validation and proving.

pub(crate) mod driver;
pub(crate) mod prepare;

pub(crate) const ROOT_CERT_DER: &[u8] = include_bytes!("root.der");

mod network;

pub(crate) use network::*;

#[cfg(test)]
mod tests {
    use super::*;

    const ATTESTATION_BYTES: &[u8] = include_bytes!("../../../../attestation.bin");
    const PUBLIC_KEY_HEX: &str = include_str!("../../../../public_key.hex");

    #[test]
    fn test_prepare_guest_input() {
        let result = prepare::prepare_guest_input(ATTESTATION_BYTES, ROOT_CERT_DER);
        assert!(result.is_ok(), "prepare_guest_input failed: {:?}", result.err());

        let input = result.unwrap();
        println!(
            "cose_signature (len={}): {:?}",
            input.cose_signature.len(),
            &input.cose_signature[..8]
        );
        println!("cose_payload len: {}", input.cose_payload.len());
        assert!(!input.chain.is_empty(), "certificate chain should not be empty");
        assert!(!input.cose_protected.is_empty(), "protected header should not be empty");
        assert!(!input.cose_payload.is_empty(), "payload should not be empty");
        assert_eq!(input.cose_signature.len(), 96);
        assert_eq!(input.root_pubkey.len(), 97);
    }

    /// Debug: parse CBOR directly to inspect PCRs map
    #[test]
    fn test_debug_pcrs_from_cbor() {
        use serde_bytes::ByteBuf;

        let (_protected, _unprotected, payload, _signature): (
            ByteBuf,
            ciborium::Value,
            ByteBuf,
            ByteBuf,
        ) = ciborium::from_reader(ATTESTATION_BYTES).unwrap();
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

    /// End-to-end local SP1 execution: verify attestation doc produces
    /// the correct committed address matching public_key.hex.
    #[tokio::test]
    #[ignore]
    async fn test_sp1_attestation_verify() {
        use sp1_sdk::Prover as _;

        let manifest_dir = env!("CARGO_MANIFEST_DIR");

        let elf_path = format!("{manifest_dir}/../../nitro-validator-testnet.elf");

        let elf_bytes = std::fs::read(&elf_path).expect("failed to read ELF");

        let guest_input = prepare::prepare_guest_input(ATTESTATION_BYTES, ROOT_CERT_DER).unwrap();

        let mut stdin = sp1_sdk::SP1Stdin::new();
        stdin.write(&guest_input);

        let client = sp1_sdk::ProverClient::builder().cpu().build().await;
        let (public_values, report) = client
            .execute(sp1_sdk::Elf::from(elf_bytes), stdin)
            .await
            .expect("SP1 execution failed");

        println!("total_instructions = {}", report.total_instruction_count());

        let pv = public_values.as_slice();
        assert_eq!(pv.len(), 64, "expected 64 bytes of public values");

        assert!(
            pv[..12].iter().all(|&b| b == 0),
            "top 12 bytes of ABI-encoded address must be zero"
        );
        let verified_addr = &pv[12..32];

        let pk_bytes =
            revm_primitives::hex::decode(PUBLIC_KEY_HEX.trim()).expect("invalid public_key.hex");
        assert_eq!(pk_bytes.len(), 65, "expected 65-byte uncompressed pubkey");
        let hash = alloy_primitives::keccak256(&pk_bytes[1..]);
        let expected_addr = &hash[12..];

        assert_eq!(verified_addr, expected_addr, "verified address does not match public_key.hex");

        let ts_bytes: [u8; 8] = pv[56..64].try_into().unwrap();
        let timestamp = u64::from_be_bytes(ts_bytes);
        assert!(timestamp > 0, "attestation timestamp must be non-zero");
        println!("attestation timestamp = {timestamp}");
    }
}
