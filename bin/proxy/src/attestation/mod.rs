//! Attestation validation and proving.

pub(crate) mod driver;
pub(crate) mod prepare;

pub(crate) const ROOT_CERT_DER: &[u8] = include_bytes!("root.der");

mod network;

pub(crate) use network::*;

#[cfg(test)]
mod tests {
    use super::*;

    const ATTESTATION_BYTES: &[u8] = include_bytes!("../../testdata/attestation.bin");

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
}
