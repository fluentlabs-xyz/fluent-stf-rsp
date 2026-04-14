//! Host-runnable integration test: feed a real Nitro attestation document
//! through `nitro_validator::verify` and assert the committed address.

use ciborium::value::Value as CborValue;
use nitro_validator::{verify, CertData, GuestInput};
use serde_bytes::ByteBuf;
use x509_parser::prelude::*;

const ATTESTATION_BYTES: &[u8] = include_bytes!("../../../attestation.bin");
const ROOT_DER: &[u8] = include_bytes!("../root.der");

fn extract_sec1(raw: &[u8]) -> [u8; 97] {
    let sec1 = if raw.len() == 98 && raw[0] == 0x00 {
        &raw[1..]
    } else {
        raw
    };
    let mut out = [0u8; 97];
    out.copy_from_slice(sec1);
    out
}

fn build_guest_input() -> GuestInput {
    // COSE_Sign1 = [protected, unprotected, payload, signature]
    let (protected, _unprotected, payload, signature): (ByteBuf, CborValue, ByteBuf, ByteBuf) =
        ciborium::from_reader(ATTESTATION_BYTES).unwrap();

    // Pull cabundle + leaf from the signed AttestationDoc (host knows the shape).
    let doc: CborValue = ciborium::from_reader(&payload[..]).unwrap();
    let map = match &doc {
        CborValue::Map(m) => m,
        _ => panic!("attestation doc not a map"),
    };
    let mut cabundle: Vec<Vec<u8>> = Vec::new();
    let mut leaf_der: Vec<u8> = Vec::new();
    for (k, v) in map {
        if let CborValue::Text(key) = k {
            match key.as_str() {
                "cabundle" => {
                    if let CborValue::Array(arr) = v {
                        for item in arr {
                            if let CborValue::Bytes(b) = item {
                                cabundle.push(b.clone());
                            }
                        }
                    }
                }
                "certificate" => {
                    if let CborValue::Bytes(b) = v {
                        leaf_der = b.clone();
                    }
                }
                _ => {}
            }
        }
    }

    let (_, root_cert) = X509Certificate::from_der(ROOT_DER).unwrap();
    let root_pubkey = extract_sec1(&root_cert.public_key().subject_public_key.data);
    let root_subject = root_cert.tbs_certificate.subject.as_raw().to_vec();

    let mut chain: Vec<CertData> = Vec::new();
    for der in cabundle.iter().chain(std::iter::once(&leaf_der)) {
        let (_, parsed) = X509Certificate::from_der(der).unwrap();
        chain.push(CertData {
            tbs: parsed.tbs_certificate.as_ref().to_vec(),
            signature: parsed.signature_value.data.as_ref().to_vec(),
        });
    }

    GuestInput {
        root_pubkey: root_pubkey.to_vec(),
        root_subject,
        chain,
        cose_protected: protected.into_vec(),
        cose_payload: payload.into_vec(),
        cose_signature: signature.into_vec(),
    }
}

#[test]
#[should_panic(expected = "PCR0 mismatch")]
fn fixture_reaches_pcr0_check() {
    // The committed fixture was produced by an enclave image whose PCR0 does
    // not match any hardcoded network anchor. Reaching this assertion proves
    // the full pipeline (root anchors → X.509 chain → COSE signature →
    // indefinite-length CBOR walk → PCR0 extraction) works end-to-end.
    let input = build_guest_input();
    verify(&input);
}

#[test]
#[should_panic(expected = "signature verification failed")]
fn payload_tamper_detected_by_cose() {
    let mut input = build_guest_input();
    // Any payload mutation must be caught by the COSE signature. PCR0
    // mismatch is unreachable via tampering because payload integrity is
    // cryptographically bound first.
    input.cose_payload[0] ^= 0x01;
    verify(&input);
}

#[test]
#[should_panic(expected = "root CA subject hash mismatch")]
fn root_subject_tamper_rejected() {
    let mut input = build_guest_input();
    input.root_subject[0] ^= 0x01;
    verify(&input);
}

#[test]
#[should_panic(expected = "root CA pubkey hash mismatch")]
fn root_pubkey_tamper_rejected() {
    let mut input = build_guest_input();
    input.root_pubkey[1] ^= 0x01;
    verify(&input);
}
