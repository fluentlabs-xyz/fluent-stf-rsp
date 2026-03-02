#![no_main]
sp1_zkvm::entrypoint!(main);

use common::{CertData, GuestInput};
use p384::ecdsa::{signature::DigestVerifier, Signature, VerifyingKey};
use sha2::{Digest as _, Sha384};

/// SHA-384 hash of the AWS Nitro root CA public key (97-byte SEC1 uncompressed).
/// Computed once using `compute_root_pubkey_hash()` from the host crate.
/// This is the sole trust anchor — if correct, the entire chain is provable.
const EXPECTED_ROOT_PUBKEY_HASH: [u8; 48] = [
    0x70, 0x86, 0x37, 0xb2, 0xaf, 0xd0, 0xda, 0x2a,
    0xfb, 0xcf, 0x8b, 0xf6, 0xe1, 0xe4, 0x28, 0x0c,
    0x28, 0xe7, 0xa0, 0xa9, 0xc2, 0x57, 0xdd, 0x8b,
    0xd4, 0x7a, 0x39, 0x48, 0xb4, 0x11, 0xeb, 0x2c,
    0x4d, 0x61, 0xf9, 0x0e, 0x79, 0xbe, 0x5f, 0x51,
    0x0a, 0xb1, 0xae, 0x24, 0x15, 0x14, 0xb6, 0x83,
];

const EXPECTED_PCR0: [u8; 48] = [
    0x05, 0x13, 0xec, 0x0c, 0xc3, 0x3f, 0xe8, 0x4c,
    0x1e, 0x4d, 0x5e, 0x4d, 0x28, 0xfa, 0x83, 0x09,
    0xf8, 0xa2, 0x89, 0xfb, 0x2d, 0x2b, 0x7d, 0x35,
    0x42, 0xeb, 0xff, 0xd3, 0x4b, 0x69, 0x30, 0x6e,
    0x7d, 0xee, 0x88, 0x97, 0xb7, 0x8a, 0x1f, 0x51,
    0x57, 0xba, 0x6f, 0x65, 0xd1, 0x9d, 0x83, 0xce,
];

/// Verify an ECDSA P-384 signature: issuer_key signed sha384(data).
/// Supports both DER (certificates) and raw 96-byte (COSE) formats.
fn verify_p384(issuer_key: &[u8; 97], data: &[u8], sig_bytes: &[u8]) {
    let vk =
        VerifyingKey::from_sec1_bytes(issuer_key).expect("invalid issuer pubkey");
    let digest = Sha384::new().chain_update(data);
    let sig = if sig_bytes.len() == 96 {
        Signature::from_bytes(sig_bytes.into()).expect("invalid raw signature")
    } else {
        Signature::from_der(sig_bytes).expect("invalid DER signature")
    };
    vk.verify_digest(digest, &sig)
        .expect("signature verification failed");
}

pub fn main() {
    let input: GuestInput = sp1_zkvm::io::read();

    // 1. Trust anchor: verify root CA pubkey against hardcoded hash
    let root_hash = Sha384::digest(&input.root_pubkey);
    assert_eq!(
        root_hash.as_slice(),
        &EXPECTED_ROOT_PUBKEY_HASH,
        "root CA pubkey hash mismatch"
    );

    // 2. Certificate chain: root -> intermediate(s) -> leaf
    assert!(!input.chain.is_empty(), "empty cert chain");

    let mut issuer_key = input.root_pubkey;
    for cert in &input.chain {
        verify_p384(&issuer_key.try_into().expect("correct size"), &cert.tbs, &cert.signature);
        issuer_key = cert.pubkey.clone();
    }
    // issuer_key now holds the leaf public key

    // 3. COSE Sign1 signature (leaf signed the attestation payload)
    verify_p384(&issuer_key.try_into().expect("correct size"), &input.sig_structure, &input.cose_signature);

    // 4. PCR0
    assert_eq!(input.pcr0, EXPECTED_PCR0, "PCR0 mismatch");

    // 5. user_data = uncompressed ECDSA public key
    assert_eq!(input.user_data.len(), 65, "invalid pubkey length");
    assert_eq!(input.user_data[0], 0x04, "not uncompressed key");

    // 6. Commit to proof public values
    sp1_zkvm::io::commit_slice(&input.user_data);
}