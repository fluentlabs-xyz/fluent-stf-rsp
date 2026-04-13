#![no_main]
sp1_zkvm::entrypoint!(main);

// Mutually-exclusive network feature guard. Exactly one of
// `mainnet` / `testnet` / `devnet` must be enabled — mirrors the
// invariant enforced in `fluent-stf-primitives`.
#[cfg(any(
    all(feature = "mainnet", feature = "testnet"),
    all(feature = "mainnet", feature = "devnet"),
    all(feature = "testnet", feature = "devnet"),
))]
compile_error!(
    "features `mainnet`, `testnet`, and `devnet` are mutually exclusive — enable exactly one"
);

#[cfg(not(any(feature = "mainnet", feature = "testnet", feature = "devnet")))]
compile_error!("exactly one of features `mainnet`, `testnet`, `devnet` must be enabled");

extern crate alloc;

use alloc::vec::Vec;
use p384::ecdsa::{signature::DigestVerifier, Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha384};
use sha3::Keccak256;

/// Pre-parsed certificate data extracted from X.509 DER on the host.
/// The guest only verifies signatures without any X.509/CBOR parsing.
#[derive(Serialize, Deserialize)]
pub struct CertData {
    /// TBS (To Be Signed) bytes — the data signed by the issuer
    #[serde(with = "serde_bytes")]
    pub tbs: Vec<u8>,
    /// DER-encoded ECDSA P-384 signature from the issuer over tbs
    #[serde(with = "serde_bytes")]
    pub signature: Vec<u8>,
    /// SEC1 uncompressed P-384 public key of this certificate (0x04 || X || Y)
    #[serde(with = "serde_bytes")]
    pub pubkey: Vec<u8>,
}

/// Everything the guest receives from the host.
#[derive(Serialize, Deserialize)]
pub struct GuestInput {
    /// Root CA public key (SEC1 uncompressed, 97 bytes).
    /// The guest verifies its hash against a hardcoded constant.
    pub root_pubkey: Vec<u8>,

    /// Certificate chain: [intermediate_0, intermediate_1, ..., leaf].
    /// root signed chain[0].tbs, chain[0].pubkey signed chain[1].tbs, etc.
    /// The last element is the leaf whose pubkey is used for COSE verification.
    pub chain: Vec<CertData>,

    /// Serialized COSE Sig_structure: ["Signature1", protected, ext_aad, payload]
    #[serde(with = "serde_bytes")]
    pub sig_structure: Vec<u8>,

    /// 96-byte raw ECDSA P-384 COSE Sign1 signature (R || S)
    #[serde(with = "serde_bytes")]
    pub cose_signature: Vec<u8>,

    /// PCR0 from the attestation document (48-byte SHA-384)
    #[serde(with = "serde_bytes")]
    pub pcr0: Vec<u8>,

    /// user_data from the attestation document
    #[serde(with = "serde_bytes")]
    pub user_data: Vec<u8>,
}

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

// ─── EXPECTED_PCR0 per network ───────────────────────────────────────────────
// Exactly one of these is selected at compile time via cargo features.
// The `scripts/update_expected_pcr0.py` helper (invoked by `make build-enclave`)
// rewrites only the block matching the current `NETWORK`.

#[cfg(feature = "mainnet")]
const EXPECTED_PCR0: [u8; 48] = [
    0x49, 0x2d, 0x7b, 0x12, 0x4f, 0x64, 0x60, 0x55,
    0x25, 0x44, 0x26, 0x3e, 0x75, 0x81, 0xb3, 0x05,
    0xeb, 0xde, 0xbc, 0x14, 0x05, 0x35, 0x0b, 0x4b,
    0x75, 0x7e, 0xb0, 0x9f, 0x5e, 0xf0, 0x2d, 0x96,
    0x35, 0x51, 0x32, 0x69, 0xaa, 0x35, 0x4f, 0x80,
    0xab, 0x3a, 0xec, 0xda, 0x18, 0x6b, 0x3d, 0xdb,
];

#[cfg(feature = "testnet")]
const EXPECTED_PCR0: [u8; 48] = [
    0xf0, 0xf7, 0x8e, 0x8f, 0x54, 0x30, 0x82, 0x6a,
    0xbf, 0xa0, 0xf2, 0x5c, 0x51, 0x6f, 0x72, 0xd7,
    0x83, 0x67, 0x7d, 0x0c, 0x21, 0xac, 0x76, 0xc5,
    0x16, 0x97, 0x62, 0x0a, 0x6f, 0x12, 0x25, 0x5a,
    0x41, 0xe0, 0xd4, 0x67, 0x5b, 0x09, 0x7b, 0xf4,
    0xe8, 0xb1, 0x58, 0x14, 0x70, 0xc2, 0x6d, 0x18,
];

#[cfg(feature = "devnet")]
const EXPECTED_PCR0: [u8; 48] = [
    0xda, 0xce, 0x52, 0x52, 0x04, 0x5a, 0x25, 0xda,
    0x90, 0x6a, 0x51, 0x62, 0x15, 0x08, 0x07, 0x37,
    0x6c, 0xe2, 0xc9, 0xc2, 0x72, 0x2b, 0xd7, 0x27,
    0xdd, 0x24, 0x6b, 0x2e, 0x2f, 0x7e, 0xd0, 0xfc,
    0x33, 0xc6, 0x93, 0x76, 0xe1, 0xea, 0x4d, 0xf0,
    0xf1, 0x8e, 0x34, 0xd5, 0x48, 0xaa, 0x57, 0x09,
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
        &root_hash[..],
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

    // 6. Derive Ethereum address: keccak256(pubkey[1..])[12..]
    let hash = Keccak256::digest(&input.user_data[1..]);
    let mut address = [0u8; 20];
    address.copy_from_slice(&hash[12..]);

    // 7. Commit abi.encode(address) — 32 bytes, left-padded with zeros
    let mut abi_encoded = [0u8; 32];
    abi_encoded[12..].copy_from_slice(&address);
    sp1_zkvm::io::commit_slice(&abi_encoded);
}