#![no_std]
extern crate alloc;

use alloc::vec::Vec;
use serde::{Deserialize, Serialize};

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
