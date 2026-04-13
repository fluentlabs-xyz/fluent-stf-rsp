use std::collections::BTreeMap;

use p384::ecdsa::{signature::DigestVerifier, Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use serde_bytes::ByteBuf;
use sha2::{Digest as _, Sha384};
use x509_parser::prelude::*;

/// Pre-parsed certificate data extracted from X.509 DER on the host.
#[derive(Serialize, Deserialize)]
pub(crate) struct CertData {
    #[serde(with = "serde_bytes")]
    pub tbs: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub signature: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub pubkey: Vec<u8>,
}

/// Everything the guest receives from the host.
#[derive(Serialize, Deserialize)]
pub(crate) struct GuestInput {
    pub root_pubkey: Vec<u8>,
    pub chain: Vec<CertData>,
    #[serde(with = "serde_bytes")]
    pub sig_structure: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub cose_signature: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub pcr0: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub user_data: Vec<u8>,
}

// ─── CBOR structures (parsed only on the host) ─────────────────────────────

#[derive(Deserialize)]
struct AttestationDoc {
    #[serde(with = "pcrs_de")]
    pcrs: BTreeMap<usize, Vec<u8>>,
    #[serde(with = "serde_bytes")]
    certificate: Vec<u8>,
    #[serde(with = "cabundle_de")]
    cabundle: Vec<Vec<u8>>,
    #[serde(default, with = "opt_bytes_de")]
    user_data: Option<Vec<u8>>,
}

// ─── Main entry point ───────────────────────────────────────────────────────

/// Parse the raw attestation document, validate the certificate chain,
/// and produce a minimal `GuestInput` for the SP1 guest program.
pub(crate) fn prepare_guest_input(
    attestation_bytes: &[u8],
    root_cert_der: &[u8],
) -> Result<GuestInput, Box<dyn std::error::Error>> {
    // 1. Parse COSE Sign1
    let (protected, _unprotected, payload, signature):
        (ByteBuf, ciborium::Value, ByteBuf, ByteBuf) =
        ciborium::from_reader(attestation_bytes)?;

    // 2. Parse AttestationDoc from COSE payload
    let doc: AttestationDoc = ciborium::from_reader(&payload[..])?;

    // 3. Extract root public key
    let (_, root_cert) = X509Certificate::from_der(root_cert_der)?;
    let root_pubkey = extract_sec1(&root_cert.public_key().subject_public_key.data)?;

    // 4. Build CertData chain (cabundle intermediates + leaf certificate)
    let mut chain = Vec::with_capacity(doc.cabundle.len() + 1);

    for ca_der in &doc.cabundle {
        let (_, ca) = X509Certificate::from_der(ca_der)?;
        chain.push(cert_to_data(&ca)?);
    }

    let (_, leaf) = X509Certificate::from_der(&doc.certificate)?;
    chain.push(cert_to_data(&leaf)?);

    // 5. Optional: verify the chain on the host too (fail fast before proving)
    {
        let mut issuer_pk = root_pubkey;
        for cert in &chain {
            verify_p384_host(&issuer_pk, &cert.tbs, &cert.signature)?;
            issuer_pk = cert.pubkey.clone().try_into().expect("correct size");
        }
    }

    // 6. Build COSE Sig_structure
    let sig_structure = build_sig_structure(&protected, &payload)?;

    // 7. Extract COSE signature (raw 96 bytes for P-384)
    let mut cose_signature = [0u8; 96];
    if signature.len() != 96 {
        return Err(format!("expected 96-byte COSE signature, got {}", signature.len()).into());
    }
    cose_signature.copy_from_slice(&signature);

    // 8. Extract PCR0
    let pcr0_vec = doc.pcrs.get(&0).ok_or("missing PCR0")?;
    let mut pcr0 = [0u8; 48];
    if pcr0_vec.len() != 48 {
        return Err("PCR0 must be 48 bytes".into());
    }
    pcr0.copy_from_slice(pcr0_vec);

    // 9. Extract user_data
    let user_data = doc.user_data.ok_or("missing user_data")?;

    Ok(GuestInput {
        root_pubkey: root_pubkey.into(),
        chain,
        sig_structure,
        cose_signature: cose_signature.into(),
        pcr0: pcr0.into(),
        user_data,
    })
}

// ─── Helpers ────────────────────────────────────────────────────────────────

/// Extract SEC1 uncompressed point (97 bytes) from X.509 BIT STRING.
fn extract_sec1(raw: &[u8]) -> Result<[u8; 97], Box<dyn std::error::Error>> {
    let sec1 = if raw.len() == 98 && raw[0] == 0x00 {
        &raw[1..]
    } else if raw.len() == 97 && raw[0] == 0x04 {
        raw
    } else {
        return Err(format!(
            "unexpected P-384 pubkey format: len={}, first=0x{:02x}",
            raw.len(),
            raw.first().copied().unwrap_or(0)
        )
        .into());
    };
    let mut out = [0u8; 97];
    out.copy_from_slice(sec1);
    Ok(out)
}

/// Convert an X509Certificate into CertData (TBS + signature + pubkey).
fn cert_to_data(cert: &X509Certificate<'_>) -> Result<CertData, Box<dyn std::error::Error>> {
    Ok(CertData {
        tbs: cert.tbs_certificate.as_ref().to_vec(),
        signature: cert.signature_value.data.to_vec(),
        pubkey: extract_sec1(&cert.public_key().subject_public_key.data)
            .expect("correct sec1")
            .to_vec(),
    })
}

/// Host-side signature verification (fail fast, not security-critical).
fn verify_p384_host(
    issuer_key: &[u8; 97],
    tbs: &[u8],
    sig_bytes: &[u8],
) -> Result<(), Box<dyn std::error::Error>> {
    let vk = VerifyingKey::from_sec1_bytes(issuer_key)?;
    let digest = Sha384::new().chain_update(tbs);
    let sig = Signature::from_der(sig_bytes)?;
    vk.verify_digest(digest, &sig)?;
    Ok(())
}

/// Build COSE Sig_structure: ["Signature1", protected, external_aad, payload]
fn build_sig_structure(
    protected: &[u8],
    payload: &[u8],
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let structure = (
        "Signature1",
        ByteBuf::from(protected.to_vec()),
        ByteBuf::from(Vec::new()),
        ByteBuf::from(payload.to_vec()),
    );
    let mut buf = Vec::new();
    ciborium::into_writer(&structure, &mut buf)?;
    Ok(buf)
}

// ─── Serde helpers ──────────────────────────────────────────────────────────

mod pcrs_de {
    use super::*;
    pub(super) fn deserialize<'de, D: serde::Deserializer<'de>>(
        d: D,
    ) -> Result<BTreeMap<usize, Vec<u8>>, D::Error> {
        let m: BTreeMap<usize, ByteBuf> = BTreeMap::deserialize(d)?;
        Ok(m.into_iter().map(|(k, v)| (k, v.into_vec())).collect())
    }
}

mod cabundle_de {
    use super::*;
    pub(super) fn deserialize<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Vec<Vec<u8>>, D::Error> {
        let v: Vec<ByteBuf> = Vec::deserialize(d)?;
        Ok(v.into_iter().map(|b| b.into_vec()).collect())
    }
}

mod opt_bytes_de {
    use serde::Deserialize;
    use serde_bytes::ByteBuf;
    pub(super) fn deserialize<'de, D: serde::Deserializer<'de>>(
        d: D,
    ) -> Result<Option<Vec<u8>>, D::Error> {
        let o: Option<ByteBuf> = Option::deserialize(d)?;
        Ok(o.map(|b| b.into_vec()))
    }
}
