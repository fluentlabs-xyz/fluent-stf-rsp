use p384::ecdsa::{signature::DigestVerifier, Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use serde_bytes::ByteBuf;
use sha2::{Digest as _, Sha384};
use x509_parser::prelude::*;

/// SHA-384 of the DER-encoded Subject DN of the AWS Nitro root CA.
const EXPECTED_ROOT_SUBJECT_HASH: [u8; 48] = [
    0xfe, 0x19, 0xf1, 0x6b, 0x73, 0xdc, 0xfd, 0xf7, 0xad, 0xa6, 0x86, 0xb2, 0x6f, 0xbc, 0x26, 0x80,
    0x0e, 0x8b, 0x49, 0x33, 0xa0, 0xc1, 0xe7, 0xa9, 0xb4, 0x0c, 0xd4, 0xea, 0x80, 0x9f, 0x18, 0x29,
    0xdc, 0x48, 0x8e, 0x14, 0x75, 0x3c, 0xbd, 0xe8, 0x76, 0x86, 0xc4, 0xd9, 0x34, 0x39, 0xf0, 0x3e,
];

#[derive(Serialize, Deserialize)]
pub(crate) struct CertData {
    #[serde(with = "serde_bytes")]
    pub tbs: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub signature: Vec<u8>,
}

/// Wire-compatible with `nitro_validator::GuestInput`. Guest parses CBOR and
/// X.509 DER structurally — host just forwards raw bytes.
#[derive(Serialize, Deserialize)]
pub(crate) struct GuestInput {
    pub root_pubkey: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub root_subject: Vec<u8>,
    pub chain: Vec<CertData>,
    #[serde(with = "serde_bytes")]
    pub cose_protected: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub cose_payload: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub cose_signature: Vec<u8>,
}

pub(crate) fn prepare_guest_input(
    attestation_bytes: &[u8],
    root_cert_der: &[u8],
) -> Result<GuestInput, Box<dyn std::error::Error>> {
    // COSE_Sign1 = [protected, unprotected, payload, signature]
    let (protected, _unprotected, payload, signature): (
        ByteBuf,
        ciborium::Value,
        ByteBuf,
        ByteBuf,
    ) = ciborium::from_reader(attestation_bytes)?;

    if signature.len() != 96 {
        return Err(format!("expected 96-byte COSE signature, got {}", signature.len()).into());
    }

    // Root pubkey + subject DN. Host validates the subject hash locally so we
    // fail fast before the prover starts.
    let (_, root_cert) = X509Certificate::from_der(root_cert_der)?;
    let root_pubkey = extract_sec1(&root_cert.public_key().subject_public_key.data)?;
    let root_subject = root_cert.tbs_certificate.subject.as_raw().to_vec();
    if Sha384::digest(&root_subject)[..] != EXPECTED_ROOT_SUBJECT_HASH {
        return Err("root CA subject hash mismatch".into());
    }

    // Extract cabundle + leaf from the signed AttestationDoc.
    let doc_payload = payload.clone().into_vec();
    let (cabundle, leaf_der) = extract_chain_der(&doc_payload)?;

    let mut chain: Vec<CertData> = Vec::with_capacity(cabundle.len() + 1);
    for der in &cabundle {
        let (_, parsed) = X509Certificate::from_der(der)?;
        chain.push(CertData {
            tbs: parsed.tbs_certificate.as_ref().to_vec(),
            signature: parsed.signature_value.data.to_vec(),
        });
    }
    let (_, leaf) = X509Certificate::from_der(&leaf_der)?;
    chain.push(CertData {
        tbs: leaf.tbs_certificate.as_ref().to_vec(),
        signature: leaf.signature_value.data.to_vec(),
    });

    // Fail-fast host verification of the chain (mirrors guest logic).
    {
        let mut issuer_pk = root_pubkey;
        for der in cabundle.iter().chain(std::iter::once(&leaf_der)) {
            let (_, parsed) = X509Certificate::from_der(der)?;
            verify_p384_host(
                &issuer_pk,
                parsed.tbs_certificate.as_ref(),
                parsed.signature_value.data.as_ref(),
            )?;
            issuer_pk = extract_sec1(&parsed.public_key().subject_public_key.data)?;
        }
    }

    Ok(GuestInput {
        root_pubkey: root_pubkey.into(),
        root_subject,
        chain,
        cose_protected: protected.into_vec(),
        cose_payload: doc_payload,
        cose_signature: signature.into_vec(),
    })
}

type ChainAndLeaf = (Vec<Vec<u8>>, Vec<u8>);

/// Decode just enough of an `AttestationDoc` CBOR map to pull out the
/// `cabundle` array and the `certificate` bstr. Host convenience only —
/// the guest parses the same payload independently.
fn extract_chain_der(payload: &[u8]) -> Result<ChainAndLeaf, Box<dyn std::error::Error>> {
    use serde::Deserialize;
    use std::collections::BTreeMap;

    #[derive(Deserialize)]
    struct Doc {
        #[serde(with = "serde_bytes")]
        certificate: Vec<u8>,
        #[serde(with = "cabundle_de")]
        cabundle: Vec<Vec<u8>>,
        #[allow(dead_code)]
        #[serde(default, with = "pcrs_de")]
        pcrs: BTreeMap<usize, Vec<u8>>,
    }

    mod cabundle_de {
        use serde::Deserialize;
        use serde_bytes::ByteBuf;
        pub(super) fn deserialize<'de, D: serde::Deserializer<'de>>(
            d: D,
        ) -> Result<Vec<Vec<u8>>, D::Error> {
            let v: Vec<ByteBuf> = Vec::deserialize(d)?;
            Ok(v.into_iter().map(|b| b.into_vec()).collect())
        }
    }
    mod pcrs_de {
        use serde::Deserialize;
        use serde_bytes::ByteBuf;
        use std::collections::BTreeMap;
        pub(super) fn deserialize<'de, D: serde::Deserializer<'de>>(
            d: D,
        ) -> Result<BTreeMap<usize, Vec<u8>>, D::Error> {
            let m: BTreeMap<usize, ByteBuf> = BTreeMap::deserialize(d)?;
            Ok(m.into_iter().map(|(k, v)| (k, v.into_vec())).collect())
        }
    }

    let doc: Doc = ciborium::from_reader(payload)?;
    Ok((doc.cabundle, doc.certificate))
}

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
