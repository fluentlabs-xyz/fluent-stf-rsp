#![no_main]
sp1_zkvm::entrypoint!(main);

extern crate alloc;

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;
use p384::ecdsa::{
    signature::DigestVerifier,
    Signature, VerifyingKey,
};
use serde::{Deserialize, Serialize};
use serde_bytes::ByteBuf;
use sha2::{Digest as _, Sha384};

#[derive(Debug)]
pub enum ValidationError {
    InvalidCBOR,
    InvalidCOSEStructure,
    InvalidSignature,
    MissingRequiredField(&'static str),
    InvalidFieldValue(&'static str),
    InvalidCertificate,
    CertificateChainFailed,
    UnsupportedDigest,
}

impl fmt::Display for ValidationError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::InvalidCBOR => write!(f, "Invalid CBOR encoding"),
            Self::InvalidCOSEStructure => write!(f, "Invalid COSE Sign1 structure"),
            Self::InvalidSignature => write!(f, "Signature verification failed"),
            Self::MissingRequiredField(field) => write!(f, "Missing field: {}", field),
            Self::InvalidFieldValue(field) => write!(f, "Invalid value: {}", field),
            Self::InvalidCertificate => write!(f, "Invalid certificate"),
            Self::CertificateChainFailed => write!(f, "Certificate chain failed"),
            Self::UnsupportedDigest => write!(f, "Unsupported digest"),
        }
    }
}

pub type Result<T> = core::result::Result<T, ValidationError>;

/// Digest algorithm enum
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Digest {
    SHA256,
    SHA384,
    SHA512,
}

/// AWS Nitro Enclaves Attestation Document
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttestationDoc {
    #[serde(rename = "module_id")]
    pub module_id: String,
    pub digest: Digest,
    pub timestamp: u64,
    #[serde(with = "pcrs_serde")]
    pub pcrs: BTreeMap<usize, Vec<u8>>,
    #[serde(with = "serde_bytes")]
    pub certificate: Vec<u8>,
    #[serde(with = "cabundle_serde")]
    pub cabundle: Vec<Vec<u8>>,
    #[serde(rename = "public_key", skip_serializing_if = "Option::is_none")]
    #[serde(with = "opt_serde_bytes")]
    pub public_key: Option<Vec<u8>>,
    #[serde(rename = "user_data", skip_serializing_if = "Option::is_none")]
    #[serde(with = "opt_serde_bytes")]
    pub user_data: Option<Vec<u8>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(with = "opt_serde_bytes")]
    pub nonce: Option<Vec<u8>>,
}

impl AttestationDoc {
    pub fn from_binary(bytes: &[u8]) -> Result<Self> {
        ciborium::from_reader(bytes).map_err(|_| ValidationError::InvalidCBOR)
    }

    pub fn to_binary(&self) -> Result<Vec<u8>> {
        let mut buf = Vec::new();
        ciborium::into_writer(self, &mut buf).map_err(|_| ValidationError::InvalidCBOR)?;
        Ok(buf)
    }
}

/// Serde helper for PCRs
mod pcrs_serde {
    use super::*;
    use alloc::collections::BTreeMap;
    use alloc::vec::Vec;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(
        map: &BTreeMap<usize, Vec<u8>>,
        serializer: S,
    ) -> core::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        use serde::ser::SerializeMap;
        let mut s = serializer.serialize_map(Some(map.len()))?;
        for (k, v) in map {
            s.serialize_entry(k, &serde_bytes::Bytes::new(v))?;
        }
        s.end()
    }

    pub fn deserialize<'de, D>(
        deserializer: D,
    ) -> core::result::Result<BTreeMap<usize, Vec<u8>>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let map: BTreeMap<usize, ByteBuf> = BTreeMap::deserialize(deserializer)?;
        Ok(map.into_iter().map(|(k, v)| (k, v.into_vec())).collect())
    }
}

/// Serde helper for certificate bundle
mod cabundle_serde {
    use super::*;
    use alloc::vec::Vec;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(vec: &Vec<Vec<u8>>, serializer: S) -> core::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        use serde::ser::SerializeSeq;
        let mut s = serializer.serialize_seq(Some(vec.len()))?;
        for item in vec {
            s.serialize_element(&serde_bytes::Bytes::new(item))?;
        }
        s.end()
    }

    pub fn deserialize<'de, D>(deserializer: D) -> core::result::Result<Vec<Vec<u8>>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let vec: Vec<ByteBuf> = Vec::deserialize(deserializer)?;
        Ok(vec.into_iter().map(|b| b.into_vec()).collect())
    }
}

/// Serde helper for optional byte arrays
mod opt_serde_bytes {
    use alloc::vec::Vec;
    use serde::{Deserialize, Deserializer, Serializer};
    use serde_bytes::ByteBuf;

    pub fn serialize<S>(
        opt: &Option<Vec<u8>>,
        serializer: S,
    ) -> core::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match opt {
            Some(v) => serializer.serialize_some(&serde_bytes::Bytes::new(v)),
            None => serializer.serialize_none(),
        }
    }

    pub fn deserialize<'de, D>(deserializer: D) -> core::result::Result<Option<Vec<u8>>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let opt: Option<ByteBuf> = Option::deserialize(deserializer)?;
        Ok(opt.map(|b| b.into_vec()))
    }
}

/// COSE Sign1 structure (raw CBOR components)
#[derive(Debug, Deserialize)]
pub struct CoseSign1Raw(
    pub ByteBuf,         // 0: protected headers
    pub ciborium::Value, // 1: unprotected headers (map or null)
    pub ByteBuf,         // 2: payload (AttestationDoc in CBOR)
    pub ByteBuf,         // 3: signature
);

impl CoseSign1Raw {
    pub fn protected(&self) -> &[u8] {
        &self.0
    }

    pub fn unprotected(&self) -> &ciborium::Value {
        &self.1
    }

    pub fn payload(&self) -> &[u8] {
        &self.2
    }

    pub fn signature(&self) -> &[u8] {
        &self.3
    }

    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        ciborium::from_reader(data).map_err(|_| ValidationError::InvalidCBOR)
    }
}

/// AWS Nitro Enclaves Attestation Validator
pub struct NitroValidator {
    root_cert: Vec<u8>,
}

impl NitroValidator {
    pub fn new(root_cert: Vec<u8>) -> Self {
        Self { root_cert }
    }

    pub fn validate(&self, attestation_bytes: &[u8]) -> Result<AttestationDoc> {
        let cose: CoseSign1Raw = ciborium::from_reader(attestation_bytes).map_err(|e| {
            println!("{}", e);
            ValidationError::InvalidCBOR
        })?;

        let att_doc = AttestationDoc::from_binary(cose.payload())?;
        self.validate_syntax(&att_doc)?;

        let verifying_key = self.validate_certificate_chain(&att_doc)?;
        self.verify_cose_signature(&cose, &verifying_key)?;

        Ok(att_doc)
    }

    fn validate_syntax(&self, doc: &AttestationDoc) -> Result<()> {
        if doc.module_id.is_empty() {
            return Err(ValidationError::InvalidFieldValue("module_id"));
        }

        if doc.digest != Digest::SHA384 {
            return Err(ValidationError::UnsupportedDigest);
        }

        if doc.timestamp == 0 {
            return Err(ValidationError::InvalidFieldValue("timestamp"));
        }

        if doc.pcrs.is_empty() || doc.pcrs.len() > 32 {
            return Err(ValidationError::InvalidFieldValue("pcrs"));
        }

        for (idx, pcr) in &doc.pcrs {
            if *idx >= 32 {
                return Err(ValidationError::InvalidFieldValue("pcr index"));
            }

            let len = pcr.len();
            if len != 32 && len != 48 && len != 64 {
                return Err(ValidationError::InvalidFieldValue("pcr length"));
            }
        }

        let cert_len = doc.certificate.len();
        if cert_len == 0 || cert_len > 1024 {
            return Err(ValidationError::InvalidFieldValue("certificate"));
        }

        if doc.cabundle.is_empty() {
            return Err(ValidationError::MissingRequiredField("cabundle"));
        }

        for cert in &doc.cabundle {
            let len = cert.len();
            if len == 0 || len > 1024 {
                return Err(ValidationError::InvalidFieldValue("cabundle cert"));
            }
        }

        if let Some(ref pk) = doc.public_key {
            let len = pk.len();
            if len == 0 || len > 1024 {
                return Err(ValidationError::InvalidFieldValue("public_key"));
            }
        }

        if let Some(ref ud) = doc.user_data {
            if ud.len() > 512 {
                return Err(ValidationError::InvalidFieldValue("user_data"));
            }
        }

        if let Some(ref n) = doc.nonce {
            if n.len() > 512 {
                return Err(ValidationError::InvalidFieldValue("nonce"));
            }
        }

        Ok(())
    }

    fn validate_certificate_chain(&self, doc: &AttestationDoc) -> Result<VerifyingKey> {
        use x509_parser::prelude::*;

        // Parse root certificate and extract public key
        let (_, root_cert) = X509Certificate::from_der(&self.root_cert)
            .map_err(|_| ValidationError::InvalidCertificate)?;
        let mut current_public_key = root_cert.public_key().subject_public_key.data.to_vec();

        // Verify intermediate CA certificates chain
        for ca_cert_der in &doc.cabundle {
            let (_, ca_cert) = X509Certificate::from_der(ca_cert_der)
                .map_err(|_| ValidationError::InvalidCertificate)?;

            Self::verify_cert_signature(&ca_cert, &current_public_key)?;
            current_public_key = ca_cert.public_key().subject_public_key.data.to_vec();
        }

        // Parse and verify leaf certificate
        let (_, leaf_cert) = X509Certificate::from_der(&doc.certificate)
            .map_err(|_| ValidationError::InvalidCertificate)?;

        Self::verify_cert_signature(&leaf_cert, &current_public_key)?;

        // Extract P-384 public key from leaf certificate
        Self::extract_p384_key(&leaf_cert.public_key().subject_public_key.data)
    }

    /// Extract P-384 verifying key from X.509 BIT STRING format
    fn extract_p384_key(pubkey_data: &[u8]) -> Result<VerifyingKey> {
        // X.509 BIT STRING may have unused bits indicator as first byte
        let sec1_bytes = if pubkey_data.len() == 98 && pubkey_data[0] == 0x00 {
            &pubkey_data[1..]
        } else {
            pubkey_data
        };

        // Verify format: 0x04 (uncompressed point) + 48 bytes X + 48 bytes Y for P-384
        if sec1_bytes.len() != 97 || sec1_bytes[0] != 0x04 {
            return Err(ValidationError::InvalidCertificate);
        }

        VerifyingKey::from_sec1_bytes(sec1_bytes).map_err(|_| ValidationError::InvalidCertificate)
    }

    /// Verify X.509 certificate signature using issuer's public key
    fn verify_cert_signature(
        cert: &x509_parser::certificate::X509Certificate,
        issuer_public_key: &[u8],
    ) -> Result<()> {
        // Extract issuer's P-384 verifying key
        let verifying_key = Self::extract_p384_key(issuer_public_key)?;

        // Get TBS (To Be Signed) certificate and create digest
        let tbs_bytes = cert.tbs_certificate.as_ref();
        let digest = Sha384::new().chain_update(tbs_bytes);

        // Parse signature (try both DER and raw formats)
        let sig_bytes = cert.signature_value.data.as_ref();
        let signature = Self::parse_signature(sig_bytes)
            .map_err(|_| ValidationError::CertificateChainFailed)?;

        // Verify signature
        verifying_key
            .verify_digest(digest, &signature)
            .map_err(|_| ValidationError::CertificateChainFailed)?;

        Ok(())
    }

    /// Parse ECDSA signature from either DER or raw format
    fn parse_signature(sig_bytes: &[u8]) -> core::result::Result<Signature, p384::ecdsa::Error> {
        if sig_bytes.len() == 96 {
            // Raw format (96 bytes for P-384: 48 bytes R + 48 bytes S)
            Signature::from_bytes(sig_bytes.into())
        } else {
            // DER format (variable length)
            Signature::from_der(sig_bytes)
        }
    }

    /// Verify COSE Sign1 signature
    fn verify_cose_signature(
        &self,
        cose: &CoseSign1Raw,
        verifying_key: &VerifyingKey,
    ) -> Result<()> {
        let sig_structure = self.construct_sig_structure(cose)?;
        let digest = Sha384::new().chain_update(&sig_structure);

        let signature = Signature::from_bytes(cose.signature().into())
            .map_err(|_| ValidationError::InvalidSignature)?;

        verifying_key
            .verify_digest(digest, &signature)
            .map_err(|_| ValidationError::InvalidSignature)?;

        Ok(())
    }

    /// Construct COSE Sign1 Sig_structure for signature verification
    /// Format: ["Signature1", protected_headers, external_aad, payload]
    fn construct_sig_structure(&self, cose: &CoseSign1Raw) -> Result<Vec<u8>> {
        let array = (
            "Signature1",
            serde_bytes::ByteBuf::from(cose.protected().to_vec()),
            serde_bytes::ByteBuf::from(Vec::new()), // empty external_aad
            serde_bytes::ByteBuf::from(cose.payload().to_vec()),
        );

        let mut sig_structure = Vec::new();
        ciborium::into_writer(&array, &mut sig_structure)
            .map_err(|_| ValidationError::InvalidCOSEStructure)?;

        Ok(sig_structure)
    }
}

/// SP1 zkVM helper functions
pub mod sp1 {
    use super::*;

    pub fn extract_user_data(doc: &AttestationDoc) -> Option<&[u8]> {
        doc.user_data.as_deref()
    }

    pub fn extract_pcrs(doc: &AttestationDoc) -> Vec<(usize, &[u8])> {
        doc.pcrs.iter().map(|(k, v)| (*k, v.as_slice())).collect()
    }

    pub fn get_timestamp(doc: &AttestationDoc) -> u64 {
        doc.timestamp
    }

    pub fn get_module_id(doc: &AttestationDoc) -> &str {
        &doc.module_id
    }
}

const AWS_ROOT_CERT: &[u8] = include_bytes!("../../root.der");

const EXPECTED_PCR0: [u8; 48] = [
    0x05, 0x13, 0xec, 0x0c, 0xc3, 0x3f, 0xe8, 0x4c, 0x1e, 0x4d, 0x5e, 0x4d, 0x28, 0xfa, 0x83, 0x09,
    0xf8, 0xa2, 0x89, 0xfb, 0x2d, 0x2b, 0x7d, 0x35, 0x42, 0xeb, 0xff, 0xd3, 0x4b, 0x69, 0x30, 0x6e,
    0x7d, 0xee, 0x88, 0x97, 0xb7, 0x8a, 0x1f, 0x51, 0x57, 0xba, 0x6f, 0x65, 0xd1, 0x9d, 0x83, 0xce,
];
const ATTESTATION: &[u8] = include_bytes!("../../attestation.bin");

pub fn main() {
    let validator = NitroValidator::new(AWS_ROOT_CERT.to_vec());
    let doc = validator.validate(ATTESTATION).expect("Invalid attestation");

    // Verify PCR0
    let pcr0 = doc.pcrs.get(&0).expect("Missing PCR0");
    assert_eq!(pcr0, &EXPECTED_PCR0, "PCR0 mismatch");

    // Extract and verify user data (public key)
    let pubkey = doc.user_data.expect("Missing user_data");
    assert_eq!(pubkey.len(), 65, "Invalid pubkey length");
    assert_eq!(pubkey[0], 0x04, "Not uncompressed ECDSA key");

    sp1_zkvm::io::commit(&pubkey);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_full_validation() {
        let validator = NitroValidator::new(AWS_ROOT_CERT.to_vec());
        let doc = validator.validate(ATTESTATION).expect("Invalid attestation");

        let pcr0 = doc.pcrs.get(&0).expect("Missing PCR0");
        assert_eq!(pcr0, &EXPECTED_PCR0, "PCR0 mismatch");

        let pubkey = doc.user_data.expect("Missing user_data");
        assert_eq!(pubkey.len(), 65, "Invalid pubkey length");
        assert_eq!(pubkey[0], 0x04, "Not uncompressed ECDSA key");
    }
}
