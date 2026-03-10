mod kms;
mod params;
mod vsock;

use anyhow::Context;
use hkdf::Hkdf;
pub use params::*;

use aws_nitro_enclaves_nsm_api::{
    api::{Request, Response},
    driver,
};

use k256::ecdsa::{signature::Signer, Signature, SigningKey};
use k256::SecretKey;

use rsp_client_executor::{executor::EthClientExecutor, io::EthClientExecutorInput};
use nitro_types::{EnclaveRequest, EnclaveResponse, EthExecutionResponse};

use ::vsock::{VsockAddr, VsockListener, VMADDR_CID_ANY};
use serde_bytes::ByteBuf;
use sha2::{Digest, Sha256};
use std::sync::Arc;
use std::thread;

use crate::nitro::{kms::KmsClient, vsock::VsockChannel};

/// The core enclave runtime. Encapsulates the full lifecycle:
/// bind → handshake → process blocks.
struct Enclave {
    listener: VsockListener,
    signing_key: Arc<SigningKey>,
}

impl Enclave {
    fn init() -> anyhow::Result<Self> {
        let listener = VsockListener::bind(&VsockAddr::new(VMADDR_CID_ANY, VSOCK_PORT))
            .context("Failed to bind VSOCK listener")?;

        let signing_key = Self::handshake(&listener)?;

        Ok(Self {
            listener,
            signing_key: Arc::new(signing_key),
        })
    }

    fn handshake(listener: &VsockListener) -> anyhow::Result<SigningKey> {
        let mut channel =
            VsockChannel::accept(listener).context("Failed to accept handshake connection")?;

        let result = Self::try_handshake(&mut channel);

        if let Err(ref e) = result {
            let resp = EnclaveResponse::Error(format!("{e:#}"));
            let _ = channel.send_bincode(&resp);
        }

        result
    }

    fn try_handshake(channel: &mut VsockChannel) -> anyhow::Result<SigningKey> {
        let raw = channel.receive().context("Failed to receive handshake")?;
        let req: EnclaveRequest =
            bincode::deserialize(&raw).context("Failed to deserialize handshake")?;

        let kms = KmsClient::new(req.credentials);

        let (signing_key, resp) = match req.encrypted_data_key {
            Some(blob) => Self::restore_key(&kms, &blob)?,
            None => Self::generate_key(&kms)?,
        };

        channel
            .send_bincode(&resp)
            .context("Failed to send handshake response")?;
        Ok(signing_key)
    }

    /// Restores an existing signing key by decrypting the blob via KMS.
    fn restore_key(
        kms: &KmsClient,
        encrypted_blob: &[u8],
    ) -> anyhow::Result<(SigningKey, EnclaveResponse)> {
        let key_bytes = kms.decrypt(encrypted_blob).context("KMS decrypt failed")?;
        let signing_key = signing_key_from_bytes(&key_bytes)?;
        let public_key = encode_public_key(&signing_key);

        let resp = EnclaveResponse::KeyRestored { public_key };

        Ok((signing_key, resp))
    }

    /// Generates a fresh signing key, encrypts it via KMS,
    /// and produces an attestation document.
    fn generate_key(kms: &KmsClient) -> anyhow::Result<(SigningKey, EnclaveResponse)> {
        let (data_key, _) = kms
            .generate_data_key()
            .context("KMS GenerateDataKey failed")?;
        let r_local = get_nsm_entropy().context("Failed to get NSM entropy")?;

        let key_bytes = derive_valid_ecdsa_key(&data_key, &r_local)?;
        let encrypted = kms.encrypt(&key_bytes).context("KMS encrypt failed")?;

        let signing_key = signing_key_from_bytes(&key_bytes)?;
        let public_key = encode_public_key(&signing_key);
        let attestation = create_attestation(&public_key)?;

        let resp = EnclaveResponse::KeyGenerated {
            encrypted_signing_key: encrypted,
            attestation,
            public_key,
        };

        Ok((signing_key, resp))
    }

    /// Main loop: accept connections and spawn a thread per block request.
    fn run(&self) -> ! {
        println!("Enclave ready to process block requests");

        loop {
            let channel = match VsockChannel::accept(&self.listener) {
                Ok(ch) => ch,
                Err(e) => {
                    eprintln!("Failed to accept connection: {e:#}");
                    continue;
                }
            };

            let key = Arc::clone(&self.signing_key);

            thread::spawn(move || {
                if let Err(e) = handle_block_session(channel, &key) {
                    eprintln!("Block session error: {e:#}");
                }
            });
        }
    }
}

// ---------------------------------------------------------------------------
// Block handling (runs inside spawned threads)
// ---------------------------------------------------------------------------

fn handle_block_session(
    mut channel: VsockChannel,
    signing_key: &SigningKey,
) -> anyhow::Result<()> {
    let result = try_execute_block(&mut channel, signing_key);

    if let Err(ref e) = result {
        let err_resp = EnclaveResponse::Error(format!("{e:#}"));
        let _ = channel.send_bincode(&err_resp);
    }

    result
}

fn try_execute_block(
    channel: &mut VsockChannel,
    signing_key: &SigningKey,
) -> anyhow::Result<()> {
    let raw = channel.receive().context("Failed to receive block input")?;
    let input: EthClientExecutorInput =
        bincode::deserialize(&raw).context("Failed to deserialize block input")?;

    let output = execute_block(input, signing_key)?;
    channel
        .send_bincode(&output)
        .context("Failed to send execution result")
}

// ---------------------------------------------------------------------------
// Pure helper functions
// ---------------------------------------------------------------------------

fn execute_block(
    input: EthClientExecutorInput,
    signing_key: &SigningKey,
) -> anyhow::Result<EthExecutionResponse> {
    let genesis = (&input.genesis)
        .try_into()
        .map_err(|_| anyhow::anyhow!("Invalid genesis configuration"))?;

    let executor = EthClientExecutor::eth(Arc::new(genesis), input.custom_beneficiary);

    let (header, events_hash) = executor
        .execute(input)
        .map_err(|e| anyhow::anyhow!("Block execution failed: {e:?}"))?;

    let block_hash = header.hash_slow();
    let parent_hash = header.parent_hash;

    let mut hasher = Sha256::new();
    hasher.update(parent_hash.as_slice());
    hasher.update(block_hash.as_slice());
    hasher.update(events_hash.withdrawal_hash.as_slice());
    hasher.update(events_hash.deposit_hash.as_slice());

    let result_hash = hasher.clone().finalize();

    hasher.update(result_hash);
    let signing_payload = hasher.finalize();

    let signature: Signature = signing_key.sign(&signing_payload);

    Ok(EthExecutionResponse {
        parent_hash,
        block_hash,
        withdrawal_hash: events_hash.withdrawal_hash,
        deposit_hash: events_hash.deposit_hash,
        result_hash: result_hash.to_vec(),
        signature: signature.to_vec(),
    })
}

fn signing_key_from_bytes(bytes: &[u8]) -> anyhow::Result<SigningKey> {
    let secret = SecretKey::from_bytes(bytes.into()).context("Invalid secp256k1 key bytes")?;
    Ok(SigningKey::from(secret))
}

fn encode_public_key(key: &SigningKey) -> Vec<u8> {
    key.verifying_key()
        .to_encoded_point(false)
        .as_bytes()
        .to_vec()
}

fn get_nsm_entropy() -> anyhow::Result<Vec<u8>> {
    let fd = driver::nsm_init();
    let response = driver::nsm_process_request(fd, Request::GetRandom);
    driver::nsm_exit(fd);

    match response {
        Response::GetRandom { random } => Ok(random),
        _ => Err(anyhow::anyhow!(
            "NSM GetRandom returned unexpected response"
        )),
    }
}

fn create_attestation(public_key: &[u8]) -> anyhow::Result<Vec<u8>> {
    let fd = driver::nsm_init();
    let response = driver::nsm_process_request(
        fd,
        Request::Attestation {
            public_key: None,
            user_data: Some(ByteBuf::from(public_key.to_vec())),
            nonce: None,
        },
    );
    driver::nsm_exit(fd);

    match response {
        Response::Attestation { document } => Ok(document),
        _ => Err(anyhow::anyhow!("NSM Attestation failed")),
    }
}

fn derive_valid_ecdsa_key(data_key: &[u8], r_local: &[u8]) -> anyhow::Result<[u8; 32]> {
    let (_, hk) = Hkdf::<Sha256>::extract(Some(r_local), data_key);

    for counter in 0..=100u32 {
        let mut candidate = [0u8; 32];
        let info = format!("enclave-signing-key-v1-{counter}");

        hk.expand(info.as_bytes(), &mut candidate)
            .map_err(|_| anyhow::anyhow!("HKDF expansion failed"))?;

        if SecretKey::from_slice(&candidate).is_ok() {
            return Ok(candidate);
        }
    }

    Err(anyhow::anyhow!(
        "Failed to derive valid key after 100 iterations"
    ))
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

pub fn main() -> anyhow::Result<()> {
    println!("Nitro enclave starting");

    let enclave = Enclave::init().context("Enclave initialization failed")?;

    println!("Initialization complete");
    enclave.run();
}