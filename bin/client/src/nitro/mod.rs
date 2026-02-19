mod kms;
mod params;
mod vsock;

use anyhow::Context;
use hkdf::Hkdf;
pub use params::*;

use aws_nitro_enclaves_nsm_api::{
    api::{Request, Response},
    driver::{self},
};

use k256::ecdsa::{signature::Signer, Signature, SigningKey};
use k256::SecretKey;

use rsp_client_executor::{
    executor::EthClientExecutor,
    io::EthClientExecutorInput,
    nitro::{EnclaveRequest, EnclaveResponse, EthExecutionResponse},
};

use ::vsock::{SockAddr, VsockListener, VMADDR_CID_ANY};
use serde_bytes::ByteBuf;
use sha2::{Digest, Sha256};
use std::sync::Arc;

use crate::nitro::{kms::KmsClient, vsock::VsockChannel};

/// Retrieves high-quality hardware entropy from the AWS Nitro Security Module (NSM).
/// Used for secure key derivation inside the enclave.
fn get_r_local() -> anyhow::Result<Vec<u8>> {
    let nsm_fd = driver::nsm_init();
    let request = Request::GetRandom;
    let response = driver::nsm_process_request(nsm_fd, request);

    let r_local = match response {
        Response::GetRandom { random } => Ok(random),
        _ => Err(anyhow::anyhow!("Failed to get entropy from NSM")),
    }?;

    driver::nsm_exit(nsm_fd);
    Ok(r_local)
}

/// Derives a valid secp256k1 private key from entropy using HKDF.
/// Ensures the resulting key is within the valid elliptic curve range.
fn derive_valid_ecdsa_key(data_key: &[u8], r_local: &[u8]) -> anyhow::Result<[u8; 32]> {
    let (_, hk) = Hkdf::<Sha256>::extract(Some(r_local), data_key);
    let mut counter = 0u32;

    loop {
        let mut candidate = [0u8; 32];
        let info = format!("enclave-signing-key-v1-{}", counter);

        hk.expand(info.as_bytes(), &mut candidate)
            .map_err(|_| anyhow::anyhow!("KDF expansion failed"))?;

        // Rejection sampling: ensure the key is valid for secp256k1
        if SecretKey::from_slice(&candidate).is_ok() {
            return Ok(candidate);
        }

        counter += 1;
        if counter > 100 {
            return Err(anyhow::anyhow!("Failed to derive a valid key after 100 iterations"));
        }
    }
}

/// Handles initialization requests: either decrypts an existing key or generates a new one.
fn handle_key_management_request(
    req: EnclaveRequest,
) -> anyhow::Result<(Vec<u8>, Option<Vec<u8>>)> {
    use tracing::info;
    let kms = KmsClient::new(req.credentials);

    match req.encrypted_data_key {
        Some(encrypted_data_key) => {
            info!("Decrypting existing signing key from KMS");
            let signing_key = kms.decrypt(&encrypted_data_key)?;
            Ok((signing_key, None))
        }
        None => {
            info!("Generating new signing key and encrypting it via KMS");
            let (data_key, _) = kms.generate_data_key()?;
            let r_local = get_r_local()?;

            let signing_key = derive_valid_ecdsa_key(&data_key, &r_local)?;
            let encrypted_signing_key = kms.encrypt(&signing_key)?;

            Ok((signing_key.to_vec(), Some(encrypted_signing_key)))
        }
    }
}

/// Processes a single Ethereum block execution request.
/// Includes deserialization, execution, hashing of results, and signing.
fn process_block_request(listener: &VsockListener, signing_key: &SigningKey) -> anyhow::Result<()> {
    // Accept incoming connection for a new block request
    let mut stream = VsockChannel::accept(listener).context("Failed to accept vsock connection")?;

    // Receive and deserialize input data
    let raw_input = stream.receive().context("Failed to receive data")?;
    let input: EthClientExecutorInput = bincode::deserialize(&raw_input)
        .map_err(|e| anyhow::anyhow!("Input deserialization failed: {}", e))?;

    // Initialize the Ethereum executor
    let genesis = (&input.genesis)
        .try_into()
        .map_err(|_| anyhow::anyhow!("Invalid genesis configuration"))?;

    let executor = EthClientExecutor::eth(Arc::new(genesis), input.custom_beneficiary);

    // Execute the client logic
    let (header, events_hash) =
        executor.execute(input).map_err(|e| anyhow::anyhow!("Block execution failed: {:?}", e))?;

    let block_hash = header.hash_slow();
    let parent_hash = header.parent_hash;

    // Compute hashes for commitment and signing
    let mut common_hasher = Sha256::new();
    common_hasher.update(parent_hash.as_slice());
    common_hasher.update(block_hash.as_slice());
    common_hasher.update(events_hash.withdrawal_hash.as_slice());
    common_hasher.update(events_hash.deposit_hash.as_slice());

    let result_hash = common_hasher.clone().finalize();

    // The signing payload includes the execution result hash
    let mut signing_hasher = common_hasher;
    signing_hasher.update(result_hash.as_slice());
    let signing_payload = signing_hasher.finalize();

    // Sign the resulting payload
    let signature: Signature = signing_key.sign(signing_payload.as_slice());

    // Prepare response structure
    let output = EthExecutionResponse {
        parent_hash,
        block_hash,
        withdrawal_hash: events_hash.withdrawal_hash,
        deposit_hash: events_hash.deposit_hash,
        result_hash: result_hash.to_vec(),
        signature: signature.to_vec(),
    };

    // Send the serialized output back to the host
    stream.send_bincode(&output).context("Failed to send execution output")?;

    Ok(())
}

pub fn main() -> anyhow::Result<()> {
    println!("Nitro enclave started");

    let addr = SockAddr::new_vsock(VMADDR_CID_ANY, VSOCK_PORT);
    let listener = VsockListener::bind(&addr).context("Failed to bind vsock listener")?;
    println!("Listener bound to port {}", VSOCK_PORT);

    // Step 1: Initial Handshake (Key Management)
    // This part runs once to set up the signing identity of the enclave.
    let mut init_stream = VsockChannel::accept(&listener)?;

    let req: EnclaveRequest = bincode::deserialize(&init_stream.receive()?).map_err(|e| {
        let resp = EnclaveResponse::Error(format!("Handshake deserialize error: {}", e));
        let _ = init_stream.send_bincode(&resp);
        anyhow::anyhow!("Handshake failed: {}", e)
    })?;

    let (signing_key_bin, encrypted_signing_key) = handle_key_management_request(req)?;

    let secret_key = SecretKey::from_bytes(signing_key_bin.as_slice().into())
        .map_err(|e| anyhow::anyhow!("Failed to reconstruct secret key: {}", e))?;
    let signing_key = SigningKey::from(secret_key);

    // If a new key was generated, provide an attestation document to the host
    if let Some(encrypted_key) = encrypted_signing_key {
        let signing_pub_key_bytes =
            signing_key.verifying_key().to_encoded_point(false).as_bytes().to_vec();

        let nsm_fd = driver::nsm_init();
        let response = driver::nsm_process_request(
            nsm_fd,
            Request::Attestation {
                public_key: None,
                user_data: Some(ByteBuf::from(signing_pub_key_bytes.clone())),
                nonce: None,
            },
        );

        let attestation_doc = match response {
            Response::Attestation { document } => Ok(document),
            _ => Err(anyhow::anyhow!("Attestation failed")),
        }?;
        driver::nsm_exit(nsm_fd);

        let resp = EnclaveResponse::EncryptedDataKey {
            encrypted_signing_key: encrypted_key,
            attestation: attestation_doc,
            public_key: signing_pub_key_bytes,
        };

        init_stream.send_bincode(&resp)?;
    }

    // Explicitly drop the initialization stream to free resources
    drop(init_stream);

    // Step 2: Main Execution Loop
    // Continues running and processing block requests until the enclave is terminated.
    println!("Enclave ready to process block requests");
    loop {
        if let Err(e) = process_block_request(&listener, &signing_key) {
            // Log error but keep the loop running for the next connection
            eprintln!("Error processing session: {:?}", e);
        }
    }
}
