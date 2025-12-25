#[cfg(feature = "nitro")]
use std::{
    fs,
    io::{Read, Write},
    path::Path,
};

#[cfg(feature = "nitro")]
use anyhow::Result;
#[cfg(feature = "nitro")]
use aws_nitro_enclaves_nsm_api::{
    api::{Request, Response},
    driver,
};
#[cfg(feature = "nitro")]
use nix::libc;
#[cfg(feature = "nitro")]
use p256::{
    ecdsa::{signature::Signer, Signature, SigningKey},
    EncodedPoint,
};
#[cfg(feature = "nitro")]
use rand_core::OsRng;
use rsp_client_executor::{executor::EthClientExecutor, io::EthClientExecutorInput};
#[cfg(feature = "sp1")]
use rsp_client_executor::{executor::DESERIALZE_INPUTS, utils::profile_report};
use serde::{Deserialize, Serialize};
#[cfg(feature = "nitro")]
use serde_bytes::ByteBuf;
#[cfg(feature = "nitro")]
use sha2::{Digest, Sha256};
#[cfg(feature = "nitro")]
use vsock::{SockAddr, VsockListener};

use std::sync::Arc;

#[cfg(feature = "sp1")]
pub fn main() {
    // Read the input.
    let input = profile_report!(DESERIALZE_INPUTS, {
        let input = sp1_zkvm::io::read_vec();
        bincode::deserialize::<EthClientExecutorInput>(&input).unwrap()
    });

    // Execute the block.
    let executor = EthClientExecutor::eth(
        Arc::new((&input.genesis).try_into().unwrap()),
        input.custom_beneficiary,
    );
    let (header, events_hash) = executor.execute(input).expect("failed to execute client");
    let block_hash = header.hash_slow();
    let parent_hash = header.parent_hash;

    // Commit the block hash.
    sp1_zkvm::io::commit(&parent_hash);
    sp1_zkvm::io::commit(&block_hash);
    sp1_zkvm::io::commit(&events_hash.withdrawal_hash);
    sp1_zkvm::io::commit(&events_hash.deposit_hash);
}

const VSOCK_PORT: u32 = 5005;
const MAX_FRAME_SIZE: usize = 64 * 1024 * 1024;
const KEY_PATH: &str = "./p256_signing.key";

#[derive(Serialize, Deserialize)]
struct AttestationUserData {
    pubkey: Vec<u8>,
    signature: Vec<u8>,
    result_hash: Vec<u8>,
}

#[cfg(feature = "nitro")]
fn load_or_generate_key() -> Result<SigningKey> {
    if Path::new(KEY_PATH).exists() {
        println!("Read existed key: path={}", KEY_PATH);
        let key_bytes = fs::read(KEY_PATH)?;
        Ok(SigningKey::from_slice(&key_bytes)?)
    } else {
        println!("Generate new key: path={}", KEY_PATH);
        let key = SigningKey::random(&mut OsRng);
        fs::write(KEY_PATH, key.to_bytes())?;
        Ok(key)
    }
}

#[cfg(feature = "nitro")]
fn main() -> anyhow::Result<()> {
    println!("Nitro enclave started, listening on vsock {}", VSOCK_PORT);

    let addr = SockAddr::new_vsock(libc::VMADDR_CID_ANY, VSOCK_PORT);
    let listener = VsockListener::bind(&addr)?;

    let signing_key = load_or_generate_key()?;
    let verify_key = signing_key.verifying_key();
    let pubkey_bytes = EncodedPoint::from(verify_key).to_bytes().to_vec();

    println!("Loaded P-256 enclave key");

    loop {
        let (mut stream, _) = listener.accept()?;
        println!("Accepted connection");

        let mut len_buf = [0u8; 4];
        stream.read_exact(&mut len_buf)?;
        let len = u32::from_be_bytes(len_buf) as usize;
        if len > MAX_FRAME_SIZE {
            return Err(anyhow::anyhow!(
                "Request frame too large: {} bytes s (cap {})",
                len,
                MAX_FRAME_SIZE
            ));
        }
        let mut buf = vec![0u8; len];
        stream.read_exact(&mut buf)?;

        println!("Received input, size: {} bytes", buf.len());

        let input: EthClientExecutorInput = bincode::deserialize(&buf)
            .map_err(|e| anyhow::anyhow!("Failed to deserialize input: {}", e))?;

        let executor = EthClientExecutor::eth(
            Arc::new((&input.genesis).try_into().unwrap()),
            input.custom_beneficiary,
        );
        let (header, events_hash) = executor
            .execute(input)
            .map_err(|e| anyhow::anyhow!("Failed to execute client: {:?}", e))?;

        let block_hash = header.hash_slow();
        let parent_hash = header.parent_hash;

        let mut hasher = Sha256::new();
        hasher.update(AsRef::<[u8]>::as_ref(&parent_hash));
        hasher.update(AsRef::<[u8]>::as_ref(&block_hash));
        hasher.update(AsRef::<[u8]>::as_ref(&events_hash.withdrawal_hash));
        hasher.update(AsRef::<[u8]>::as_ref(&events_hash.deposit_hash));
        let result_hash = hasher.finalize();

        let signature: Signature = signing_key.sign(&result_hash);

        let user_data = AttestationUserData {
            pubkey: pubkey_bytes.clone(),
            signature: signature.to_bytes().to_vec(),
            result_hash: result_hash.to_vec(),
        };

        let user_data_cbor = serde_cbor::to_vec(&user_data)?;

        let nsm_fd = driver::nsm_init();
        let response = driver::nsm_process_request(
            nsm_fd,
            Request::Attestation {
                public_key: None,
                user_data: Some(ByteBuf::from(user_data_cbor)),
                nonce: None,
            },
        );

        let attestation_doc = match response {
            Response::Attestation { document } => document,
            _ => return Err(anyhow::anyhow!("Failed to get attestation document")),
        };
        driver::nsm_exit(nsm_fd);

        let output = serde_json::json!({
            "parent_hash": hex::encode(parent_hash),
            "block_hash": hex::encode(block_hash),
            "withdrawal_hash": hex::encode(events_hash.withdrawal_hash),
            "deposit_hash": hex::encode(events_hash.deposit_hash),
            "result_hash": hex::encode(result_hash),
            "attestation": attestation_doc,
        });

        let serialized = serde_json::to_vec(&output)?;
        let resp_len = serialized.len() as u32;
        stream.write_all(&resp_len.to_be_bytes())?;
        stream.write_all(&serialized)?;
        stream.flush()?;
        println!("Sent response, size: {} bytes", serialized.len());
    }
}
