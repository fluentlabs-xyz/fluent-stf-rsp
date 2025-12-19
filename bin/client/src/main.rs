#![cfg_attr(feature = "sp1", no_main)]

#[cfg(feature = "sp1")]
sp1_zkvm::entrypoint!(main);

use rsp_client_executor::{executor::EthClientExecutor, io::EthClientExecutorInput};
#[cfg(feature = "sp1")]
use rsp_client_executor::{executor::DESERIALZE_INPUTS, utils::profile_report};
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

#[cfg(feature = "nitro")]
fn main() -> anyhow::Result<()> {
    use aws_nitro_enclaves_nsm_api::{
        api::{Request, Response},
        driver,
    };
    use nix::libc;
    use serde_bytes::ByteBuf;
    use sha2::{Digest, Sha256};
    use std::io::{Read, Write};
    use vsock::{SockAddr, VsockListener};

    println!("Enclave started, listening on vsock port 5005");

    let addr = SockAddr::new_vsock(libc::VMADDR_CID_ANY, 5005);

    let listener = VsockListener::bind(&addr)?;

    loop {
        let (mut stream, _addr) = listener.accept()?;
        println!("Accepted connection");

        const MAX_FRAME_SIZE: usize = 64 * 1024 * 1024;

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

        let nsm_fd = driver::nsm_init();
        let request = Request::Attestation {
            public_key: None,
            user_data: Some(ByteBuf::from(result_hash.to_vec())),
            nonce: None,
        };
        let response = driver::nsm_process_request(nsm_fd, request);
        let attestation_doc = match response {
            Response::Attestation { document } => document,
            _ => return Err(anyhow::anyhow!("Failed to get attestation document")),
        };
        driver::nsm_exit(nsm_fd);

        let output = serde_json::json!({
            "parent_hash": hex::encode(AsRef::<[u8]>::as_ref(&parent_hash)),
            "block_hash": hex::encode(AsRef::<[u8]>::as_ref(&block_hash)),
            "withdrawal_hash": hex::encode(AsRef::<[u8]>::as_ref(&events_hash.withdrawal_hash)),
            "deposit_hash": hex::encode(AsRef::<[u8]>::as_ref(&events_hash.deposit_hash)),
            "result_hash": hex::encode(result_hash),
            "attestation": attestation_doc,
        });

        let serialized = serde_json::to_vec(&output)?;
        let resp_len: u32 = serialized
            .len()
            .try_into()
            .map_err(|_| anyhow::anyhow!("Response too large: {} bytes", serialized.len()))?;
        stream.write_all(&resp_len.to_be_bytes())?;
        stream.write_all(&serialized)?;
        stream.flush()?;
        println!("Sent response, size: {} bytes", serialized.len());
    }
}
