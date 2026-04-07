use std::sync::Arc;

use alloy_eips::eip2718::Encodable2718;
use alloy_network::Ethereum;
use alloy_primitives::B256;
use alloy_provider::RootProvider;
use kzg_rs::{Blob, Bytes48, KzgProof, KzgSettings};
use reth_chainspec::ChainSpec;
use rsp_blob_builder::build_blobs_from_blocks;
use rsp_client_executor::executor::EthClientExecutor;
use rsp_host_executor::EthHostExecutor;
use rsp_primitives::genesis::Genesis;
use sha2::{Digest, Sha256};

use crate::blob;
use crate::sp1::BlobVerificationInput;

const START_BLOCK: u64 = 22610746;
const RPC_URL: &str = "http://207.154.218.23:8545";

#[tokio::test(flavor = "multi_thread")]
async fn test_sp1_full_flow() {
    let chain_spec: Arc<ChainSpec> = Arc::new((&Genesis::Fluent).try_into().unwrap());
    let host_executor = EthHostExecutor::eth(chain_spec.clone(), None);
    let client_executor = EthClientExecutor::eth(chain_spec, None);

    let rpc_url = url::Url::parse(RPC_URL).expect("invalid RPC URL");
    let provider = RootProvider::<Ethereum>::new_http(rpc_url);

    let executor_input = host_executor
        .execute(START_BLOCK, &provider, Genesis::Fluent, None, false)
        .await
        .expect("host_executor failed");

    let block_number = executor_input.current_block.header.number;

    let tx_data: Vec<u8> = executor_input
        .current_block
        .body
        .transactions
        .iter()
        .flat_map(|tx| tx.encoded_2718())
        .collect();

    let built_blobs = build_blobs_from_blocks(START_BLOCK, &[tx_data.clone()])
        .expect("build_blobs_from_blocks failed");

    let blob_input = BlobVerificationInput {
        blobs: built_blobs.iter().map(|b| b.blob.clone()).collect(),
        commitments: built_blobs.iter().map(|b| b.commitment.clone()).collect(),
        proofs: built_blobs.iter().map(|b| b.proof.clone()).collect(),
    };

    let (header, decompressed) = blob::decode_blob_payload(&blob_input.blobs).unwrap();
    let blob_tx_data =
        blob::extract_block_tx_data(&header, &decompressed, block_number).unwrap();

    let tx_data_hash_exec = B256::from_slice(&Sha256::digest(&tx_data));

    let (_header, _events_hash) =
        client_executor.execute(executor_input).expect("client_executor failed");

    let kzg_settings =
        KzgSettings::load_trusted_setup_file().expect("failed to load KZG trusted setup");

    let mut versioned_hashes: Vec<B256> = Vec::new();
    for i in 0..blob_input.blobs.len() {
        let blob = Blob::from_slice(&blob_input.blobs[i]).expect("invalid blob slice");
        let commitment =
            Bytes48::from_slice(&blob_input.commitments[i]).expect("invalid commitment");
        let proof = Bytes48::from_slice(&blob_input.proofs[i]).expect("invalid proof");

        assert!(
            KzgProof::verify_blob_kzg_proof(blob, &commitment, &proof, &kzg_settings)
                .expect("KZG internal error"),
            "KZG verification failed at blob index {i}"
        );

        let hash = Sha256::digest(commitment.as_slice());
        let mut vh = B256::default();
        vh[0] = 0x01;
        vh[1..].copy_from_slice(&hash[1..]);
        versioned_hashes.push(vh);
    }

    let blob_tx_data_hash = B256::from_slice(&Sha256::digest(blob_tx_data));

    assert_eq!(tx_data_hash_exec, blob_tx_data_hash, "EXEC vs DA tx_data mismatch");
    assert_eq!(versioned_hashes.len(), built_blobs.len());
    assert!(versioned_hashes.iter().all(|vh| vh[0] == 0x01));
}
