// TODO: Fix tests after enclave protocol refactor (fa1a0c7).
// - `execute_block_challenge` and `handle_submit_batch_from_responses` removed
// - `handle_submit_batch` signature changed (now takes 6 args)

// use std::sync::{Arc, Mutex};
//
// use alloy_eips::eip2718::Encodable2718;
// use alloy_network::Ethereum;
// use alloy_provider::RootProvider;
// use k256::ecdsa::SigningKey;
// use reth_chainspec::ChainSpec;
// use rsp_blob_builder::build_blobs_from_blocks;
// use rsp_host_executor::EthHostExecutor;
// use rsp_primitives::genesis::Genesis;
//
// use crate::nitro::{
//     execute_block, execute_block_challenge, handle_submit_batch,
//     handle_submit_batch_from_responses, BlockStore,
// };
//
// const N: u64 = 64;
// const START_BLOCK: u64 = 22610746;
// const RPC_URL: &str = "http://207.154.218.23:8545";
//
// #[tokio::test(flavor = "multi_thread")]
// async fn test_nitro_full_flow() {
//     let signing_key = SigningKey::random(&mut rand::thread_rng());
//     let block_store = Arc::new(Mutex::new(BlockStore::new()));
//
//     let chain_spec: Arc<ChainSpec> = Arc::new((&Genesis::Fluent).try_into().unwrap());
//     let host_executor = EthHostExecutor::eth(chain_spec, None);
//     let rpc_url = url::Url::parse(RPC_URL).expect("invalid RPC URL");
//     let provider = RootProvider::<Ethereum>::new_http(rpc_url);
//
//     let mut responses = Vec::new();
//     let mut tx_data_per_block: Vec<Vec<u8>> = Vec::new();
//
//     for block_num in START_BLOCK..START_BLOCK + N {
//         let input = host_executor
//             .execute(block_num, &provider, Genesis::Fluent, None, false)
//             .await
//             .unwrap_or_else(|e| panic!("host_executor failed for block {block_num}: {e}"));
//
//         let tx_data: Vec<u8> =
//             input.current_block.body.transactions.iter().flat_map(|tx| tx.encoded_2718()).collect();
//         tx_data_per_block.push(tx_data);
//
//         let resp = execute_block(input, &signing_key, &block_store)
//             .unwrap_or_else(|e| panic!("execute_block failed for block {block_num}: {e}"));
//         responses.push(resp);
//     }
//
//     let built_blobs = build_blobs_from_blocks(START_BLOCK, &tx_data_per_block)
//         .expect("build_blobs_from_blocks failed");
//     let raw_blobs: Vec<Vec<u8>> = built_blobs.iter().map(|b| b.blob.clone()).collect();
//
//     {
//         let store = block_store.lock().expect("block_store mutex poisoned");
//         let batch_resp =
//             handle_submit_batch(START_BLOCK, START_BLOCK + N - 1, &raw_blobs, &signing_key, &store)
//                 .expect("handle_submit_batch failed");
//         assert_eq!(batch_resp.versioned_hashes.len(), built_blobs.len());
//         assert_eq!(batch_resp.batch_root.len(), 32);
//     }
//
//     let batch_resp2 = handle_submit_batch_from_responses(&responses, &raw_blobs, &signing_key)
//         .expect("handle_submit_batch_from_responses failed");
//     assert_eq!(batch_resp2.versioned_hashes.len(), built_blobs.len());
//
//     let challenge_input = host_executor
//         .execute(START_BLOCK, &provider, Genesis::Fluent, None, false)
//         .await
//         .expect("host_executor failed for challenge block");
//
//     let challenge_resp =
//         execute_block_challenge(challenge_input, &raw_blobs, &signing_key, &block_store)
//             .expect("execute_block_challenge failed");
//
//     assert_eq!(challenge_resp.block_number, START_BLOCK);
// }
