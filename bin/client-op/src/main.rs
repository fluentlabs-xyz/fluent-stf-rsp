#![no_main]
sp1_zkvm::entrypoint!(main);

use rsp_client_executor::{executor::OpClientExecutor, io::OpClientExecutorInput};
use std::sync::Arc;

pub fn main() {
    // Read the input.
    let input = sp1_zkvm::io::read_vec();
    let input = bincode::deserialize::<OpClientExecutorInput>(&input).unwrap();

    // Execute the block.
    let executor = OpClientExecutor::optimism(Arc::new((&input.genesis).try_into().unwrap()));
    let (header, events_hash) = executor.execute(input).expect("failed to execute client");
    let block_hash = header.hash_slow();
    let block_number = header.number;

    // Commit the block hash.
    sp1_zkvm::io::commit(&block_number);
    sp1_zkvm::io::commit(&block_hash);
    sp1_zkvm::io::commit(&events_hash.withdrawal_hash);
    sp1_zkvm::io::commit(&events_hash.deposit_hash);
}
