//! Compute per-block bridge roots from `eth_getLogs` output.
//!
//! Pure port of the in-zkVM logic from
//! `crates/executor/client/src/events_hash.rs`, adapted to operate on
//! `&[alloy_rpc_types::Log]` (what `eth_getLogs` returns) instead of
//! `ExecutionOutcome<Receipt>`. Same offsets, same Merkle scheme with
//! last-leaf duplication, same `ZERO_BYTES_HASH` sentinel for empty deposit
//! lists (which is `keccak256("")`).
//!
//! No success-status filter: reverted txs cannot emit logs (LOG* opcodes
//! revert with the tx), so the executor's `TxReceipt::status` filter is
//! byte-equivalent to no filter for any on-chain log set.

use alloy_primitives::{b256, Keccak256, B256};
use alloy_rpc_types::Log;
use fluent_stf_primitives::{BRIDGE_DEPOSIT_TOPIC, BRIDGE_ROLLBACK_TOPIC, BRIDGE_WITHDRAWAL_TOPIC};

const ZERO_BYTES_HASH: B256 =
    b256!("c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470");

// Mirrors offsets in `events_hash.rs`:
// SentMessage data layout: value(0) | chainId(32) | blockNumber(64) |
//                          nonce(96) | messageHash(128)
const SEND_OFFSET: usize = 128;
// ReceivedMessage data: messageHash(0) | ...
const RECEIVE_OFFSET: usize = 0;
// RollbackMessage data: messageHash(0) | blockNumber(32)
const ROLLBACK_OFFSET: usize = 0;

pub(crate) struct BridgeRoots {
    pub withdrawal_root: B256,
    pub deposit_root: B256,
    pub deposit_count: u16,
}

/// Compute the three header fields from one block's bridge logs.
///
/// `logs` MUST be already filtered by bridge address and by block, in the
/// canonical order returned by `eth_getLogs` (execution order).
pub(crate) fn compute_block_roots(logs: &[&Log]) -> BridgeRoots {
    let mut withdrawal_leaves: Vec<B256> = Vec::new();
    let mut deposit_hashes: Vec<B256> = Vec::new();

    for log in logs {
        let Some(topic0) = log.topic0() else { continue };
        let data = log.data().data.as_ref();

        if *topic0 == BRIDGE_WITHDRAWAL_TOPIC && data.len() >= SEND_OFFSET + 32 {
            withdrawal_leaves.push(B256::from_slice(&data[SEND_OFFSET..SEND_OFFSET + 32]));
        } else if *topic0 == BRIDGE_ROLLBACK_TOPIC && data.len() >= ROLLBACK_OFFSET + 32 {
            withdrawal_leaves.push(B256::from_slice(&data[ROLLBACK_OFFSET..ROLLBACK_OFFSET + 32]));
        } else if *topic0 == BRIDGE_DEPOSIT_TOPIC && data.len() >= RECEIVE_OFFSET + 32 {
            deposit_hashes.push(B256::from_slice(&data[RECEIVE_OFFSET..RECEIVE_OFFSET + 32]));
        }
    }

    let deposit_count = deposit_hashes.len() as u16;
    let deposit_root = if deposit_hashes.is_empty() {
        ZERO_BYTES_HASH
    } else {
        let mut h = Keccak256::new();
        for hash in &deposit_hashes {
            h.update(hash);
        }
        h.finalize()
    };
    let withdrawal_root = merkle_root(withdrawal_leaves);

    BridgeRoots { withdrawal_root, deposit_root, deposit_count }
}

fn merkle_root(mut leaves: Vec<B256>) -> B256 {
    if leaves.is_empty() {
        return ZERO_BYTES_HASH;
    }
    while leaves.len() > 1 {
        if !leaves.len().is_multiple_of(2) {
            leaves.push(*leaves.last().unwrap());
        }
        for i in 0..leaves.len() / 2 {
            let mut h = Keccak256::new();
            h.update(leaves[i * 2]);
            h.update(leaves[i * 2 + 1]);
            leaves[i] = h.finalize();
        }
        leaves.truncate(leaves.len() / 2);
    }
    leaves[0]
}
