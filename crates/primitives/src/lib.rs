#![cfg_attr(not(test), warn(unused_crate_dependencies))]

// Mutually-exclusive feature guard.
#[cfg(any(
    all(feature = "mainnet", feature = "testnet"),
    all(feature = "mainnet", feature = "devnet"),
    all(feature = "testnet", feature = "devnet"),
))]
compile_error!(
    "features `mainnet`, `testnet`, and `devnet` are mutually exclusive — enable exactly one"
);

#[cfg(not(any(feature = "mainnet", feature = "testnet", feature = "devnet")))]
compile_error!("exactly one of features `mainnet`, `testnet`, `devnet` must be enabled");

// ─── Per-network constants ──────────────────────────────────────────────────
// All network-specific constants live in a single private `network` module,
// gated by exactly one feature. The contents are re-exported below so callers
// see a flat surface (`fluent_stf_primitives::BRIDGE_ADDRESS`, etc.).
//
// `NITRO_VERIFIER_ADDRESS` — domain separator used when signing batches
// inside the Nitro enclave so signatures cannot be replayed across chains
// or across different verifier deployments.
//
// `BRIDGE_*` — single source of truth for the bridge contract address +
// event topics. Consumed by both the in-zkVM executor
// (`crates/executor/client/src/executor.rs`) and the host-side blob builder
// (`crates/blob-builder`) so the two cannot drift.
//
// testnet/devnet currently mirror mainnet as a placeholder; update when the
// real deployments exist.

#[cfg(feature = "mainnet")]
mod network {
    use alloy_primitives::{address, b256, Address, B256};

    pub const FLUENT_CHAIN_ID: u64 = 25363;

    pub const NITRO_VERIFIER_ADDRESS: [u8; 20] = [
        0x26, 0x3B, 0xC4, 0xab, 0xD8, 0xD5, 0x3b, 0x6e, 0x05, 0x41, 0xba, 0xc1, 0x5E, 0x47, 0x37,
        0x03, 0x57, 0x0b, 0x41, 0x1A,
    ];

    pub const BRIDGE_ADDRESS: Address = address!("0x9CAcf613fC29015893728563f423fD26dCdB8Ddc");
    pub const BRIDGE_WITHDRAWAL_TOPIC: B256 =
        b256!("0x7b397c6ce16a73396390bf270a2021417ca4d97f44e82cdce3f5eb750fd34134");
    pub const BRIDGE_ROLLBACK_TOPIC: B256 =
        b256!("0xdf7aa00ff05158efbc91b05d801c14d80f3d08daf5b13c7f066030c864be3d65");
    pub const BRIDGE_DEPOSIT_TOPIC: B256 =
        b256!("0xc5797c3a3c0e6c245576d05b8c3929881b44e1a21fdb4f1b118ede3c009683c5");
}

#[cfg(feature = "testnet")]
mod network {
    use alloy_primitives::{address, b256, Address, B256};

    pub const FLUENT_CHAIN_ID: u64 = 0x5202;

    pub const NITRO_VERIFIER_ADDRESS: [u8; 20] = [
        0x26, 0x3B, 0xC4, 0xab, 0xD8, 0xD5, 0x3b, 0x6e, 0x05, 0x41, 0xba, 0xc1, 0x5E, 0x47, 0x37,
        0x03, 0x57, 0x0b, 0x41, 0x1A,
    ];
    pub const BRIDGE_ADDRESS: Address = address!("0x9CAcf613fC29015893728563f423fD26dCdB8Ddc");
    pub const BRIDGE_WITHDRAWAL_TOPIC: B256 =
        b256!("0x7b397c6ce16a73396390bf270a2021417ca4d97f44e82cdce3f5eb750fd34134");
    pub const BRIDGE_ROLLBACK_TOPIC: B256 =
        b256!("0xdf7aa00ff05158efbc91b05d801c14d80f3d08daf5b13c7f066030c864be3d65");
    pub const BRIDGE_DEPOSIT_TOPIC: B256 =
        b256!("0xc5797c3a3c0e6c245576d05b8c3929881b44e1a21fdb4f1b118ede3c009683c5");
}

#[cfg(feature = "devnet")]
mod network {
    use alloy_primitives::{address, b256, Address, B256};

    pub const FLUENT_CHAIN_ID: u64 = 0x5201;

    pub const NITRO_VERIFIER_ADDRESS: [u8; 20] = [
        0x26, 0x3B, 0xC4, 0xab, 0xD8, 0xD5, 0x3b, 0x6e, 0x05, 0x41, 0xba, 0xc1, 0x5E, 0x47, 0x37,
        0x03, 0x57, 0x0b, 0x41, 0x1A,
    ];

    pub const BRIDGE_ADDRESS: Address = address!("0x9CAcf613fC29015893728563f423fD26dCdB8Ddc");
    pub const BRIDGE_WITHDRAWAL_TOPIC: B256 =
        b256!("0x7b397c6ce16a73396390bf270a2021417ca4d97f44e82cdce3f5eb750fd34134");
    pub const BRIDGE_ROLLBACK_TOPIC: B256 =
        b256!("0xdf7aa00ff05158efbc91b05d801c14d80f3d08daf5b13c7f066030c864be3d65");
    pub const BRIDGE_DEPOSIT_TOPIC: B256 =
        b256!("0xc5797c3a3c0e6c245576d05b8c3929881b44e1a21fdb4f1b118ede3c009683c5");
}

pub use network::*;

/// `NITRO_VERIFIER_ADDRESS` as an `Address` for host-side code.
pub const NITRO_VERIFIER_ADDR: alloy_primitives::Address =
    alloy_primitives::Address::new(NITRO_VERIFIER_ADDRESS);

pub mod account_proof;
pub(crate) mod fluent_genesis;

pub use fluent_genesis::chainspec as fluent_chainspec;
