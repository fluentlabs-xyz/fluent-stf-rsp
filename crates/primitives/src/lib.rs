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

#[cfg(feature = "mainnet")]
pub const FLUENT_CHAIN_ID: u64 = 25363;
#[cfg(feature = "testnet")]
pub const FLUENT_CHAIN_ID: u64 = 0x5202;
#[cfg(feature = "devnet")]
pub const FLUENT_CHAIN_ID: u64 = 0x5201;

pub mod account_proof;
pub(crate) mod fluent_genesis;

pub use fluent_genesis::chainspec as fluent_chainspec;
