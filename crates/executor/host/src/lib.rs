#![cfg_attr(not(test), warn(unused_crate_dependencies))]

use rsp_client_executor::evm::FluentEvmConfig;

use alloy_chains::Chain;
pub use error::Error as HostError;
use fluent_stf_primitives::fluent_chainspec;
use revm_primitives::Address;
use std::{path::PathBuf, sync::Arc};
use url::Url;

#[cfg(feature = "alerting")]
pub mod alerting;

mod error;

mod executor_components;
#[cfg(feature = "sp1")]
pub use executor_components::MaybeProveWithCycles;
pub use executor_components::{EthExecutorComponents, ExecutorComponents};

mod full_executor;
#[cfg(feature = "sp1")]
pub use full_executor::build_executor;
#[cfg(feature = "nitro")]
pub use full_executor::build_executor_with_nitro;
pub use full_executor::{BlockExecutor, EitherExecutor, FullExecutor};

mod hooks;
pub use hooks::ExecutionHooks;

mod host_executor;
pub use host_executor::{EthHostExecutor, HostExecutor};

pub fn create_eth_block_execution_strategy_factory(
    _custom_beneficiary: Option<Address>,
) -> FluentEvmConfig {
    FluentEvmConfig::new_with_default_factory(Arc::new(fluent_chainspec()))
}

#[cfg(feature = "nitro")]
#[derive(Debug, Clone, Copy)]
pub struct NitroConfig {
    pub enclave_cid: u32,
    pub enclave_port: u32,
}

#[cfg(feature = "nitro")]
impl Default for NitroConfig {
    fn default() -> Self {
        Self { enclave_cid: 10, enclave_port: 5005 }
    }
}

#[derive(Debug)]
pub struct Config {
    pub chain: Chain,
    pub rpc_url: Option<Url>,
    pub cache_dir: Option<PathBuf>,
    pub custom_beneficiary: Option<Address>,
    #[cfg(feature = "sp1")]
    pub prove_mode: Option<sp1_sdk::SP1ProofMode>,
    pub skip_client_execution: bool,
    pub opcode_tracking: bool,
    #[cfg(feature = "nitro")]
    pub nitro_config: Option<NitroConfig>,
}

impl Config {
    pub fn fluent() -> Self {
        Self {
            chain: Chain::from_id(fluent_stf_primitives::FLUENT_CHAIN_ID),
            rpc_url: None,
            cache_dir: None,
            custom_beneficiary: None,
            #[cfg(feature = "sp1")]
            prove_mode: None,
            skip_client_execution: false,
            opcode_tracking: false,
            #[cfg(feature = "nitro")]
            nitro_config: None,
        }
    }
}
