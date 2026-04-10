use std::{future::Future, time::Duration};

use alloy_consensus::Block;
use reth_primitives_traits::NodePrimitives;

pub trait ExecutionHooks: Send {
    fn on_execution_start(
        &self,
        _block_number: u64,
    ) -> impl Future<Output = eyre::Result<()>> + Send {
        async { Ok(()) }
    }

    #[cfg(feature = "sp1")]
    fn on_execution_end<P: NodePrimitives>(
        &self,
        _executed_block: &Block<P::SignedTx>,
        _execution_report: &sp1_sdk::ExecutionReport,
    ) -> impl Future<Output = eyre::Result<()>> {
        async { Ok(()) }
    }

    fn on_proving_start(&self, _block_number: u64) -> impl Future<Output = eyre::Result<()>> {
        async { Ok(()) }
    }

    #[cfg(feature = "sp1")]
    fn on_proving_end(
        &self,
        _block_number: u64,
        _proof_bytes: &[u8],
        _vk: &sp1_sdk::SP1VerifyingKey,
        _cycle_count: Option<u64>,
        _proving_duration: Duration,
    ) -> impl Future<Output = eyre::Result<()>> {
        async { Ok(()) }
    }

    #[cfg(feature = "nitro")]
    fn on_nitro_attestation_end(
        &self,
        _block_number: u64,
        _attestation: &[u8],
        _proving_duration: Duration,
    ) -> impl Future<Output = eyre::Result<()>> {
        async { Ok(()) }
    }
}

impl ExecutionHooks for () {}
