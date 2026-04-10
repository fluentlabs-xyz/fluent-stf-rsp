use std::marker::PhantomData;

use alloy_network::Ethereum;
use alloy_provider::Network;
use eyre::Ok;
use reth_chainspec::ChainSpec;
use reth_ethereum_primitives::EthPrimitives;
use reth_evm::ConfigureEvm;
use reth_primitives_traits::NodePrimitives;
use rsp_client_executor::{evm::FluentEvmConfig, BlockValidator, IntoInput, IntoPrimitives};
use rsp_primitives::genesis::Genesis;
use serde::de::DeserializeOwned;

use crate::ExecutionHooks;

pub trait ExecutorComponents {
    type Prover: Send + Sync + 'static;

    type Network: Network;

    type Primitives: NodePrimitives
        + DeserializeOwned
        + IntoPrimitives<Self::Network>
        + IntoInput
        + BlockValidator<Self::ChainSpec>;

    type EvmConfig: ConfigureEvm<Primitives = Self::Primitives>;

    type ChainSpec;

    type Hooks: ExecutionHooks;

    fn try_into_chain_spec(genesis: &Genesis) -> eyre::Result<Self::ChainSpec>;
}

#[cfg(feature = "sp1")]
pub trait MaybeProveWithCycles: sp1_sdk::Prover {
    fn prove_with_cycles(
        &self,
        pk: &Self::ProvingKey,
        stdin: sp1_sdk::SP1Stdin,
        mode: sp1_sdk::SP1ProofMode,
    ) -> impl std::future::Future<
        Output = Result<(sp1_sdk::SP1ProofWithPublicValues, Option<u64>), eyre::Error>,
    > + Send;
}

#[cfg(feature = "sp1")]
impl MaybeProveWithCycles for sp1_sdk::CpuProver {
    async fn prove_with_cycles(
        &self,
        pk: &Self::ProvingKey,
        stdin: sp1_sdk::SP1Stdin,
        mode: sp1_sdk::SP1ProofMode,
    ) -> Result<(sp1_sdk::SP1ProofWithPublicValues, Option<u64>), eyre::Error> {
        use sp1_sdk::{ProveRequest, Prover};
        let proof = self.prove(pk, stdin).mode(mode).await.map_err(|err| eyre::eyre!("{err}"))?;
        Ok((proof, None))
    }
}

#[cfg(feature = "sp1")]
impl MaybeProveWithCycles for sp1_sdk::CudaProver {
    async fn prove_with_cycles(
        &self,
        pk: &Self::ProvingKey,
        stdin: sp1_sdk::SP1Stdin,
        mode: sp1_sdk::SP1ProofMode,
    ) -> Result<(sp1_sdk::SP1ProofWithPublicValues, Option<u64>), eyre::Error> {
        use sp1_sdk::{ProveRequest, Prover};
        let proof = self.prove(pk, stdin).mode(mode).await.map_err(|err| eyre::eyre!("{err}"))?;
        // CudaProver in SP1 v6 no longer returns cycles directly
        Ok((proof, None))
    }
}

#[cfg(feature = "sp1")]
impl MaybeProveWithCycles for sp1_sdk::env::EnvProver {
    async fn prove_with_cycles(
        &self,
        pk: &Self::ProvingKey,
        stdin: sp1_sdk::SP1Stdin,
        mode: sp1_sdk::SP1ProofMode,
    ) -> Result<(sp1_sdk::SP1ProofWithPublicValues, Option<u64>), eyre::Error> {
        use sp1_sdk::{ProveRequest, Prover};
        let proof = self.prove(pk, stdin).mode(mode).await.map_err(|err| eyre::eyre!("{err}"))?;
        Ok((proof, None))
    }
}

#[derive(Debug, Default)]
pub struct EthExecutorComponents<H, P = ()> {
    phantom: PhantomData<(H, P)>,
}

impl<H, P> ExecutorComponents for EthExecutorComponents<H, P>
where
    H: ExecutionHooks,
    P: Send + Sync + 'static,
{
    type Prover = P;

    type Network = Ethereum;

    type Primitives = EthPrimitives;

    type EvmConfig = FluentEvmConfig;

    type ChainSpec = ChainSpec;

    type Hooks = H;

    fn try_into_chain_spec(genesis: &Genesis) -> eyre::Result<ChainSpec> {
        let spec = genesis.try_into()?;
        Ok(spec)
    }
}
