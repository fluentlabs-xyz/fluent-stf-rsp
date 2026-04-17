//! Shared domain types used by the embedded forward driver and the orchestrator.

// Shared enclave response types live in the `nitro-types` workspace crate
// so the orchestrator, proxy, and enclave cannot drift out of sync.
pub use nitro_types::{
    EthExecutionResponse, InvalidSignaturesResponse, SignBatchRootRequest, SubmitBatchResponse,
};

/// A witness payload ready to be sent to the proving backend.
///
/// `payload` contains a bincode-serialized `ClientExecutorInput<FluentPrimitives>`.
/// The orchestrator forwards it as-is — no deserialization needed on the transport layer.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ProveRequest {
    /// L2 block number this witness corresponds to.
    pub block_number: u64,
    /// Bincode-serialized witness data.
    pub payload: Vec<u8>,
}
