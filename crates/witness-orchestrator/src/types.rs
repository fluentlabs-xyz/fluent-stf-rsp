//! Shared domain types used by both the node (server) and the courier (client).

use std::sync::Arc;

/// A witness payload ready to be sent to the proving backend.
///
/// `payload` contains a bincode-serialized `ClientExecutorInput<FluentPrimitives>`.
/// The courier forwards it as-is — no deserialization needed on the transport layer.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ProveRequest {
    /// L2 block number this witness corresponds to.
    pub block_number: u64,
    /// Bincode-serialized witness data.
    pub payload: Vec<u8>,
}

/// Arc-wrapped prove request for cheap cloning across broadcast subscribers.
pub type SharedProveRequest = Arc<ProveRequest>;

// Shared enclave response types live in the `nitro-types` workspace crate
// so the orchestrator, proxy, and enclave cannot drift out of bincode sync.
pub use nitro_types::{EthExecutionResponse, SubmitBatchResponse};

use alloy_primitives::Address;

/// Response from proxy when batch signing fails due to enclave key rotation.
/// Proxy-owned type — kept local because it is not part of `nitro-types`.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct InvalidSignaturesResponse {
    pub invalid_blocks: Vec<u64>,
    pub enclave_address: Address,
}
