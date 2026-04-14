/// Generated protobuf and gRPC types.
pub mod proto {
    tonic::include_proto!("fluent.witness.v1");
}

pub mod hub;
pub mod server;
pub mod types;

/// Maximum gRPC message size (encoding + decoding) used by both the witness
/// server and orchestrator client. Large enough for full SP1 block witnesses.
pub const MAX_GRPC_MESSAGE_SIZE: usize = 512 * 1024 * 1024;
