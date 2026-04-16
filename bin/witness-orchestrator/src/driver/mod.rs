//! Embedded forward-sync driver: re-executes L2 blocks against a writable
//! `ProviderFactory`, produces witnesses via `execute_exex_with_block`, and
//! emits `ProveRequest`s into the orchestrator channel.

mod forward;
mod node_types;

pub(crate) use forward::{open_writable_factory, run, DriverConfig};
pub(crate) use node_types::FluentMdbxNode;
