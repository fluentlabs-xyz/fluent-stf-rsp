//! Minimal HTTP server exposing cold witness storage for external consumers
//! (e.g. `proxy` building client input for challenge/mock SP1 endpoints).
//!
//! Avoids cross-process `redb` file lock conflicts: the orchestrator owns the
//! cold store, and other processes read through this endpoint.

use std::sync::Arc;

use axum::{
    body::Bytes,
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
    routing::get,
    Router,
};
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};

use crate::hub::WitnessHub;

/// Run the witness HTTP server until `shutdown` is cancelled.
///
/// Endpoints:
/// - `GET /witness/{block_number}` → 200 with raw bincode-serialized
///   `EthClientExecutorInput` bytes, or 404 if missing from cold storage.
pub(crate) async fn run(
    listen_addr: String,
    hub: Arc<WitnessHub>,
    shutdown: CancellationToken,
) -> eyre::Result<()> {
    let app = Router::new().route("/witness/{block_number}", get(get_witness)).with_state(hub);

    let listener = tokio::net::TcpListener::bind(&listen_addr)
        .await
        .map_err(|e| eyre::eyre!("witness server bind {listen_addr}: {e}"))?;

    info!(listen_addr, "Witness HTTP server listening");

    axum::serve(listener, app)
        .with_graceful_shutdown(async move { shutdown.cancelled().await })
        .await
        .map_err(|e| eyre::eyre!("witness server error: {e}"))
}

async fn get_witness(
    Path(block_number): Path<u64>,
    State(hub): State<Arc<WitnessHub>>,
) -> impl IntoResponse {
    match hub.get_witness(block_number).await {
        Some(req) => (StatusCode::OK, Bytes::from(req.payload)).into_response(),
        None => {
            warn!(block_number, "Cold witness lookup miss");
            StatusCode::NOT_FOUND.into_response()
        }
    }
}
