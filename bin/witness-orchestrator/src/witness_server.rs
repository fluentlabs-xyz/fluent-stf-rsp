//! Minimal HTTP server exposing witness bytes to external consumers (e.g. the
//! `proxy` building client input for challenge/mock SP1 endpoints).
//!
//! Serves cold-store hits verbatim; on a cold miss the request falls through
//! to an MDBX-backed rebuild via [`Driver::get_or_build_witness`], keeping the
//! proxy off the host-execute path whenever MDBX has the block.
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
use tracing::{error, info, warn};

use crate::driver::Driver;

/// Run the witness HTTP server until `shutdown` is cancelled.
///
/// Endpoints:
/// - `GET /witness/{block_number}` → 200 with raw bincode-serialized `EthClientExecutorInput` bytes
///   (served from cold storage or rebuilt from MDBX on cold miss), 404 if the block is beyond the
///   MDBX tip, or 500 on a rebuild failure.
pub(crate) async fn run(
    listen_addr: String,
    driver: Arc<Driver>,
    shutdown: CancellationToken,
) -> eyre::Result<()> {
    let app = Router::new().route("/witness/{block_number}", get(get_witness)).with_state(driver);

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
    State(driver): State<Arc<Driver>>,
) -> impl IntoResponse {
    match driver.get_or_build_witness(block_number).await {
        Ok(Some(payload)) => (StatusCode::OK, Bytes::from(payload)).into_response(),
        Ok(None) => {
            warn!(block_number, "Witness lookup: block not in MDBX and not cached");
            StatusCode::NOT_FOUND.into_response()
        }
        Err(e) => {
            error!(block_number, err = %e, "Witness rebuild failed");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}
