//! Standalone fake beacon server binary for e2e tests.
//!
//! Serves `GET /eth/v1/beacon/blob_sidecars/:slot` with empty data.
//! The e2e test driver populates blobs via `POST /admin/insert_sidecars`.
//!
//! Usage: LISTEN_ADDR=0.0.0.0:5052 fake-beacon

use e2e_tests::{
    blob_builder::BuiltBlob,
    fake_beacon::{fake_beacon_router, FakeBeaconState},
};

use alloy_primitives::B256;
use axum::{extract::State, routing::post, Json, Router};
use serde::Deserialize;
use std::net::SocketAddr;

// ---------------------------------------------------------------------------
// Admin API types
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct InsertRequest {
    slot: u64,
    blobs: Vec<BlobData>,
}

#[derive(Deserialize)]
struct BlobData {
    blob: String,
    commitment: String,
    proof: String,
    versioned_hash: String,
}

// ---------------------------------------------------------------------------
// Admin handler
// ---------------------------------------------------------------------------

async fn insert_handler(
    State(state): State<FakeBeaconState>,
    Json(req): Json<InsertRequest>,
) -> &'static str {
    let blobs: Vec<BuiltBlob> = req
        .blobs
        .into_iter()
        .filter_map(|b| {
            Some(BuiltBlob {
                blob: hex::decode(&b.blob).ok()?,
                commitment: hex::decode(&b.commitment).ok()?,
                proof: hex::decode(&b.proof).ok()?,
                versioned_hash: B256::from_slice(&hex::decode(&b.versioned_hash).ok()?),
            })
        })
        .collect();

    state.insert_sidecars(req.slot, blobs);
    "ok"
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

#[tokio::main]
async fn main() -> eyre::Result<()> {
    tracing_subscriber::fmt::init();

    let addr: SocketAddr =
        std::env::var("LISTEN_ADDR").unwrap_or_else(|_| "0.0.0.0:5052".into()).parse()?;

    let state = FakeBeaconState::new();

    let app: Router = fake_beacon_router()
        .route("/admin/insert_sidecars", post(insert_handler))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(addr).await?;
    let bound = listener.local_addr()?;
    tracing::info!(%bound, "Fake beacon server listening");

    axum::serve(listener, app).await?;

    Ok(())
}
