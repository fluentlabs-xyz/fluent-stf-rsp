//! Fake Beacon API server for e2e tests.
//!
//! Serves `GET /eth/v1/beacon/blob_sidecars/:slot` — the only endpoint
//! that `blob.rs` in the proxy calls.
//!
//! The test driver pre-populates blob sidecars via `insert_sidecars` before
//! the proxy fetches them.

use crate::blob_builder::BuiltBlob;

use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::{Arc, RwLock},
};

use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
    routing::get,
    Json, Router,
};
use serde::Serialize;
use tracing::info;

// ---------------------------------------------------------------------------
// Types matching what blob.rs expects to deserialize
// ---------------------------------------------------------------------------

/// Response format for `GET /eth/v1/beacon/blob_sidecars/:slot`.
///
/// blob.rs deserializes: `{ "data": [{ "blob": "0x…", "kzg_commitment": "0x…" }] }`
#[derive(Serialize)]
struct BlobSidecarsResponse {
    data: Vec<BlobSidecarJson>,
}

#[derive(Serialize)]
struct BlobSidecarJson {
    blob: String,
    kzg_commitment: String,
    kzg_proof: String,
}

// ---------------------------------------------------------------------------
// Shared state
// ---------------------------------------------------------------------------

/// Fake beacon state: slot → list of blob sidecars.
#[derive(Clone, Default, Debug)]
pub struct FakeBeaconState {
    inner: Arc<RwLock<HashMap<u64, Vec<BuiltBlob>>>>,
}

impl FakeBeaconState {
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert blobs for a given beacon slot.
    ///
    /// Called by the test driver after building blobs and determining the
    /// target slot (from the L1 block timestamp).
    pub fn insert_sidecars(&self, slot: u64, blobs: Vec<BuiltBlob>) {
        let mut map = self.inner.write().unwrap();
        map.entry(slot).or_default().extend(blobs);
        info!(slot, "Fake beacon: inserted blob sidecars");
    }

    /// Read blobs for a given slot. Used by the beacon handler and the
    /// standalone binary.
    pub fn get_sidecars(&self, slot: u64) -> Option<Vec<BuiltBlob>> {
        let map = self.inner.read().unwrap();
        map.get(&slot).cloned()
    }
}

// ---------------------------------------------------------------------------
// Axum handler
// ---------------------------------------------------------------------------

async fn blob_sidecars_handler(
    State(state): State<FakeBeaconState>,
    Path(slot): Path<u64>,
) -> impl IntoResponse {
    match state.get_sidecars(slot) {
        Some(blobs) => {
            let data: Vec<BlobSidecarJson> = blobs
                .iter()
                .map(|b| BlobSidecarJson {
                    blob: format!("0x{}", hex::encode(&b.blob)),
                    kzg_commitment: format!("0x{}", hex::encode(&b.commitment)),
                    kzg_proof: format!("0x{}", hex::encode(&b.proof)),
                })
                .collect();

            (StatusCode::OK, Json(BlobSidecarsResponse { data })).into_response()
        }
        None => {
            // Beacon API returns 200 with empty data when no blobs at that slot
            (StatusCode::OK, Json(BlobSidecarsResponse { data: vec![] })).into_response()
        }
    }
}

// ---------------------------------------------------------------------------
// Server
// ---------------------------------------------------------------------------

/// Build the fake beacon router (without state bound).
///
/// Call `.with_state(state)` after adding any extra routes (e.g. admin API in the binary).
pub fn fake_beacon_router() -> Router<FakeBeaconState> {
    Router::new().route("/eth/v1/beacon/blob_sidecars/{slot}", get(blob_sidecars_handler))
}

/// Start the fake beacon server. Returns the bound address.
///
/// The server runs in the background on a tokio task.
pub async fn start_fake_beacon(
    state: FakeBeaconState,
    addr: SocketAddr,
) -> eyre::Result<SocketAddr> {
    let app = fake_beacon_router().with_state(state);
    let listener = tokio::net::TcpListener::bind(addr).await?;
    let bound = listener.local_addr()?;
    info!(%bound, "Fake beacon server listening");

    tokio::spawn(async move {
        axum::serve(listener, app).await.ok();
    });

    Ok(bound)
}
