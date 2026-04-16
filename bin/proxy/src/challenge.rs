use std::collections::HashSet;
use std::sync::Arc;

use alloy_primitives::Address;
use revm_primitives::{hex, B256};
use sp1_sdk::{
    network::{prover::NetworkProver, Error as Sp1NetworkError},
    HashableKey, ProveRequest, Prover, ProvingKey, SP1ProvingKey, SP1Stdin,
};
use tracing::info;

use crate::attestation::{fetch_ha_prover_count, fetch_ha_whitelist, identify_fulfiller};

pub(crate) async fn run_challenge_proof(
    client: Arc<NetworkProver>,
    pk: Arc<SP1ProvingKey>,
    stdin: SP1Stdin,
    challenge_id: B256,
    block_number: u64,
) {
    let mut blacklist: HashSet<Address> = HashSet::new();

    loop {
        let whitelist = match fetch_ha_whitelist(&blacklist).await {
            Ok(w) => w,
            Err(e) => {
                tracing::error!(
                    challenge_id = %hex::encode(challenge_id),
                    "Failed to fetch HA whitelist: {e}"
                );
                if let Some(db) = crate::db::db() {
                    db.set_challenge_failed(challenge_id, &format!("{e}"));
                }
                return;
            }
        };

        info!(
            challenge_id = %hex::encode(challenge_id),
            block_number,
            whitelist_size = whitelist.len(),
            blacklist_size = blacklist.len(),
            "Submitting challenge proof to SP1 network"
        );

        let id = match client
            .prove(pk.as_ref(), stdin.clone())
            .groth16()
            .max_price_per_pgu(500_000_000u64)
            .whitelist(Some(whitelist))
            .request()
            .await
        {
            Ok(id) => id,
            Err(e) => {
                tracing::error!(
                    challenge_id = %hex::encode(challenge_id),
                    "Challenge proof request failed: {e}"
                );
                if let Some(db) = crate::db::db() {
                    db.set_challenge_failed(challenge_id, &format!("{e}"));
                }
                return;
            }
        };

        if let Some(db) = crate::db::db() {
            db.update_challenge_sp1_request_id(challenge_id, id);
        }

        info!(
            challenge_id = %hex::encode(challenge_id),
            sp1_request_id = %hex::encode(id),
            "Challenge proof submitted"
        );

        match client.wait_proof(id, None, None).await {
            Ok(proof) => {
                info!(
                    challenge_id = %hex::encode(challenge_id),
                    "Challenge proof ready"
                );

                let proof_bytes = match bincode::serialize(&proof.proof) {
                    Ok(b) => b,
                    Err(e) => {
                        if let Some(db) = crate::db::db() {
                            db.set_challenge_failed(
                                challenge_id,
                                &format!("Failed to serialize proof: {e}"),
                            );
                        }
                        return;
                    }
                };

                let public_values = proof.public_values.as_slice().to_vec();
                let vk_hash = pk.verifying_key().hash_bytes();

                if let Some(db) = crate::db::db() {
                    db.set_challenge_completed(
                        challenge_id,
                        &proof_bytes,
                        &public_values,
                        &vk_hash,
                    );
                }
                return;
            }
            Err(e) => {
                let is_retriable = e.downcast_ref::<Sp1NetworkError>().is_some_and(|ne| {
                    matches!(
                        ne,
                        Sp1NetworkError::RequestUnfulfillable { .. }
                            | Sp1NetworkError::RequestTimedOut { .. }
                            | Sp1NetworkError::RequestAuctionTimedOut { .. }
                    )
                });

                if !is_retriable {
                    tracing::error!(
                        challenge_id = %hex::encode(challenge_id),
                        "Challenge proof failed (non-retriable): {e}"
                    );
                    if let Some(db) = crate::db::db() {
                        db.set_challenge_failed(challenge_id, &format!("{e}"));
                    }
                    return;
                }

                if let Some(fulfiller) = identify_fulfiller(&client, id).await {
                    tracing::warn!(
                        challenge_id = %hex::encode(challenge_id),
                        fulfiller = %fulfiller,
                        "Challenge prover returned unfulfillable — blacklisting"
                    );
                    blacklist.insert(fulfiller);
                } else {
                    tracing::warn!(
                        challenge_id = %hex::encode(challenge_id),
                        "Challenge proof failed, could not identify fulfiller"
                    );
                }

                let ha_count = fetch_ha_prover_count().await.unwrap_or(0);
                if ha_count > 0 && blacklist.len() >= ha_count {
                    tracing::warn!(
                        "All HA provers blacklisted ({}) — resetting blacklist",
                        blacklist.len()
                    );
                    blacklist.clear();
                }
            }
        }
    }
}
