use hex_literal::hex;
use serde::{Deserialize, Serialize};
use sp1_sdk::{include_elf, HashableKey, ProverClient, SP1Stdin};

mod prepare;
use prepare::{prepare_guest_input};

const ELF: &[u8] = include_elf!("nitro-validator");

const EXPECTED_PUBKEY: [u8; 65] = hex!(
    "045716cab03a4ffe03ec68236c716f62b84fd69a9d77f736bd8414755012ac78b14ac0bb5ec44962985ce96439f8ebbcf7e9e75fc05eef27d9a249672dcf2635b8"
);

const ROOT_CERT_DER: &[u8] = include_bytes!("../../root.der");
const ATTESTATION: &[u8] = include_bytes!("../../attestation.bin");

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SP1EnclaveProofFixture {
    vkey: String,
    public_values: String,
    proof: String,
}

fn main() {
    // Prepare guest input: parse CBOR/X.509, validate cert chain on host
    let guest_input = prepare_guest_input(ATTESTATION, ROOT_CERT_DER)
        .expect("Failed to prepare guest input");

    let client = ProverClient::from_env();

    let mut stdin = SP1Stdin::new();
    stdin.write(&guest_input);

    println!("Setting up proving keys...");
    let (pk, vk) = client.setup(ELF);

    // Generate Groth16 proof for on-chain verification
    println!("\n🔄 Generating Groth16 proof for Solidity...");
    let proof_groth16 = client
        .prove(&pk, &stdin)
        .groth16()
        .run()
        .expect("Failed to generate Groth16 proof");

    println!("✅ Groth16 proof generated");

    // Guest uses commit_slice(&user_data), so read raw bytes
    let pubkey_bytes = proof_groth16.public_values.as_slice();
    assert_eq!(
        pubkey_bytes,
        &EXPECTED_PUBKEY,
        "Pubkey mismatch! Expected specific enclave key"
    );

    // Verify Groth16 proof
    client
        .verify(&proof_groth16, &vk)
        .expect("Groth16 verification failed");
    println!("✅ Groth16 proof verified");

    let fixture = SP1EnclaveProofFixture {
        vkey: vk.bytes32().to_string(),
        public_values: format!("0x{}", hex::encode(proof_groth16.public_values.as_slice())),
        proof: format!("0x{}", hex::encode(proof_groth16.bytes())),
    };

    std::fs::write(
        "proof-fixture.json",
        serde_json::to_string_pretty(&fixture).unwrap(),
    )
    .expect("Failed to write proof fixture");

    println!("✅ Proof fixture saved to proof-fixture.json");
}