use hex_literal::hex;
use serde::{Deserialize, Serialize};
use sp1_sdk::{include_elf, HashableKey, ProverClient, SP1Stdin};

const ELF: &[u8] = include_elf!("nitro-validator");

const EXPECTED_PUBKEY: [u8; 65] = hex!(
    "0431f26074907216725a3a7630488ba898bb32a29fee2b04f144878b162dea172262b1bcd836f08f2d3c766ecb01fd6fa2ce2c4b5dcc636eb2f7c6321cee18496b"
);

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SP1EnclaveProofFixture {
    vkey: String,
    public_values: String,
    proof: String,
}

fn main() {
    let client = ProverClient::from_env();

    let stdin = SP1Stdin::new();

    println!("Setting up proving keys...");
    let (pk, vk) = client.setup(ELF);

    // Generate Groth16 proof for on-chain verification
    println!("\n🔄 Generating Groth16 proof for Solidity...");
    let mut proof_groth16 =
        client.prove(&pk, &stdin).groth16().run().expect("Failed to generate Groth16 proof");

    println!("✅ Groth16 proof generated");

    let pubkey = proof_groth16.public_values.read::<Vec<u8>>();
    assert_eq!(
        pubkey.as_slice(),
        &EXPECTED_PUBKEY,
        "Pubkey mismatch! Expected specific enclave key"
    );

    // Save the proof
    proof_groth16.save("proof-with-pis.bin").expect("Failed to save proof");
    println!("✅ Proof saved to proof-with-pis.bin");

    // Verify Groth16 proof
    client.verify(&proof_groth16, &vk).expect("Groth16 verification failed");
    println!("✅ Groth16 proof verified");

    let fixture = SP1EnclaveProofFixture {
        vkey: vk.bytes32().to_string(),
        public_values: format!("0x{}", hex::encode(proof_groth16.public_values.to_vec())),
        proof: format!("0x{}", hex::encode(proof_groth16.bytes())),
    };

    // Сохрани fixture в JSON
    std::fs::write("proof-fixture.json", serde_json::to_string_pretty(&fixture).unwrap())
        .expect("Failed to write proof fixture");

    println!("✅ Proof fixture saved to proof-fixture.json");
}
