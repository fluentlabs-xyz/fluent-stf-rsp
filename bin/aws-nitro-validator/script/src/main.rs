use hex_literal::hex;
use sp1_sdk::{ProverClient, SP1Stdin, include_elf};

const ELF: &[u8] = include_elf!("nitro-validator");

const EXPECTED_PUBKEY: [u8; 65] = hex!(
    "0431f26074907216725a3a7630488ba898bb32a29fee2b04f144878b162dea172262b1bcd836f08f2d3c766ecb01fd6fa2ce2c4b5dcc636eb2f7c6321cee18496b"
);

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
}


// fn main() {
//     let client = ProverClient::from_env();
//     let stdin = SP1Stdin::new();
//     let (mut public_values, report) = client.execute(ELF, &stdin).run().expect("Execution failed");

//     // Печатаем статистику
//     println!("\n📊 Execution Report:");
//     println!("  Total cycles: {}", report.total_instruction_count());
//     println!("  Total syscalls: {}", report.total_syscall_count());
//     println!("  Cycle breakdown:");
// }
