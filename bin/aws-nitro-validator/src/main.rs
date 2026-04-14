#![no_main]
sp1_zkvm::entrypoint!(main);

pub fn main() {
    let input: nitro_validator::GuestInput = sp1_zkvm::io::read();
    let (addr_word, timestamp_sec) = nitro_validator::verify(&input);

    // ABI-encode `(address, uint64)` as 64 bytes: padded address || padded uint64.
    let mut out = [0u8; 64];
    out[..32].copy_from_slice(&addr_word);
    out[64 - 8..].copy_from_slice(&timestamp_sec.to_be_bytes());
    sp1_zkvm::io::commit_slice(&out);
}
