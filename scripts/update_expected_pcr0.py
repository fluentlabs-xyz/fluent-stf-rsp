#!/usr/bin/env python3
"""Rewrite the `EXPECTED_PCR0` constant (for a given network) in
nitro-validator `lib.rs` from the JSON produced by `nitro-cli build-enclave`.

Usage:
    update_expected_pcr0.py <nitro-cli-output.json> <lib.rs> <network>

`network` must be one of: mainnet, testnet, devnet.
Only the `#[cfg(feature = "<network>")] pub const EXPECTED_PCR0 …` block is rewritten.
"""
import json
import pathlib
import re
import sys

NETWORKS = ("mainnet", "testnet", "devnet")


def main() -> None:
    if len(sys.argv) != 4:
        sys.exit(
            "usage: update_expected_pcr0.py <nitro-cli-output.json> <lib.rs> <network>"
        )

    pcr_json = pathlib.Path(sys.argv[1])
    lib_rs = pathlib.Path(sys.argv[2])
    network = sys.argv[3]

    if network not in NETWORKS:
        sys.exit(f"network must be one of {NETWORKS}, got {network!r}")

    data = json.loads(pcr_json.read_text())
    pcr0_hex = data["Measurements"]["PCR0"]
    if len(pcr0_hex) != 96:
        sys.exit(f"expected 96 hex chars (48 bytes), got {len(pcr0_hex)}: {pcr0_hex!r}")

    bytes_list = [f"0x{pcr0_hex[i : i + 2]}" for i in range(0, 96, 2)]
    rows = [
        "    " + ", ".join(bytes_list[row * 8 : (row + 1) * 8]) + ","
        for row in range(6)
    ]
    new_block = (
        f'#[cfg(feature = "{network}")]\n'
        "pub const EXPECTED_PCR0: [u8; 48] = [\n"
        + "\n".join(rows)
        + "\n];"
    )

    src = lib_rs.read_text()
    pattern = re.compile(
        r'#\[cfg\(feature = "' + re.escape(network) + r'"\)\]\s*\n'
        r"pub const EXPECTED_PCR0: \[u8; 48\] = \[[^\]]*\];",
        re.DOTALL,
    )
    new_src, n = pattern.subn(new_block, src)
    if n != 1:
        sys.exit(
            f"expected 1 EXPECTED_PCR0 block for feature `{network}` in {lib_rs}, "
            f"found {n}"
        )

    lib_rs.write_text(new_src)
    print(f"Updated EXPECTED_PCR0[{network}] in {lib_rs} → {pcr0_hex}")


if __name__ == "__main__":
    main()
