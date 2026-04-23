#!/usr/bin/env python3
"""Rewrite the per-network vkey cells and the global `commit` cell in
the identity table of a README, from the SP1-verifier keys emitted by
`cargo prove vkey` during `build-client-docker` /
`build-nitro-validator-docker`.

Usage:
    update_readme_vkeys.py <rsp-client.vkey> <nitro-validator.vkey> <README.md> <network>

Patches three sentinel blocks:
    <!-- rsp-vkey:<network>:begin -->`0x…`<!-- rsp-vkey:<network>:end -->
    <!-- nv-vkey:<network>:begin -->`0x…`<!-- nv-vkey:<network>:end -->
    <!-- commit:begin -->`<short-sha>[-dirty]`<!-- commit:end -->

Commit SHA is `git rev-parse --short HEAD`. Dirty marker is appended
if `git status --porcelain` reports any change inside the flake source
allowlist (bin/client, crates/, Cargo.toml, Cargo.lock) — the README
itself and auto-patched lib.rs are intentionally excluded so that a
previous run's rewrite does not make the next invocation look dirty.
"""
import pathlib
import re
import subprocess
import sys

NETWORKS = ("mainnet", "testnet", "devnet")
FLAKE_SOURCE_PATHS = ("bin/client", "crates", "Cargo.toml", "Cargo.lock")


def read_vkey(path: pathlib.Path) -> str:
    line = path.read_text().strip()
    if not re.fullmatch(r"0x[0-9a-fA-F]{64}", line):
        sys.exit(f"{path}: not a 0x-prefixed 32-byte hex string (got {line!r})")
    return line.lower()


def git_commit() -> str:
    sha = subprocess.check_output(
        ["git", "rev-parse", "--short", "HEAD"]
    ).decode().strip()
    dirty_output = subprocess.check_output(
        ["git", "status", "--porcelain", "--"] + list(FLAKE_SOURCE_PATHS)
    ).decode().strip()
    return sha + ("-dirty" if dirty_output else "")


def patch_sentinel(src: str, tag: str, value: str) -> str:
    pattern = re.compile(
        r"<!-- " + re.escape(tag) + r":begin -->"
        r".*?"
        r"<!-- " + re.escape(tag) + r":end -->",
        re.DOTALL,
    )
    replacement = f"<!-- {tag}:begin -->`{value}`<!-- {tag}:end -->"
    new_src, n = pattern.subn(replacement, src)
    if n != 1:
        sys.exit(f"expected exactly 1 `{tag}` sentinel block, found {n}")
    return new_src


def main() -> None:
    if len(sys.argv) != 5:
        sys.exit(
            "usage: update_readme_vkeys.py <rsp.vkey> <nv.vkey> <README.md> <network>"
        )
    rsp_vkey_path = pathlib.Path(sys.argv[1])
    nv_vkey_path = pathlib.Path(sys.argv[2])
    readme = pathlib.Path(sys.argv[3])
    network = sys.argv[4]

    if network not in NETWORKS:
        sys.exit(f"network must be one of {NETWORKS}, got {network!r}")

    rsp_vkey = read_vkey(rsp_vkey_path)
    nv_vkey = read_vkey(nv_vkey_path)
    commit = git_commit()

    src = readme.read_text()
    src = patch_sentinel(src, f"rsp-vkey:{network}", rsp_vkey)
    src = patch_sentinel(src, f"nv-vkey:{network}", nv_vkey)
    src = patch_sentinel(src, "commit", commit)
    readme.write_text(src)
    print(f"Updated vkeys[{network}] + commit in {readme}")


if __name__ == "__main__":
    main()