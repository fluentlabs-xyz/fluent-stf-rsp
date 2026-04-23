#!/usr/bin/env python3
"""Enforce the identity-vs-major-version invariant.

Rule: if any PCR0 or vkey sentinel in README.md has changed relative to
git HEAD, the workspace release version (read from bin/client/Cargo.toml
and cross-checked against bin/aws-nitro-validator/Cargo.toml) MUST have
a strictly greater MAJOR component than the version at HEAD.

Rationale: PCR0 / vkey define the cryptographic root of trust. Any
change is a backwards-incompatible redeploy — the L1 NitroVerifier
whitelist, contracts, and operator configs all have to be re-pinned.
SemVer MAJOR is exactly the lever for that signalling.

Usage:
    check_version_bump.py

Intended to run as the last step of `make build-release`. Exits 0 if:
  * README.md does not exist at HEAD (initial commit — nothing to diff)
  * HEAD README has no identity sentinels yet (first release bootstrapping)
  * No sentinel values changed
  * Sentinel values changed AND current MAJOR > HEAD MAJOR

Exits non-zero (with a diff report) otherwise.

Bypass via env `SKIP_VERSION_CHECK=1`. Intended only for exceptional
cases (e.g. fixing a typo in a sentinel value without a real rebuild);
leave a note in the commit message explaining why.
"""
import os
import pathlib
import re
import subprocess
import sys

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
README = REPO_ROOT / "README.md"
CLIENT_CARGO = REPO_ROOT / "bin" / "client" / "Cargo.toml"
NV_CARGO = REPO_ROOT / "bin" / "aws-nitro-validator" / "Cargo.toml"

SENTINEL_RE = re.compile(
    r"<!-- ((?:pcr0|rsp-vkey|nv-vkey):(?:mainnet|testnet|devnet)):begin -->"
    r"`([^`]*)`"
    r"<!-- \1:end -->"
)

VERSION_RE = re.compile(
    r"^\[package\][^\[]*?^\s*version\s*=\s*\"(\d+)\.(\d+)\.(\d+)\"",
    re.MULTILINE | re.DOTALL,
)


def extract_values(readme_src: str) -> dict:
    return {m.group(1): m.group(2) for m in SENTINEL_RE.finditer(readme_src)}


def git_show(path: str):
    try:
        return subprocess.check_output(
            ["git", "show", f"HEAD:{path}"],
            stderr=subprocess.DEVNULL,
            cwd=REPO_ROOT,
        ).decode()
    except subprocess.CalledProcessError:
        return None


def parse_version(cargo_toml_src: str, label: str):
    m = VERSION_RE.search(cargo_toml_src)
    if not m:
        sys.exit(f"could not parse [package].version from {label}")
    return tuple(int(x) for x in m.groups())


def version_str(v):
    return ".".join(str(x) for x in v)


def main() -> None:
    if os.environ.get("SKIP_VERSION_CHECK") == "1":
        print("SKIP_VERSION_CHECK=1 — version-bump check skipped")
        return

    cur_client_ver = parse_version(CLIENT_CARGO.read_text(), str(CLIENT_CARGO))
    cur_nv_ver = parse_version(NV_CARGO.read_text(), str(NV_CARGO))
    if cur_client_ver != cur_nv_ver:
        sys.exit(
            f"version mismatch in working tree: "
            f"{CLIENT_CARGO} = {version_str(cur_client_ver)}, "
            f"{NV_CARGO} = {version_str(cur_nv_ver)} — bump both together"
        )
    cur_ver = cur_client_ver

    head_readme = git_show("README.md")
    if head_readme is None:
        print("README.md not present at HEAD — skipping (initial commit)")
        return
    head_vals = extract_values(head_readme)
    if not head_vals:
        print("HEAD README has no identity sentinels — skipping (bootstrap release)")
        return

    cur_vals = extract_values(README.read_text())
    diff = {
        k: (head_vals.get(k), cur_vals.get(k))
        for k in set(head_vals) | set(cur_vals)
        if head_vals.get(k) != cur_vals.get(k)
    }
    if not diff:
        print(
            f"OK: no PCR0/vkey changes relative to HEAD — "
            f"version {version_str(cur_ver)} does not need a major bump"
        )
        return

    head_cargo = git_show("bin/client/Cargo.toml")
    if head_cargo is None:
        sys.exit(
            "PCR0/vkey changed but bin/client/Cargo.toml is not tracked at HEAD — "
            "cannot enforce major bump"
        )
    head_ver = parse_version(head_cargo, "bin/client/Cargo.toml@HEAD")

    if cur_ver[0] > head_ver[0]:
        print(
            f"OK: major bumped ({version_str(head_ver)} → {version_str(cur_ver)}); "
            f"{len(diff)} identity anchor(s) changed"
        )
        return

    changed = "\n    ".join(
        f"{k}: {old!r} → {new!r}" for k, (old, new) in sorted(diff.items())
    )
    sys.exit(
        "error: PCR0/vkey changed but MAJOR version was not bumped.\n"
        f"  HEAD version:     {version_str(head_ver)}\n"
        f"  Current version:  {version_str(cur_ver)}\n"
        f"  Changed anchors:\n    {changed}\n"
        "\n"
        "  Identity anchors (PCR0 / vkey) are the cryptographic root of\n"
        "  trust — any change is a backwards-incompatible redeploy. Bump\n"
        "  the MAJOR in all three Cargo.toml files:\n"
        "    - Cargo.toml                         ([workspace.package].version)\n"
        "    - bin/client/Cargo.toml              ([package].version)\n"
        "    - bin/aws-nitro-validator/Cargo.toml ([package].version)\n"
        "  and rerun `make build-release`. Override with\n"
        "  SKIP_VERSION_CHECK=1 only for exceptional cases (and document\n"
        "  the reason in the commit message)."
    )


if __name__ == "__main__":
    main()
