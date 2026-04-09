#!/usr/bin/env python3
"""
Continuous SP1 mock execution tester.

Finds the latest blob batch from L1, decodes the blob header to discover
the L2 block range, picks up to 10 random blocks, and sends each to
POST /mock/sp1/request. Repeats with the next-latest batch.

Usage:
    python3 scripts/test_mock_sp1.py [--proxy http://127.0.0.1:18080] [--api-key test123] [--blocks-per-batch 10]

Env vars (fallback):
    PROXY_URL, API_KEY, L1_RPC_URL, L1_CONTRACT_ADDR, L1_BEACON_URL,
    BEACON_GENESIS_TIMESTAMP, L1_CONTRACT_DEPLOY_BLOCK
"""

import argparse
import json
import os
import random
import struct
import sys
import time
import urllib.request

import brotli

# ── defaults ──────────────────────────────────────────────────────────────

BATCH_BLOBS_SUBMITTED_TOPIC = "0xf44cf3c80142f89d4e6fab4a80df6526af611649f05cae080bd0484d2b383bb1"
BYTES_PER_FIELD = 31
FIELD_SIZE = 32
FIELDS_PER_BLOB = 4096
FIXED_HEADER_SIZE = 8 + 8 + 4


# ── helpers ───────────────────────────────────────────────────────────────

def rpc_call(url: str, method: str, params: list):
    body = json.dumps({"jsonrpc": "2.0", "method": method, "params": params, "id": 1}).encode()
    req = urllib.request.Request(url, data=body, headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=30) as resp:
        data = json.loads(resp.read())
    if "error" in data:
        raise RuntimeError(f"RPC error: {data['error']}")
    return data["result"]


def beacon_get(url: str, path: str):
    full = f"{url.rstrip('/')}{path}"
    req = urllib.request.Request(full, headers={"User-Agent": "fluent-sp1-tester/1.0"})
    with urllib.request.urlopen(req, timeout=60) as resp:
        return json.loads(resp.read())


def hex_to_int(h: str) -> int:
    return int(h, 16)


def decanonicalize(blob_bytes: bytes) -> bytes:
    result = bytearray()
    offset = 0
    max_raw = FIELDS_PER_BLOB * BYTES_PER_FIELD
    while offset < len(blob_bytes) and len(result) < max_raw:
        offset += 1  # skip 0x00 padding
        remaining = max_raw - len(result)
        take = min(remaining, BYTES_PER_FIELD, len(blob_bytes) - offset)
        result.extend(blob_bytes[offset : offset + take])
        offset += BYTES_PER_FIELD
    return bytes(result)


def versioned_hash_from_commitment(commitment: bytes) -> bytes:
    """EIP-4844: 0x01 || SHA256(commitment)[1:]"""
    import hashlib
    h = hashlib.sha256(commitment).digest()
    return b"\x01" + h[1:]


def decode_blob_header(raw_blobs: list[bytes]) -> tuple[int, int]:
    """Decanonicalize + brotli decompress blobs, return (from_block, to_block)."""
    all_raw = bytearray()
    for blob in raw_blobs:
        all_raw.extend(decanonicalize(blob))

    decompressed = brotli.decompress(bytes(all_raw))

    if len(decompressed) < FIXED_HEADER_SIZE:
        raise RuntimeError(f"Blob payload too short: {len(decompressed)} bytes")

    from_block = struct.unpack(">Q", decompressed[0:8])[0]
    to_block = struct.unpack(">Q", decompressed[8:16])[0]
    return from_block, to_block


# ── main logic ────────────────────────────────────────────────────────────

def find_recent_batches(l1_rpc: str, contract: str, deploy_block: int, count: int = 20) -> list[dict]:
    """Return the last `count` BatchBlobsSubmitted events, newest first."""
    latest = hex_to_int(rpc_call(l1_rpc, "eth_blockNumber", []))

    # Search last 50k blocks (enough for recent batches)
    from_block = max(deploy_block, latest - 50_000)

    logs = rpc_call(l1_rpc, "eth_getLogs", [{
        "address": contract,
        "fromBlock": hex(from_block),
        "toBlock": "latest",
        "topics": [BATCH_BLOBS_SUBMITTED_TOPIC],
    }])

    batches = []
    for log in logs:
        batch_index = hex_to_int(log["topics"][1])
        l1_block = hex_to_int(log["blockNumber"])
        batches.append({"batch_index": batch_index, "l1_block": l1_block})

    # Dedupe by batch_index (keep last occurrence), newest first
    seen = {}
    for b in batches:
        seen[b["batch_index"]] = b
    result = sorted(seen.values(), key=lambda x: x["batch_index"], reverse=True)
    return result[:count]


def fetch_blob_for_batch(
    l1_rpc: str, contract: str, beacon_url: str, beacon_genesis: int,
    l1_block: int, batch_index: int,
) -> list[bytes]:
    """Fetch raw blob bytes for a batch, filtered by on-chain versioned hashes."""
    # 1. Get expected versioned hashes from contract
    selector = bytes.fromhex("50f0e746")  # cast sig "batchBlobHashes(uint256)"
    call_data = "0x" + selector.hex() + batch_index.to_bytes(32, "big").hex()
    result = rpc_call(l1_rpc, "eth_call", [
        {"to": contract, "data": call_data}, "latest"
    ])
    # ABI decode: offset (32B) + length (32B) + N * bytes32
    raw_result = bytes.fromhex(result[2:])
    if len(raw_result) < 64:
        raise RuntimeError(f"batchBlobHashes returned too short: {len(raw_result)}")
    num_hashes = int.from_bytes(raw_result[32:64], "big")
    expected_hashes = set()
    for i in range(num_hashes):
        vh = raw_result[64 + i * 32 : 64 + (i + 1) * 32]
        expected_hashes.add(vh)

    # 2. Fetch blob sidecars from beacon
    block = rpc_call(l1_rpc, "eth_getBlockByNumber", [hex(l1_block), False])
    timestamp = hex_to_int(block["timestamp"])
    slot = (timestamp - beacon_genesis) // 12

    data = beacon_get(beacon_url, f"/eth/v1/beacon/blob_sidecars/{slot}")

    # 3. Filter by versioned hash
    blobs = []
    for sc in data["data"]:
        commitment_hex = sc["kzg_commitment"]
        if commitment_hex.startswith("0x"):
            commitment_hex = commitment_hex[2:]
        commitment = bytes.fromhex(commitment_hex)
        vh = versioned_hash_from_commitment(commitment)
        if vh in expected_hashes:
            blob_hex = sc["blob"]
            if blob_hex.startswith("0x"):
                blob_hex = blob_hex[2:]
            blobs.append(bytes.fromhex(blob_hex))

    if not blobs:
        raise RuntimeError(f"No matching blobs found for batch {batch_index} in slot {slot}")

    return blobs


def send_mock_request(proxy_url: str, api_key: str, block_number: int, batch_index: int) -> dict:
    body = json.dumps({"block_number": block_number, "batch_index": batch_index}).encode()
    req = urllib.request.Request(
        f"{proxy_url.rstrip('/')}/mock/sp1/request",
        data=body,
        headers={"Content-Type": "application/json", "x-api-key": api_key},
    )
    try:
        with urllib.request.urlopen(req, timeout=600) as resp:
            return json.loads(resp.read())
    except urllib.error.HTTPError as e:
        return {"success": False, "error": f"HTTP {e.code}: {e.read().decode()}"}


def main():
    parser = argparse.ArgumentParser(description="Continuous SP1 mock execution tester")
    parser.add_argument("--proxy", default=os.environ.get("PROXY_URL", "http://127.0.0.1:18080"))
    parser.add_argument("--api-key", default=os.environ.get("API_KEY", "test123"))
    parser.add_argument("--blocks-per-batch", type=int, default=10)
    parser.add_argument("--l1-rpc", default=os.environ.get("L1_RPC_URL"))
    parser.add_argument("--contract", default=os.environ.get("L1_CONTRACT_ADDR"))
    parser.add_argument("--beacon", default=os.environ.get("L1_BEACON_URL"))
    parser.add_argument("--beacon-genesis", type=int,
                        default=int(os.environ.get("BEACON_GENESIS_TIMESTAMP", "1655733600")))
    parser.add_argument("--deploy-block", type=int,
                        default=int(os.environ.get("L1_CONTRACT_DEPLOY_BLOCK", "0")))
    args = parser.parse_args()

    if not all([args.l1_rpc, args.contract, args.beacon]):
        print("ERROR: --l1-rpc, --contract, --beacon are required (or set env vars)")
        sys.exit(1)

    print(f"Proxy:   {args.proxy}")
    print(f"L1 RPC:  {args.l1_rpc}")
    print(f"Beacon:  {args.beacon}")
    print(f"Contract: {args.contract}")
    print(f"Blocks per batch: {args.blocks_per_batch}")
    print()

    round_num = 0
    processed_batches = set()

    while True:
        round_num += 1
        print(f"{'='*60}")
        print(f"Round {round_num} — fetching recent batches...")

        try:
            batches = find_recent_batches(args.l1_rpc, args.contract, args.deploy_block)
        except Exception as e:
            print(f"  ERROR fetching batches: {e}")
            time.sleep(30)
            continue

        # Pick an unprocessed batch (newest first)
        batch = None
        for b in batches:
            if b["batch_index"] not in processed_batches:
                batch = b
                break

        if batch is None:
            print("  All recent batches processed. Waiting 60s for new ones...")
            time.sleep(60)
            processed_batches.clear()  # reset to recheck
            continue

        batch_index = batch["batch_index"]
        l1_block = batch["l1_block"]
        processed_batches.add(batch_index)

        print(f"  Batch {batch_index} (L1 block {l1_block})")

        # Fetch blobs and decode header
        try:
            blobs = fetch_blob_for_batch(args.l1_rpc, args.contract, args.beacon, args.beacon_genesis, l1_block, batch_index)
            from_block, to_block = decode_blob_header(blobs)
            print(f"  L2 block range: {from_block} .. {to_block} ({to_block - from_block + 1} blocks)")
        except Exception as e:
            print(f"  ERROR decoding blobs: {e}")
            continue

        # Pick random blocks
        all_blocks = list(range(from_block, to_block + 1))
        sample_size = min(args.blocks_per_batch, len(all_blocks))
        selected = sorted(random.sample(all_blocks, sample_size))

        print(f"  Selected {sample_size} blocks: {selected}")
        print()

        passed = 0
        failed = 0
        for i, block_num in enumerate(selected, 1):
            print(f"  [{i}/{sample_size}] Block {block_num}, batch {batch_index} ... ", end="", flush=True)
            t0 = time.time()
            result = send_mock_request(args.proxy, args.api_key, block_num, batch_index)
            elapsed = time.time() - t0

            if result.get("success"):
                passed += 1
                print(f"OK ({elapsed:.1f}s)")
            else:
                failed += 1
                err = result.get("error", "unknown")
                print(f"FAIL ({elapsed:.1f}s): {err}")

        print()
        print(f"  Batch {batch_index} results: {passed} passed, {failed} failed")
        print()


if __name__ == "__main__":
    main()
