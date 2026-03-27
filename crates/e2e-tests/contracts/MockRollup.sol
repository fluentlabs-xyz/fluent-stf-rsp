// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

/// Minimal L1 mock contract for e2e tests.
///
/// Implements the interface that `blob.rs` expects:
/// - `batchBlobHashes(uint256)` — returns versioned hashes for a batch
/// - `BatchBlobsSubmitted` event — emitted when blobs are submitted
///
/// Additionally provides:
/// - `acceptNextBatch()` — emits `BatchHeadersSubmitted`
/// - `preconfirmBatch()` — emits `BatchAccepted`, stores last signature
contract MockRollup {
    // ── Types ────────────────────────────────────────────────────────────
    struct L2BlockHeader {
        bytes32 previousBlockHash;
        bytes32 blockHash;
        bytes32 withdrawalRoot;
        bytes32 depositRoot;
        uint256 depositCount;
    }

    // ── Storage ──────────────────────────────────────────────────────────
    mapping(uint256 => bytes32[]) internal _batchBlobHashes;
    uint256 public nextBatchIndex;
    uint256 public lastPreconfirmedBatch = type(uint256).max;
    bytes public lastSignature;

    // ── Events (must match what blob.rs filters for) ─────────────────────
    event BatchBlobsSubmitted(
        uint256 indexed batchIndex,
        uint256 numBlobs,
        uint256 totalSoFar
    );

    event BatchHeadersSubmitted(
        uint256 indexed batchIndex,
        bytes32 batchRoot,
        uint256 expectedBlobsCount
    );

    event BatchAccepted(uint256 indexed batchIndex);

    // ── Functions ────────────────────────────────────────────────────────

    /// Store versioned hashes for a batch. Called by the test driver to
    /// simulate what `submitBlobs` does on the real L1 contract.
    function submitBlobs(
        uint256 batchIndex,
        bytes32[] calldata blobHashes
    ) external {
        for (uint256 i = 0; i < blobHashes.length; i++) {
            _batchBlobHashes[batchIndex].push(blobHashes[i]);
        }
        emit BatchBlobsSubmitted(
            batchIndex,
            blobHashes.length,
            _batchBlobHashes[batchIndex].length
        );
        // Signal that blobs are ready for this batch — matches real Rollup.submitBlobs
        // behaviour and is used by the courier's l1_listener to trigger batch signing.
        emit BatchAccepted(batchIndex);
    }

    /// Read versioned hashes for a batch (called by proxy via eth_call).
    function batchBlobHashes(
        uint256 batchIndex
    ) external view returns (bytes32[] memory) {
        return _batchBlobHashes[batchIndex];
    }

    /// Accept a batch of block headers and compute a Merkle root.
    function acceptNextBatch(
        L2BlockHeader[] calldata blockHeaders,
        uint256 expectedBlobsCount
    ) external {
        uint256 batchIndex = nextBatchIndex++;
        bytes32 batchRoot = _merkleRoot(blockHeaders);
        emit BatchHeadersSubmitted(batchIndex, batchRoot, expectedBlobsCount);
    }

    /// Preconfirm a batch with a nitro signature.
    function preconfirmBatch(
        address nitroVerifier,
        uint256 batchIndex,
        bytes calldata signature
    ) external {
        lastPreconfirmedBatch = batchIndex;
        lastSignature = signature;
    }

    // ── Internal ─────────────────────────────────────────────────────────

    /// Compute a Merkle root from L2BlockHeaders.
    ///
    /// Leaf = keccak256(previousBlockHash ++ blockHash ++ withdrawalRoot ++ depositRoot)
    /// Pairs = keccak256(left ++ right). Odd node is duplicated.
    function _merkleRoot(L2BlockHeader[] calldata headers) internal pure returns (bytes32) {
        uint256 n = headers.length;
        if (n == 0) return bytes32(0);

        bytes32[] memory layer = new bytes32[](n);
        for (uint256 i = 0; i < n; i++) {
            layer[i] = keccak256(abi.encodePacked(
                headers[i].previousBlockHash,
                headers[i].blockHash,
                headers[i].withdrawalRoot,
                headers[i].depositRoot
            ));
        }

        while (layer.length > 1) {
            uint256 len = layer.length;
            uint256 nextLen = (len + 1) / 2;
            bytes32[] memory next = new bytes32[](nextLen);
            for (uint256 i = 0; i < len / 2; i++) {
                next[i] = keccak256(abi.encodePacked(layer[i * 2], layer[i * 2 + 1]));
            }
            if (len % 2 == 1) {
                bytes32 last = layer[len - 1];
                next[nextLen - 1] = keccak256(abi.encodePacked(last, last));
            }
            layer = next;
        }

        return layer[0];
    }
}
