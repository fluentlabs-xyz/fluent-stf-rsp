// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {ISP1Verifier} from "@sp1-contracts/ISP1Verifier.sol";

/**
 * @title Enclave
 * @notice Smart contract for verifying AWS Nitro Enclave attestations via SP1 zero-knowledge proofs
 * @dev This contract provides two-phase verification:
 *      1. Attestation phase: Verify ZK proof that enclave generated a specific public key
 *      2. Block verification phase: Verify ECDSA signatures from the attested enclave
 */
contract Enclave {
    // ============ State Variables ============
    
    /// @notice SP1 verifier contract address
    address public immutable verifier;
    
    /// @notice Program verification key hash for SP1 proof validation
    bytes32 public immutable programVKey;

    /// @notice Expected public key from the enclave (65 bytes with 0x04 prefix)
    bytes public constant EXPECTED_PUBKEY =
        hex"0431f26074907216725a3a7630488ba898bb32a29fee2b04f144878b162dea172262b1bcd836f08f2d3c766ecb01fd6fa2ce2c4b5dcc636eb2f7c6321cee18496b";

    /// @notice Ethereum address derived from the expected public key
    address public constant ENCLAVE_ADDRESS = 0x678FeB097B8b8bb3567D8d8831Fe2a1358096d36;

    /// @notice Flag indicating whether attestation has been successfully verified
    bool public isAttestationVerified;

    /// @notice Ethereum address of the verified enclave (computed during attestation)
    address public enclaveAddress;

    /// @notice Mapping to track which blocks have been verified
    /// @dev blockHash => verified status
    mapping(bytes32 => bool) public verifiedBlocks;

    // ============ Events ============

    /// @notice Emitted when attestation is successfully verified
    /// @param pubkey The public key extracted from the ZK proof
    event AttestationVerified(bytes pubkey);

    /// @notice Emitted when a block signature is successfully verified
    /// @param blockHash Hash of the verified block
    /// @param parentHash Hash of the parent block
    event BlockVerified(bytes32 indexed blockHash, bytes32 parentHash);

    // ============ Constructor ============

    /**
     * @notice Initialize the Enclave contract
     * @param _verifier Address of the SP1 verifier contract
     * @param _programVKey Program verification key for SP1 proof validation
     */
    constructor(address _verifier, bytes32 _programVKey) {
        verifier = _verifier;
        programVKey = _programVKey;
    }

    // ============ External Functions ============

    /**
     * @notice Verify the enclave attestation using SP1 zero-knowledge proof
     * @dev This function can only be called once. It verifies:
     *      1. The SP1 proof is valid
     *      2. The public key matches the expected value
     *      3. The derived address matches the expected enclave address
     * @param _publicValues Public values from the SP1 proof (contains the enclave's public key)
     * @param _proofBytes The SP1 Groth16 proof bytes
     */
    function verifyAttestation(
        bytes calldata _publicValues,
        bytes calldata _proofBytes
    ) external {
        require(!isAttestationVerified, "Already verified");

        // Step 1: Verify the SP1 zero-knowledge proof
        ISP1Verifier(verifier).verifyProof(
            programVKey,
            _publicValues,
            _proofBytes
        );

        // Step 2: Extract public key from public values (skip 8-byte length prefix)
        bytes memory receivedPubkey = _publicValues[8:];

        // Step 3: Derive Ethereum address from the public key
        address derivedAddress = pubkeyToAddress(receivedPubkey);

        // Step 4: Verify the public key matches expected value
        require(
            keccak256(receivedPubkey) == keccak256(EXPECTED_PUBKEY),
            "pk mismatch"
        );

        // Step 5: Verify the derived address matches expected enclave address
        require(
            derivedAddress == ENCLAVE_ADDRESS,
            "adress mismatch"
        );

        // Mark attestation as verified
        isAttestationVerified = true;
        emit AttestationVerified(receivedPubkey);
    }

    /**
     * @notice Verify a block signature from the attested enclave
     * @dev Can be called multiple times after successful attestation.
     *      Verifies ECDSA signature using the custom signing payload format.
     * @param parentHash Hash of the parent block
     * @param blockHash Hash of the current block
     * @param withdrawalHash Hash of withdrawal events
     * @param depositHash Hash of deposit events
     * @param signature ECDSA signature (65 bytes: r + s + v)
     * @return bool True if verification succeeds
     */
    function verifyBlock(
        bytes32 parentHash,
        bytes32 blockHash,
        bytes32 withdrawalHash,
        bytes32 depositHash,
        bytes calldata signature
    ) external returns (bool) {
        require(isAttestationVerified, "Attestation not verified");
        require(signature.length == 65, "Invalid signature length");

        // Step 1: Compute the signing payload using custom hash scheme
        bytes32 signingPayload = computeSigningPayload(
            parentHash,
            blockHash,
            withdrawalHash,
            depositHash
        );

        // Step 2: Recover the signer's address from the ECDSA signature
        address signer = recoverSigner(signingPayload, signature);

        // Step 3: Verify the signer is the attested enclave
        require(signer == ENCLAVE_ADDRESS, "Invalid signer");
        
        // Step 4: Prevent replay attacks
        require(!verifiedBlocks[blockHash], "Already verified");

        // Mark block as verified
        verifiedBlocks[blockHash] = true;
        emit BlockVerified(blockHash, parentHash);
        return true;
    }

    // ============ Public Functions ============

    /**
     * @notice Compute the signing payload using double SHA256 hash scheme
     * @dev Payload = SHA256(parent || block || withdrawal || deposit || SHA256(parent || block || withdrawal || deposit))
     * @param parentHash Hash of the parent block
     * @param blockHash Hash of the current block
     * @param withdrawalHash Hash of withdrawal events
     * @param depositHash Hash of deposit events
     * @return bytes32 The computed signing payload
     */
    function computeSigningPayload(
        bytes32 parentHash,
        bytes32 blockHash,
        bytes32 withdrawalHash,
        bytes32 depositHash
    ) public pure returns (bytes32) {
        // First hash: SHA256 of all four components
        bytes32 resultHash = sha256(
            abi.encodePacked(parentHash, blockHash, withdrawalHash, depositHash)
        );

        // Second hash: SHA256 of all components plus the first hash
        bytes32 signingPayload = sha256(
            abi.encodePacked(
                parentHash,
                blockHash,
                withdrawalHash,
                depositHash,
                resultHash
            )
        );

        return signingPayload;
    }

    // ============ Internal Functions ============

    /**
     * @notice Recover the signer address from an ECDSA signature
     * @dev Uses raw message hash without Ethereum signed message prefix
     * @param messageHash The hash that was signed
     * @param signature The ECDSA signature (65 bytes)
     * @return address The recovered signer address
     */
    function recoverSigner(
        bytes32 messageHash,
        bytes calldata signature
    ) internal pure returns (address) {
        bytes32 r;
        bytes32 s;
        uint8 v;

        // Extract r, s, v from signature bytes
        assembly {
            r := calldataload(signature.offset)
            s := calldataload(add(signature.offset, 32))
            v := byte(0, calldataload(add(signature.offset, 64)))
        }

        // Recover address using ecrecover precompile
        return ecrecover(messageHash, v, r, s);
    }

    /**
     * @notice Convert an ECDSA public key to an Ethereum address
     * @dev Address = last 20 bytes of keccak256(pubkey)
     *      Handles both compressed (64 bytes) and uncompressed (65 bytes with 0x04 prefix) formats
     * @param pubkey The public key bytes (64 or 65 bytes)
     * @return address The derived Ethereum address
     */
    function pubkeyToAddress(bytes memory pubkey) internal pure returns (address) {
        require(pubkey.length == 64 || pubkey.length == 65, "Invalid pubkey length");
        
        // If uncompressed format (0x04 prefix), skip the first byte
        bytes memory keyData = pubkey.length == 65 
            ? sliceBytes(pubkey, 1, 64) 
            : pubkey;
        
        // Compute address from keccak256 hash (last 20 bytes)
        return address(uint160(uint256(keccak256(keyData))));
    }

    /**
     * @notice Extract a slice from a bytes array
     * @param data The source bytes array
     * @param start Starting index
     * @param length Number of bytes to extract
     * @return bytes memory The extracted slice
     */
    function sliceBytes(bytes memory data, uint256 start, uint256 length)
        internal
        pure
        returns (bytes memory)
    {
        bytes memory result = new bytes(length);
        for (uint256 i = 0; i < length; i++) {
            result[i] = data[start + i];
        }
        return result;
    }
}
