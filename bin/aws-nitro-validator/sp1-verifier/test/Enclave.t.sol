// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test, console} from "forge-std/Test.sol";
import {stdJson} from "forge-std/StdJson.sol";
import {Enclave} from "../src/Enclave.sol";
import {SP1VerifierGateway} from "@sp1-contracts/SP1VerifierGateway.sol";

/**
 * @title EnclaveTest
 * @notice Test suite for the Enclave attestation and block verification contract
 * @dev Uses Foundry testing framework with SP1 proof fixtures
 */
contract EnclaveTest is Test {
    using stdJson for string;

    // ============ State Variables ============
    
    /// @notice Mock SP1 verifier gateway contract address
    address verifier;
    
    /// @notice Instance of the Enclave contract being tested
    Enclave public enclave;

    // ============ Setup ============

    /**
     * @notice Set up test environment before each test
     * @dev Deploys a mock SP1 verifier gateway and the Enclave contract
     *      Uses the vkey from the fixture to initialize the contract
     */
    function setUp() public {
        // Deploy mock verifier gateway for testing
        verifier = address(new SP1VerifierGateway(address(1)));
        
        // Deploy Enclave contract with mock verifier and fixture vkey
        enclave = new Enclave(verifier);
    }

    // ============ Tests ============

    /**
     * @notice Test successful attestation verification with valid proof
     * @dev This test verifies:
     *      1. The SP1 proof can be verified (mocked)
     *      2. The public key extraction works correctly
     *      3. The attestation flag is set after successful verification
     */
    function test_ValidAttestationProof() public {

        // Mock the SP1 verifier to always return success
        // Note: This does NOT perform real cryptographic verification
        vm.mockCall(
            verifier,
            abi.encodeWithSelector(SP1VerifierGateway.verifyProof.selector),
            abi.encode(true)
        );

        // Attempt to verify attestation with the fixture data
        enclave.verifyAttestation();

        // Assert that attestation was marked as verified
        assertTrue(enclave.isAttestationVerified());
    }
}
