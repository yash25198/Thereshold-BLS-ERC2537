// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import "../src/BLSVerifier.sol";

contract BLSVerifierTest is Test {
    BLSVerifier public verifier;

    // Test data
    bytes32 pubKeyX1 =
        0x0000000000000000000000000000000001fa51618cb9cb3d292a23aec4047f73;
    bytes32 pubKeyX2 =
        0x8b5934fca05f06f2e1acee10dadef068cf2f67fe09ff0b42fa70bc8b0e2c4e46;
    bytes32 pubKeyY1 =
        0x000000000000000000000000000000000ffc70cf999ee7b27b48294c17b064c6;
    bytes32 pubKeyY2 =
        0xcd29be4024f91d099c3d75d41044f2479ef5b490551e56444e7f733e87435f40;

    bytes32 sigX0_1 =
        0x000000000000000000000000000000000a3e2cd331d963759d13f3babacc042f;
    bytes32 sigX0_2 =
        0x08888916ee0a674c55677208df521d86afe97a60c03825871bb85c437136cfc8;
    bytes32 sigX1_1 =
        0x00000000000000000000000000000000101e4d1a91e23f19de8d488b6bc0c4c4;
    bytes32 sigX1_2 =
        0x57cf0d8346e3c9f1ae7b095cedee459033a519b8d4c3250454ece03a23ddbae0;
    bytes32 sigY0_1 =
        0x00000000000000000000000000000000091278f443ec62937ae85069098166c8;
    bytes32 sigY0_2 =
        0x107e272cb11b0b0f3a0796f38271f0eaf6942fae8e868491cf3e25bfaa2e0194;
    bytes32 sigY1_1 =
        0x00000000000000000000000000000000121b2437b6662d583770e60e9a429cb0;
    bytes32 sigY1_2 =
        0xcae05aa99fd0f98b14b26cf2b8f812a6d24d1cd989dd94ad5f8d24b04b995072;

    // Expected output for hashToG2("Hello")
    bytes32 expectedX0_1 =
        0x00000000000000000000000000000000126237acf33eaedac7f7d1e6114320c6;
    bytes32 expectedX0_2 =
        0x6b61c8463a9ed7d7201f11e16a2c6f0785888387e86ca2656fd5abdbbc206a58;
    bytes32 expectedX1_1 =
        0x000000000000000000000000000000000faeefba7be0583160c4111834801e23;
    bytes32 expectedX1_2 =
        0x93ba0a396405daf605632b949dc187697c0872d42bd25fd8e969b85260558105;
    bytes32 expectedY0_1 =
        0x0000000000000000000000000000000017244b659153699c955c9666ac41ad58;
    bytes32 expectedY0_2 =
        0x744d456cf53e99a704e26d23dd67a1ceef2bccd2ae4f2e17b697fa7ba175a717;
    bytes32 expectedY1_1 =
        0x0000000000000000000000000000000010dfe8f22a34200cf7e79e062633b55f;
    bytes32 expectedY1_2 =
        0xefe69f4bff3a0323c12c37a0c4cff248da8844fafdc34775e3a15c320b918161;

    // The message that was signed
    bytes message = "Hello";

    function setUp() public {
        verifier = new BLSVerifier();
    }

    function test_HashToG2() public {
        // Call the hashToG2 function
        BLS.G2Point memory result = verifier.hashMessageToG2(message);

        // Verify each component of the result against expected values
        assertEq(result.x_c0_a, expectedX0_1, "HashToG2 x_c0_a mismatch");
        assertEq(result.x_c0_b, expectedX0_2, "HashToG2 x_c0_b mismatch");
        assertEq(result.x_c1_a, expectedX1_1, "HashToG2 x_c1_a mismatch");
        assertEq(result.x_c1_b, expectedX1_2, "HashToG2 x_c1_b mismatch");
        assertEq(result.y_c0_a, expectedY0_1, "HashToG2 y_c0_a mismatch");
        assertEq(result.y_c0_b, expectedY0_2, "HashToG2 y_c0_b mismatch");
        assertEq(result.y_c1_a, expectedY1_1, "HashToG2 y_c1_a mismatch");
        assertEq(result.y_c1_b, expectedY1_2, "HashToG2 y_c1_b mismatch");

        // Log the result for debugging
        emit log_named_bytes32("Result x_c0_a", result.x_c0_a);
        emit log_named_bytes32("Result x_c0_b", result.x_c0_b);
        emit log_named_bytes32("Result x_c1_a", result.x_c1_a);
        emit log_named_bytes32("Result x_c1_b", result.x_c1_b);
        emit log_named_bytes32("Result y_c0_a", result.y_c0_a);
        emit log_named_bytes32("Result y_c0_b", result.y_c0_b);
        emit log_named_bytes32("Result y_c1_a", result.y_c1_a);
        emit log_named_bytes32("Result y_c1_b", result.y_c1_b);
    }

    function test_VerifyValidSignature() public view {
        // Arrange
        BLS.G1Point memory pubKey = BLS.G1Point(
            pubKeyX1,
            pubKeyX2,
            pubKeyY1,
            pubKeyY2
        );

        BLS.G2Point memory signature = BLS.G2Point(
            sigX0_1,
            sigX0_2,
            sigX1_1,
            sigX1_2,
            sigY0_1,
            sigY0_2,
            sigY1_1,
            sigY1_2
        );

        // Act & Assert
        bool result = verifier.verifySignature(
            message,
            pubKey,
            signature,
            true
        );
        assertTrue(result, "Valid signature should be verified successfully");
    }

    function test_VerifyWithDifferentMessage() public view {
        // Arrange
        BLS.G1Point memory pubKey = BLS.G1Point(
            pubKeyX1,
            pubKeyX2,
            pubKeyY1,
            pubKeyY2
        );

        BLS.G2Point memory signature = BLS.G2Point(
            sigX0_1,
            sigX0_2,
            sigX1_1,
            sigX1_2,
            sigY0_1,
            sigY0_2,
            sigY1_1,
            sigY1_2
        );

        bytes memory differentMessage = "HelloWorld";

        // Act & Assert
        bool result = verifier.verifySignature(
            differentMessage,
            pubKey,
            signature,
            false
        );
        assertFalse(
            result,
            "Signature for different message should fail verification"
        );
    }

    function test_VerifyWithoutNegation() public view {
        // Arrange
        BLS.G1Point memory pubKey = BLS.G1Point(
            pubKeyX1,
            pubKeyX2,
            pubKeyY1,
            pubKeyY2
        );

        BLS.G2Point memory signature = BLS.G2Point(
            sigX0_1,
            sigX0_2,
            sigX1_1,
            sigX1_2,
            sigY0_1,
            sigY0_2,
            sigY1_1,
            sigY1_2
        );

        // Verify using negation flag
        bool resultWithNegation = verifier.verifySignature(
            message,
            pubKey,
            signature,
            false
        );

        // The negation flag should change the verification result
        assertFalse(
            resultWithNegation,
            "Verification with negation should produce different result"
        );
    }

    function test_VerifySignatureWithPoint() public view {
        // Arrange
        BLS.G1Point memory pubKey = BLS.G1Point(
            pubKeyX1,
            pubKeyX2,
            pubKeyY1,
            pubKeyY2
        );

        BLS.G2Point memory signature = BLS.G2Point(
            sigX0_1,
            sigX0_2,
            sigX1_1,
            sigX1_2,
            sigY0_1,
            sigY0_2,
            sigY1_1,
            sigY1_2
        );

        // Hash the message to a G2 point
        BLS.G2Point memory messagePoint = verifier.hashMessageToG2(message);

        // Act
        bool result = verifier.verifySignatureWithPoint(
            messagePoint,
            pubKey,
            signature,
            true
        );

        // Assert
        assertTrue(
            result,
            "Verification with pre-hashed message point should succeed"
        );
    }
}
