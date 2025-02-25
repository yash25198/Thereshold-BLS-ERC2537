// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {BLS} from "./lib/BLS.sol";

/**
 * @title BLSVerifier
 * @notice A contract that verifies BLS signatures using the precompile.
 * @dev This contract is based on the BLS standard defined in EIP-2537.
 */

contract BLSVerifier {
    using BLS for *;

    /// @notice The generator point for G1.
    BLS.G1Point G1_GENERATOR =
        BLS.G1Point(
            0x0000000000000000000000000000000017f1d3a73197d7942695638c4fa9ac0f,
            0xc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb,
            0x0000000000000000000000000000000008b3f481e3aaa0f1a09e30ed741d8ae4,
            0xfcf5e095d5d00af600db18cb2c04b3edd03cc744a2888ae40caa232946c5e7e1
        );

    /// @notice The negated generator point for G1.
    BLS.G1Point NEGATED_G1_GENERATOR =
        BLS.G1Point(
            0x0000000000000000000000000000000017f1d3a73197d7942695638c4fa9ac0f,
            0xc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb,
            0x00000000000000000000000000000000114d1d6855d545a8aa7d76c8cf2e21f2,
            0x67816aef1db507c96655b9d5caac42364e6f38ba0ecb751bad54dcd6b939c2ca
        );

    /**
     * @notice Verifies a single BLS signature against a given message and public key.
     * @param message The signed message (byte array).
     * @param pubKey The signer's public key (a point in G1).
     * @param signature The BLS signature (a point in G2).
     * @return True if the signature is valid, false otherwise.
     */
    function verifySignature(
        bytes memory message,
        BLS.G1Point memory pubKey,
        BLS.G2Point memory signature
    ) public view returns (bool) {
        // Compute H(m): map the message to a point in G2.
        BLS.G2Point memory hm = BLS.hashToG2(message);

        return verifySignatureWithPoint(hm, pubKey, signature, true);
    }

    /**
     * @notice Verifies a signature against a pre-hashed message (already mapped to G2)
     * @param messagePoint The message already mapped to a G2 point.
     * @param pubKey The signer's public key (a point in G1).
     * @param signature The BLS signature (a point in G2).
     * @param negate Whether to negate the generator point.
     * @return True if the signature is valid, false otherwise.
     */
    function verifySignatureWithPoint(
        BLS.G2Point memory messagePoint,
        BLS.G1Point memory pubKey,
        BLS.G2Point memory signature,
        bool negate
    ) public view returns (bool) {
        // Prepare input arrays for the pairing check.
        BLS.G1Point[] memory g1Points = new BLS.G1Point[](2);
        BLS.G2Point[] memory g2Points = new BLS.G2Point[](2);

        if (negate) {
            g1Points[0] = NEGATED_G1_GENERATOR; // -G1
        } else {
            g1Points[0] = G1_GENERATOR; // G1
        }
        g1Points[1] = pubKey; // Public key

        g2Points[0] = signature; // Signature
        g2Points[1] = messagePoint; // Already a G2 point

        // The pairing precompile (via BLS.pairing) returns true if the product equals one.
        return BLS.pairing(g1Points, g2Points);
    }

    /**
     * @notice Maps a message to a G2 point (hash-to-curve)
     * @param message The message to map
     * @return The message mapped to a G2 point
     */
    function hashMessageToG2(
        bytes memory message
    ) public view returns (BLS.G2Point memory) {
        return BLS.hashToG2(message);
    }
}
