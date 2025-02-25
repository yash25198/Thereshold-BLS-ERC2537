# BLS Verification Contracts

## Overview

This directory contains Solidity contracts for on-chain verification of BLS (Boneh-Lynn-Shacham) signatures using the BLS12-381 curve. These contracts leverage the EIP-2537 precompiles to perform the necessary elliptic curve operations for signature verification.

## Contracts

### BLSVerifier.sol

The main verification contract that provides public functions for validating BLS signatures. This contract implements the verification logic for the BLS signature scheme with the following key features:

- Supports verification of single BLS signatures
- Provides hash-to-curve functionality to map messages to points on the G2 curve
- Implements the pairing check required for BLS signature verification
- Supports both raw message verification and pre-hashed message verification
- Configurable to handle different BLS signature variants through a negation flag

### BLS.sol (Library)

A utility library that wraps the EIP-2537 precompiles for BLS12-381 operations:

- Provides a structured interface to the BLS12-381 precompiles
- Implements data structures for representing points on the G1 and G2 curves
- Provides functions for elliptic curve operations such as addition and scalar multiplication
- Implements the hash-to-curve algorithm for mapping arbitrary messages to points on G2
- Contains pairing check functionality for signature verification

## Usage Guide

### Verifying a Signature

To verify a BLS signature using these contracts:

1. Instantiate the `BLSVerifier` contract
2. Call `verifySignature` with the message, public key (G1 point) and signature (G2 point)

```solidity
// Example usage
BLSVerifier verifier = new BLSVerifier();
bool isValid = verifier.verifySignature(
    message,      // The message that was signed (bytes)
    publicKey,    // The signer's public key (G1 point)
    signature,    // The BLS signature (G2 point)
);
```

### Working with Pre-hashed Messages

For applications where you want to reuse a hashed message point:

```solidity
// First hash the message to a G2 point
BLS.G2Point memory messagePoint = verifier.hashMessageToG2(message);

// Then verify using the pre-hashed point
bool isValid = verifier.verifySignatureWithPoint(
    messagePoint, // The message mapped to a G2 point
    publicKey,    // The signer's public key (G1 point)
    signature,    // The BLS signature (G2 point)
    true          // Negation flag 
);
```

## BLS Signature Scheme Details

These contracts implement BLS signature verification with the following properties:

- **Curve**: BLS12-381
- **Domain Separation Tag (DST)**: "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_" per draft 7 of the BLS signature spec
- **Public Keys**: Points on the G1 curve
- **Signatures**: Points on the G2 curve
- **Hash-to-Curve**: Implements the hash-to-curve algorithm specified in the BLS signature spec
- **Pairing Check**: Uses the pairing precompile to perform the signature verification equation

## EIP-2537 Precompiles

The contracts use the following EIP-2537 precompiles:

- **BLS12_G1ADD** (0x0B): Addition on G1
- **BLS12_G1MSM** (0x0C): Multi-scalar multiplication on G1
- **BLS12_G2ADD** (0x0D): Addition on G2
- **BLS12_G2MSM** (0x0E): Multi-scalar multiplication on G2
- **BLS12_PAIRING_CHECK** (0x0F): Pairing check
- **BLS12_MAP_FP_TO_G1** (0x10): Map field element to G1
- **BLS12_MAP_FP2_TO_G2** (0x11): Map field element to G2

## Integration with Threshold BLS

These contracts support verification of threshold BLS signatures as described in the project, where:

1. Distributed key generation creates key pairs across multiple nodes
2. A threshold number of nodes sign independently
3. Signatures are aggregated off-chain
4. The aggregated signature is verified on-chain using these contracts



## References

- [Solady BLS Implementation](https://github.com/Vectorized/solady/blob/main/src/utils/ext/ithaca/BLS.sol)