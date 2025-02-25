# Threshold BLS Signatures

Implementation of BLS threshold signatures using BLS12-381 curve with dual verification with support for Ethereum on-chain verification via EIP-2537 precompiles.

## Features

- BLS threshold signature scheme using BLS12-381 curve
- Dual verification using Herumi and ConsenSys implementations
- Command-line tools for key generation, signing, and verification
- Prepared for future EIP-2537 integration


## Usage

### Generate Keys
Generate key pairs for threshold signing:

```bash
go run cmd/util/generate_keys.go \
    -threshold 13 \
    -total 20 \
    -output keys.txt
```

### Create Signature
Sign a message using threshold signatures:

```bash
go run cmd/main.go \
    -message "Hello, Ethereum!" \
    -nodes 1,2,3,4,5,7,8,11,13,16,17,19,20 \
    -threshold 13 \
    -total 20
```

### Verify Signature
Verify a signature independently:

```bash
go run cmd/verify/verify.go \
    -message "Hello, Ethereum!" \
    -signature <hex_signature> \
    -pubkey <hex_pubkey>
```

## Code Examples

### Initialize Scheme
```go
scheme, err := crypto.NewSignatureScheme(13, 20)
if err != nil {
    log.Fatal(err)
}
```

### Sign Message
```go
signature, err := scheme.Sign(message, signingNodes)
if err != nil {
    log.Fatal(err)
}
```

### Verify Signature
```go
result, err := scheme.VerifySignature(message, signature)
if err != nil {
    log.Fatal(err)
}

if result.IsValid {
    fmt.Println("Signature is valid!")
}
```


## Implementation Notes
- This project uses [herumi/bls-eth-go-binary](https://github.com/herumi/bls-eth-go-binary) which implements interface mentioned in Ethereum 2 phase 0 for signature aggregation and verification. 
- Provides verification by both Herumi and ConsenSys implementations
  - Hash-to-curve uses `BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_` DST
  - Uses [draft 7](https://tools.ietf.org/html/draft-irtf-cfrg-bls-signature-07) of the BLS signature spec
  - Public keys are in G1, signatures in G2 (opposite of standard BLS)

## Track

- [x] Add signature aggregation and verification
- [x] On-chain verification with EIP-2537

## References

- [EIP-2537: BLS12-381 curve operations](https://eips.ethereum.org/EIPS/eip-2537)
- [BLS12-381 For The Rest Of Us](https://hackmd.io/@benjaminion/bls12-381)
- [herumi/bls-eth-go-binary](https://github.com/herumi/bls-eth-go-binary)
- [Ethereum 2.0 BLS Specification](https://github.com/ethereum/consensus-specs/blob/dev/specs/phase0/beacon-chain.md#bls-signatures)
