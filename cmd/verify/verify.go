package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"log"

	"github.com/herumi/bls-eth-go-binary/bls"
	"github.com/yash25198/threshold_bls_erc2537/internal/crypto"
)

func main() {
	messageFlag := flag.String("message", "", "Original message")
	signatureFlag := flag.String("signature", "", "Hex-encoded signature")
	pubkeyFlag := flag.String("pubkey", "", "Hex-encoded group public key")

	flag.Parse()

	if *messageFlag == "" || *signatureFlag == "" || *pubkeyFlag == "" {
		flag.Usage()
		log.Fatal("All flags are required")
	}

	// Decode signature
	sigBytes, err := hex.DecodeString(*signatureFlag)
	if err != nil {
		log.Fatalf("Failed to decode signature: %v\n", err)
	}
	var sig bls.Sign
	err = sig.Deserialize(sigBytes)
	if err != nil {
		log.Fatalf("Failed to deserialize signature: %v\n", err)
	}

	// Decode public key
	pubBytes, err := hex.DecodeString(*pubkeyFlag)
	if err != nil {
		log.Fatalf("Failed to decode public key: %v\n", err)
	}
	var pubKey bls.PublicKey
	err = pubKey.Deserialize(pubBytes)
	if err != nil {
		log.Fatalf("Failed to deserialize public key: %v\n", err)
	}

	// Create minimal scheme for verification
	scheme := &crypto.SignatureScheme{
		GroupPublicKey: &pubKey,
	}

	// Verify signature
	verificationResult, err := scheme.VerifySignature([]byte(*messageFlag), &sig)
	if err != nil {
		log.Fatalf("Verification error: %v\n", err)
	}

	fmt.Printf("\nSignature Verification Results\n")
	fmt.Printf("============================\n")
	fmt.Printf("Message: %s\n", *messageFlag)
	fmt.Printf("Signature: %s\n", *signatureFlag)
	fmt.Printf("Public Key: %s\n\n", *pubkeyFlag)
	fmt.Printf("Herumi Verification: %v\n", verificationResult.HerumiVerification)
	fmt.Printf("ConsenSys Verification: %v\n", verificationResult.ConsensysVerification)
	fmt.Printf("Overall Validity: %v\n", verificationResult.IsValid)

	if !verificationResult.IsValid {
		log.Fatal("Signature verification failed")
	}
}
