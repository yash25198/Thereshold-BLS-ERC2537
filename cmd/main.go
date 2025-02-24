// cmd/main.go
package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"

	"github.com/yash25198/threshold_bls_erc2537/internal/crypto"
)

func main() {
	// Define command line flags
	messageFlag := flag.String("message", "", "Message to sign")
	nodesFlag := flag.String("nodes", "", "Comma-separated list of signing node indices")
	thresholdFlag := flag.Int("threshold", 13, "Threshold value for signature scheme")
	totalNodesFlag := flag.Int("total", 20, "Total number of nodes")
	verboseFlag := flag.Bool("verbose", false, "Enable verbose output")

	flag.Parse()

	// Validate inputs
	if *messageFlag == "" {
		log.Fatal("Message is required. Use -message flag")
	}

	if *nodesFlag == "" {
		log.Fatal("Signing nodes are required. Use -nodes flag (comma-separated)")
	}

	// Parse signing nodes
	nodeStrs := strings.Split(*nodesFlag, ",")
	signingNodes := make([]int, 0, len(nodeStrs))
	for _, nodeStr := range nodeStrs {
		node, err := strconv.Atoi(strings.TrimSpace(nodeStr))
		if err != nil {
			log.Fatalf("Invalid node index: %s", nodeStr)
		}
		signingNodes = append(signingNodes, node)
	}

	// Initialize scheme
	scheme, err := crypto.NewSignatureScheme(*thresholdFlag, *totalNodesFlag)
	if err != nil {
		log.Fatalf("Failed to initialize signature scheme: %v\n", err)
	}

	// Sign message
	message := []byte(*messageFlag)
	signature, err := scheme.Sign(message, signingNodes)
	if err != nil {
		log.Fatalf("Failed to generate signature: %v\n", err)
	}

	// Verify signature
	verificationResult, err := scheme.VerifySignature(message, signature)
	if err != nil {
		log.Fatalf("Signature verification error: %v\n", err)
	}

	// Output results
	fmt.Printf("\nBLS Threshold Signature Results\n")
	fmt.Printf("================================\n")
	fmt.Printf("Message: %s\n", *messageFlag)
	fmt.Printf("Threshold: %d\n", *thresholdFlag)
	fmt.Printf("Total Nodes: %d\n", *totalNodesFlag)
	fmt.Printf("Signing Nodes: %v\n", signingNodes)

	if *verboseFlag {
		fmt.Printf("\nSignature Details:\n")
		fmt.Printf("Signature (hex): %x\n", signature.Serialize())
		fmt.Printf("Group Public Key (hex): %x\n", scheme.GroupPublicKey.Serialize())

		fmt.Printf("\nParticipating Node Public Keys:\n")
		for _, nodeIndex := range signingNodes {
			node := scheme.Nodes[nodeIndex-1]
			fmt.Printf("Node %d: %x\n", node.Index, node.PublicKey.Serialize())
		}
	}

	fmt.Printf("\nVerification Results:\n")
	fmt.Printf("Herumi Verification: %v\n", verificationResult.HerumiVerification)
	fmt.Printf("ConsenSys Verification: %v\n", verificationResult.ConsensysVerification)
	fmt.Printf("Overall Validity: %v\n", verificationResult.IsValid)

	if !verificationResult.IsValid {
		os.Exit(1)
	}
}
