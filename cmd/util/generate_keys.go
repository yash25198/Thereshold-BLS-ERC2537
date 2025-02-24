package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/yash25198/threshold_bls_erc2537/internal/crypto"
)

func main() {
	thresholdFlag := flag.Int("threshold", 13, "Threshold value")
	totalNodesFlag := flag.Int("total", 20, "Total number of nodes")
	outputFlag := flag.String("output", "", "Output file for keys (optional)")

	flag.Parse()

	// Initialize scheme
	scheme, err := crypto.NewSignatureScheme(*thresholdFlag, *totalNodesFlag)
	if err != nil {
		log.Fatalf("Failed to initialize scheme: %v\n", err)
	}

	// Format output
	output := fmt.Sprintf("BLS Threshold Key Generation\n")
	output += fmt.Sprintf("===========================\n")
	output += fmt.Sprintf("Threshold: %d\n", *thresholdFlag)
	output += fmt.Sprintf("Total Nodes: %d\n\n", *totalNodesFlag)
	output += fmt.Sprintf("Group Public Key: %s\n\n",
		hex.EncodeToString(scheme.GroupPublicKey.Serialize()))

	output += "Node Keys:\n"
	for _, node := range scheme.Nodes {
		output += fmt.Sprintf("Node %d:\n", node.Index)
		output += fmt.Sprintf("  Private Key: %s\n",
			hex.EncodeToString(node.PrivateKey.Serialize()))
		output += fmt.Sprintf("  Public Key:  %s\n\n",
			hex.EncodeToString(node.PublicKey.Serialize()))
	}

	// Write to file or stdout
	if *outputFlag != "" {
		err := os.WriteFile(*outputFlag, []byte(output), 0644)
		if err != nil {
			log.Fatalf("Failed to write output: %v\n", err)
		}
		fmt.Printf("Keys written to %s\n", *outputFlag)
	} else {
		fmt.Print(output)
	}
}
