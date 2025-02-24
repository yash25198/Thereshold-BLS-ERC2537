package crypto

import (
	"github.com/herumi/bls-eth-go-binary/bls"
)

// Node represents a participant in the threshold signature scheme
type Node struct {
	Index      int
	PrivateKey *bls.SecretKey
	PublicKey  *bls.PublicKey
}

// SchemeParams contains the parameters for the threshold signature scheme
type SchemeParams struct {
	Threshold  int
	TotalNodes int
}

// SignatureScheme represents the complete threshold signature system
type SignatureScheme struct {
	Params           SchemeParams
	Nodes            []*Node
	GroupPublicKey   *bls.PublicKey
	MasterSecretKeys []bls.SecretKey
}

// VerificationResult contains verification results from both libraries
type VerificationResult struct {
	HerumiVerification    bool
	ConsensysVerification bool
	IsValid               bool // True only if both verifications pass
}
