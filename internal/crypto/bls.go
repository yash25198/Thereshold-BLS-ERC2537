package crypto

import (
	"fmt"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fp"
	"github.com/herumi/bls-eth-go-binary/bls"
)

func init() {
	err := bls.Init(bls.BLS12_381)
	if err != nil {
		panic(fmt.Sprintf("failed to initialize BLS: %v", err))
	}
	bls.SetETHmode(bls.EthModeDraft07)
}

// NewSignatureScheme creates a new threshold signature scheme
func NewSignatureScheme(threshold, totalNodes int) (*SignatureScheme, error) {
	if threshold > totalNodes {
		return nil, fmt.Errorf("threshold cannot be greater than total nodes")
	}

	var masterSecret bls.SecretKey
	masterSecret.SetByCSPRNG()

	masterSecretKeys := masterSecret.GetMasterSecretKey(threshold)
	nodes := make([]*Node, totalNodes)

	for i := 0; i < totalNodes; i++ {
		var id bls.ID
		err := id.SetDecString(fmt.Sprintf("%d", i+1))
		if err != nil {
			return nil, fmt.Errorf("failed to set ID: %v", err)
		}

		var sk bls.SecretKey
		err = sk.Set(masterSecretKeys, &id)
		if err != nil {
			return nil, fmt.Errorf("failed to generate share for node %d: %v", i+1, err)
		}

		nodes[i] = &Node{
			Index:      i + 1,
			PrivateKey: &sk,
			PublicKey:  sk.GetPublicKey(),
		}
	}

	return &SignatureScheme{
		Params: SchemeParams{
			Threshold:  threshold,
			TotalNodes: totalNodes,
		},
		Nodes:            nodes,
		GroupPublicKey:   masterSecret.GetPublicKey(),
		MasterSecretKeys: masterSecretKeys,
	}, nil
}

// Sign generates a threshold signature using the provided signing nodes
func (ss *SignatureScheme) Sign(message []byte, signingNodes []int) (*bls.Sign, error) {
	if len(signingNodes) < ss.Params.Threshold {
		return nil, fmt.Errorf("not enough signing nodes: got %d, need %d",
			len(signingNodes), ss.Params.Threshold)
	}

	sigs := make([]bls.Sign, len(signingNodes))
	idVec := make([]bls.ID, len(signingNodes))

	for i, nodeIndex := range signingNodes {
		if nodeIndex <= 0 || nodeIndex > ss.Params.TotalNodes {
			return nil, fmt.Errorf("invalid node index: %d", nodeIndex)
		}

		node := ss.Nodes[nodeIndex-1]
		sigs[i] = *node.PrivateKey.SignByte(message)

		err := idVec[i].SetDecString(fmt.Sprintf("%d", node.Index))
		if err != nil {
			return nil, fmt.Errorf("failed to set ID for recovery: %v", err)
		}
	}

	var groupSig bls.Sign
	err := groupSig.Recover(sigs, idVec)
	if err != nil {
		return nil, fmt.Errorf("failed to recover group signature: %v", err)
	}

	return &groupSig, nil
}

// VerifySignature performs verification using both Herumi and ConsenSys implementations
func (ss *SignatureScheme) VerifySignature(message []byte, signature *bls.Sign) (*VerificationResult, error) {
	// Herumi verification
	herumiResult := signature.VerifyByte(ss.GroupPublicKey, message)

	// ConsenSys verification
	consensysResult, err := ss.verifyConsensys(message, signature)
	if err != nil {
		return nil, fmt.Errorf("consensys verification failed: %v", err)
	}

	return &VerificationResult{
		HerumiVerification:    herumiResult,
		ConsensysVerification: consensysResult,
		IsValid:               herumiResult && consensysResult,
	}, nil
}

// verifyConsensys implements verification using the ConsenSys library
func (ss *SignatureScheme) verifyConsensys(message []byte, signature *bls.Sign) (bool, error) {
	pubKeyBytes := ss.GroupPublicKey.SerializeUncompressed()
	sigBytes := signature.SerializeUncompressed()

	// Parse the public key (point in G1)
	pubKey := new(bls12381.G1Affine)
	if len(pubKeyBytes) != 96 {
		return false, fmt.Errorf("invalid public key length")
	}

	// Parse signature coordinates
	pX, err := decodeFieldElement(pubKeyBytes[0:48])
	if err != nil {
		return false, fmt.Errorf("failed to decode public key x: %v", err)
	}
	pY, err := decodeFieldElement(pubKeyBytes[48:96])
	if err != nil {
		return false, fmt.Errorf("failed to decode public key y: %v", err)
	}

	pubKey.X = pX
	pubKey.Y = pY

	if !pubKey.IsOnCurve() {
		return false, fmt.Errorf("public key is not on curve")
	}

	// Parse the signature (point in G2)
	if len(sigBytes) != 192 {
		return false, fmt.Errorf("invalid signature length")
	}

	sig := new(bls12381.G2Affine)

	// Parse each field element
	x1, err := decodeFieldElement(sigBytes[0:48])
	if err != nil {
		return false, fmt.Errorf("failed to decode sig x1: %v", err)
	}
	x0, err := decodeFieldElement(sigBytes[48:96])
	if err != nil {
		return false, fmt.Errorf("failed to decode sig x0: %v", err)
	}
	y1, err := decodeFieldElement(sigBytes[96:144])
	if err != nil {
		return false, fmt.Errorf("failed to decode sig y1: %v", err)
	}
	y0, err := decodeFieldElement(sigBytes[144:192])
	if err != nil {
		return false, fmt.Errorf("failed to decode sig y0: %v", err)
	}

	sig.X.A0 = x0
	sig.X.A1 = x1
	sig.Y.A0 = y0
	sig.Y.A1 = y1

	// Get the correct G1 generator
	_, _, g1, _ := bls12381.Generators()

	// Hash message to G2
	dst := []byte("BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_")
	hashedMsg, err := bls12381.HashToG2(message, dst)
	if err != nil {
		return false, fmt.Errorf("failed to hash message to G2: %v", err)
	}

	// Negate the hashed message for pairing equation
	hashedMsgNeg := new(bls12381.G2Affine).Neg(&hashedMsg)

	// Pairing check setup
	g1Points := []bls12381.G1Affine{g1, *pubKey}
	g2Points := []bls12381.G2Affine{*sig, *hashedMsgNeg}

	valid, err := bls12381.PairingCheck(g1Points, g2Points)
	if err != nil {
		return false, fmt.Errorf("failed during pairing check: %v", err)
	}

	return valid, nil
}

// decodeFieldElement decodes a 48-byte big-endian encoding into a field element
func decodeFieldElement(in []byte) (fp.Element, error) {
	if len(in) != 48 {
		return fp.Element{}, fmt.Errorf("input length must be 48 bytes")
	}

	var bytes [48]byte
	copy(bytes[:], in[:])

	z, err := fp.BigEndian.Element(&bytes)
	if err != nil {
		return fp.Element{}, fmt.Errorf("failed to decode field element: %v", err)
	}

	return z, nil
}
