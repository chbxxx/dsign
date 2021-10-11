package bhcheck

import (
	"github.com/bluehelix-chain/dsign/bhcrypto"
	"github.com/bluehelix-chain/dsign/bhcrypto/bhs256k1"
	"github.com/radicalrafi/gomorph/gaillier"
	"math/big"
)

type EvidenceType int

const (
	Negative         EvidenceType = 0x1
	PQProofCheater   EvidenceType = 0x2
	ShamirCheck      EvidenceType = 0x3
	SendingCheater   EvidenceType = 0x4
	ReceivingCheater EvidenceType = 0x5
	SchnorrCheater   EvidenceType = 0x6
	SiProofCheater   EvidenceType = 0x7
	SiCheckCheater   EvidenceType = 0x8
)

type Evidence struct {
	Type                      EvidenceType
	NegativeNodes             []string
	PQProofEvidences          []*PQProofEvidence
	ShamirCheckEvidence       []*ShamirCheckEvidence
	SendingCheaterEvidences   []*SendingCheaterEvidence
	ReceivingCheaterEvidences []*ReceivingCheaterEvidence
	SchnorrCheaterEvidences   []*SchnorrCheaterEvidence
	SiProofCheaterEvidences   []*SiProofCheaterEvidence
	SiCheckCheaterEvidences   []*SiCheckCheaterEvidence
}

func (e *Evidence) SetNegativeNodes(negativeNodes []string) {
	e.NegativeNodes = negativeNodes
	e.Type = Negative
}

func (e *Evidence) SetPQProofEvidences(pqProofEvidences []*PQProofEvidence) {
	e.PQProofEvidences = pqProofEvidences
	e.Type = PQProofCheater
}

func (e *Evidence) SetShamirCheckEvidence(shamirCheckEvidence []*ShamirCheckEvidence) {
	e.ShamirCheckEvidence = shamirCheckEvidence
	e.Type = ShamirCheck
}

func (e *Evidence) SetSendingCheaterEvidences(sendingCheaterEvidences []*SendingCheaterEvidence) {
	e.SendingCheaterEvidences = sendingCheaterEvidences
	e.Type = SendingCheater
}

func (e *Evidence) SetReceivingCheaterEvidences(receivingCheaterEvidences []*ReceivingCheaterEvidence) {
	e.ReceivingCheaterEvidences = receivingCheaterEvidences
	e.Type = ReceivingCheater
}

func (e *Evidence) SetSchnorrCheaterEvidences(schnorrCheaterEvidences []*SchnorrCheaterEvidence) {
	e.SchnorrCheaterEvidences = schnorrCheaterEvidences
	e.Type = SchnorrCheater
}

func (e *Evidence) SetSiProofCheaterEvidences(siProofCheaterEvidences []*SiProofCheaterEvidence) {
	e.SiProofCheaterEvidences = siProofCheaterEvidences
	e.Type = SiProofCheater
}

func (e *Evidence) SetSiCheckCheaterEvidences(siCheckCheaterEvidences []*SiCheckCheaterEvidence) {
	e.SiCheckCheaterEvidences = siCheckCheaterEvidences
	e.Type = SiCheckCheater
}

type PQProofEvidence struct {
	Label string
	Proof PQZKProof
}

type ShamirCheckEvidence struct {
	Label     string
	ShamirPub []byte
	Proof     SchnorrZKProof
}

type SendingCheaterEvidence struct {
	Label  string
	Proof  SenderRangeProof
	Msg    []byte
	Pubkey *gaillier.PubKey
}

type ReceivingCheaterEvidence struct {
	Label  string
	Proof  ReceiverRangeProof
	M1     []byte
	M2     []byte
	Pubkey *gaillier.PubKey
}

type SchnorrCheaterEvidence struct {
	Label  string
	Proof  SchnorrZKProof
	Pubkey *bhs256k1.PublicKey
}

type SiProofCheaterEvidence struct {
	Label             string
	Proof             SiZKProof
	SigR, SigRY, EccN *big.Int
}

type SiCheckCheaterEvidence struct {
	Label  string
	Check  SiZKCheck
	BX, BY *big.Int
}

type PrivatePQZKProof struct {
	Z []*big.Int
	X []*big.Int
	Y *big.Int
}

type PrivateReceiverRangeProof struct {
	MuX, MuY, Z, ZD, T, V, W, S, S1, S2, T1, T2, XX, XY *big.Int
}

type SchnorrZKProof struct {
	Pub bhcrypto.BhPublicKey
	Num *big.Int
}

type SiZKProof struct {
	VX, VY, AX, AY, BX, BY, AlphaX, AlphaY, BetaX, BetaY, T, U *big.Int
}

//在完成Si的零知识证明检查后，需要在不暴露Si的前提下进行S的正确性的检查
type SiZKCheck struct {
	U, T *bhs256k1.PublicKey
}
