package dsign

import (
	"math/big"

	"github.com/bluehelix-chain/dsign/types"
	"github.com/btcsuite/btcd/btcec"
	"github.com/radicalrafi/gomorph/gaillier"
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
	ShamirCheckEvidence       *ShamirCheckEvidence
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

func (e *Evidence) SetShamirCheckEvidence(shamirCheckEvidence *ShamirCheckEvidence) {
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
	Proof types.PQZKProof
}

type ShamirCheckEvidence struct {
	Pub      *btcec.PublicKey
	Evidence []types.KeyGenPhase3Msg
}

type SendingCheaterEvidence struct {
	Label  string
	Proof  types.SenderRangeProof
	Msg    []byte
	Pubkey *gaillier.PubKey
}

type ReceivingCheaterEvidence struct {
	Label  string
	Proof  types.ReceiverRangeProof
	M1     []byte
	M2     []byte
	Pubkey *gaillier.PubKey
}

type SchnorrCheaterEvidence struct {
	Label  string
	Proof  types.SchnorrZKProof
	Pubkey *btcec.PublicKey
}

type SiProofCheaterEvidence struct {
	Label             string
	Proof             types.SiZKProof
	SigR, SigRY, EccN *big.Int
}

type SiCheckCheaterEvidence struct {
	Label  string
	Check  types.SiZKCheck
	BX, BY *big.Int
}
