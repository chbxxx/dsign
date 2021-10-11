package dsign

import (
	"errors"
	"github.com/bluehelix-chain/dsign/bhcrypto/bhcheck"
	"github.com/bluehelix-chain/dsign/bhcrypto/bhs256k1"
	"math/big"

	"github.com/bluehelix-chain/dsign/communicator"
	"github.com/bluehelix-chain/dsign/logger"
)

const errorV = byte(0xFF)

type Signer struct {
	label    string
	logger   logger.Logger
	sch      bhcheck.Schnorr
	random   bhcheck.Random
	response bhcheck.Response
	siProof  bhcheck.SiProof
	siCheck  bhcheck.SiCheck
}

func NewSigner(label string, logger logger.Logger) *Signer {
	return &Signer{
		label:    label,
		logger:   logger,
		sch:      &bhcheck.HonestSchnorr{},
		random:   &bhcheck.HonestRandom{},
		response: &bhcheck.HonestResponse{},
		siProof:  &bhcheck.HonestSiProof{},
		siCheck:  &bhcheck.HonestSiCheck{},
	}
}

func (s *Signer) WithSchnorr(sch bhcheck.Schnorr) *Signer {
	s.sch = sch
	return s
}

func (s *Signer) WithRandom(random bhcheck.Random) *Signer {
	s.random = random
	return s
}

func (s *Signer) WithResponse(response bhcheck.Response) *Signer {
	s.response = response
	return s
}

func (s *Signer) WithSiProof(siProof bhcheck.SiProof) *Signer {
	s.siProof = siProof
	return s
}

func (s *Signer) WithSiCheck(siCheck bhcheck.SiCheck) *Signer {
	s.siCheck = siCheck
	return s
}

func (s *Signer) Sign(t, n int, nodekey *NodeKey, nodeList []string, hash []byte,
	comm communicator.Communicator) (*bhs256k1.Signature, byte, *Node, *bhcheck.Evidence, error) {

	p := len(nodeList)
	// t <= p <= n
	if t > p || p > n {
		return nil, errorV, nil, nil, errors.New("invalid params")
	}
	if !isInList(s.label, nodeList) {
		return nil, errorV, nil, nil, errors.New("not in sign list")
	}
	node, err := NewNode(t, p, n, s.label, nodeList, bhs256k1.S256(), nodekey, comm, s.random, s.logger)
	if err != nil {
		return nil, errorV, nil, nil, err
	}
	node.GetKeySignPhase1MsgSent()
	s.logger.Debug("Finish shamir")
	node.comm.SendKeySignPhase1Message(node.KeySignPhase1MsgSent)
	evidence := &bhcheck.Evidence{}
	for i := 0; i < p-1; i++ {
		msg, err := node.comm.GetKeySignPhase1Message()
		if err != nil {
			received := []string{s.label}
			for _, msg := range node.KeySignPhase1MsgReceived {
				received = append(received, msg.LabelFrom)
			}
			negativeNodes := getMissingStrings(received, nodeList)
			evidence.SetNegativeNodes(negativeNodes)
			return nil, errorV, node, evidence, err
		}
		node.KeySignPhase1MsgReceived = append(node.KeySignPhase1MsgReceived, msg)
	}
	s.logger.Debug("KeySignPhase1 finishes receiving")
	s.logger.Debug("Node starts computing")
	senderEvidenceList, err1 := node.GetKeySignPhase2MsgSent(s.response)
	if err1 != nil {
		s.logger.Error("Initiator range proof fail", "label", node.label, "err", err1)
		evidence.SetSendingCheaterEvidences(senderEvidenceList)
		return nil, hash[0], node, evidence, err1
	}
	s.logger.Debug("Initiator range proof passed")
	s.logger.Debug("All nodes computation finishes")
	s.logger.Debug("KeySignPhase2 starts sending")
	node.comm.SendKeySignPhase2Message(node.KeySignPhase2MsgSent)
	for i := 0; i < p-1; i++ {
		msg, err := node.comm.GetKeySignPhase2Message()
		if err != nil {
			received := []string{s.label}
			for _, msg := range node.KeySignPhase2MsgReceived {
				received = append(received, msg.LabelFrom)
			}
			negativeNodes := getMissingStrings(received, nodeList)
			evidence.SetNegativeNodes(negativeNodes)
			return nil, errorV, node, evidence, err
		}
		node.KeySignPhase2MsgReceived = append(node.KeySignPhase2MsgReceived, msg)
	}
	s.logger.Debug("KeySignPhase2 finishes receiving")
	s.logger.Debug("Node starts computing")
	receiverEvidenceList, err2 := node.GetKeySignPhase3And4MsgSent(s.sch)
	if err2 != nil {
		s.logger.Error("Responder range proof fail", "label", node.label, "err", err2)
		evidence.SetReceivingCheaterEvidences(receiverEvidenceList)
		return nil, hash[0], node, evidence, err2
	}
	s.logger.Debug("Responder range proof pass")
	s.logger.Debug("All nodes computation finishes")
	s.logger.Debug("KeySignPhase3And4 starts sending")
	node.comm.SendKeySignPhase3And4Message(node.KeySignPhase3And4MsgSent, nodeList)
	for i := 0; i < p-1; i++ {
		msg, err := node.comm.GetKeySignPhase3And4Message()
		if err != nil {
			received := []string{s.label}
			for _, msg := range node.KeySignPhase3And4MsgReceived {
				received = append(received, msg.LabelFrom)
			}
			negativeNodes := getMissingStrings(received, nodeList)
			evidence.SetNegativeNodes(negativeNodes)
			return nil, errorV, node, evidence, err
		}
		node.KeySignPhase3And4MsgReceived = append(node.KeySignPhase3And4MsgReceived, msg)
	}
	s.logger.Debug("KeySignPhase3And4 finishes receiving")
	s.logger.Debug("Node starts computing")
	schnorrEvidenceList, err3 := node.GetKeySignPhase5AAnd5BMsgSent(hash, s.siProof)
	if err3 != nil {
		s.logger.Error("Schnorr proof fail", "label", node.label, "err", err3)
		evidence.SetSchnorrCheaterEvidences(schnorrEvidenceList)
		return nil, hash[0], node, evidence, err3
	}
	s.logger.Debug("Schnorr proof pass")
	s.logger.Debug("All nodes computation finishes")
	s.logger.Debug("KeySignPhase5A starts sending")
	node.comm.SendKeySignPhase5AMessage(node.KeySignPhase5AMsgSent, nodeList)
	for i := 0; i < p; i++ {
		msg, err := node.comm.GetKeySignPhase5AMessage()
		if err != nil {
			received := []string{s.label}
			for _, msg := range node.KeySignPhase5AMsgReceived {
				received = append(received, msg.LabelFrom)
			}
			negativeNodes := getMissingStrings(received, nodeList)
			evidence.SetNegativeNodes(negativeNodes)
			return nil, errorV, node, evidence, err
		}
		node.KeySignPhase5AMsgReceived = append(node.KeySignPhase5AMsgReceived, msg)
	}
	s.logger.Debug("KeySignPhase5A finish receiving")
	s.logger.Debug("KeySignPhase5B starts sending")
	node.comm.SendKeySignPhase5BMessage(node.KeySignPhase5BMsgSent, nodeList)
	for i := 0; i < p; i++ {
		msg, err := node.comm.GetKeySignPhase5BMessage()
		if err != nil {
			received := []string{s.label}
			for _, msg := range node.KeySignPhase5BMsgReceived {
				received = append(received, msg.LabelFrom)
			}
			negativeNodes := getMissingStrings(received, nodeList)
			evidence.SetNegativeNodes(negativeNodes)
			return nil, errorV, node, evidence, err
		}
		node.KeySignPhase5BMsgReceived = append(node.KeySignPhase5BMsgReceived, msg)
	}
	s.logger.Debug("KeySignPhase5B finish receiving")
	s.logger.Debug("Node starts computing")
	siProofEvidenceList, err4 := node.GetKeySignPhase5CAnd5DMsgSent(hash, nodekey, s.siCheck)
	if err4 != nil {
		s.logger.Error("SiProof fail", "label", node.label, "err", err4)
		evidence.SetSiProofCheaterEvidences(siProofEvidenceList)
		return nil, hash[0], node, evidence, err4
	}
	s.logger.Debug("SiProof pass")
	s.logger.Debug("All nodes computation finishes")
	s.logger.Debug("KeySignPhase5C starts sending")
	node.comm.SendKeySignPhase5CMessage(node.KeySignPhase5CMsgSent, nodeList)
	for i := 0; i < p; i++ {
		msg, err := node.comm.GetKeySignPhase5CMessage()
		if err != nil {
			received := []string{s.label}
			for _, msg := range node.KeySignPhase5CMsgReceived {
				received = append(received, msg.LabelFrom)
			}
			negativeNodes := getMissingStrings(received, nodeList)
			evidence.SetNegativeNodes(negativeNodes)
			return nil, errorV, node, evidence, err
		}
		node.KeySignPhase5CMsgReceived = append(node.KeySignPhase5CMsgReceived, msg)
	}
	s.logger.Debug("KeySignPhase5C finishes receiving")
	s.logger.Debug("KeySignPhase5D starts sending")
	node.comm.SendKeySignPhase5DMessage(node.KeySignPhase5DMsgSent, nodeList)
	for i := 0; i < p; i++ {
		msg, err := node.comm.GetKeySignPhase5DMessage()
		if err != nil {
			received := []string{s.label}
			for _, msg := range node.KeySignPhase5DMsgReceived {
				received = append(received, msg.LabelFrom)
			}
			negativeNodes := getMissingStrings(received, nodeList)
			evidence.SetNegativeNodes(negativeNodes)
			return nil, errorV, node, evidence, err
		}
		node.KeySignPhase5DMsgReceived = append(node.KeySignPhase5DMsgReceived, msg)
	}
	s.logger.Debug("KeySignPhase5D finishes receiving")
	s.logger.Debug("Node starts computing")
	siCheckEvidenceList, err5 := node.GetKeySignPhase5EMsgSent()
	if err5 != nil {
		s.logger.Error("GetKeySignPhase5CAnd5DMsgSent fail", "label", node.label, "err", err5)
		evidence.SetSiCheckCheaterEvidences(siCheckEvidenceList)
		return nil, hash[0], node, evidence, err5
	}
	s.logger.Debug("All nodes computation finishes")
	s.logger.Debug("KeySignPhase5E starts sending")
	node.comm.SendKeySignPhase5EMessage(node.KeySignPhase5EMsgSent, nodeList)
	for i := 0; i < p; i++ {
		msg, err := node.comm.GetKeySignPhase5EMessage()
		if err != nil {
			received := []string{s.label}
			for _, msg := range node.KeySignPhase5EMsgReceived {
				received = append(received, msg.LabelFrom)
			}
			negativeNodes := getMissingStrings(received, nodeList)
			evidence.SetNegativeNodes(negativeNodes)
			return nil, errorV, node, evidence, err
		}
		node.KeySignPhase5EMsgReceived = append(node.KeySignPhase5EMsgReceived, msg)
	}
	recid := node.KeySignPhase5EMsgReceived[0].GetNativeV()
	for _, v := range node.KeySignPhase5EMsgReceived {
		if v.GetNativeV() != recid {
			s.logger.Error("KeySignPhase5EMsg received fail", "label", node.label)
			return nil, errorV, node, nil, errors.New("KeySignPhase5EMsg received error")
		}
	}
	resultS := big.NewInt(0)
	resultR := big.NewInt(0)

	for _, v := range node.KeySignPhase5EMsgReceived {
		resultS.Add(resultS, v.GetNativeSigs())
	}
	resultS.Mod(resultS, node.EccN)
	resultR.Mod(node.KeySignPhase5EMsgReceived[0].GetNativeSigr(), node.EccN)
	//subS = -s mod n
	//resultS = min(subs,s)
	subS := new(big.Int).Sub(big.NewInt(0), resultS)
	subS = subS.Mod(subS, node.EccN)
	if resultS.Cmp(subS) > 0 {
		resultS = subS
		recid = 1 - recid
	}

	signatureF := &bhs256k1.Signature{}
	signatureF.R = resultR
	signatureF.S = resultS
	return signatureF, recid, node, nil, nil
}

//return a*b+c
func computeLinearSum(a, b, c *big.Int) *big.Int {
	result := new(big.Int).Mul(a, b)
	result = result.Add(result, c)
	return result
}
