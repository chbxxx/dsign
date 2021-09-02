package dsign

import (
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"math/big"

	"github.com/bluehelix-chain/dsign/commit"
	"github.com/bluehelix-chain/dsign/communicator"
	"github.com/bluehelix-chain/dsign/logger"
	"github.com/bluehelix-chain/dsign/primes"
	"github.com/bluehelix-chain/dsign/types"
	sssa "github.com/bluehelix-chain/sssa-golang"
	"github.com/btcsuite/btcd/btcec"
	"github.com/radicalrafi/gomorph/gaillier"
)

const errorV = byte(0xFF)

type Signer struct {
	label    string
	logger   logger.Logger
	sch      Schnorr
	random   Random
	response Response
	siProof  SiProof
	siCheck  SiCheck
}

func NewSigner(label string, logger logger.Logger) *Signer {
	return &Signer{
		label:    label,
		logger:   logger,
		sch:      &HonestSchnorr{},
		random:   &HonestRandom{},
		response: &HonestResponse{},
		siProof:  &HonestSiProof{},
		siCheck:  &HonestSiCheck{},
	}
}

func (s *Signer) WithSchnorr(sch Schnorr) *Signer {
	s.sch = sch
	return s
}

func (s *Signer) WithRandom(random Random) *Signer {
	s.random = random
	return s
}

func (s *Signer) WithResponse(response Response) *Signer {
	s.response = response
	return s
}

func (s *Signer) WithSiProof(siProof SiProof) *Signer {
	s.siProof = siProof
	return s
}

func (s *Signer) WithSiCheck(siCheck SiCheck) *Signer {
	s.siCheck = siCheck
	return s
}

func (s *Signer) Sign(t, n int, nodekey *NodeKey, nodeList []string, hash []byte,
	comm communicator.Communicator) (*btcec.Signature, byte, *Node, *Evidence, error) {

	p := len(nodeList)
	// t <= p <= n
	if t > p || p > n {
		return nil, errorV, nil, nil, errors.New("invalid params")
	}
	if !isInList(s.label, nodeList) {
		return nil, errorV, nil, nil, errors.New("not in sign list")
	}
	node, err := NewNode(t, p, n, s.label, nodeList, btcec.S256(), nodekey, comm, s.random, s.logger)
	if err != nil {
		return nil, errorV, nil, nil, err
	}
	node.GetKeySignPhase1MsgSent()
	s.logger.Debug("Finish shamir")
	node.comm.SendKeySignPhase1Message(node.KeySignPhase1MsgSent)
	evidence := &Evidence{}
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

	signatureF := &btcec.Signature{}
	signatureF.R = resultR
	signatureF.S = resultS
	return signatureF, recid, node, nil, nil
}

//p为参加签名的列表, label为节点下标，shares为该节点接收到的分片和
//label为参加签名的节点，其下标在所有签名节点中下标的位置。
func keyCombine(p []string, label string, shares []sssa.ShareXY) *big.Int {
	//shareSum := shares[0]
	//这种写法把shares[0]的指针赋给shareSum，会改变share[0].Y，多次调用shares会出bug
	shareSum := big.NewInt(0).Set(shares[0].Y)
	for k, v := range shares {
		if k != 0 {
			shareSum.Add(shareSum, v.Y)
		}
	}
	num, deno := sssa.CalBs(p, label)
	result := sssa.CalFinal(shareSum, num, deno)
	return result
}

type Node struct {
	T, P, N                      int
	label                        string
	NTilde, h1, h2               map[string]*big.Int
	Nodelist                     []string
	prtKey                       *big.Int
	paillierPubKey               *gaillier.PubKey
	paillierPrtKey               *gaillier.PrivKey
	randNumArray                 []*big.Int
	KeySignPhase1MsgReceived     []types.KeySignPhase1Msg
	KeySignPhase2MsgReceived     []types.KeySignPhase2Msg
	KeySignPhase3And4MsgReceived []types.KeySignPhase3And4Msg
	KeySignPhase5AMsgReceived    []types.KeySignPhase5AMsg
	KeySignPhase5BMsgReceived    []types.KeySignPhase5BMsg
	KeySignPhase5CMsgReceived    []types.KeySignPhase5CMsg
	KeySignPhase5DMsgReceived    []types.KeySignPhase5DMsg
	KeySignPhase5EMsgReceived    []types.KeySignPhase5EMsg
	KeySignPhase1MsgSent         []types.KeySignPhase1Msg
	KeySignPhase2MsgSent         []types.KeySignPhase2Msg
	KeySignPhase3And4MsgSent     types.KeySignPhase3And4Msg
	KeySignPhase5AMsgSent        types.KeySignPhase5AMsg
	KeySignPhase5BMsgSent        types.KeySignPhase5BMsg
	KeySignPhase5CMsgSent        types.KeySignPhase5CMsg
	KeySignPhase5DMsgSent        types.KeySignPhase5DMsg
	KeySignPhase5EMsgSent        types.KeySignPhase5EMsg
	shares                       []sssa.ShareXY
	Address                      map[string]string
	comm                         communicator.Communicator

	k                                        *big.Int
	r                                        *big.Int
	sigRBlindFactor                          *big.Int
	vBlindFactor, aBlindFactor, bBlindFactor *big.Int
	uBlindFactor, tBlindFactor               *big.Int
	theaLocal                                *big.Int
	theaInverse                              *big.Int
	cure                                     elliptic.Curve
	sigLocalR                                types.SigR
	sigR                                     *big.Int
	sigS                                     *big.Int
	SigRY                                    *big.Int
	EccN                                     *big.Int
	paillierRk, paillierRr                   *big.Int
	siL, siRho                               *big.Int //用于si的零知识证明的两个随机数
	q, qCube                                 *big.Int

	Logger logger.Logger
}

func NewNode(threash, participants, num int, label string, nodelist []string, cure elliptic.Curve,
	nodekey *NodeKey, comm communicator.Communicator, r Random, logger logger.Logger) (*Node, error) {

	pubKey, prtKey, err := gaillier.GenerateKeyPair(rand.Reader, paillierLength)
	if err != nil {
		return nil, err
	}
	t := &Node{}
	tempShares := []sssa.ShareXY{}
	for k := range nodekey.ShareReceived {
		tempShares = append(tempShares, nodekey.ShareReceived[k])
	}
	t.shares = tempShares
	t.Nodelist = nodelist
	t.cure = cure
	t.T = threash
	t.P = participants
	t.N = num
	t.label = label
	t.EccN = cure.Params().N
	//计算wi=λi,S*xi，完成(t,n)分片到(p,p)分片的映射
	t.prtKey = keyCombine(t.Nodelist, t.label, tempShares)
	tempk := r.randomNum(maxRand)
	tempr := r.randomNum(maxRand)
	tempSiL, _ := rand.Int(rand.Reader, t.EccN)
	tempSiRho, _ := rand.Int(rand.Reader, t.EccN)
	t.k = tempk
	t.r = tempr
	t.sigRBlindFactor, _ = rand.Int(rand.Reader, maxRand)
	t.vBlindFactor, _ = rand.Int(rand.Reader, maxRand)
	t.aBlindFactor, _ = rand.Int(rand.Reader, maxRand)
	t.bBlindFactor, _ = rand.Int(rand.Reader, maxRand)
	t.uBlindFactor, _ = rand.Int(rand.Reader, maxRand)
	t.tBlindFactor, _ = rand.Int(rand.Reader, maxRand)
	t.siL = tempSiL
	t.siRho = tempSiRho
	temp := []*big.Int{}
	for i := 0; i < t.P-1; i++ {
		num, _ := rand.Int(rand.Reader, maxRand)
		temp = append(temp, num)
	}
	t.randNumArray = temp
	t.paillierPubKey, t.paillierPrtKey = pubKey, prtKey
	t.comm = comm
	t.NTilde = make(map[string]*big.Int)
	t.h1 = make(map[string]*big.Int)
	t.h2 = make(map[string]*big.Int)
	for _, v := range t.Nodelist {
		t.NTilde[v] = nodekey.NTilde[v]
		t.h1[v] = nodekey.h1[v]
		t.h2[v] = nodekey.h2[v]
	}
	t.q = big.NewInt(0).Set(t.EccN)
	t.qCube = big.NewInt(0).Exp(t.q, big.NewInt(3), nil)

	t.Logger = logger
	return t, nil
}

func (t *Node) SetLabel(l string) {
	t.label = l
}

func (t *Node) GetLabel() string {
	return t.label
}

func (t *Node) SetNodeList(nodeList []string) {
	t.Nodelist = nodeList
}

func (t *Node) IsInNodeList() bool {
	for _, v := range t.Nodelist {
		if t.label == v {
			return true
		}
	}
	return false
}

func PaillierEnc(num *big.Int, pubKey *gaillier.PubKey) ([]byte, *big.Int) {
	r := primes.GetRandomPositiveRelativelyPrimeInt(pubKey.N)
	result, _ := PaillierEncrypt(pubKey, num.Bytes(), r)
	return result.Bytes(), r
}

func paillierDec(message []byte, prtKey *gaillier.PrivKey) *big.Int {
	temp, _ := gaillier.Decrypt(prtKey, message)
	result := new(big.Int).SetBytes(temp)
	return result
}

func getAnotherPart(message []byte, pubKey *gaillier.PubKey, randomNum, ownNum *big.Int, oneCipher []byte, oneR *big.Int) ([]byte, *big.Int) {
	cA := message
	gama := randomNum
	b := ownNum
	pub := pubKey
	encGama := gaillier.Mul(pub, oneCipher, gama.Bytes())
	r := big.NewInt(0).Exp(oneR, gama, pub.Nsq)
	cB := gaillier.Mul(pubKey, cA, b.Bytes())
	cB = gaillier.Add(pubKey, cB, encGama)

	return cB, r
}

func (t *Node) GetKeySignPhase1MsgSent() {
	t.KeySignPhase1MsgSent = make([]types.KeySignPhase1Msg, t.P-1)
	oneCipher, oneR := PaillierEnc(big.NewInt(1), t.paillierPubKey)
	messageK := gaillier.Mul(t.paillierPubKey, oneCipher, t.k.Bytes())
	messageR := gaillier.Mul(t.paillierPubKey, oneCipher, t.r.Bytes())
	t.paillierRk = big.NewInt(0).Exp(oneR, t.k, t.paillierPubKey.Nsq)
	t.paillierRr = big.NewInt(0).Exp(oneR, t.r, t.paillierPubKey.Nsq)
	meetSelf := false
	for k, v := range t.Nodelist {
		if v == t.label {
			meetSelf = true
			continue
		}
		if meetSelf {
			k = k - 1
		}
		t.KeySignPhase1MsgSent[k].LabelFrom = t.label
		t.KeySignPhase1MsgSent[k].LabelTo = v
		t.KeySignPhase1MsgSent[k].MessageK = messageK
		t.KeySignPhase1MsgSent[k].MessageR = messageR
		pubkey := getPubkeyByNum(t.k)
		t.KeySignPhase1MsgSent[k].SetNativeSigRCommit(commit.GetPubkeyCommit(pubkey, t.sigRBlindFactor))
		t.KeySignPhase1MsgSent[k].SetNativePaillierPubKey(t.paillierPubKey)
		nTilde, h1, h2 := t.NTilde[v], t.h1[v], t.h2[v]
		proofK := t.GetSenderRangeProof(t.k, t.paillierRk, nTilde, h1, h2, oneCipher)
		proofR := t.GetSenderRangeProof(t.r, t.paillierRr, nTilde, h1, h2, oneCipher)
		t.KeySignPhase1MsgSent[k].SetNativeSenderRangeProofK(proofK)
		t.KeySignPhase1MsgSent[k].SetNativeSenderRangeProofR(proofR)
	}
}

func (t *Node) GetKeySignPhase2MsgSent(re Response) ([]*SendingCheaterEvidence, error) {
	t.KeySignPhase2MsgSent = make([]types.KeySignPhase2Msg, t.P-1)
	errStr := ""
	var evidenceList []*SendingCheaterEvidence = make([]*SendingCheaterEvidence, 0)
	for k, v := range t.KeySignPhase1MsgReceived { //KeySignPhase1MsgReceived中不包含自身
		if !t.CheckSenderRangeProof(v.GetNativeSenderRangeProofK(), v.MessageK, v.GetNativePaillierPubKey()) {
			errStr = errStr + v.LabelFrom + "K\n"
			temp := &SendingCheaterEvidence{v.LabelFrom, v.GetNativeSenderRangeProofK(), v.MessageK, v.GetNativePaillierPubKey()}
			evidenceList = append(evidenceList, temp)
		}
		if !t.CheckSenderRangeProof(v.GetNativeSenderRangeProofR(), v.MessageR, v.GetNativePaillierPubKey()) {
			errStr = errStr + v.LabelFrom + "R\n"
			temp := &SendingCheaterEvidence{v.LabelFrom, v.GetNativeSenderRangeProofR(), v.MessageR, v.GetNativePaillierPubKey()}
			evidenceList = append(evidenceList, temp)
		}
		if errStr != "" {
			continue
		}
		t.KeySignPhase2MsgSent[k].LabelFrom = t.label
		t.KeySignPhase2MsgSent[k].LabelTo = v.LabelFrom
		var Rk, Rr *big.Int
		nTilde, h1, h2 := t.NTilde[v.LabelFrom], t.h1[v.LabelFrom], t.h2[v.LabelFrom]
		pub := v.GetNativePaillierPubKey()
		oneCipher, oneR := PaillierEnc(big.NewInt(1), pub)
		t.KeySignPhase2MsgSent[k].MessageKResponse, Rk = getAnotherPart(v.MessageK, pub, t.randNumArray[k], t.r, oneCipher, oneR)
		t.KeySignPhase2MsgSent[k].MessageRResponse, Rr = getAnotherPart(v.MessageR, pub, t.randNumArray[k], t.prtKey, oneCipher, oneR)
		reR, rePrtKey := re.respond(t.r, t.prtKey)
		proofK := t.GetReceiverRangeProof(reR, t.randNumArray[k], Rk, v.MessageK, v.GetNativePaillierPubKey(), nTilde, h1, h2)
		proofR := t.GetReceiverRangeProof(rePrtKey, t.randNumArray[k], Rr, v.MessageR, v.GetNativePaillierPubKey(), nTilde, h1, h2)
		t.KeySignPhase2MsgSent[k].SetNativeReceiverRangeProofK(proofK)
		t.KeySignPhase2MsgSent[k].SetNativeReceiverRangeProofR(proofR)
	}
	if errStr != "" {
		return evidenceList, errors.New(errStr)
	}
	return nil, nil
}

func (t *Node) GetKeySignPhase3And4MsgSent(sh Schnorr) ([]*ReceivingCheaterEvidence, error) {
	t.KeySignPhase3And4MsgSent.LabelFrom = t.label
	thea := new(big.Int).Mul(t.k, t.r)
	errStr := ""
	var evidenceList []*ReceivingCheaterEvidence = make([]*ReceivingCheaterEvidence, 0)
	for k, v := range t.KeySignPhase2MsgReceived {
		if !t.CheckReceiverRangeProof(v.GetNativeReceiverRangeProofK(), t.KeySignPhase1MsgSent[k].MessageK, v.MessageKResponse, t.paillierPubKey) {
			errStr = errStr + v.LabelFrom + "K\n"
			temp := &ReceivingCheaterEvidence{v.LabelFrom, v.GetNativeReceiverRangeProofK(), t.KeySignPhase1MsgSent[k].MessageK, v.MessageKResponse, t.paillierPubKey}
			evidenceList = append(evidenceList, temp)
		}
		if !t.CheckReceiverRangeProof(v.GetNativeReceiverRangeProofR(), t.KeySignPhase1MsgSent[k].MessageR, v.MessageRResponse, t.paillierPubKey) {
			errStr = errStr + v.LabelFrom + "R\n"
			temp := &ReceivingCheaterEvidence{v.LabelFrom, v.GetNativeReceiverRangeProofR(), t.KeySignPhase1MsgSent[k].MessageR, v.MessageRResponse, t.paillierPubKey}
			evidenceList = append(evidenceList, temp)
		}
		if errStr != "" {
			continue
		}
		temp := paillierDec(v.MessageKResponse, t.paillierPrtKey)
		thea.Add(thea, temp)
	}
	if errStr != "" {
		return evidenceList, errors.New(errStr)
	}
	for _, v := range t.randNumArray {
		thea.Sub(thea, v)
	}
	thea.Mod(thea, t.cure.Params().N)
	t.theaLocal = thea

	temp := types.SigRNative{}
	temp.X, temp.Y = elliptic.Curve.ScalarBaseMult(t.cure, t.k.Bytes())
	t.KeySignPhase3And4MsgSent.SetNativeSigOthersR(temp)
	t.KeySignPhase3And4MsgSent.SetNativeBlindFactor(t.sigRBlindFactor)
	t.KeySignPhase3And4MsgSent.SetNativeThea(thea)
	t.KeySignPhase3And4MsgSent.SetNativeSchnorrZKProof(sh.proof(t.k))
	return nil, nil
}

func (t *Node) GetKeySignPhase5AAnd5BMsgSent(hash []byte, siProof SiProof) ([]*SchnorrCheaterEvidence, error) {
	errStr := ""
	var schnorrEvidenceList []*SchnorrCheaterEvidence = make([]*SchnorrCheaterEvidence, 0)
	for _, v := range t.KeySignPhase3And4MsgReceived {
		if v.LabelFrom == t.GetLabel() {
			continue
		}
		temp := t.getSigOthersRByLabel(v.LabelFrom)
		tempX, tempY := big.NewInt(0).SetBytes(temp.X), big.NewInt(0).SetBytes(temp.Y)
		check := &btcec.PublicKey{}
		check.Curve = btcec.S256()
		check.X, check.Y = big.NewInt(0), big.NewInt(0)
		check.X, check.Y = check.Add(check.X, check.Y, tempX, tempY)
		var commitment [32]byte
		for _, v1 := range t.KeySignPhase1MsgReceived {
			if v1.LabelFrom == v.LabelFrom {
				commitment = v1.GetNativeSigRCommit()
			}
		}
		blindFactor := v.GetNativeBlindFactor()
		if !commit.CheckPubkeyCommit(commitment, check, blindFactor) {
			errStr = errStr + v.LabelFrom + "COMMITMENT CHECK FAIL"
		}
		if !CheckPubkeyProof(v.GetNativeSchnorrZKProof(), check) {
			errStr = errStr + v.LabelFrom + " SCHNORR PROOF CHECK FAIL"
			tempEvidence := &SchnorrCheaterEvidence{v.LabelFrom, v.GetNativeSchnorrZKProof(), check}
			schnorrEvidenceList = append(schnorrEvidenceList, tempEvidence)
		}
	}
	if errStr != "" {
		return schnorrEvidenceList, errors.New(errStr)
	}
	t.GetSigR()
	t.GetSigS(hash)
	t.KeySignPhase5AMsgSent.LabelFrom = t.label
	t.KeySignPhase5BMsgSent.LabelFrom = t.label
	proof := siProof.GetSiProof(t, t.sigS, t.siL, t.siRho)
	v, a, b := &btcec.PublicKey{}, &btcec.PublicKey{}, &btcec.PublicKey{}
	v.Curve, a.Curve, b.Curve = btcec.S256(), btcec.S256(), btcec.S256()
	v.X, v.Y, a.X, a.Y, b.X, b.Y = proof.VX, proof.VY, proof.AX, proof.AY, proof.BX, proof.BY
	vCommit, aCommit, bCommit := commit.GetPubkeyCommit(v, t.vBlindFactor), commit.GetPubkeyCommit(a, t.aBlindFactor), commit.GetPubkeyCommit(b, t.bBlindFactor)
	t.KeySignPhase5AMsgSent.SetNativeCommit(vCommit, aCommit, bCommit)
	t.KeySignPhase5BMsgSent.SetNativeSiProof(proof)
	t.KeySignPhase5BMsgSent.SetNativeBlindFactor(t.vBlindFactor, t.aBlindFactor, t.bBlindFactor)
	return nil, nil
}

func (t *Node) GetKeySignPhase5CAnd5DMsgSent(hash []byte, key *NodeKey, siCheck SiCheck) ([]*SiProofCheaterEvidence, error) {
	errStr := ""
	var siProofEvidenceList []*SiProofCheaterEvidence = make([]*SiProofCheaterEvidence, 0)
	for _, v := range t.KeySignPhase5BMsgReceived {
		var vCommit, aCommit, bCommit [32]byte
		for _, v1 := range t.KeySignPhase5AMsgReceived {
			if v1.LabelFrom == v.LabelFrom {
				vCommit, aCommit, bCommit = v1.GetNativeCommit()
			}
		}
		vBlindFactor, aBlindFactor, bBlindFactor := v.GetNativeBlindFactor()
		proof := v.GetNativeSiProof()
		v0, a, b := &btcec.PublicKey{}, &btcec.PublicKey{}, &btcec.PublicKey{}
		v0.Curve, a.Curve, b.Curve = btcec.S256(), btcec.S256(), btcec.S256()
		v0.X, v0.Y, a.X, a.Y, b.X, b.Y = proof.VX, proof.VY, proof.AX, proof.AY, proof.BX, proof.BY
		if !commit.CheckPubkeyCommit(vCommit, v0, vBlindFactor) || !commit.CheckPubkeyCommit(aCommit, a, aBlindFactor) ||
			!commit.CheckPubkeyCommit(bCommit, b, bBlindFactor) {
			errStr = errStr + v.LabelFrom + "COMMITMENT CHECK FAIL"
		}
		if !t.CheckSiProof(proof) {
			errStr = errStr + v.LabelFrom + " SiProof Fail"
			tempEvidence := &SiProofCheaterEvidence{v.LabelFrom, v.GetNativeSiProof(), t.sigR, t.SigRY, t.EccN}
			siProofEvidenceList = append(siProofEvidenceList, tempEvidence)
		}
	}
	if errStr != "" {
		return siProofEvidenceList, errors.New(errStr)
	}
	t.KeySignPhase5CMsgSent.LabelFrom = t.label
	t.KeySignPhase5DMsgSent.LabelFrom = t.label
	check := siCheck.GetSiCheck(t, hash, key.PubkeySum)
	u, t0 := check.U, check.T
	uCommit, tCommit := commit.GetPubkeyCommit(u, t.uBlindFactor), commit.GetPubkeyCommit(t0, t.tBlindFactor)
	t.KeySignPhase5CMsgSent.SetNativeCommit(uCommit, tCommit)
	t.KeySignPhase5DMsgSent.SetNativeSiCheck(check)
	t.KeySignPhase5DMsgSent.SetNativeBlindFactor(t.uBlindFactor, t.tBlindFactor)
	return nil, nil
}

func (t *Node) GetKeySignPhase5EMsgSent() ([]*SiCheckCheaterEvidence, error) {
	errStr := ""
	for _, v := range t.KeySignPhase5DMsgReceived {
		var uCommit, tCommit [32]byte
		for _, v1 := range t.KeySignPhase5CMsgReceived {
			if v1.LabelFrom == v.LabelFrom {
				uCommit, tCommit = v1.GetNativeCommit()
			}
		}
		uBlindFactor, tBlindFactor := v.GetNativeBlindFactor()
		check := v.GetNativeSiCheck()
		if !commit.CheckPubkeyCommit(uCommit, check.U, uBlindFactor) || !commit.CheckPubkeyCommit(tCommit, check.T, tBlindFactor) {
			errStr = errStr + v.LabelFrom + "COMMITMENT CHECK FAIL"
		}
	}
	if errStr != "" {
		return nil, errors.New(errStr)
	}
	siCheckEvidenceList, err := t.CheckSiCheck()
	if err != nil {
		return siCheckEvidenceList, err
	}
	t.KeySignPhase5EMsgSent.LabelFrom = t.label
	t.KeySignPhase5EMsgSent.SetNativeSigr(t.sigR)
	t.KeySignPhase5EMsgSent.SetNativeSigs(t.sigS)
	t.KeySignPhase5EMsgSent.SetNativeV(byte(t.SigRY.Bit(0)))
	return nil, nil
}

func (t *Node) getSigOthersRByLabel(label string) types.SigR {
	for _, v := range t.KeySignPhase3And4MsgReceived {
		if v.LabelFrom == label {
			return *v.SigOthersR
		}
	}
	return types.SigR{}
}

func (t *Node) GetSigS(hash []byte) {
	rd := new(big.Int).Mul(t.r, t.prtKey)

	for _, v := range t.KeySignPhase2MsgReceived {
		temp1 := paillierDec(v.MessageRResponse, t.paillierPrtKey)
		rd.Add(rd, temp1)
	}
	for _, v := range t.randNumArray {
		rd.Sub(rd, v)
	}
	theaInverse := new(big.Int).Set(t.theaLocal)

	for _, v := range t.KeySignPhase3And4MsgReceived {
		theaInverse.Add(theaInverse, v.GetNativeThea())
	}
	theaInverse.ModInverse(theaInverse, t.cure.Params().N)
	t.theaInverse = theaInverse
	e := hashToInt(hash, btcec.S256())
	tempS := new(big.Int).Mul(e, t.r)
	rd.Mul(rd, t.sigR)
	rd.Add(rd, tempS)
	rd.Mul(rd, t.theaInverse)
	t.sigS = rd.Mod(rd, t.cure.Params().N)

}

func (t *Node) GetSigR() {
	ecdsaPub := btcec.PublicKey{}
	ecdsaPub.Curve = t.cure
	resultX, resultY := elliptic.Curve.ScalarBaseMult(t.cure, t.k.Bytes())
	t.sigLocalR.X = resultX.Bytes()
	t.sigLocalR.Y = resultY.Bytes()
	for _, v := range t.KeySignPhase3And4MsgReceived {
		temp := v.GetNativeSigOthersR()
		resultX, resultY = ecdsaPub.Add(resultX, resultY, temp.X, temp.Y)
	}
	t.sigR = resultX
	t.SigRY = resultY
}

func (t *Node) CheckSig(signnode []types.KeySignPhase5EMsg, keynode []types.KeyGenPhase2Msg, hash []byte) {
	resultS := big.NewInt(0)
	resultR := big.NewInt(0)
	pubKeySum := &btcec.PublicKey{}
	pubKeySum.Curve = btcec.S256()
	pubKeySum.X = big.NewInt(0)
	pubKeySum.Y = big.NewInt(0)
	for _, v := range keynode {
		temp := v.GetNativePubKey()
		pubKeySum.X, pubKeySum.Y = pubKeySum.Add(pubKeySum.X, pubKeySum.Y, temp.X, temp.Y)
	}
	for _, v := range signnode {
		resultS.Add(resultS, v.GetNativeSigs())
	}
	resultS.Mod(resultS, t.EccN)
	resultR.Mod(signnode[0].GetNativeSigr(), t.EccN)
	signatureF := btcec.Signature{}
	signatureF.R = resultR
	signatureF.S = resultS

	if signatureF.Verify(hash, pubKeySum) {
		t.Logger.Debug("PASS")
	} else {
		t.Logger.Debug("FAIL")
	}
}

func getCofCommits(cof []*big.Int) []*btcec.PublicKey {
	commits := make([]*btcec.PublicKey, len(cof))
	for i, v := range cof {
		tempCommit := &btcec.PublicKey{}
		tempCommit.Curve = btcec.S256()
		tempCommit.X, tempCommit.Y = tempCommit.ScalarBaseMult(v.Bytes())
		commits[i] = tempCommit
	}
	return commits
}

func getCheckByX(x *big.Int, commits []*btcec.PublicKey) *btcec.PublicKey {
	check := &btcec.PublicKey{}
	check.Curve = btcec.S256()
	check.X, check.Y = big.NewInt(0), big.NewInt(0)
	for k, v := range commits {
		temp := big.NewInt(0)
		bigK := big.NewInt(int64(k))
		temp.Exp(x, bigK, nil)
		expMul := &btcec.PublicKey{}
		expMul.Curve = btcec.S256()
		expMul.X, expMul.Y = expMul.ScalarMult(v.X, v.Y, temp.Bytes())
		check.X, check.Y = check.Add(check.X, check.Y, expMul.X, expMul.Y)
	}
	return check
}

func getCheckByY(y *big.Int) *btcec.PublicKey {
	check := &btcec.PublicKey{}
	check.Curve = btcec.S256()
	check.X, check.Y = check.ScalarBaseMult(y.Bytes())
	return check
}

func hashToInt(hash []byte, c elliptic.Curve) *big.Int {
	orderBits := c.Params().N.BitLen()
	orderBytes := (orderBits + 7) / 8
	if len(hash) > orderBytes {
		hash = hash[:orderBytes]
	}

	ret := new(big.Int).SetBytes(hash)
	excess := len(hash)*8 - orderBits
	if excess > 0 {
		ret.Rsh(ret, uint(excess))
	}
	return ret
}

//TODO:更好的方法随机生成与max互质的re
func randGCD(max *big.Int) *big.Int {
	re, _ := rand.Int(rand.Reader, max)
	for big.NewInt(0).GCD(nil, nil, re, max).Cmp(big.NewInt(1)) != 0 {
		re, _ = rand.Int(rand.Reader, max)
	}
	return re
}

func (t *Node) GetSenderRangeProof(m, r, nTilde, h1, h2 *big.Int, oneCipher []byte) types.SenderRangeProof {
	//generate randam α β γ ρ
	range1 := big.NewInt(0).Mul(t.qCube, nTilde)
	range2 := big.NewInt(0).Mul(t.q, nTilde)
	alpha, _ := rand.Int(rand.Reader, t.qCube)
	beta := randGCD(t.paillierPubKey.N)
	gamma, _ := rand.Int(rand.Reader, range1)
	rho, _ := rand.Int(rand.Reader, range2)
	//compute z μ w
	N := nTilde
	z1 := big.NewInt(0).Exp(h1, m, N)
	z2 := big.NewInt(0).Exp(h2, rho, N)
	z := z1.Mul(z1, z2)
	z = z.Mod(z, N)
	w1 := big.NewInt(0).Exp(h1, alpha, N)
	w2 := big.NewInt(0).Exp(h2, gamma, N)
	w := w1.Mul(w1, w2)
	w = w.Mod(w, N)
	mu, _ := PaillierEncrypt(t.paillierPubKey, alpha.Bytes(), beta)
	//compute e
	//文献27中没有做e的交互，而是使用如下的方法用hash确定e的值
	hash := sha256.New()
	_, _ = hash.Write(z.Bytes())
	_, _ = hash.Write(w.Bytes())
	_, _ = hash.Write(mu.Bytes())
	e := big.NewInt(0).SetBytes(hash.Sum(nil))
	e = e.Mod(e, t.EccN)
	//compute s s1 s2
	s := big.NewInt(0).Exp(r, e, t.paillierPubKey.N)
	s = s.Mul(s, beta)
	s = s.Mod(s, t.paillierPubKey.N)
	s1 := computeLinearSum(e, m, alpha)
	s2 := computeLinearSum(e, rho, gamma)
	//generate proof
	result := types.SenderRangeProof{
		Z:  z,
		W:  w,
		Mu: mu,
		S:  s,
		S1: s1,
		S2: s2,
	}
	return result
}

func (t *Node) CheckSenderRangeProof(proof types.SenderRangeProof, encM []byte, pubkey *gaillier.PubKey) bool {
	//check s1 <= q^3
	c := big.NewInt(0).SetBytes(encM)
	if proof.S1.Cmp(t.qCube) > 0 {
		return false
	}
	//check μ = Τ^s1*s^N*c^-e
	hash := sha256.New()
	_, _ = hash.Write(proof.Z.Bytes())
	_, _ = hash.Write(proof.W.Bytes())
	_, _ = hash.Write(proof.Mu.Bytes())
	e := big.NewInt(0).SetBytes(hash.Sum(nil))
	e = e.Mod(e, t.EccN)
	check1, _ := PaillierEncrypt(pubkey, proof.S1.Bytes(), proof.S)
	check1 = check1.Mul(check1, big.NewInt(0).Exp(c, big.NewInt(0).Sub(big.NewInt(0), e), pubkey.Nsq))
	check1 = check1.Mod(check1, pubkey.Nsq)
	if proof.Mu.Cmp(check1) != 0 {
		return false
	}
	//check w = h1^s1*h2^s2*z^-e
	N := t.NTilde[t.label]
	w := big.NewInt(0).Set(proof.W)
	w1 := big.NewInt(0).Exp(t.h1[t.label], proof.S1, N)
	w2 := big.NewInt(0).Exp(t.h2[t.label], proof.S2, N)
	wMul := big.NewInt(0).Mul(w1, w2)
	w3 := big.NewInt(0).Exp(proof.Z, big.NewInt(0).Sub(big.NewInt(0), e), N)
	wMul = wMul.Mul(wMul, w3)
	wMul = wMul.Mod(wMul, N)
	return wMul.Cmp(w) == 0
}

//x*Ec1+E(y),r为paillier中使用的随机数,encM为上轮收到的加密的信息
func (t *Node) GetReceiverRangeProof(x, y, r *big.Int, encM []byte, pubkey *gaillier.PubKey, nTilde, h1, h2 *big.Int) types.ReceiverRangeProof {
	c1 := big.NewInt(0).SetBytes(encM)
	//generate randam α ρ ρ‘ σ β γ τ
	range1 := big.NewInt(0).Mul(t.q, nTilde)
	range2 := big.NewInt(0).Mul(t.qCube, nTilde)
	alpha, _ := rand.Int(rand.Reader, t.qCube)
	rho, _ := rand.Int(rand.Reader, range1)
	rhoD, _ := rand.Int(rand.Reader, range2)
	sigma, _ := rand.Int(rand.Reader, range1)
	tau, _ := rand.Int(rand.Reader, range1)
	beta := randGCD(pubkey.N)
	gamma := randGCD(pubkey.N)
	//compute u z z' t v w
	curve := btcec.S256()
	N := nTilde
	muX, muY := curve.ScalarBaseMult(alpha.Bytes())
	z1 := big.NewInt(0).Exp(h1, x, N)
	z2 := big.NewInt(0).Exp(h2, rho, N)
	z := z1.Mul(z1, z2)
	z = z.Mod(z, N)
	zD1 := big.NewInt(0).Exp(h1, alpha, N)
	zD2 := big.NewInt(0).Exp(h2, rhoD, N)
	zD := zD1.Mul(zD1, zD2)
	zD = zD.Mod(zD, N)
	tt1 := big.NewInt(0).Exp(h1, y, N)
	tt2 := big.NewInt(0).Exp(h2, sigma, N)
	tt := tt1.Mul(tt1, tt2)
	tt = tt.Mod(tt, N)
	v1 := new(big.Int).Exp(c1, alpha, pubkey.Nsq)
	v2, _ := PaillierEncrypt(pubkey, gamma.Bytes(), beta)
	v := v1.Mul(v1, v2)
	v = v.Mod(v, pubkey.Nsq)
	w1 := big.NewInt(0).Exp(h1, gamma, N)
	w2 := big.NewInt(0).Exp(h2, tau, N)
	w := w1.Mul(w1, w2)
	w = w.Mod(w, N)
	//compute e
	hash := sha256.New()
	_, _ = hash.Write(muX.Bytes())
	_, _ = hash.Write(muY.Bytes())
	_, _ = hash.Write(z.Bytes())
	_, _ = hash.Write(zD.Bytes())
	_, _ = hash.Write(v.Bytes())
	_, _ = hash.Write(w.Bytes())
	e := big.NewInt(0).SetBytes(hash.Sum(nil))
	e = e.Mod(e, t.EccN)
	//compute s s1 s2
	s := big.NewInt(0).Exp(r, e, pubkey.N)
	s = s.Mul(s, beta)
	s = s.Mod(s, pubkey.N)
	s1 := computeLinearSum(e, x, alpha)
	s2 := computeLinearSum(e, rho, rhoD)
	t1 := computeLinearSum(e, y, gamma)
	t2 := computeLinearSum(e, sigma, tau)
	//generate proof
	XX, XY := curve.ScalarBaseMult(x.Bytes())
	// tempC2, _ := PaillierEncrypt(pubkey, y.Bytes(), r)
	// c2 := new(big.Int).Mod(new(big.Int).Mul(tempC2, new(big.Int).Exp(c1, x, pubkey.Nsq)), pubkey.Nsq)
	result1 := types.ReceiverRangeProof{
		MuX: muX,
		MuY: muY,
		Z:   z,
		ZD:  zD,
		T:   tt,
		V:   v,
		W:   w,
		S:   s,
		S1:  s1,
		S2:  s2,
		T1:  t1,
		T2:  t2,
		XX:  XX,
		XY:  XY,
	}
	return result1
}

func (t *Node) CheckReceiverRangeProof(p types.ReceiverRangeProof, m1 []byte, m2 []byte, pubkey *gaillier.PubKey) bool {
	c1 := big.NewInt(0).SetBytes(m1)
	c2 := big.NewInt(0).SetBytes(m2)
	if p.S1.Cmp(t.qCube) > 0 {
		return false
	}
	//check s1.G = e.X*u
	hash := sha256.New()
	_, _ = hash.Write(p.MuX.Bytes())
	_, _ = hash.Write(p.MuY.Bytes())
	_, _ = hash.Write(p.Z.Bytes())
	_, _ = hash.Write(p.ZD.Bytes())
	_, _ = hash.Write(p.V.Bytes())
	_, _ = hash.Write(p.W.Bytes())
	e := big.NewInt(0).SetBytes(hash.Sum(nil))
	e = e.Mod(e, t.EccN)
	curve := btcec.S256()
	check1X, check1Y := curve.ScalarBaseMult(p.S1.Bytes())
	check1CompareX, check1CompareY := curve.ScalarMult(p.XX, p.XY, e.Bytes())
	check1CompareX, check1CompareY = curve.Add(p.MuX, p.MuY, check1CompareX, check1CompareY)
	if check1X.Cmp(check1CompareX) != 0 || check1Y.Cmp(check1CompareY) != 0 {
		return false
	}
	//check h1^s1*h2^s2 = z^e*z'
	N := t.NTilde[t.label]
	check2 := big.NewInt(0).Exp(t.h1[t.label], p.S1, N)
	check2Temp := big.NewInt(0).Exp(t.h2[t.label], p.S2, N)
	check2 = check2.Mul(check2, check2Temp)
	check2 = check2.Mod(check2, N)
	check2Compare := big.NewInt(0).Exp(p.Z, e, N)
	check2Compare = check2Compare.Mul(check2Compare, p.ZD)
	check2Compare = check2Compare.Mod(check2Compare, N)
	if check2.Cmp(check2Compare) != 0 {
		return false
	}
	//check h1^t1*h2^t2 = t^e*w
	check3 := big.NewInt(0).Exp(t.h1[t.label], p.T1, N)
	check3Temp := big.NewInt(0).Exp(t.h2[t.label], p.T2, N)
	check3 = check3.Mul(check3, check3Temp)
	check3 = check3.Mod(check3, N)
	check3Compare := big.NewInt(0).Exp(p.T, e, N)
	check3Compare = check3Compare.Mul(check3Compare, p.W)
	check3Compare = check3Compare.Mod(check3Compare, N)
	if check3.Cmp(check3Compare) != 0 {
		return false
	}
	//c1^s1*s^N*T^t1 = c2^e*v mod N^2
	check4, _ := PaillierEncrypt(pubkey, p.T1.Bytes(), p.S)
	check4 = check4.Mod(check4, pubkey.Nsq)
	check4 = new(big.Int).Mod(new(big.Int).Mul(check4, new(big.Int).Exp(c1, p.S1, pubkey.Nsq)), pubkey.Nsq)
	check4Compare := new(big.Int).Mod(new(big.Int).Mul(p.V, new(big.Int).Exp(c2, e, pubkey.Nsq)), pubkey.Nsq)
	return check4.Cmp(check4Compare) == 0
}

//s为局部的签名的s,l,rho为随机生成的用于0知识证明的随机数
func (t *Node) GetSiProof(s, l, rho *big.Int) types.SiZKProof {
	//生成Vi,Ai,Bi
	localV := &btcec.PublicKey{}
	localV.Curve = btcec.S256()
	localV.X, localV.Y = localV.ScalarMult(t.sigR, t.SigRY, s.Bytes())
	tempV := getPubkeyByNum(l)
	localV.X, localV.Y = localV.Add(localV.X, localV.Y, tempV.X, tempV.Y)
	localA := getPubkeyByNum(rho)
	localB := &btcec.PublicKey{}
	localB.Curve = btcec.S256()
	localB.X, localB.Y = tempV.ScalarMult(tempV.X, tempV.Y, rho.Bytes())
	//随机生成a,b
	a, _ := btcec.NewPrivateKey(btcec.S256())
	b, _ := btcec.NewPrivateKey(btcec.S256())
	//生成alpha,beta
	alpha, beta := &btcec.PublicKey{}, &btcec.PublicKey{}
	alpha.Curve = btcec.S256()
	beta.Curve = btcec.S256()
	tempAlpha := getPubkeyByNum(b.D)
	alpha.X, alpha.Y = alpha.ScalarMult(t.sigR, t.SigRY, a.D.Bytes())
	alpha.X, alpha.Y = alpha.Add(alpha.X, alpha.Y, tempAlpha.X, tempAlpha.Y)
	beta.X, beta.Y = beta.ScalarMult(localA.X, localA.Y, b.D.Bytes())
	//生成c
	hash := sha256.New()
	_, _ = hash.Write(alpha.X.Bytes())
	_, _ = hash.Write(alpha.Y.Bytes())
	_, _ = hash.Write(beta.X.Bytes())
	_, _ = hash.Write(beta.Y.Bytes())
	c := big.NewInt(0).SetBytes(hash.Sum(nil))
	c = c.Mod(c, t.EccN)
	//生成T,u
	T := computeLinearSum(c, s, a.D)
	u := computeLinearSum(c, l, b.D)
	result := types.SiZKProof{
		VX:     localV.X,
		VY:     localV.Y,
		AX:     localA.X,
		AY:     localA.Y,
		BX:     localB.X,
		BY:     localB.Y,
		AlphaX: alpha.X,
		AlphaY: alpha.Y,
		BetaX:  beta.X,
		BetaY:  beta.Y,
		T:      T,
		U:      u,
	}
	return result
}

//
func (t *Node) CheckSiProof(proof types.SiZKProof) bool {
	//t.R+u.G = alpha+c.V
	check1 := &btcec.PublicKey{}
	check1.Curve = btcec.S256()
	check1.X, check1.Y = check1.ScalarMult(t.sigR, t.SigRY, proof.T.Bytes())
	tempCheck1 := getPubkeyByNum(proof.U)
	check1.X, check1.Y = check1.Add(check1.X, check1.Y, tempCheck1.X, tempCheck1.Y)

	hash := sha256.New()
	_, _ = hash.Write(proof.AlphaX.Bytes())
	_, _ = hash.Write(proof.AlphaY.Bytes())
	_, _ = hash.Write(proof.BetaX.Bytes())
	_, _ = hash.Write(proof.BetaY.Bytes())
	c := big.NewInt(0).SetBytes(hash.Sum(nil))
	c = c.Mod(c, t.EccN)
	check1Compare := &btcec.PublicKey{}
	check1Compare.Curve = btcec.S256()
	check1Compare.X, check1Compare.Y = check1Compare.ScalarMult(proof.VX, proof.VY, c.Bytes())
	check1Compare.X, check1Compare.Y = check1Compare.Add(check1Compare.X, check1Compare.Y, proof.AlphaX, proof.AlphaY)
	if !check1.IsEqual(check1Compare) {
		return false
	}
	//u.A = beta+c.B
	check2 := &btcec.PublicKey{}
	check2.Curve = btcec.S256()
	check2.X, check2.Y = check2.ScalarMult(proof.AX, proof.AY, proof.U.Bytes())
	check2Compare := &btcec.PublicKey{}
	check2Compare.Curve = btcec.S256()
	check2Compare.X, check2Compare.Y = check2Compare.ScalarMult(proof.BX, proof.BY, c.Bytes())
	check2Compare.X, check2Compare.Y = check2Compare.Add(check2Compare.X, check2Compare.Y, proof.BetaX, proof.BetaY)
	return check2.IsEqual(check2Compare)
}

//hash为需要签名的对象，pubkey为最终的公钥
func (t *Node) GetSiCheck(hash []byte, pubkey *btcec.PublicKey) types.SiZKCheck {
	//V:=sum(vi)- (e.G + r*da.G)
	//U := V*rho
	e := hashToInt(hash, btcec.S256())
	V := getPubkeyByNum(e)
	tempVx, tempVy := pubkey.ScalarMult(pubkey.X, pubkey.Y, t.sigR.Bytes())
	V.X, V.Y = V.Add(V.X, V.Y, tempVx, tempVy)
	V.Y = V.Y.Sub(btcec.S256().P, V.Y)
	U := &btcec.PublicKey{}
	U.Curve = btcec.S256()
	U.X, U.Y = big.NewInt(0), big.NewInt(0)
	for _, v := range t.KeySignPhase5BMsgReceived {
		p := v.GetNativeSiProof()
		U.X, U.Y = U.Add(U.X, U.Y, p.VX, p.VY)
	}
	U.X, U.Y = U.Add(U.X, U.Y, V.X, V.Y)
	U.X, U.Y = U.ScalarMult(U.X, U.Y, t.siRho.Bytes())
	T := &btcec.PublicKey{}
	T.Curve = btcec.S256()
	T.X, T.Y = big.NewInt(0), big.NewInt(0)
	for _, v := range t.KeySignPhase5BMsgReceived {
		if v.LabelFrom != t.label {
			p := v.GetNativeSiProof()
			T.X, T.Y = T.Add(T.X, T.Y, p.AX, p.AY)
		}
	}
	T.X, T.Y = T.ScalarMult(T.X, T.Y, t.siL.Bytes())
	return types.SiZKCheck{
		U: U,
		T: T,
	}
}

//无法得知作弊节点，返回的是所有节点的信息
func (t *Node) CheckSiCheck() ([]*SiCheckCheaterEvidence, error) {
	var siCheckEvidenceList []*SiCheckCheaterEvidence = make([]*SiCheckCheaterEvidence, 0)
	//sum(Ti+Bi)== sum(Ui)
	check := &btcec.PublicKey{}
	check.Curve = btcec.S256()
	check.X, check.Y = big.NewInt(0), big.NewInt(0)
	for _, v0 := range t.KeySignPhase5BMsgReceived {
		temp := &btcec.PublicKey{}
		temp.Curve = btcec.S256()
		temp.X, temp.Y = big.NewInt(0), big.NewInt(0)
		for _, v1 := range t.KeySignPhase5DMsgReceived {
			if v0.LabelFrom == v1.LabelFrom {
				p := v0.GetNativeSiProof()
				c := v1.GetNativeSiCheck()
				tempSiCheckCheaterEvidence := &SiCheckCheaterEvidence{v1.LabelFrom, v1.GetNativeSiCheck(), p.BX, p.BY}
				siCheckEvidenceList = append(siCheckEvidenceList, tempSiCheckCheaterEvidence)
				temp.X, temp.Y = temp.Add(p.BX, p.BY, c.T.X, c.T.Y)
			}
		}
		check.X, check.Y = check.Add(check.X, check.Y, temp.X, temp.Y)
	}
	checkCompare := &btcec.PublicKey{}
	checkCompare.Curve = btcec.S256()
	checkCompare.X, checkCompare.Y = big.NewInt(0), big.NewInt(0)
	for _, v := range t.KeySignPhase5DMsgReceived {
		c := v.GetNativeSiCheck()
		checkCompare.X, checkCompare.Y = checkCompare.Add(checkCompare.X, checkCompare.Y, c.U.X, c.U.Y)
	}
	if !check.IsEqual(checkCompare) {
		return siCheckEvidenceList, errors.New("SiCheck Fail")
	}
	return nil, nil
}

//return a*b+c
func computeLinearSum(a, b, c *big.Int) *big.Int {
	result := new(big.Int).Mul(a, b)
	result = result.Add(result, c)
	return result
}
