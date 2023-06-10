package dsign

import (
	"errors"
	"github.com/bluehelix-chain/dsign/bhcrypto"
	"github.com/bluehelix-chain/dsign/bhcrypto/bhcheck"
	"github.com/bluehelix-chain/dsign/bhcrypto/bhs256k1"
	"github.com/bluehelix-chain/dsign/bhsssa"
	"github.com/bluehelix-chain/dsign/logger"
	"math/big"

	"github.com/bluehelix-chain/dsign/communicator"
	"github.com/bluehelix-chain/dsign/types"
)

var (
	maxRand, _       = new(big.Int).SetString("11579208923731619542357098500868790", 10)
	pqProofK         = 16
	paillierLength   = 2048
	rsaLength        = 1024
	rsaMaxReuseTimes = 10
)

type KeyGenerator struct {
	label        string
	share        bhcheck.Share
	sch          bhcheck.Schnorr
	pq           bhcheck.PQProof
	rsaGenerator *bhcrypto.RSAParameterGenerator
	logger       logger.Logger
}

func NewKeyGenerator(label string, logger logger.Logger) *KeyGenerator {
	return &KeyGenerator{
		label:        label,
		logger:       logger,
		share:        &bhcheck.HonestShare{},
		sch:          &bhcheck.HonestSchnorr{},
		pq:           &bhcheck.HonestPQProof{},
		rsaGenerator: bhcrypto.NewRSAParameterGenerator(rsaLength, rsaMaxReuseTimes),
	}
}

func (kg *KeyGenerator) WithShare(share bhcheck.Share) *KeyGenerator {
	kg.share = share
	return kg
}

func (kg *KeyGenerator) WithSchnorr(sch bhcheck.Schnorr) *KeyGenerator {
	kg.sch = sch
	return kg
}

func (kg *KeyGenerator) WithPQProof(pq bhcheck.PQProof) *KeyGenerator {
	kg.pq = pq
	return kg
}

func (kg *KeyGenerator) KeyGen(nodeList []string, t int, comm communicator.Communicator) (*NodeKey, *bhcheck.Evidence, error) {
	n := len(nodeList)
	if t > n {
		return nil, nil, errors.New("invalid params")
	}
	if !isInList(kg.label, nodeList) {
		return nil, nil, errors.New("not in sign list")
	}

	coeff := getCoeff(nodeList)
	rsaParameter, err := kg.rsaGenerator.GetRSAParameter()
	if err != nil {
		return nil, nil, err
	}

	nodekey, err := NewNodeKey(kg.label, t, n, coeff, comm, kg.pq, rsaParameter, kg.logger)
	if err != nil {
		return nil, nil, err
	}
	nodekey.comm.SendKeyGenPhase1Message(nodekey.KeyGenPhase1MsgSent)
	evidence := &bhcheck.Evidence{}
	for i := 0; i < n; i++ {
		msg, err := nodekey.comm.GetKeyGenPhase1Message()
		if err != nil {
			received := []string{kg.label}
			for _, msg := range nodekey.KeyGenPhase1MsgReceived {
				received = append(received, msg.LabelFrom)
			}
			negativeNodes := getMissingStrings(received, nodeList)
			evidence.SetNegativeNodes(negativeNodes)
			return nil, evidence, err
		}
		nodekey.KeyGenPhase1MsgReceived = append(nodekey.KeyGenPhase1MsgReceived, msg)
	}
	nodekey.GetKeyGenPhase1MsgMap()

	if err := nodekey.GetKeyGenPhase2MsgSent(); err != nil {
		return nil, nil, err
	}

	nodekey.comm.SendKeyGenPhase2Message(nodekey.KeyGenPhase2MsgSent)
	for i := 0; i < n; i++ {
		msg, err := nodekey.comm.GetKeyGenPhase2Message()
		if err != nil {
			received := []string{kg.label}
			for _, msg := range nodekey.KeyGenPhase2MsgReceived {
				received = append(received, msg.LabelFrom)
			}
			negativeNodes := getMissingStrings(received, nodeList)
			evidence.SetNegativeNodes(negativeNodes)
			return nil, evidence, err
		}
		nodekey.KeyGenPhase2MsgReceived = append(nodekey.KeyGenPhase2MsgReceived, msg)
	}
	nodekey.GetKeyGenPhase2MsgMap()
	if !nodekey.CheckShamirCommit() || !nodekey.CheckPubKeyCommit() {
		// TODO: return the true evidence
		return nil, nil, errors.New("COMMITMENT CHECK FAIL")
	}
	pqEvidenceList, err := nodekey.CheckPQProof()
	if err != nil {
		evidence.SetPQProofEvidences(pqEvidenceList)
		return nil, evidence, err
	}

	nodekey.GetKeyGenPhase3MsgSent(kg.share, kg.sch)
	nodekey.comm.SendKeyGenPhase3Message(nodekey.KeyGenPhase3MsgSent)
	errStr := ""
	var schnorrEvidenceList []*bhcheck.SchnorrCheaterEvidence = make([]*bhcheck.SchnorrCheaterEvidence, 0)
	for i := 0; i < n; i++ {
		temp, err := nodekey.comm.GetKeyGenPhase3Message()
		if err != nil {
			received := []string{kg.label}
			for _, msg := range nodekey.KeyGenPhase3MsgReceived {
				received = append(received, msg.LabelFrom)
			}
			negativeNodes := getMissingStrings(received, nodeList)
			evidence.SetNegativeNodes(negativeNodes)
			return nil, evidence, err
		}
		nodekey.KeyGenPhase3MsgReceived = append(nodekey.KeyGenPhase3MsgReceived, temp)
		p := temp.GetNativeSchnorrZKProof()
		label := temp.LabelFrom
		pubKey, _ := bhs256k1.ParsePubKey(nodekey.KeyGenPhase2MsgMap[label].PubKey, bhs256k1.S256())
		if !bhcheck.CheckPubkeyProof(p, pubKey, bhs256k1.S256()) {
			errStr = errStr + temp.LabelFrom + " SCHNORR PROOF CHECK FAIL"
			tempEvidence := &bhcheck.SchnorrCheaterEvidence{temp.LabelFrom, p, pubKey}
			schnorrEvidenceList = append(schnorrEvidenceList, tempEvidence)
		}
	}
	if errStr != "" {
		evidence.SetSchnorrCheaterEvidences(schnorrEvidenceList)
		return nil, evidence, errors.New(errStr)
	}
	//TODO:ok==false时，检查所有C(n,t)+C(n,t+1)+……+C(n,n)的组合，找出作弊节点
	ok, shamirEvidence := nodekey.checkFinalShare()
	if !ok {
		evidence.SetShamirCheckEvidence(shamirEvidence)
		return nil, evidence, errors.New("FINAL SHAMIR CHECK FAIL")
	}

	return nodekey, nil, nil

}

//For External Extract data from Nodekey
func GetKeyGenData(n *NodeKey) *types.KeyGenData {
	entry := &types.KeyGenData{
		Label:         n.GetLabel(),
		SignThreshold: uint64(n.T),
		Paras:         make([]*types.ParameterMap, 0),
		PubKeySum:     n.PubkeySum.SerializeCompressed(),
		KeyNodes:      make([]string, len(n.KeyNodes)),
	}

	copy(entry.KeyNodes, n.KeyNodes)

	for k, v := range n.ShareReceived {
		tempPara := &types.ParameterMap{}
		tempPara.Label = k
		tempPara.Share = &types.ShareXY{
			X: v.X.Bytes(),
			Y: v.Y.Bytes(),
		}
		tempPara.NTilde = n.NTilde[k].Bytes()
		tempPara.H1 = n.h1[k].Bytes()
		tempPara.H2 = n.h2[k].Bytes()
		entry.Paras = append(entry.Paras, tempPara)
	}
	return entry
}

//For External Recover data to Nodekey
func SetKeyGenData(data *types.KeyGenData) *NodeKey {
	nodeKey := &NodeKey{}
	nodeKey.SetLabel(data.Label)
	nodeKey.N = len(data.Paras)
	nodeKey.T = int(data.SignThreshold)
	nodeKey.ShareReceived = make(map[string]bhsssa.ShareXY)
	nodeKey.NTilde = make(map[string]*big.Int)
	nodeKey.h1 = make(map[string]*big.Int)
	nodeKey.h2 = make(map[string]*big.Int)
	nodeKey.KeyNodes = make([]string, len(data.KeyNodes))
	copy(nodeKey.KeyNodes, data.KeyNodes)
	for _, para := range data.Paras {
		tempShare := bhsssa.ShareXY{
			X: new(big.Int).SetBytes(para.Share.X),
			Y: new(big.Int).SetBytes(para.Share.Y),
		}
		nodeKey.ShareReceived[para.Label] = tempShare
		nodeKey.NTilde[para.Label] = new(big.Int).SetBytes(para.NTilde)
		nodeKey.h1[para.Label] = new(big.Int).SetBytes(para.H1)
		nodeKey.h2[para.Label] = new(big.Int).SetBytes(para.H2)
	}
	nodeKey.PubkeySum, _ = bhs256k1.ParsePubKey(data.PubKeySum, bhs256k1.S256())
	return nodeKey
}
