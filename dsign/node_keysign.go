package dsign

import (
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"github.com/bluehelix-chain/dsign/bhcrypto"
	"github.com/bluehelix-chain/dsign/bhcrypto/bhcheck"
	"github.com/bluehelix-chain/dsign/bhcrypto/bhs256k1"
	"github.com/bluehelix-chain/dsign/bhsssa"
	"github.com/bluehelix-chain/dsign/communicator"
	"github.com/bluehelix-chain/dsign/logger"
	"github.com/bluehelix-chain/dsign/types"
	"github.com/radicalrafi/gomorph/gaillier"
	"math/big"
)

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
	shares                       []bhsssa.ShareXY
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
	nodekey *NodeKey, comm communicator.Communicator, r bhcheck.Random, logger logger.Logger) (*Node, error) {

	pubKey, prtKey, err := gaillier.GenerateKeyPair(rand.Reader, paillierLength)
	if err != nil {
		return nil, err
	}
	t := &Node{}
	tempShares := []bhsssa.ShareXY{}
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
	t.prtKey = bhsssa.KeyCombine(t.Nodelist, t.label, tempShares, bhsssa.S256k1Prime)
	tempk := r.RandomNum(maxRand)
	tempr := r.RandomNum(maxRand)
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
	oneCipher, oneR := bhcrypto.PaillierEnc(big.NewInt(1), t.paillierPubKey)
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
		pubkey := bhs256k1.GetPubkeyByNum(t.k)
		t.KeySignPhase1MsgSent[k].SetNativeSigRCommit(bhcheck.GetPubkeyCommit(pubkey, t.sigRBlindFactor, bhs256k1.S256()))
		t.KeySignPhase1MsgSent[k].SetNativePaillierPubKey(t.paillierPubKey)
		nTilde, h1, h2 := t.NTilde[v], t.h1[v], t.h2[v]
		proofK := t.GetSenderRangeProof(t.k, t.paillierRk, nTilde, h1, h2, oneCipher)
		proofR := t.GetSenderRangeProof(t.r, t.paillierRr, nTilde, h1, h2, oneCipher)
		t.KeySignPhase1MsgSent[k].SetNativeSenderRangeProofK(proofK)
		t.KeySignPhase1MsgSent[k].SetNativeSenderRangeProofR(proofR)
	}
}

func (t *Node) GetKeySignPhase2MsgSent(re bhcheck.Response) ([]*bhcheck.SendingCheaterEvidence, error) {
	t.KeySignPhase2MsgSent = make([]types.KeySignPhase2Msg, t.P-1)
	errStr := ""
	var evidenceList []*bhcheck.SendingCheaterEvidence = make([]*bhcheck.SendingCheaterEvidence, 0)
	for k, v := range t.KeySignPhase1MsgReceived { //KeySignPhase1MsgReceived中不包含自身
		if !CheckSenderRangeProof(t.NTilde[t.label], t.h1[t.label], t.h2[t.label], t.qCube, t.EccN, v.GetNativeSenderRangeProofK(), v.MessageK, v.GetNativePaillierPubKey()) {
			errStr = errStr + v.LabelFrom + "K\n"
			temp := &bhcheck.SendingCheaterEvidence{v.LabelFrom, v.GetNativeSenderRangeProofK(), v.MessageK, v.GetNativePaillierPubKey()}
			evidenceList = append(evidenceList, temp)
		}
		if !CheckSenderRangeProof(t.NTilde[t.label], t.h1[t.label], t.h2[t.label], t.qCube, t.EccN, v.GetNativeSenderRangeProofR(), v.MessageR, v.GetNativePaillierPubKey()) {
			errStr = errStr + v.LabelFrom + "R\n"
			temp := &bhcheck.SendingCheaterEvidence{v.LabelFrom, v.GetNativeSenderRangeProofR(), v.MessageR, v.GetNativePaillierPubKey()}
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
		oneCipher, oneR := bhcrypto.PaillierEnc(big.NewInt(1), pub)
		t.KeySignPhase2MsgSent[k].MessageKResponse, Rk = getAnotherPart(v.MessageK, pub, t.randNumArray[k], t.r, oneCipher, oneR)
		t.KeySignPhase2MsgSent[k].MessageRResponse, Rr = getAnotherPart(v.MessageR, pub, t.randNumArray[k], t.prtKey, oneCipher, oneR)
		reR, rePrtKey := re.Respond(t.r, t.prtKey)
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

func (t *Node) GetKeySignPhase3And4MsgSent(sh bhcheck.Schnorr) ([]*bhcheck.ReceivingCheaterEvidence, error) {
	t.KeySignPhase3And4MsgSent.LabelFrom = t.label
	thea := new(big.Int).Mul(t.k, t.r)
	errStr := ""
	var evidenceList []*bhcheck.ReceivingCheaterEvidence = make([]*bhcheck.ReceivingCheaterEvidence, 0)
	for k, v := range t.KeySignPhase2MsgReceived {
		if !t.CheckReceiverRangeProof(v.GetNativeReceiverRangeProofK(), t.KeySignPhase1MsgSent[k].MessageK, v.MessageKResponse, t.paillierPubKey) {
			errStr = errStr + v.LabelFrom + "K\n"
			temp := &bhcheck.ReceivingCheaterEvidence{v.LabelFrom, v.GetNativeReceiverRangeProofK(), t.KeySignPhase1MsgSent[k].MessageK, v.MessageKResponse, t.paillierPubKey}
			evidenceList = append(evidenceList, temp)
		}
		if !t.CheckReceiverRangeProof(v.GetNativeReceiverRangeProofR(), t.KeySignPhase1MsgSent[k].MessageR, v.MessageRResponse, t.paillierPubKey) {
			errStr = errStr + v.LabelFrom + "R\n"
			temp := &bhcheck.ReceivingCheaterEvidence{Label: v.LabelFrom, Proof: v.GetNativeReceiverRangeProofR(), M1: t.KeySignPhase1MsgSent[k].MessageR, M2: v.MessageRResponse, Pubkey: t.paillierPubKey}
			evidenceList = append(evidenceList, temp)
		}
		if errStr != "" {
			continue
		}
		temp := bhcrypto.PaillierDec(v.MessageKResponse, t.paillierPrtKey)
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
	t.KeySignPhase3And4MsgSent.SetNativeSchnorrZKProof(sh.Proof(t.k, bhs256k1.S256()))
	return nil, nil
}

func (t *Node) GetKeySignPhase5AAnd5BMsgSent(hash []byte, siProof bhcheck.SiProof) ([]*bhcheck.SchnorrCheaterEvidence, error) {
	errStr := ""
	var schnorrEvidenceList []*bhcheck.SchnorrCheaterEvidence = make([]*bhcheck.SchnorrCheaterEvidence, 0)
	for _, v := range t.KeySignPhase3And4MsgReceived {
		if v.LabelFrom == t.GetLabel() {
			continue
		}
		temp := t.getSigOthersRByLabel(v.LabelFrom)
		tempX, tempY := big.NewInt(0).SetBytes(temp.X), big.NewInt(0).SetBytes(temp.Y)
		check := &bhs256k1.PublicKey{}
		check.Curve = bhs256k1.S256()
		check.X, check.Y = big.NewInt(0), big.NewInt(0)
		check.X, check.Y = check.Add(check.X, check.Y, tempX, tempY)
		var commitment [32]byte
		for _, v1 := range t.KeySignPhase1MsgReceived {
			if v1.LabelFrom == v.LabelFrom {
				commitment = v1.GetNativeSigRCommit()
			}
		}
		blindFactor := v.GetNativeBlindFactor()
		if !bhcheck.CheckPubkeyCommit(commitment, check, blindFactor, bhs256k1.S256()) {
			errStr = errStr + v.LabelFrom + "COMMITMENT CHECK FAIL"
		}
		if !bhcheck.CheckPubkeyProof(v.GetNativeSchnorrZKProof(), check, bhs256k1.S256()) {
			errStr = errStr + v.LabelFrom + " SCHNORR PROOF CHECK FAIL"
			tempEvidence := &bhcheck.SchnorrCheaterEvidence{Label: v.LabelFrom, Proof: v.GetNativeSchnorrZKProof(), Pubkey: check}
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
	proof := siProof.GetSiProof(t.sigR, t.SigRY, t.sigS, t.siL, t.siRho)
	v, a, b := &bhs256k1.PublicKey{}, &bhs256k1.PublicKey{}, &bhs256k1.PublicKey{}
	v.Curve, a.Curve, b.Curve = bhs256k1.S256(), bhs256k1.S256(), bhs256k1.S256()
	v.X, v.Y, a.X, a.Y, b.X, b.Y = proof.VX, proof.VY, proof.AX, proof.AY, proof.BX, proof.BY
	vCommit, aCommit, bCommit := bhcheck.GetPubkeyCommit(v, t.vBlindFactor, bhs256k1.S256()), bhcheck.GetPubkeyCommit(a, t.aBlindFactor, bhs256k1.S256()), bhcheck.GetPubkeyCommit(b, t.bBlindFactor, bhs256k1.S256())
	t.KeySignPhase5AMsgSent.SetNativeCommit(vCommit, aCommit, bCommit)
	t.KeySignPhase5BMsgSent.SetNativeSiProof(proof)
	t.KeySignPhase5BMsgSent.SetNativeBlindFactor(t.vBlindFactor, t.aBlindFactor, t.bBlindFactor)
	return nil, nil
}

func (t *Node) GetKeySignPhase5CAnd5DMsgSent(hash []byte, key *NodeKey, siCheck bhcheck.SiCheck) ([]*bhcheck.SiProofCheaterEvidence, error) {
	errStr := ""
	var siProofEvidenceList []*bhcheck.SiProofCheaterEvidence = make([]*bhcheck.SiProofCheaterEvidence, 0)
	for _, v := range t.KeySignPhase5BMsgReceived {
		var vCommit, aCommit, bCommit [32]byte
		for _, v1 := range t.KeySignPhase5AMsgReceived {
			if v1.LabelFrom == v.LabelFrom {
				vCommit, aCommit, bCommit = v1.GetNativeCommit()
			}
		}
		vBlindFactor, aBlindFactor, bBlindFactor := v.GetNativeBlindFactor()
		proof := v.GetNativeSiProof()
		v0, a, b := &bhs256k1.PublicKey{}, &bhs256k1.PublicKey{}, &bhs256k1.PublicKey{}
		v0.Curve, a.Curve, b.Curve = bhs256k1.S256(), bhs256k1.S256(), bhs256k1.S256()
		v0.X, v0.Y, a.X, a.Y, b.X, b.Y = proof.VX, proof.VY, proof.AX, proof.AY, proof.BX, proof.BY
		if !bhcheck.CheckPubkeyCommit(vCommit, v0, vBlindFactor, bhs256k1.S256()) || !bhcheck.CheckPubkeyCommit(aCommit, a, aBlindFactor, bhs256k1.S256()) ||
			!bhcheck.CheckPubkeyCommit(bCommit, b, bBlindFactor, bhs256k1.S256()) {
			errStr = errStr + v.LabelFrom + "COMMITMENT CHECK FAIL"
		}
		if !t.CheckSiProof(proof) {
			errStr = errStr + v.LabelFrom + " SiProof Fail"
			tempEvidence := &bhcheck.SiProofCheaterEvidence{Label: v.LabelFrom, Proof: v.GetNativeSiProof(), SigR: t.sigR, SigRY: t.SigRY, EccN: t.EccN}
			siProofEvidenceList = append(siProofEvidenceList, tempEvidence)
		}
	}
	if errStr != "" {
		return siProofEvidenceList, errors.New(errStr)
	}
	t.KeySignPhase5CMsgSent.LabelFrom = t.label
	t.KeySignPhase5DMsgSent.LabelFrom = t.label

	all5BSum := bhs256k1.PublicKey{}
	all5BSum.Curve = bhs256k1.S256()
	all5BSum.X, all5BSum.Y = big.NewInt(0), big.NewInt(0)
	for _, v := range t.KeySignPhase5BMsgReceived {
		p := v.GetNativeSiProof()
		all5BSum.X, all5BSum.Y = all5BSum.Add(all5BSum.X, all5BSum.Y, p.VX, p.VY)
	}

	others5BSum := &bhs256k1.PublicKey{}
	others5BSum.Curve = bhs256k1.S256()
	others5BSum.X, others5BSum.Y = big.NewInt(0), big.NewInt(0)
	for _, v := range t.KeySignPhase5BMsgReceived {
		if v.LabelFrom != t.label {
			p := v.GetNativeSiProof()
			others5BSum.X, others5BSum.Y = others5BSum.Add(others5BSum.X, others5BSum.Y, p.AX, p.AY)
		}
	}

	check := siCheck.GetSiCheck(t.siRho, t.siL, all5BSum.X, all5BSum.Y, others5BSum.X, others5BSum.Y, t.sigR, hash, key.PubkeySum)
	u, t0 := check.U, check.T
	uCommit, tCommit := bhcheck.GetPubkeyCommit(u, t.uBlindFactor, bhs256k1.S256()), bhcheck.GetPubkeyCommit(t0, t.tBlindFactor, bhs256k1.S256())
	t.KeySignPhase5CMsgSent.SetNativeCommit(uCommit, tCommit)
	t.KeySignPhase5DMsgSent.SetNativeSiCheck(check)
	t.KeySignPhase5DMsgSent.SetNativeBlindFactor(t.uBlindFactor, t.tBlindFactor)
	return nil, nil
}

func (t *Node) GetKeySignPhase5EMsgSent() ([]*bhcheck.SiCheckCheaterEvidence, error) {
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
		if !bhcheck.CheckPubkeyCommit(uCommit, check.U, uBlindFactor, bhs256k1.S256()) || !bhcheck.CheckPubkeyCommit(tCommit, check.T, tBlindFactor, bhs256k1.S256()) {
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
		temp1 := bhcrypto.PaillierDec(v.MessageRResponse, t.paillierPrtKey)
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
	e := bhcheck.HashToInt(hash, bhs256k1.S256())
	tempS := new(big.Int).Mul(e, t.r)
	rd.Mul(rd, t.sigR)
	rd.Add(rd, tempS)
	rd.Mul(rd, t.theaInverse)
	t.sigS = rd.Mod(rd, t.cure.Params().N)

}

func (t *Node) GetSigR() {
	ecdsaPub := bhs256k1.PublicKey{}
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
	pubKeySum := &bhs256k1.PublicKey{}
	pubKeySum.Curve = bhs256k1.S256()
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
	signatureF := bhs256k1.Signature{}
	signatureF.R = resultR
	signatureF.S = resultS

	if signatureF.Verify(hash, pubKeySum) {
		t.Logger.Debug("PASS")
	} else {
		t.Logger.Debug("FAIL")
	}
}

func getCofCommits(cof []*big.Int) []*bhs256k1.PublicKey {
	commits := make([]*bhs256k1.PublicKey, len(cof))
	for i, v := range cof {
		tempCommit := &bhs256k1.PublicKey{}
		tempCommit.Curve = bhs256k1.S256()
		tempCommit.X, tempCommit.Y = tempCommit.ScalarBaseMult(v.Bytes())
		commits[i] = tempCommit
	}
	return commits
}

func getCheckByX(x *big.Int, commits []*bhs256k1.PublicKey) *bhs256k1.PublicKey {
	check := &bhs256k1.PublicKey{}
	check.Curve = bhs256k1.S256()
	check.X, check.Y = big.NewInt(0), big.NewInt(0)
	for k, v := range commits {
		temp := big.NewInt(0)
		bigK := big.NewInt(int64(k))
		temp.Exp(x, bigK, nil)
		expMul := &bhs256k1.PublicKey{}
		expMul.Curve = bhs256k1.S256()
		expMul.X, expMul.Y = expMul.ScalarMult(v.X, v.Y, temp.Bytes())
		check.X, check.Y = check.Add(check.X, check.Y, expMul.X, expMul.Y)
	}
	return check
}

func getCheckByY(y *big.Int) *bhs256k1.PublicKey {
	check := &bhs256k1.PublicKey{}
	check.Curve = bhs256k1.S256()
	check.X, check.Y = check.ScalarBaseMult(y.Bytes())
	return check
}

//TODO:更好的方法随机生成与max互质的re
func randGCD(max *big.Int) *big.Int {
	re, _ := rand.Int(rand.Reader, max)
	for big.NewInt(0).GCD(nil, nil, re, max).Cmp(big.NewInt(1)) != 0 {
		re, _ = rand.Int(rand.Reader, max)
	}
	return re
}

func (t *Node) GetSenderRangeProof(m, r, nTilde, h1, h2 *big.Int, oneCipher []byte) bhcheck.SenderRangeProof {
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
	mu, _ := bhcrypto.PaillierEncWithR(alpha.Bytes(), beta, t.paillierPubKey)
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
	result := bhcheck.SenderRangeProof{
		Z:  z,
		W:  w,
		Mu: mu,
		S:  s,
		S1: s1,
		S2: s2,
	}
	return result
}

func CheckSenderRangeProof(nTilde, h1, h2, qCube, EccN *big.Int, proof bhcheck.SenderRangeProof, encM []byte, pubkey *gaillier.PubKey) bool {
	//check s1 <= q^3
	c := big.NewInt(0).SetBytes(encM)
	if proof.S1.Cmp(qCube) > 0 {
		return false
	}
	//check μ = Τ^s1*s^N*c^-e
	hash := sha256.New()
	_, _ = hash.Write(proof.Z.Bytes())
	_, _ = hash.Write(proof.W.Bytes())
	_, _ = hash.Write(proof.Mu.Bytes())
	e := big.NewInt(0).SetBytes(hash.Sum(nil))
	e = e.Mod(e, EccN)
	check1, _ := bhcrypto.PaillierEncWithR(proof.S1.Bytes(), proof.S, pubkey)
	check1 = check1.Mul(check1, big.NewInt(0).Exp(c, big.NewInt(0).Sub(big.NewInt(0), e), pubkey.Nsq))
	check1 = check1.Mod(check1, pubkey.Nsq)
	if proof.Mu.Cmp(check1) != 0 {
		return false
	}
	//check w = h1^s1*h2^s2*z^-e
	N := nTilde
	w := big.NewInt(0).Set(proof.W)
	w1 := big.NewInt(0).Exp(h1, proof.S1, N)
	w2 := big.NewInt(0).Exp(h2, proof.S2, N)
	wMul := big.NewInt(0).Mul(w1, w2)
	w3 := big.NewInt(0).Exp(proof.Z, big.NewInt(0).Sub(big.NewInt(0), e), N)
	wMul = wMul.Mul(wMul, w3)
	wMul = wMul.Mod(wMul, N)
	return wMul.Cmp(w) == 0
}

//x*Ec1+E(y),r为paillier中使用的随机数,encM为上轮收到的加密的信息
func (t *Node) GetReceiverRangeProof(x, y, r *big.Int, encM []byte, pubkey *gaillier.PubKey, nTilde, h1, h2 *big.Int) bhcheck.ReceiverRangeProof {
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
	curve := bhs256k1.S256()
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
	v2, _ := bhcrypto.PaillierEncWithR(gamma.Bytes(), beta, pubkey)
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
	// tempC2, _ := PaillierEncWithR(pubkey, y.Bytes(), r)
	// c2 := new(big.Int).Mod(new(big.Int).Mul(tempC2, new(big.Int).Exp(c1, x, pubkey.Nsq)), pubkey.Nsq)
	result1 := bhcheck.ReceiverRangeProof{
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

func (t *Node) CheckReceiverRangeProof(p bhcheck.ReceiverRangeProof, m1 []byte, m2 []byte, pubkey *gaillier.PubKey) bool {
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
	curve := bhs256k1.S256()
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
	check4, _ := bhcrypto.PaillierEncWithR(p.T1.Bytes(), p.S, pubkey)
	check4 = check4.Mod(check4, pubkey.Nsq)
	check4 = new(big.Int).Mod(new(big.Int).Mul(check4, new(big.Int).Exp(c1, p.S1, pubkey.Nsq)), pubkey.Nsq)
	check4Compare := new(big.Int).Mod(new(big.Int).Mul(p.V, new(big.Int).Exp(c2, e, pubkey.Nsq)), pubkey.Nsq)
	return check4.Cmp(check4Compare) == 0
}

//无法得知作弊节点，返回的是所有节点的信息
func (t *Node) CheckSiCheck() ([]*bhcheck.SiCheckCheaterEvidence, error) {
	var siCheckEvidenceList []*bhcheck.SiCheckCheaterEvidence = make([]*bhcheck.SiCheckCheaterEvidence, 0)
	//sum(Ti+Bi)== sum(Ui)
	check := &bhs256k1.PublicKey{}
	check.Curve = bhs256k1.S256()
	check.X, check.Y = big.NewInt(0), big.NewInt(0)
	for _, v0 := range t.KeySignPhase5BMsgReceived {
		temp := &bhs256k1.PublicKey{}
		temp.Curve = bhs256k1.S256()
		temp.X, temp.Y = big.NewInt(0), big.NewInt(0)
		for _, v1 := range t.KeySignPhase5DMsgReceived {
			if v0.LabelFrom == v1.LabelFrom {
				p := v0.GetNativeSiProof()
				c := v1.GetNativeSiCheck()
				tempSiCheckCheaterEvidence := &bhcheck.SiCheckCheaterEvidence{Label: v1.LabelFrom, Check: v1.GetNativeSiCheck(), BX: p.BX, BY: p.BY}
				siCheckEvidenceList = append(siCheckEvidenceList, tempSiCheckCheaterEvidence)
				temp.X, temp.Y = temp.Add(p.BX, p.BY, c.T.X, c.T.Y)
			}
		}
		check.X, check.Y = check.Add(check.X, check.Y, temp.X, temp.Y)
	}
	checkCompare := &bhs256k1.PublicKey{}
	checkCompare.Curve = bhs256k1.S256()
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

func (t *Node) CheckSiProof(proof bhcheck.SiZKProof) bool {
	//t.R+u.G = alpha+c.V
	check1 := &bhs256k1.PublicKey{}
	check1.Curve = bhs256k1.S256()
	check1.X, check1.Y = check1.ScalarMult(t.sigR, t.SigRY, proof.T.Bytes())
	tempCheck1 := bhs256k1.GetPubkeyByNum(proof.U)
	check1.X, check1.Y = check1.Add(check1.X, check1.Y, tempCheck1.X, tempCheck1.Y)

	hash := sha256.New()
	_, _ = hash.Write(proof.AlphaX.Bytes())
	_, _ = hash.Write(proof.AlphaY.Bytes())
	_, _ = hash.Write(proof.BetaX.Bytes())
	_, _ = hash.Write(proof.BetaY.Bytes())
	c := big.NewInt(0).SetBytes(hash.Sum(nil))
	c = c.Mod(c, t.EccN)
	check1Compare := &bhs256k1.PublicKey{}
	check1Compare.Curve = bhs256k1.S256()
	check1Compare.X, check1Compare.Y = check1Compare.ScalarMult(proof.VX, proof.VY, c.Bytes())
	check1Compare.X, check1Compare.Y = check1Compare.Add(check1Compare.X, check1Compare.Y, proof.AlphaX, proof.AlphaY)
	if !check1.IsEqual(check1Compare) {
		return false
	}
	//u.A = beta+c.B
	check2 := &bhs256k1.PublicKey{}
	check2.Curve = bhs256k1.S256()
	check2.X, check2.Y = check2.ScalarMult(proof.AX, proof.AY, proof.U.Bytes())
	check2Compare := &bhs256k1.PublicKey{}
	check2Compare.Curve = bhs256k1.S256()
	check2Compare.X, check2Compare.Y = check2Compare.ScalarMult(proof.BX, proof.BY, c.Bytes())
	check2Compare.X, check2Compare.Y = check2Compare.Add(check2Compare.X, check2Compare.Y, proof.BetaX, proof.BetaY)
	return check2.IsEqual(check2Compare)
}
