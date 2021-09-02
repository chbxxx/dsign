package dsign

import (
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"math/big"

	"github.com/bluehelix-chain/dsign/commit"
	"github.com/bluehelix-chain/dsign/communicator"
	"github.com/bluehelix-chain/dsign/primes"
	"github.com/bluehelix-chain/dsign/types"
	sssa "github.com/bluehelix-chain/sssa-golang"

	"github.com/btcsuite/btcd/btcec"
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
	share        Share
	sch          Schnorr
	pq           PQProof
	rsaGenerator *primes.RSAParameterGenerator
}

func NewKeyGenerator(label string) *KeyGenerator {
	return &KeyGenerator{
		label:        label,
		share:        &HonestShare{},
		sch:          &HonestSchnorr{},
		pq:           &HonestPQProof{},
		rsaGenerator: primes.NewRSAParameterGenerator(rsaLength, rsaMaxReuseTimes),
	}
}

func (kg *KeyGenerator) WithShare(share Share) *KeyGenerator {
	kg.share = share
	return kg
}

func (kg *KeyGenerator) WithSchnorr(sch Schnorr) *KeyGenerator {
	kg.sch = sch
	return kg
}

func (kg *KeyGenerator) WithPQProof(pq PQProof) *KeyGenerator {
	kg.pq = pq
	return kg
}

func (kg *KeyGenerator) KeyGen(nodeList []string, t int, comm communicator.Communicator) (*NodeKey, *Evidence, error) {
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

	nodekey, err := NewNodeKey(kg.label, t, n, coeff, comm, kg.pq, rsaParameter)
	if err != nil {
		return nil, nil, err
	}
	nodekey.comm.SendKeyGenPhase1Message(nodekey.KeyGenPhase1MsgSent)
	evidence := &Evidence{}
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
	if !nodekey.CheckPubKeyCommit() || !nodekey.CheckShamirCommit() {
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
	var schnorrEvidenceList []*SchnorrCheaterEvidence = make([]*SchnorrCheaterEvidence, 0)
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
		pubKey, _ := btcec.ParsePubKey(nodekey.KeyGenPhase2MsgMap[label].PubKey, btcec.S256())
		if !CheckPubkeyProof(p, pubKey) {
			errStr = errStr + temp.LabelFrom + " SCHNORR PROOF CHECK FAIL"
			tempEvidence := &SchnorrCheaterEvidence{temp.LabelFrom, p, pubKey}
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
		evidence.SetShamirCheckEvidence(&shamirEvidence)
		return nil, evidence, errors.New("FINAL SHAMIR CHECK FAIL")
	}

	return nodekey, nil, nil

}

//生成公私钥对，以及私钥的(t,n)分片
func keyGen(t, n int, coeff []*big.Int) (
	*btcec.PrivateKey, map[string]sssa.ShareXY, []*btcec.PublicKey) {
	for {
		newPriKey, _ := btcec.NewPrivateKey(btcec.S256())
		share, cof, err := sssa.Create(t, n, newPriKey.D, coeff)
		if err == nil {
			return newPriKey, share, getCofCommits(cof)
		}
	}
}

type NodeKey struct {
	label                   string
	coeff                   []*big.Int
	shamirSharePrtKey       *btcec.PrivateKey
	shamirSharePubKey       map[string]*btcec.PublicKey
	prtKey                  *btcec.PrivateKey                //私钥
	pubKey                  *btcec.PublicKey                 //公钥
	blindFactor             *big.Int                         //用于commit的致盲因子
	pubKeyCommit            [32]byte                         //公钥的commit
	cofCommit               []*btcec.PublicKey               //shamir系数的commit
	KeyGenPhase1MsgSent     types.KeyGenPhase1Msg            //发送给其他节点的KeyGenPhase1Msg
	KeyGenPhase1MsgReceived []types.KeyGenPhase1Msg          //接收到的其他节点的KeyGenPhase1Msg
	KeyGenPhase2MsgSent     map[string]types.KeyGenPhase2Msg //发送给其他节点的KeyGenPhase2Msg
	KeyGenPhase2MsgReceived []types.KeyGenPhase2Msg          //接收到的其他节点的KeyGenPhase2Msg
	KeyGenPhase3MsgSent     types.KeyGenPhase3Msg            //发送给其他节点的KeyGenPhase3Msg
	KeyGenPhase3MsgReceived []types.KeyGenPhase3Msg          //接收其他节点的KeyGenPhase3Msg
	shareOwn                sssa.ShareXY                     //自己的shamir私钥分片
	shareArray              map[string]sssa.ShareXY          //发送给其他节点的私钥分片
	ShareReceived           map[string]sssa.ShareXY          //接收到的私钥分片
	T, N                    int                              //threashold、N
	KeyGenPhase1MsgMap      map[string]types.KeyGenPhase1Msg //节点label->KeyGenPhase1Msg的映射
	KeyGenPhase2MsgMap      map[string]types.KeyGenPhase2Msg //节点label->KeyGenPhase2Msg
	comm                    communicator.Communicator
	NTilde, h1, h2          map[string]*big.Int
	PubkeySum               *btcec.PublicKey
	KeyNodes                []string
}

func NewNodeKey(label string, T, N int, coeff []*big.Int, comm communicator.Communicator, p PQProof, rsaParameter *primes.RSAParameter) (*NodeKey, error) {
	nTilde, pTilde, qTilde, h1, h2 := rsaParameter.NTilde, rsaParameter.PTilde, rsaParameter.QTilde, rsaParameter.H1, rsaParameter.H2
	n := &NodeKey{}
	n.label = label
	n.coeff = coeff
	n.T = T
	n.N = N
	prtKey, tempShareArray, tempCofcommit := keyGen(T, N, n.coeff)
	n.prtKey = prtKey
	n.pubKey = n.prtKey.PubKey()
	var err error
	n.shamirSharePrtKey, err = btcec.NewPrivateKey(btcec.S256())
	if err != nil {
		return nil, err
	}
	n.shamirSharePubKey = make(map[string]*btcec.PublicKey)
	n.shamirSharePubKey[label] = n.shamirSharePrtKey.PubKey()
	n.blindFactor, _ = rand.Int(rand.Reader, maxRand)
	n.cofCommit = tempCofcommit
	n.pubKeyCommit = commit.GetPubkeyCommit(n.pubKey, n.blindFactor)
	n.shareArray = tempShareArray
	n.shareOwn = tempShareArray[n.label]
	n.ShareReceived = make(map[string]sssa.ShareXY)
	n.KeyGenPhase2MsgSent = make(map[string]types.KeyGenPhase2Msg, n.N)
	n.KeyGenPhase1MsgMap = make(map[string]types.KeyGenPhase1Msg)
	n.KeyGenPhase2MsgMap = make(map[string]types.KeyGenPhase2Msg)
	//KeyGenPhase1初始化
	tempKeyGenPhase1 := types.KeyGenPhase1Msg{}
	tempKeyGenPhase1.LabelFrom = n.label
	tempKeyGenPhase1.SetNativePubKeyCommit(n.pubKeyCommit)
	tempKeyGenPhase1.SetNativeCofCommit(n.cofCommit)
	tempKeyGenPhase1.SetNativeRSAParas(nTilde, h1, h2)
	tempKeyGenPhase1.SetNativePQProof(p.GetPQProof(nTilde, pTilde, qTilde, pqProofK))
	tempKeyGenPhase1.SetNativePubKey(n.shamirSharePubKey[label])
	n.KeyGenPhase1MsgSent = tempKeyGenPhase1
	n.comm = comm
	n.NTilde = make(map[string]*big.Int)
	n.h1 = make(map[string]*big.Int)
	n.h2 = make(map[string]*big.Int)
	n.NTilde[n.label] = nTilde
	n.h1[n.label] = h1
	n.h2[n.label] = h2

	return n, nil
}

//生成广播给shareArray中节点的KeyGenPhase2Msg
func (n *NodeKey) GetKeyGenPhase2MsgSent() error {
	for k, v := range n.shareArray {
		temp := types.KeyGenPhase2Msg{}
		temp.LabelFrom = n.label
		temp.LabelTo = k
		temp.SetNativePubKey(n.pubKey)
		if n.shamirSharePubKey[k] == nil {
			return errors.New("err shamir pubkey")
		}
		temp.SetNativeShare(n.shamirSharePubKey[k], v)
		temp.SetNativeBlindFactor(n.blindFactor)
		n.KeyGenPhase2MsgSent[k] = temp
	}

	return nil
}

//生成广播给所有节点的KeyGenPhase3Msg
func (n *NodeKey) GetKeyGenPhase3MsgSent(s Share, sh Schnorr) {
	n.KeyGenPhase3MsgSent.LabelFrom = n.label
	y := big.NewInt(0)
	for _, v := range n.KeyGenPhase2MsgReceived {
		y = y.Add(y, n.ShareReceived[v.LabelFrom].Y)
	}
	y = s.share(y)
	n.KeyGenPhase3MsgSent.SetNativeShamirPubKey(getPubkeyByNum(y))
	n.KeyGenPhase3MsgSent.SetNativeSchnorrZKProof(sh.proof(n.prtKey.D))
}

//从接收到的消息队列里生成映射
func (n *NodeKey) GetKeyGenPhase1MsgMap() {
	for _, v := range n.KeyGenPhase1MsgReceived {
		n.KeyGenPhase1MsgMap[v.LabelFrom] = v
		n.NTilde[v.LabelFrom], n.h1[v.LabelFrom], n.h2[v.LabelFrom] = v.GetNativeRSAParas()
		n.shamirSharePubKey[v.LabelFrom] = v.GetNativePubKey()
	}
}

//从接收到的消息队列里生成映射
func (n *NodeKey) GetKeyGenPhase2MsgMap() {
	for _, v := range n.KeyGenPhase2MsgReceived {
		n.KeyGenPhase2MsgMap[v.LabelFrom] = v
	}
}

func (n *NodeKey) CheckPQProof() ([]*PQProofEvidence, error) {
	errStr := ""
	var PQPrrofEvidenceList []*PQProofEvidence = make([]*PQProofEvidence, 0)
	for _, v := range n.KeyGenPhase1MsgReceived {
		p := v.GetNativePQProof()
		nTilde, _, _ := v.GetNativeRSAParas()
		strA := nTilde.String() + nTilde.String()
		A, _ := big.NewInt(0).SetString(strA, 10)
		hash := sha256.New()
		_, _ = hash.Write(nTilde.Bytes())
		for _, v := range p.Z {
			_, _ = hash.Write(v.Bytes())
		}
		e := big.NewInt(0).SetBytes(hash.Sum(nil))

		len1, len2 := len(p.X), len(p.Z)
		if len1 != pqProofK || len2 != pqProofK {
			errStr = errStr + v.LabelFrom + " PQProof Fail"
			tempEvidence := &PQProofEvidence{v.LabelFrom, p}
			PQPrrofEvidenceList = append(PQPrrofEvidenceList, tempEvidence)
			continue
		}

		for k, v2 := range p.Z {
			exp := big.NewInt(0).Sub(p.Y, big.NewInt(0).Mul(nTilde, e))
			if p.Y.Cmp(big.NewInt(0)) == -1 || p.Y.Cmp(A) >= 0 || p.X[k].Cmp(big.NewInt(0).Exp(v2, exp, nTilde)) != 0 {
				errStr = errStr + v.LabelFrom + " PQProof Fail"
				tempEvidence := &PQProofEvidence{v.LabelFrom, p}
				PQPrrofEvidenceList = append(PQPrrofEvidenceList, tempEvidence)
				break
			}
		}
	}
	if errStr != "" {
		return PQPrrofEvidenceList, errors.New(errStr)
	}
	return nil, nil
}

//检验pubkey commit
func (n *NodeKey) CheckPubKeyCommit() bool {
	if len(n.KeyGenPhase1MsgMap) != n.N {
		return false
	}
	if len(n.KeyGenPhase2MsgMap) != n.N {
		return false
	}
	for _, v := range n.coeff {
		tempR0Msg := n.KeyGenPhase1MsgMap[v.String()]
		tempR1Msg := n.KeyGenPhase2MsgMap[v.String()]
		if !commit.CheckPubkeyCommit(tempR0Msg.GetNativePubKeyCommit(), tempR1Msg.GetNativePubKey(), tempR1Msg.GetNativeBlindFactor()) {
			return false
		}
	}
	return true
}

//检验shamir commit
//cof数组是对shamir分片(Create)中的系数进行椭圆加密的结果，可以通过f(xi)=a0+a1*xi+……+at*xi^t (mod q)进行检验
//如果作弊节点对不同节点发送根据不同的系数计算的结果，则他们各自合理可以通过shamir commit的检查，但是无法合成出真正的私钥
//当对不同节点发送的系数相同时，与final shamir check等价
func (n *NodeKey) CheckShamirCommit() bool {
	if len(n.KeyGenPhase1MsgMap) != n.N {
		return false
	}
	if len(n.KeyGenPhase2MsgMap) != n.N {
		return false
	}
	shareSum := sssa.ShareXY{}
	shareSum.X, shareSum.Y = big.NewInt(0), big.NewInt(0)
	shareSum.X.Add(shareSum.X, n.shareOwn.X)
	for _, v := range n.coeff {
		tempR1Msg := n.KeyGenPhase2MsgMap[v.String()]
		n.ShareReceived[tempR1Msg.LabelFrom] = tempR1Msg.GetNativeShare(n.shamirSharePrtKey)
		shareSum.Y.Add(shareSum.Y, n.ShareReceived[tempR1Msg.LabelFrom].Y)
	}
	finalCommit := make([]*btcec.PublicKey, 0)
	if _, ok := n.KeyGenPhase2MsgMap[n.coeff[0].String()]; !ok || len(n.KeyGenPhase1MsgMap) < n.N {
		return false
	}
	for _, v := range n.coeff {
		tempR0Msg := n.KeyGenPhase1MsgMap[v.String()]
		cof := tempR0Msg.GetNativeCofCommit()
		tempR1Msg := n.KeyGenPhase2MsgMap[v.String()]
		if !cof[0].IsEqual(tempR1Msg.GetNativePubKey()) {
			return false
		}
	}
	for i := 0; i < len(n.KeyGenPhase1MsgMap[n.coeff[1].String()].CofCommit); i++ {
		tempPubkey := &btcec.PublicKey{}
		tempPubkey.Curve = btcec.S256()
		tempPubkey.X, tempPubkey.Y = big.NewInt(0), big.NewInt(0)
		for _, v := range n.coeff {
			tempR0Msg := n.KeyGenPhase1MsgMap[v.String()]
			cof := tempR0Msg.GetNativeCofCommit()
			tempPubkey.X, tempPubkey.Y = tempPubkey.Add(tempPubkey.X, tempPubkey.Y, cof[i].X, cof[i].Y)
		}
		finalCommit = append(finalCommit, tempPubkey)
	}
	checkX := getCheckByX(shareSum.X, finalCommit)
	checkY := getCheckByY(shareSum.Y)
	return checkX.IsEqual(checkY)
}

func (n *NodeKey) SetLabel(l string) {
	n.label = l
}

func (n *NodeKey) GetLabel() string {
	return n.label
}

// 返回最终计算的公钥和
func (n *NodeKey) PubKeySum() *btcec.PublicKey {
	pubKeySum := &btcec.PublicKey{}
	pubKeySum.Curve = btcec.S256()
	pubKeySum.X = big.NewInt(0)
	pubKeySum.Y = big.NewInt(0)
	for _, v := range n.KeyGenPhase2MsgReceived {
		pubKeySum.X, pubKeySum.Y = pubKeySum.Add(pubKeySum.X, pubKeySum.Y, v.GetNativePubKey().X, v.GetNativePubKey().Y)
	}
	return pubKeySum
}

//判断最终的私钥分片是否正确
func (n *NodeKey) checkFinalShare() (bool, ShamirCheckEvidence) {
	finalPubkey := n.PubKeySum()
	n.PubkeySum = finalPubkey
	checkArray := generateCheckArrays(n.T, n.N, n.coeff)
	checkResult := true
	re := ShamirCheckEvidence{}
	for _, v := range checkArray {
		check := &btcec.PublicKey{}
		check.Curve = btcec.S256()
		check.X, check.Y = big.NewInt(0), big.NewInt(0)
		//遍历KeyGenPhase3Msg
		for _, v0 := range n.KeyGenPhase3MsgReceived {
			//判断该KeyGenPhase3Msg是否在randomNodeList中
			for _, v1 := range v {
				if v0.LabelFrom == v1 {
					temp := calShamirPubkeys(v0, v)
					check.X, check.Y = check.Add(check.X, check.Y, temp.X, temp.Y)
				}
			}
		}
		if !finalPubkey.IsEqual(check) {
			checkResult = false
			re = ShamirCheckEvidence{finalPubkey, n.KeyGenPhase3MsgReceived}
		}
	}
	return checkResult, re
}

//生成两个检查下标列表,[1-t][n-t,n]，可以覆盖所有参与分片的节点，一般情况下可以发现有节点在shamir分片中作弊
func generateCheckArrays(t, n int, coeff []*big.Int) [][]string {
	allLablels := make([]string, n)
	for i := 0; i < n; i++ {
		allLablels[i] = coeff[i].String()
	}
	result1 := allLablels[:t]
	result2 := allLablels[n-t : n]
	result := make([][]string, 0)
	result = append(result, result1)
	result = append(result, result2)
	return result
}

//根据KeyGenPhase3Msg，计算share.G*Li
func calShamirPubkeys(msg types.KeyGenPhase3Msg, participants []string) *btcec.PublicKey {
	var v string
	for _, v = range participants {
		if msg.LabelFrom == v {
			break
		}
	}
	num, deno := sssa.CalBs(participants, v)
	Li := sssa.CalLi(num, deno)
	result := &btcec.PublicKey{}
	result.Curve = btcec.S256()
	result.X, result.Y = result.ScalarMult(msg.GetNativeShamirPubKey().X, msg.GetNativeShamirPubKey().Y, Li.Bytes())
	return result
}

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

func SetKeyGenData(data *types.KeyGenData) *NodeKey {
	nodeKey := &NodeKey{}
	nodeKey.SetLabel(data.Label)
	nodeKey.N = len(data.Paras)
	nodeKey.T = int(data.SignThreshold)
	nodeKey.ShareReceived = make(map[string]sssa.ShareXY)
	nodeKey.NTilde = make(map[string]*big.Int)
	nodeKey.h1 = make(map[string]*big.Int)
	nodeKey.h2 = make(map[string]*big.Int)
	nodeKey.KeyNodes = make([]string, len(data.KeyNodes))
	copy(nodeKey.KeyNodes, data.KeyNodes)
	for _, para := range data.Paras {
		tempShare := sssa.ShareXY{
			X: new(big.Int).SetBytes(para.Share.X),
			Y: new(big.Int).SetBytes(para.Share.Y),
		}
		nodeKey.ShareReceived[para.Label] = tempShare
		nodeKey.NTilde[para.Label] = new(big.Int).SetBytes(para.NTilde)
		nodeKey.h1[para.Label] = new(big.Int).SetBytes(para.H1)
		nodeKey.h2[para.Label] = new(big.Int).SetBytes(para.H2)
	}
	nodeKey.PubkeySum, _ = btcec.ParsePubKey(data.PubKeySum, btcec.S256())
	return nodeKey
}
