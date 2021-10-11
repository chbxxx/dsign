package dsign

import (
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
	"math/big"
)

type NodeKey struct {
	label                   string
	coeff                   []*big.Int
	shamirSharePrtKey       *bhs256k1.PrivateKey
	shamirSharePubKey       map[string]*bhs256k1.PublicKey
	prtKey                  *bhs256k1.PrivateKey             //私钥
	pubKey                  *bhs256k1.PublicKey              //公钥
	blindFactor             *big.Int                         //用于commit的致盲因子
	pubKeyCommit            [32]byte                         //公钥的commit
	cofCommit               []*bhs256k1.PublicKey            //shamir系数的commit
	KeyGenPhase1MsgSent     types.KeyGenPhase1Msg            //发送给其他节点的KeyGenPhase1Msg
	KeyGenPhase1MsgReceived []types.KeyGenPhase1Msg          //接收到的其他节点的KeyGenPhase1Msg
	KeyGenPhase2MsgSent     map[string]types.KeyGenPhase2Msg //发送给其他节点的KeyGenPhase2Msg
	KeyGenPhase2MsgReceived []types.KeyGenPhase2Msg          //接收到的其他节点的KeyGenPhase2Msg
	KeyGenPhase3MsgSent     types.KeyGenPhase3Msg            //发送给其他节点的KeyGenPhase3Msg
	KeyGenPhase3MsgReceived []types.KeyGenPhase3Msg          //接收其他节点的KeyGenPhase3Msg
	shareOwn                bhsssa.ShareXY                   //自己的shamir私钥分片
	shareArray              map[string]bhsssa.ShareXY        //发送给其他节点的私钥分片
	ShareReceived           map[string]bhsssa.ShareXY        //接收到的私钥分片
	T, N                    int                              //threashold、N
	KeyGenPhase1MsgMap      map[string]types.KeyGenPhase1Msg //节点label->KeyGenPhase1Msg的映射
	KeyGenPhase2MsgMap      map[string]types.KeyGenPhase2Msg //节点label->KeyGenPhase2Msg
	comm                    communicator.Communicator
	NTilde, h1, h2          map[string]*big.Int
	PubkeySum               *bhs256k1.PublicKey
	KeyNodes                []string
}

func NewNodeKey(label string, T, N int, coeff []*big.Int, comm communicator.Communicator, p bhcheck.PQProof, rsaParameter *bhcrypto.RSAParameter, logger logger.Logger) (*NodeKey, error) {
	nTilde, pTilde, qTilde, h1, h2 := rsaParameter.NTilde, rsaParameter.PTilde, rsaParameter.QTilde, rsaParameter.H1, rsaParameter.H2
	n := &NodeKey{}
	n.label = label
	n.coeff = coeff
	n.T = T
	n.N = N
	prtKey, tempShareArray, tempCofcommit := genPkShares(T, N, n.coeff)
	n.prtKey = prtKey
	n.pubKey = n.prtKey.PubKey()
	var err error
	n.shamirSharePrtKey, err = bhs256k1.NewPrivateKey(bhs256k1.S256())
	if err != nil {
		return nil, err
	}
	n.shamirSharePubKey = make(map[string]*bhs256k1.PublicKey)
	n.shamirSharePubKey[label] = n.shamirSharePrtKey.PubKey()
	n.blindFactor, _ = rand.Int(rand.Reader, maxRand)
	n.cofCommit = tempCofcommit
	n.pubKeyCommit = bhcheck.GetPubkeyCommit(n.pubKey, n.blindFactor, bhs256k1.S256())
	n.shareArray = tempShareArray
	n.shareOwn = tempShareArray[n.label]
	n.ShareReceived = make(map[string]bhsssa.ShareXY)
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
func (n *NodeKey) GetKeyGenPhase3MsgSent(s bhcheck.Share, sh bhcheck.Schnorr) {
	n.KeyGenPhase3MsgSent.LabelFrom = n.label
	y := big.NewInt(0)
	for _, v := range n.KeyGenPhase2MsgReceived {
		y = y.Add(y, n.ShareReceived[v.LabelFrom].Y)
	}
	y = s.Share(y)
	n.KeyGenPhase3MsgSent.SetNativeShamirPubKey(bhs256k1.GetPubkeyByNum(y))
	n.KeyGenPhase3MsgSent.SetNativeSchnorrZKProof(sh.Proof(n.prtKey.D, bhs256k1.S256()))
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

func (n *NodeKey) CheckPQProof() ([]*bhcheck.PQProofEvidence, error) {
	errStr := ""
	var PQPrrofEvidenceList []*bhcheck.PQProofEvidence = make([]*bhcheck.PQProofEvidence, 0)
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
			tempEvidence := &bhcheck.PQProofEvidence{v.LabelFrom, p}
			PQPrrofEvidenceList = append(PQPrrofEvidenceList, tempEvidence)
			continue
		}

		for k, v2 := range p.Z {
			exp := big.NewInt(0).Sub(p.Y, big.NewInt(0).Mul(nTilde, e))
			if p.Y.Cmp(big.NewInt(0)) == -1 || p.Y.Cmp(A) >= 0 || p.X[k].Cmp(big.NewInt(0).Exp(v2, exp, nTilde)) != 0 {
				errStr = errStr + v.LabelFrom + " PQProof Fail"

				tempEvidence := &bhcheck.PQProofEvidence{v.LabelFrom, p}
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
		if !bhcheck.CheckPubkeyCommit(tempR0Msg.GetNativePubKeyCommit(), tempR1Msg.GetNativePubKey(), tempR1Msg.GetNativeBlindFactor(), bhs256k1.S256()) {
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
	shareSum := bhsssa.ShareXY{}
	shareSum.X, shareSum.Y = big.NewInt(0), big.NewInt(0)
	shareSum.X.Add(shareSum.X, n.shareOwn.X)
	for _, v := range n.coeff {
		tempR1Msg := n.KeyGenPhase2MsgMap[v.String()]
		n.ShareReceived[tempR1Msg.LabelFrom] = tempR1Msg.GetNativeShare(n.shamirSharePrtKey)
		shareSum.Y.Add(shareSum.Y, n.ShareReceived[tempR1Msg.LabelFrom].Y)
	}
	finalCommit := make([]*bhs256k1.PublicKey, 0)
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
		tempPubkey := &bhs256k1.PublicKey{}
		tempPubkey.Curve = bhs256k1.S256()
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

//生成公私钥对，以及私钥的(t,n)分片
func genPkShares(t, n int, coeff []*big.Int) (
	*bhs256k1.PrivateKey, map[string]bhsssa.ShareXY, []*bhs256k1.PublicKey) {
	for {
		newPriKey, _ := bhs256k1.NewPrivateKey(bhs256k1.S256())
		share, cof, err := bhsssa.CreateShareSecrets(t, n, newPriKey.D, coeff, bhsssa.S256k1Prime)
		if err == nil {
			return newPriKey, share, getCofCommits(cof)
		}
	}
}

// 返回最终计算的公钥和
func (n *NodeKey) PubKeySum() *bhs256k1.PublicKey {
	pubKeySum := &bhs256k1.PublicKey{}
	pubKeySum.Curve = bhs256k1.S256()
	pubKeySum.X = big.NewInt(0)
	pubKeySum.Y = big.NewInt(0)
	for _, v := range n.KeyGenPhase2MsgReceived {
		pubKeySum.X, pubKeySum.Y = pubKeySum.Add(pubKeySum.X, pubKeySum.Y, v.GetNativePubKey().X, v.GetNativePubKey().Y)
	}
	return pubKeySum
}

//判断最终的私钥分片是否正确
func (n *NodeKey) checkFinalShare() (bool, []*bhcheck.ShamirCheckEvidence) {
	finalPubkey := n.PubKeySum()
	n.PubkeySum = finalPubkey
	checkArray := bhcheck.GenerateCheckArrays(n.T, n.N, n.coeff)
	checkResult := true
	re := []*bhcheck.ShamirCheckEvidence{}
	for _, v := range checkArray {
		check := &bhs256k1.PublicKey{}
		check.Curve = bhs256k1.S256()
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
			for _, v := range n.KeyGenPhase3MsgReceived {
				proof_pub, _ := bhs256k1.ParsePubKey(v.Proof.GetPubKey(), bhs256k1.S256())
				re = append(re, &bhcheck.ShamirCheckEvidence{v.LabelFrom, v.ShamirPub, bhcheck.SchnorrZKProof{proof_pub, big.NewInt(0).SetBytes(v.Proof.Num)}})
			}

		}
	}
	return checkResult, re
}

//根据KeyGenPhase3Msg，计算share.G*Li
func calShamirPubkeys(msg types.KeyGenPhase3Msg, participants []string) *bhs256k1.PublicKey {
	var v string
	for _, v = range participants {
		if msg.LabelFrom == v {
			break
		}
	}
	num, deno := bhsssa.CalBs(participants, v, bhsssa.S256k1Prime)
	Li := bhsssa.CalLi(num, deno, bhsssa.S256k1Prime)
	result := &bhs256k1.PublicKey{}
	result.Curve = bhs256k1.S256()
	result.X, result.Y = result.ScalarMult(msg.GetNativeShamirPubKey().X, msg.GetNativeShamirPubKey().Y, Li.Bytes())
	return result
}
