package dsigned25519

import (
	"errors"
	"fmt"
	"github.com/bluehelix-chain/dsign/bhcrypto/bhcheck"
	"github.com/bluehelix-chain/dsign/bhcrypto/bhed25519"
	"github.com/bluehelix-chain/dsign/bhcrypto/bhs256k1"
	"github.com/bluehelix-chain/dsign/bhsssa"
	"github.com/bluehelix-chain/dsign/communicator"
	"github.com/bluehelix-chain/dsign/types"

	"math/big"
	"strconv"
)

type NodeEdKeyGen struct {
	label                string
	comm                 communicator.EdCommunicator
	T, N                 int                                //threashold、N
	EdKeyGenPhase1MsgMap map[string]types.EdKeyGenPhase1Msg //label->EdKeyGenPhase1Msg Mapping
	EdKeyGenPhase2MsgMap map[string]types.EdKeyGenPhase2Msg //label->EdKeyGenPhase2Msg Mapping
	EdKeyGenPhase3MsgMap map[string]types.EdKeyGenPhase3Msg //label->EdKeyGenPhase3Msg Mapping

	coeff             []*big.Int
	shamirSharePrtKey *bhed25519.PrivateKey
	shamirSharePubKey map[string]*bhed25519.PublicKey
	prtKey            *bhed25519.PrivateKey
	pubKey            *bhed25519.PublicKey

	blindFactor  *big.Int //blind factor for commit
	pubKeyCommit [32]byte
	cofCommit    []*bhed25519.PublicKey //shamir cof's commit

	shareOwn   bhsssa.ShareXY            //Local Shamir Secrets Shares
	shareArray map[string]bhsssa.ShareXY //The Shamir Secrets Shares to others

	FullPubKey    *bhed25519.PublicKey
	ShareReceived map[string]bhsssa.ShareXY //The Shamir Secrets Shares from others

	EdKeyGenPhase1MsgSent     types.EdKeyGenPhase1Msg
	EdKeyGenPhase1MsgReceived []types.EdKeyGenPhase1Msg
	EdKeyGenPhase2MsgSent     map[string]types.EdKeyGenPhase2Msg
	EdKeyGenPhase2MsgReceived []types.EdKeyGenPhase2Msg
	EdKeyGenPhase3MsgSent     types.EdKeyGenPhase3Msg
	EdKeyGenPhase3MsgReceived []types.EdKeyGenPhase3Msg
}

func NewNodeEdKey(label string, T int, N int, coeff []*big.Int, comm communicator.EdCommunicator) (*NodeEdKeyGen, error) {
	fmt.Printf("NodeKey %s is creating \n", label)
	n := &NodeEdKeyGen{}
	n.label = label
	n.comm = comm
	n.coeff = coeff
	n.T = T // Threshold
	n.N = N // Total

	//生成本地的私钥、公钥。以及本地私钥放到别的地方存储的公分片。cofCommit是每个 cof 乘 曲线原点
	n.prtKey, n.pubKey, n.shareArray, n.cofCommit = keyGen(T, N, n.coeff)
	n.shamirSharePubKey = make(map[string]*bhed25519.PublicKey)
	//生成稍等共享密钥分片的时候加密所需要的公私钥对 TODO: 一定有更好的命名方式
	var shamirShareprikey *bhed25519.PrivateKey
	var shamirSharepubkey *bhed25519.PublicKey
	for shamirShareprikey == nil || shamirSharepubkey == nil {
		shamirShareprikey, shamirSharepubkey, _ = bhed25519.PrivKeyFromScalar(bhed25519.GetRandomPositiveInt(bhed25519.Edwards().N).Bytes()) //TODO: 随机数确定真的是随机数
	}
	n.shamirSharePrtKey = shamirShareprikey
	n.shamirSharePubKey[n.label] = shamirSharepubkey

	for n.blindFactor == nil || n.blindFactor == big.NewInt(0) {
		n.blindFactor = bhed25519.GetRandomPositiveInt(bhed25519.Edwards().N)
	}
	n.pubKeyCommit = bhcheck.GetPubkeyCommit(n.pubKey, n.blindFactor, bhed25519.Edwards())

	//从所有的私钥分片中取出来属于本地的私钥分片。
	n.shareOwn = n.shareArray[n.label]
	//初始化稍等用来接受其他人分享过来的私钥分片的地方
	n.ShareReceived = make(map[string]bhsssa.ShareXY)

	//先准备一些数据
	n.EdKeyGenPhase2MsgSent = make(map[string]types.EdKeyGenPhase2Msg, n.N)
	n.EdKeyGenPhase1MsgMap = make(map[string]types.EdKeyGenPhase1Msg)
	n.EdKeyGenPhase2MsgMap = make(map[string]types.EdKeyGenPhase2Msg)
	//-------Start to Prepare EdKeyGenPhase1 Msg---
	tempEdKeyGenPhase1 := types.EdKeyGenPhase1Msg{}
	tempEdKeyGenPhase1.LabelFrom = n.label
	//这个地方是要把系数*基点之后的所有数据序列化之后拼凑到一个byte里。
	//带有Native的基本都是本身有一个pb类型，但我们还需要给他写一个Get/Set，那就加上一个native作为区分
	tempEdKeyGenPhase1.SetNativeCofCommit(n.cofCommit)
	tempEdKeyGenPhase1.SetNativePubKeyCommit(n.pubKeyCommit)
	//设置定向秘密分享时候用的加密公钥
	tempEdKeyGenPhase1.SetNativeShamirSharePubKey(n.shamirSharePubKey[n.label])
	n.EdKeyGenPhase1MsgSent = tempEdKeyGenPhase1
	return n, nil
}

func (n *NodeEdKeyGen) GetEdKeyGenPhase2MsgSent() error {
	for k, v := range n.shareArray {
		temp := types.EdKeyGenPhase2Msg{}
		temp.LabelFrom = n.label
		temp.LabelTo = k
		temp.SetNativePubKey(n.pubKey)
		if n.shamirSharePubKey[k] == nil {
			return errors.New("err shamir share's pubkey is nil")
		}
		temp.SetNativeShare(n.shamirSharePubKey[k], v)
		temp.SetNativeBlindFactor(n.blindFactor)
		n.EdKeyGenPhase2MsgSent[k] = temp
	}

	return nil
}

//检验pubkey commit
func (n *NodeEdKeyGen) CheckEdPubKeyCommit() (bool, *bhcheck.Evidence) {
	evidences := &bhcheck.Evidence{}
	if len(n.EdKeyGenPhase1MsgMap) != n.N {
		return false, evidences
	}
	if len(n.EdKeyGenPhase2MsgMap) != n.N {
		return false, evidences
	}
	for _, v := range n.coeff {
		tempR1Msg := n.EdKeyGenPhase1MsgMap[v.String()]
		tempR2Msg := n.EdKeyGenPhase2MsgMap[v.String()]
		if !bhcheck.CheckPubkeyCommit(tempR1Msg.GetNativePubKeyCommit(), tempR2Msg.GetNativePubKey(), tempR2Msg.GetNativeBlindFactor(), bhed25519.Edwards()) {
			return false, evidences
		}
	}
	return true, evidences
}

//TODO:Clean up and fix the problem
func (n *NodeEdKeyGen) CheckEdShamirCommit() bool {

	if len(n.EdKeyGenPhase1MsgMap) != n.N {
		return false
	}
	if len(n.EdKeyGenPhase2MsgMap) != n.N {
		return false
	}
	shareSum := bhsssa.ShareXY{}
	shareSum.X, shareSum.Y = big.NewInt(0), big.NewInt(0)
	shareSum.X.Add(shareSum.X, n.shareOwn.X)
	//Recovery my own share's X and
	for _, v := range n.coeff {
		tempR2Msg := n.EdKeyGenPhase2MsgMap[v.String()]
		n.ShareReceived[tempR2Msg.LabelFrom] = tempR2Msg.GetNativeShare(n.shamirSharePrtKey)
		shareSum.Y.Add(shareSum.Y, n.ShareReceived[tempR2Msg.LabelFrom].Y)
	}

	finalCommit := make([]*bhed25519.PublicKey, 0)
	if _, ok := n.EdKeyGenPhase2MsgMap[n.coeff[0].String()]; !ok || len(n.EdKeyGenPhase1MsgMap) < n.N {
		return false
	}
	//Very Basic Check about where others' cof
	for _, v := range n.coeff {
		tempR1Msg := n.EdKeyGenPhase1MsgMap[v.String()]
		cof := tempR1Msg.GetNativeCofCommit()
		tempR2Msg := n.EdKeyGenPhase2MsgMap[v.String()]
		if cof[0].X.Cmp(tempR2Msg.GetNativePubKey().X) != 0 || cof[0].Y.Cmp(tempR2Msg.GetNativePubKey().Y) != 0 {
			return false
		}

	}

	for i := 0; i < len(n.EdKeyGenPhase1MsgMap[n.coeff[0].String()].CofCommit); i++ {
		tempPubkey := &bhed25519.PublicKey{}
		tempPubkey.Curve = bhed25519.Edwards()
		for j, v := range n.coeff {
			tempR1Msg := n.EdKeyGenPhase1MsgMap[v.String()]
			cof := tempR1Msg.GetNativeCofCommit()
			if j == 0 {
				tempPubkey.X, tempPubkey.Y = cof[i].X, cof[i].Y
			} else {
				tempPubkey.X, tempPubkey.Y = bhed25519.Edwards().Add(tempPubkey.X, tempPubkey.Y, cof[i].X, cof[i].Y)
			}
		}
		finalCommit = append(finalCommit, tempPubkey)
	}

	////
	//Initial sum_XX,sum_YY
	sum_XX, sum_YY := big.NewInt(0), big.NewInt(0)
	//计算g*ShareY, 并且累加到全剧
	gY_X, gY_Y := bhed25519.Edwards().ScalarBaseMult(shareSum.Y.Bytes())

	//分别检查点是否在多项式子上
	for k, v := range n.coeff {
		from := v.String()
		tempR1Msg := n.EdKeyGenPhase1MsgMap[from]

		//拿对方的cof commit g*c0,g*c1 xxxxx
		gcoff := tempR1Msg.GetNativeCofCommit()

		//计算g*c0 + g*c1*X ..... 并且累加到全剧
		sum_X, sum_Y, t := gcoff[0].GetX(), gcoff[0].GetY(), big.NewInt(1)
		if !bhed25519.Edwards().IsOnCurve(sum_X, sum_Y) {
			panic(n.label + "Init Sum X,Sum Y Not ont the curve")
		}
		for j := 1; j < len(gcoff); j++ {
			t = t.Mul(t, shareSum.X).Mod(t, bhed25519.Edwards().N)
			gcoffXt_X, gcoffXt_Y := gcoff[j].ScalarMult(gcoff[j].X, gcoff[j].Y, t.Bytes())
			if !bhed25519.Edwards().IsOnCurve(gcoffXt_X, gcoffXt_Y) {
				panic(n.label + "gcoffXt Not ont the curve")
			}

			sum_X, sum_Y = bhed25519.Edwards().Add(sum_X, sum_Y, gcoffXt_X, gcoffXt_Y)
			if !bhed25519.Edwards().IsOnCurve(sum_X, sum_Y) {
				panic(n.label + "Sumed X Y Not ont the curve")
			}
		}
		//for the very frist round, just initial sum_XX and sum_YY, dont add (0,0)
		if k == 0 {
			sum_XX, sum_YY = sum_X, sum_Y
		} else {
			sum_XX, sum_YY = bhed25519.Edwards().Add(sum_XX, sum_YY, sum_X, sum_Y)
		}

	}

	return gY_X.Cmp(sum_XX) == 0 && gY_Y.Cmp(sum_YY) == 0
}

//判断最终的私钥分片是否正确
func (n *NodeEdKeyGen) checkFinalShare() (bool, []*bhcheck.ShamirCheckEvidence) {
	re := []*bhcheck.ShamirCheckEvidence{}
	localPubKeySum := &bhed25519.PublicKey{}
	localPubKeySum.Curve = bhed25519.Edwards()
	localPubKeySum.X = big.NewInt(0)
	localPubKeySum.Y = big.NewInt(0)
	for i, v := range n.EdKeyGenPhase2MsgReceived {
		if i == 0 {
			localPubKeySum.X, localPubKeySum.Y = v.GetNativePubKey().X, v.GetNativePubKey().Y
		} else {
			localPubKeySum.X, localPubKeySum.Y = localPubKeySum.Add(localPubKeySum.X, localPubKeySum.Y, v.GetNativePubKey().X, v.GetNativePubKey().Y)
		}

	}

	fmt.Println("localPubKeySum equal to final: " + strconv.FormatBool(localPubKeySum.IsEqual(n.FullPubKey)))
	checkArray := bhcheck.GenerateCheckArrays(n.T, n.N, n.coeff)
	checkResult := true
	//re := ShamirCheckEvidence{}
	for _, vi := range checkArray {
		var check bhed25519.PublicKey
		check.Curve = bhed25519.Edwards()
		check.X, check.Y = big.NewInt(0), big.NewInt(0)
		//遍历KeyGenPhase3Msg
		for _, msg3i := range n.EdKeyGenPhase3MsgReceived {
			//判断该KeyGenPhase3Msg是否在randomNodeList中
			for _, vj := range vi {
				if msg3i.LabelFrom == vj {

					temp := calShamirPubkeys(msg3i, vi)
					if check.X.Cmp(big.NewInt(0)) == 0 || check.Y.Cmp(big.NewInt(0)) == 0 {
						check.X, check.Y = temp.X, temp.Y
					} else {
						check.X, check.Y = check.Add(check.X, check.Y, temp.X, temp.Y)
					}

				}
			}
		}
		if !localPubKeySum.IsEqual(check) {
			checkResult = false
			for _, v := range n.EdKeyGenPhase3MsgReceived {
				proof_pub, _ := bhs256k1.ParsePubKey(v.Proof.GetPubKey(), bhs256k1.S256())
				re = append(re, &bhcheck.ShamirCheckEvidence{v.LabelFrom, v.ShamirPub, bhcheck.SchnorrZKProof{proof_pub, big.NewInt(0).SetBytes(v.Proof.Num)}})
			}
		}
	}
	return checkResult, re

}

//For External Extract data from Nodekey
func GetKeyGenData(n *NodeEdKeyGen) *types.EdKeyGenData {
	entry := &types.EdKeyGenData{
		Label:         n.label,
		SignThreshold: uint64(n.T),
		Paras:         make([]*types.EdParameterMap, 0),
		PubKeySum:     n.FullPubKey.SerializeCompressed(),
	}

	for k, v := range n.ShareReceived {
		tempPara := &types.EdParameterMap{}
		tempPara.Label = k
		tempPara.Share = &types.EdShareXY{
			X: v.X.Bytes(),
			Y: v.Y.Bytes(),
		}

		entry.Paras = append(entry.Paras, tempPara)
	}
	return entry
}

//For External Recover data to Nodekey
func SetKeyGenData(data *types.EdKeyGenData) *NodeEdKeyGen {
	nodeKey := &NodeEdKeyGen{}
	nodeKey.label = (data.Label)
	nodeKey.N = len(data.Paras)
	nodeKey.T = int(data.SignThreshold)
	nodeKey.ShareReceived = make(map[string]bhsssa.ShareXY)

	for _, para := range data.Paras {
		tempShare := bhsssa.ShareXY{
			X: new(big.Int).SetBytes(para.Share.X),
			Y: new(big.Int).SetBytes(para.Share.Y),
		}
		nodeKey.ShareReceived[para.Label] = tempShare
	}
	nodeKey.FullPubKey, _ = bhed25519.ParsePubKey(data.PubKeySum)
	return nodeKey
}

//根据KeyGenPhase3Msg，计算share.G*Li
func calShamirPubkeys(msg types.EdKeyGenPhase3Msg, participants []string) *bhed25519.PublicKey {
	var v string
	for _, v = range participants {
		if msg.LabelFrom == v {
			break
		}
	}

	num, deno := bhsssa.CalBs(participants, v, bhsssa.Ed25519Prime)
	Li := bhsssa.CalLi(num, deno, bhsssa.Ed25519Prime)
	result := &bhed25519.PublicKey{}
	result.Curve = bhed25519.Edwards()
	result.X, result.Y = result.ScalarMult(msg.GetNativeShamirPubKey().X, msg.GetNativeShamirPubKey().Y, Li.Bytes())

	return result
}

func getCheckByY(y *big.Int) *bhed25519.PublicKey {
	check := &bhed25519.PublicKey{}
	check.Curve = bhed25519.Edwards()
	check.X, check.Y = bhed25519.Edwards().ScalarBaseMult(y.Bytes())
	return check
}

//生成公私钥对，以及私钥的(t,n)分片
func keyGen(t, n int, coeff []*big.Int) (
	*bhed25519.PrivateKey, *bhed25519.PublicKey, map[string]bhsssa.ShareXY, []*bhed25519.PublicKey) {

	var prikey *bhed25519.PrivateKey
	var pubkey *bhed25519.PublicKey

	for prikey == nil || pubkey == nil {
		prikey, pubkey, _ = bhed25519.PrivKeyFromScalar(bhed25519.GetRandomPositiveInt(bhed25519.Edwards().N).Bytes()) //TODO: 随机数确定真的是随机数
	}

	//节点自身的私钥分片，系数。 Coff0 = 秘密。
	tempShareArray, coff, _ := bhsssa.CreateShareSecrets(t, n, prikey.GetD(), coeff, bhsssa.Ed25519Prime)

	return prikey, pubkey, tempShareArray, getCofCommits(coff)
}

func getCofCommits(cof []*big.Int) []*bhed25519.PublicKey {
	commits := make([]*bhed25519.PublicKey, len(cof))
	for i, v := range cof {
		tempCommit := &bhed25519.PublicKey{}
		tempCommit.Curve = bhed25519.Edwards()
		tempCommit.X, tempCommit.Y = tempCommit.ScalarBaseMult(v.Bytes())
		commits[i] = tempCommit
	}
	return commits
}

func byteTo32(data []byte) *[32]byte {
	var result [32]byte

	if len(data) < 32 {
		return nil
	}

	copy(result[:], data)
	return &result
}
