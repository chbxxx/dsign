package dsigned25519

import (
	"errors"

	"github.com/bluehelix-chain/dsign/bhcrypto/bhcheck"
	"github.com/bluehelix-chain/dsign/bhcrypto/bhed25519"
	"github.com/bluehelix-chain/dsign/communicator"
	"github.com/bluehelix-chain/dsign/logger"
	"math/big"
)

type EdKeyGenerator struct {
	label  string
	logger logger.Logger
	//TODO:Object Design of ZKPROOF
	sch bhcheck.HonestSchnorr
}

func NewEdKeyGenerator(label string, logger logger.Logger) *EdKeyGenerator {
	return &EdKeyGenerator{
		label:  label,
		logger: logger,
		sch:    bhcheck.HonestSchnorr{},
	}
}

func (kg *EdKeyGenerator) KeyGen(nodeList []string, T int, comm communicator.EdCommunicator) (*NodeEdKeyGen, *bhcheck.Evidence, error) {
	//准备一个evidence来放有问题的信息
	evidence := &bhcheck.Evidence{}
	N := len(nodeList)
	//检查Threshold不能比整体的N还要大。
	if T > N {
		//TODO: properly error handling flow.
		kg.logger.Error("T & N numbers not match")
		return nil, nil, errors.New("T & N numbers not match")
	}

	//检查本机是否存在与所有签名的列表中
	if !isInList(kg.label, nodeList) {
		return nil, nil, errors.New("this node does not in Sign List")
	}

	//初始化本机,同时已经准备好了EdKeygenPhase1
	var t, err = NewNodeEdKey(kg.label, T, N, getCoeff(nodeList), comm)
	if err != nil {
		return nil, nil, err
	}

	//调用通讯方法，开始广播Phase1 Msg

	t.comm.SendEdKeyGenPhase1Msg(t.EdKeyGenPhase1MsgSent)

	//收其他的广播
	for i := 0; i < N; i++ {
		msg, err := t.comm.GetEdKeyGenPhase1Msg()
		if err != nil {
			//错误处理 TODO: 这里missing part很搞笑，因为是循环，所以missing的不一定有问题
			received := []string{kg.label}
			for _, msg := range t.EdKeyGenPhase1MsgReceived {
				received = append(received, msg.LabelFrom)
			}

			negativeNodes := getMissingStrings(received, nodeList)
			evidence.SetNegativeNodes(negativeNodes)
			kg.logger.Error("EdKeyGenPhase1 lacking msg")
			return nil, evidence, err
		}
		//把收到的信息放到对象里
		t.EdKeyGenPhase1MsgReceived = append(t.EdKeyGenPhase1MsgReceived, msg)
	}
	//把Phase1收到的信息原地进行映射，本来是一个方法调用，我修改成了直接调用
	//t.GetEdKeyGenPhase1MsgMap()
	for _, v := range t.EdKeyGenPhase1MsgReceived {
		t.EdKeyGenPhase1MsgMap[v.LabelFrom] = v
		t.shamirSharePubKey[v.LabelFrom] = v.GetNativeShamirSharePubKey()
	}

	//准备第二轮要发送的消息
	if err := t.GetEdKeyGenPhase2MsgSent(); err != nil {
		return nil, nil, err
	}

	//发送第二轮加密过后的密码
	t.comm.SendEdKeyGenPhase2Msg(t.EdKeyGenPhase2MsgSent)

	//收第二轮消息
	for i := 0; i < N; i++ {
		msg, err := t.comm.GetEdKeyGenPhase2Msg()
		if err != nil {
			//错误处理 TODO: 这里missing part很搞笑，因为是循环，所以missing的不一定有问题
			received := []string{kg.label}
			for _, msg := range t.EdKeyGenPhase2MsgReceived {
				received = append(received, msg.LabelFrom)
			}
			kg.logger.Error("EdKeyGenPhase2 lacking msg")
			negativeNodes := getMissingStrings(received, nodeList)
			evidence.SetNegativeNodes(negativeNodes)

			return nil, evidence, err
		}
		//把收到的信息放到对象里
		t.EdKeyGenPhase2MsgReceived = append(t.EdKeyGenPhase2MsgReceived, msg)
	}

	//把Phase2收到的信息原地进行映射
	for _, v := range t.EdKeyGenPhase2MsgReceived {
		t.EdKeyGenPhase2MsgMap[v.LabelFrom] = v
	}

	//从2中恢复并解密出来出来属于自己的密钥分片
	for _, v := range t.coeff {
		tempR2Msg := t.EdKeyGenPhase2MsgMap[v.String()]
		t.ShareReceived[tempR2Msg.LabelFrom] = tempR2Msg.GetNativeShare(t.shamirSharePrtKey)
	}
	checkPubKeyCommitResult, checkPubKeyCommitEvidence := t.CheckEdPubKeyCommit()
	if !checkPubKeyCommitResult || !t.CheckEdShamirCommit() {
		return nil, checkPubKeyCommitEvidence, errors.New("COMMITMENT CHECK FAIL")
	}
	//第3步，ZKProof
	t.EdKeyGenPhase3MsgSent.LabelFrom = t.label
	y := big.NewInt(0)
	for _, v := range t.ShareReceived {
		y = y.Add(y, v.Y)
	}
	tempPubkey := bhed25519.GetEdPubkeyByNum(y)
	t.EdKeyGenPhase3MsgSent.SetNativeShamirPubKey(tempPubkey)
	t.EdKeyGenPhase3MsgSent.SetNativeSchnorrZKProof(kg.sch.Proof(t.prtKey.GetD(), bhed25519.Edwards()))

	t.comm.SendEdKeyGenPhase3Msg(t.EdKeyGenPhase3MsgSent)

	errStr := ""
	var schnorrEvidenceList []*bhcheck.SchnorrCheaterEvidence = make([]*bhcheck.SchnorrCheaterEvidence, 0)
	for i := 0; i < N; i++ {
		temp, err := t.comm.GetEdKeyGenPhase3Msg()
		if err != nil {
			received := []string{kg.label}
			for _, msg := range t.EdKeyGenPhase3MsgReceived {
				received = append(received, msg.LabelFrom)
			}
			negativeNodes := getMissingStrings(received, nodeList)
			evidence.SetNegativeNodes(negativeNodes)
			kg.logger.Error("EdKeyGenPhase3 lacking msg")
			return nil, evidence, err
		}
		t.EdKeyGenPhase3MsgReceived = append(t.EdKeyGenPhase3MsgReceived, temp)
		p := temp.GetNativeSchnorrZKProof()
		label := temp.LabelFrom
		pubKey, _ := bhed25519.ParsePubKey(t.EdKeyGenPhase2MsgMap[label].PubKey)
		if !bhcheck.CheckPubkeyProof(p, pubKey, bhed25519.Edwards()) {
			errStr = errStr + temp.LabelFrom + " SCHNORR PROOF CHECK FAIL"
		}
	}
	if errStr != "" {
		evidence.SetSchnorrCheaterEvidences(schnorrEvidenceList)
		return nil, evidence, errors.New(errStr)
	}

	//从2中拿到所有人的pub并计算最终的
	pubKeyList := make([]*bhed25519.PublicKey, N)
	for i, v := range t.coeff {
		tempR2Msg := t.EdKeyGenPhase2MsgMap[v.String()]
		pubKeyList[i], err = bhed25519.ParsePubKey(tempR2Msg.PubKey)
		if err != nil {
			kg.logger.Error("Recovery PubKey Failed")
			return nil, nil, err
		}
	}

	t.FullPubKey = bhed25519.CombinePubkeys(pubKeyList)

	//TODO:ok==false时，检查所有C(n,t)+C(n,t+1)+……+C(n,n)的组合，找出作弊节点
	//TODO: 优化Evidence等对象，
	ok, shamirEvidence := t.checkFinalShare()
	if !ok {

		evidence.SetShamirCheckEvidence(shamirEvidence)
		return nil, evidence, errors.New("FINAL SHAMIR CHECK FAIL")
	}

	return t, evidence, nil
}

// Utilities
func getCoeff(nodeList []string) []*big.Int {
	coeff := make([]*big.Int, len(nodeList))
	for i := range nodeList {
		c, _ := big.NewInt(0).SetString(nodeList[i], 10)
		coeff[i] = c
	}
	return coeff
}

func isInList(s string, list []string) bool {
	for _, str := range list {
		if s == str {
			return true
		}
	}
	return false
}

func getMissingStrings(has []string, all []string) []string {
	var missing []string
	for _, n := range all {
		var found bool
		for _, s := range has {
			if s == n {
				found = true
				break
			}
		}
		if !found {
			missing = append(missing, n)
		}
	}
	return missing
}
