package dsigned25519

import (
	"fmt"
	"github.com/bluehelix-chain/dsign/communicator"
	"github.com/bluehelix-chain/dsign/logger"
	"github.com/stretchr/testify/assert"
	"math/big"
	"strconv"
	"testing"
)

func TestLocalKeySign(t *testing.T) {
	for i := 0; i < 100; i++ {
		T := 3
		P := 4
		N := 5
		testLocalSign(T, P, N, t)
	}

}

func testLocalSign(T, P, N int, t *testing.T) {
	str := "123456781234567845678123"
	hash := []byte(str)

	nodeList, dstSignNode := getNodes(N)
	signNodeList := nodeList[:P]
	var nodekeys = make(map[string]*NodeEdKeyGen, N)

	done := make(chan string)
	for i := range dstSignNode {
		go func(label string) {
			var comm communicator.EdCommunicator
			localComm := communicator.NewLocalEdCommunicator(dstSignNode, N, label)
			comm = localComm

			//每个Node都有一个Generator，每个节点都去call 自己的KeyGen
			EdkeyGenerater := NewEdKeyGenerator(label, logger.DefaultLogger)
			nodekeys[label], _, _ = EdkeyGenerater.KeyGen(nodeList, T, comm)

			signer := NewSigner(label, logger.DefaultLogger)
			sig, _, _, _ := signer.Sign(T, P, N, label, nodekeys[label], signNodeList, hash, comm)

			if isInNodeList(label, signNodeList) {
				fmt.Printf("Label %s: Sig.R is %s, Sig.S is %s \n", label, sig.R, sig.S)

				assert.True(t, sig.Verify(hash, nodekeys[label].FullPubKey), "Verification failure!")
				done <- label + ":" + strconv.FormatBool(sig.Verify(hash, nodekeys[label].FullPubKey))

			} else {
				done <- label + "Error"
			}
		}(i)
	}

	doneNum := 0
	for v := range done {
		fmt.Println(v)
		doneNum++
		if doneNum == N {
			break
		}
	}

	//For debug usage code
	/*
		var FullPubkey []byte
		//var FullPrikey []byte
		//Cal original nodekeys's pubkey and prikey
		combinePriKeyBigInt := big.NewInt(0)

		for k, v := range nodekeys {
			FullPubkey = v.FullPubKey.Serialize()
			shareReceivedSlice := make([]edsssa.ShareXY, 0, len(v.ShareReceived))

			for _, value := range v.ShareReceived {

				shareReceivedSlice = append(shareReceivedSlice, value)
			}
			combinePriKeyBigInt = combinePriKeyBigInt.Add(combinePriKeyBigInt, edsssa.KeyCombine(nodeList, k, shareReceivedSlice))
			combinePriKeyBigInt = combinePriKeyBigInt.Mod(combinePriKeyBigInt, types.Edwards().N)
		}
		fullprifrompriv, fullpubfrompriv, _ := types.PrivKeyFromScalar(combinePriKeyBigInt.Bytes())

		fmt.Printf("Test 1: Nodekey's pubkey %s \n        "+
			"Combi pubkey %s \n        "+
			"Combi prikey %s \n",
			hex.EncodeToString(FullPubkey),
			hex.EncodeToString(fullpubfrompriv.Serialize()),
			hex.EncodeToString(fullprifrompriv.Serialize()))

		combinePriKeyBigIntFromSign := big.NewInt(0)

		for _, v := range nodePkeys {
			combinePriKeyBigIntFromSign = combinePriKeyBigIntFromSign.Add(combinePriKeyBigIntFromSign, v)
			combinePriKeyBigIntFromSign = combinePriKeyBigIntFromSign.Mod(combinePriKeyBigIntFromSign, types.Edwards().N)
		}
		fullprifromsign, fullpubfromsign, _ := types.PrivKeyFromScalar(combinePriKeyBigIntFromSign.Bytes())
		fmt.Printf("Test 2: Nodekey's pubkey %s \n        "+
			"Combi pubkey %s \n        "+
			"Combi prikey %s \n",
			hex.EncodeToString(FullPubkey),
			hex.EncodeToString(fullprifromsign.Serialize()),
			hex.EncodeToString(fullpubfromsign.Serialize()))*/
}

func isInNodeList(label string, nodelist []string) bool {
	for _, v := range nodelist {
		if label == v {
			return true
		}
	}
	return false
}

func getNodes(n int) ([]string, map[string]*communicator.EdChanNode) {
	var nodeList []string = make([]string, n)
	var nodes map[string]*communicator.EdChanNode = make(map[string]*communicator.EdChanNode)
	for i, _ := range nodeList {
		label := big.NewInt(int64(2 + i)).String()
		nodeList[i] = label
		nodes[label] = communicator.NewEdChanNode(n)
	}
	return nodeList, nodes
}
