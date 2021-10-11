package dsigned25519

import (
	"encoding/hex"
	"fmt"
	"github.com/bluehelix-chain/dsign/bhcrypto/bhed25519"
	"github.com/bluehelix-chain/dsign/bhcrypto/bhs256k1"
	"github.com/bluehelix-chain/dsign/bhsssa"
	"github.com/bluehelix-chain/dsign/communicator"
	"github.com/bluehelix-chain/dsign/logger"
	"github.com/stretchr/testify/assert"
	"math/big"

	"testing"
)

func TestKeyGen(t *testing.T) {
	for i := 0; i < 100; i++ {
		testCommunicator(t)
	}
}

func testCommunicator(t *testing.T) {
	N := 3
	T := 2
	var nodeList, nodes = getNodes(N)
	var nodeKeys = make(map[string]*NodeEdKeyGen, N)
	done := make(chan string)
	for i := range nodes {
		go func(label string) {
			//这里来模拟一下网络通讯，每个人都会有一个全局一样的communicator
			var comm communicator.EdCommunicator
			var err error
			localComm := communicator.NewLocalEdCommunicator(nodes, N, label)
			comm = localComm

			//每个Node都有一个Generator，每个节点都去call 自己的KeyGen
			EdKeyGenerator := NewEdKeyGenerator(label, logger.DefaultLogger)
			nodeKeys[label], _, err = EdKeyGenerator.KeyGen(nodeList, T, comm)

			if err != nil {
				done <- "Failed!" + err.Error()
			} else {
				done <- "Done!"
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

	combinePriKeyBigInt := big.NewInt(0)
	var FullPubKey []byte
	for k, v := range nodeKeys {

		FullPubKey = v.FullPubKey.Serialize()
		shareReceivedSlice := make([]bhsssa.ShareXY, 0, len(v.ShareReceived))

		for _, value := range v.ShareReceived {

			shareReceivedSlice = append(shareReceivedSlice, value)
		}
		combinePriKeyBigInt = combinePriKeyBigInt.Add(combinePriKeyBigInt, bhsssa.KeyCombine(nodeList, k, shareReceivedSlice, bhsssa.Ed25519Prime))

	}
	combinePriKeyBigInt = combinePriKeyBigInt.Mod(combinePriKeyBigInt, bhed25519.Edwards().N)

	_, fullpubfrompriv, _ := bhed25519.PrivKeyFromScalar(combinePriKeyBigInt.Bytes())

	fmt.Printf("Full Prikey: %s \n", hex.EncodeToString(combinePriKeyBigInt.Bytes()))
	fmt.Printf("Full Pub from prikey: %s \n", hex.EncodeToString(fullpubfrompriv.Serialize()))
	assert.Equal(t, FullPubKey, fullpubfrompriv.Serialize(), "PubKey Not Match")
}

func TestAdd(t *testing.T) {

	for i := 1; i < 100; i++ {
		BaseX, BaseY := big.NewInt(int64(i)), big.NewInt(int64(100+i))

		fmt.Printf("Base X: %s Base Y: %s \n", BaseX.String(), BaseY.String())
		//edAdd
		tempPubkey := &bhed25519.PublicKey{}
		tempPubkey.Curve = bhed25519.Edwards()
		tempPubkey.X, tempPubkey.Y = big.NewInt(0), big.NewInt(0)
		tempPubkey.X, tempPubkey.Y = tempPubkey.Add(tempPubkey.X, tempPubkey.Y, BaseX, BaseY)
		fmt.Printf("Ed Add X: %s Ed Add Y: %s \n", tempPubkey.X.String(), tempPubkey.Y.String())

		tempBTCPubkey := &bhs256k1.PublicKey{}
		tempBTCPubkey.Curve = bhs256k1.S256()
		tempBTCPubkey.X, tempBTCPubkey.Y = big.NewInt(0), big.NewInt(0)
		tempBTCPubkey.X, tempBTCPubkey.Y = tempBTCPubkey.Add(tempBTCPubkey.X, tempBTCPubkey.Y, BaseX, BaseY)
		fmt.Printf("Btc Add X: %s Btc Add Y: %s \n", tempBTCPubkey.X.String(), tempBTCPubkey.Y.String())
		fmt.Println("===============")

	}

}

func TestExcahnge(t *testing.T) {

	for i := 1; i < 100; i++ {
		BaseX, BaseY := big.NewInt(int64(i)), big.NewInt(int64(100+i))
		//prikey, _ := bhed25519.GeneratePrivateKey()
		fmt.Printf("Base X: %s Base Y: %s \n", BaseX.String(), BaseY.String())
		//edAdd
		//tempPubkey := prikey.PubKey()
		expMul1 := &bhed25519.PublicKey{}
		expMul1.Curve = bhed25519.Edwards()
		expMul2 := &bhed25519.PublicKey{}
		expMul2.Curve = bhed25519.Edwards()
		expMul1.X, expMul1.Y = expMul1.ScalarBaseMult(BaseX.Bytes())
		expMul2.X, expMul2.Y = expMul2.ScalarBaseMult(BaseY.Bytes())
		expMul1.X, expMul1.Y = expMul1.Add(expMul1.X, expMul1.Y, expMul2.X, expMul2.Y)
		fmt.Printf("Ed Add X: %s Ed Add Y: %s \n", expMul1.X.String(), expMul1.Y.String())

		expMul3 := &bhed25519.PublicKey{}
		expMul3.Curve = bhed25519.Edwards()
		var BaseXplusY = BaseX
		BaseXplusY.Add(BaseXplusY, BaseY)
		expMul3.X, expMul3.Y = expMul3.ScalarBaseMult(BaseXplusY.Bytes())

		fmt.Printf("Btc Add X: %s Btc Add Y: %s \n", expMul3.X.String(), expMul3.Y.String())
		fmt.Println("===============")

	}

}

func TestShareFinalCheckEssential(t *testing.T) {
	N := 3
	T := 3
	var coeff []*big.Int = make([]*big.Int, N)
	coeff[0], _ = big.NewInt(0).SetString("2", 10)
	coeff[1], _ = big.NewInt(0).SetString("3", 10)
	coeff[2], _ = big.NewInt(0).SetString("4", 10)

	var coeffString []string = make([]string, N)
	coeffString[0] = "2"
	coeffString[1] = "3"
	coeffString[2] = "4"

	var prikey2 *bhed25519.PrivateKey
	var pubkey2 *bhed25519.PublicKey
	var prikey3 *bhed25519.PrivateKey
	var pubkey3 *bhed25519.PublicKey
	var prikey4 *bhed25519.PrivateKey
	var pubkey4 *bhed25519.PublicKey
	for prikey2 == nil || pubkey2 == nil {
		prikey2, pubkey2, _ = bhed25519.PrivKeyFromScalar(bhed25519.GetRandomPositiveInt(bhed25519.Edwards().N).Bytes()) //TODO: 随机数确定真的是随机数
	}
	for prikey3 == nil || pubkey3 == nil {
		prikey3, pubkey3, _ = bhed25519.PrivKeyFromScalar(bhed25519.GetRandomPositiveInt(bhed25519.Edwards().N).Bytes()) //TODO: 随机数确定真的是随机数
	}
	for prikey4 == nil || pubkey4 == nil {
		prikey4, pubkey4, _ = bhed25519.PrivKeyFromScalar(bhed25519.GetRandomPositiveInt(bhed25519.Edwards().N).Bytes()) //TODO: 随机数确定真的是随机数
	}

	tempShareArray2, _, _ := bhsssa.CreateShareSecrets(T, N, prikey2.GetD(), coeff, bhsssa.Ed25519Prime)
	tempShareArray3, _, _ := bhsssa.CreateShareSecrets(T, N, prikey3.GetD(), coeff, bhsssa.Ed25519Prime)
	tempShareArray4, _, _ := bhsssa.CreateShareSecrets(T, N, prikey4.GetD(), coeff, bhsssa.Ed25519Prime)

	finalprikeyD := big.NewInt(0)
	finalprikeyD = big.NewInt(0).Add(prikey2.GetD(), prikey3.GetD())
	finalprikeyD = big.NewInt(0).Add(finalprikeyD, prikey4.GetD())
	finalprikeyD = big.NewInt(0).Mod(finalprikeyD, bhed25519.Edwards().N)

	_, finalpubkey, _ := bhed25519.PrivKeyFromScalar(finalprikeyD.Bytes())

	pubKeyList := make([]*bhed25519.PublicKey, 0)
	pubKeyList = append(pubKeyList, pubkey2)
	pubKeyList = append(pubKeyList, pubkey3)
	pubKeyList = append(pubKeyList, pubkey4)

	finalpubkeyCombine := bhed25519.CombinePubkeys(pubKeyList)

	y2 := big.NewInt(0)
	y3 := big.NewInt(0)
	y4 := big.NewInt(0)

	num2, deno2 := bhsssa.CalBs(coeffString, "2", bhsssa.Ed25519Prime)
	Li2 := bhsssa.CalLi(num2, deno2, bhsssa.Ed25519Prime)

	num3, deno3 := bhsssa.CalBs(coeffString, "3", bhsssa.Ed25519Prime)
	Li3 := bhsssa.CalLi(num3, deno3, bhsssa.Ed25519Prime)

	num4, deno4 := bhsssa.CalBs(coeffString, "4", bhsssa.Ed25519Prime)
	Li4 := bhsssa.CalLi(num4, deno4, bhsssa.Ed25519Prime)

	y2 = y2.Add(y2, tempShareArray2["2"].Y)
	y2 = y2.Add(y2, tempShareArray3["2"].Y)
	y2 = y2.Add(y2, tempShareArray4["2"].Y)

	y3 = y3.Add(y3, tempShareArray2["3"].Y)
	y3 = y3.Add(y3, tempShareArray3["3"].Y)
	y3 = y3.Add(y3, tempShareArray4["3"].Y)

	y4 = y4.Add(y4, tempShareArray2["4"].Y)
	y4 = y4.Add(y4, tempShareArray3["4"].Y)
	y4 = y4.Add(y4, tempShareArray4["4"].Y)

	y2Li2Pub := &bhed25519.PublicKey{}
	y2Li2Pub.X, y2Li2Pub.Y = bhed25519.Edwards().ScalarBaseMult(y2.Mul(y2, Li2).Bytes())

	y3Li3Pub := &bhed25519.PublicKey{}
	y3Li3Pub.X, y3Li3Pub.Y = bhed25519.Edwards().ScalarBaseMult(y3.Mul(y3, Li3).Bytes())

	y4Li4Pub := &bhed25519.PublicKey{}
	y4Li4Pub.X, y4Li4Pub.Y = bhed25519.Edwards().ScalarBaseMult(y4.Mul(y4, Li4).Bytes())

	finalyLIPub := &bhed25519.PublicKey{}
	finalyLIPub.Curve = bhed25519.Edwards()

	finalyLIPub.X, finalyLIPub.Y = y2Li2Pub.X, y2Li2Pub.Y
	finalyLIPub.X, finalyLIPub.Y = finalyLIPub.Add(finalyLIPub.X, finalyLIPub.Y, y3Li3Pub.X, y3Li3Pub.Y)
	finalyLIPub.X, finalyLIPub.Y = finalyLIPub.Add(finalyLIPub.X, finalyLIPub.Y, y4Li4Pub.X, y4Li4Pub.Y)

	assert.Equal(t, true, finalpubkey.IsEqual(finalpubkeyCombine), "Err Pubkey combine")
	assert.Equal(t, true, finalpubkey.IsEqual(finalyLIPub), "Err finalyLIPub")

}

func TestKeyCombine(t *testing.T) {
	N := 3
	T := 3
	var coeff []*big.Int = make([]*big.Int, N)
	coeff[0], _ = big.NewInt(0).SetString("2", 10)
	coeff[1], _ = big.NewInt(0).SetString("3", 10)
	coeff[2], _ = big.NewInt(0).SetString("4", 10)

	var coeffString []string = make([]string, N)
	coeffString[0] = "2"
	coeffString[1] = "3"
	coeffString[2] = "4"

	var prikey2 *bhed25519.PrivateKey
	var pubkey2 *bhed25519.PublicKey
	var prikey3 *bhed25519.PrivateKey
	var pubkey3 *bhed25519.PublicKey
	var prikey4 *bhed25519.PrivateKey
	var pubkey4 *bhed25519.PublicKey

	for prikey2 == nil || pubkey2 == nil {
		prikey2, pubkey2, _ = bhed25519.PrivKeyFromScalar(bhed25519.GetRandomPositiveInt(bhed25519.Edwards().N).Bytes()) //TODO: 随机数确定真的是随机数
	}
	for prikey3 == nil || pubkey3 == nil {
		prikey3, pubkey3, _ = bhed25519.PrivKeyFromScalar(bhed25519.GetRandomPositiveInt(bhed25519.Edwards().N).Bytes()) //TODO: 随机数确定真的是随机数
	}
	for prikey4 == nil || pubkey4 == nil {
		prikey4, pubkey4, _ = bhed25519.PrivKeyFromScalar(bhed25519.GetRandomPositiveInt(bhed25519.Edwards().N).Bytes()) //TODO: 随机数确定真的是随机数
	}

	tempShareArray2, _, _ := bhsssa.CreateShareSecrets(T, N, prikey2.GetD(), coeff, bhsssa.Ed25519Prime)
	tempShareArray3, _, _ := bhsssa.CreateShareSecrets(T, N, prikey3.GetD(), coeff, bhsssa.Ed25519Prime)
	tempShareArray4, _, _ := bhsssa.CreateShareSecrets(T, N, prikey4.GetD(), coeff, bhsssa.Ed25519Prime)

	finalprikeyD := prikey2.GetD()
	finalprikeyD = finalprikeyD.Add(finalprikeyD, prikey3.GetD())
	finalprikeyD = finalprikeyD.Add(finalprikeyD, prikey4.GetD())
	finalprikeyD = finalprikeyD.Mod(finalprikeyD, bhed25519.Edwards().N)

	finalprikey, finalpubkey, _ := bhed25519.PrivKeyFromScalar(finalprikeyD.Bytes())

	pubKeyList := make([]*bhed25519.PublicKey, 0)
	pubKeyList = append(pubKeyList, pubkey2)
	pubKeyList = append(pubKeyList, pubkey3)
	pubKeyList = append(pubKeyList, pubkey4)

	finalpubkeyCombine := bhed25519.CombinePubkeys(pubKeyList)

	assert.Equal(t, true, finalpubkey.IsEqual(finalpubkeyCombine), "Err Pubkey combine")

	pureShareArray2 := make([]bhsssa.ShareXY, 0)
	pureShareArray2 = append(pureShareArray2, tempShareArray2["2"])
	pureShareArray2 = append(pureShareArray2, tempShareArray3["2"])
	pureShareArray2 = append(pureShareArray2, tempShareArray4["2"])

	pureShareArray3 := make([]bhsssa.ShareXY, 0)
	pureShareArray3 = append(pureShareArray3, tempShareArray2["3"])
	pureShareArray3 = append(pureShareArray3, tempShareArray3["3"])
	pureShareArray3 = append(pureShareArray3, tempShareArray4["3"])

	pureShareArray4 := make([]bhsssa.ShareXY, 0)
	pureShareArray4 = append(pureShareArray4, tempShareArray2["4"])
	pureShareArray4 = append(pureShareArray4, tempShareArray3["4"])
	pureShareArray4 = append(pureShareArray4, tempShareArray4["4"])

	Final2Combine := bhsssa.KeyCombine(coeffString, "2", pureShareArray2, bhsssa.Ed25519Prime)
	Final3Combine := bhsssa.KeyCombine(coeffString, "3", pureShareArray3, bhsssa.Ed25519Prime)
	Final4Combine := bhsssa.KeyCombine(coeffString, "4", pureShareArray4, bhsssa.Ed25519Prime)

	combinePriKeyBigIntOK := big.NewInt(0)
	combinePriKeyBigIntOK = combinePriKeyBigIntOK.Add(combinePriKeyBigIntOK, Final2Combine)
	combinePriKeyBigIntOK = combinePriKeyBigIntOK.Add(combinePriKeyBigIntOK, Final3Combine)
	combinePriKeyBigIntOK = combinePriKeyBigIntOK.Add(combinePriKeyBigIntOK, Final4Combine)
	combinePriKeyBigIntOK = combinePriKeyBigIntOK.Mod(combinePriKeyBigIntOK, bhed25519.Edwards().N)

	fullprifrompriok, fullpubfromprivok, _ := bhed25519.PrivKeyFromScalar(combinePriKeyBigIntOK.Bytes())

	assert.Equal(t, true, fullprifrompriok.GetD().Cmp(finalprikey.GetD()) == 0, "Pri Check NOT OK")
	assert.Equal(t, true, finalpubkeyCombine.IsEqual(fullpubfromprivok), "Pub Check NOT OK")

}

func TestKeyGenData(t *testing.T) {
	nodeKey := &NodeEdKeyGen{}
	nodeKey.label = "12345"
	nodeKey.T, nodeKey.N = 3, 5
	var coeff = [5]string{"12345", "23451", "34512", "45123", "51234"}
	nodeKey.ShareReceived = make(map[string]bhsssa.ShareXY)

	for k, v := range coeff {
		x, _ := big.NewInt(0).SetString(v, 10)
		y := big.NewInt(int64(k))
		tempShare := bhsssa.ShareXY{
			X: x,
			Y: y,
		}
		nodeKey.ShareReceived[v] = tempShare

	}
	priKey := bhed25519.NewPrivateKey(big.NewInt(666666777778888))
	nodeKey.FullPubKey, _ = bhed25519.ParsePubKey(priKey.PubKey().SerializeCompressed())

	data := GetKeyGenData(nodeKey)
	nodeKeyLoad := SetKeyGenData(data)

	assert.Equal(t, nodeKey.T, nodeKeyLoad.T)
	assert.Equal(t, nodeKey.N, nodeKeyLoad.N)
	for _, v := range coeff {
		assert.Equal(t, nodeKey.ShareReceived[v], nodeKeyLoad.ShareReceived[v])
	}
}
