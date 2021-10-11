package dsign

import (
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"github.com/bluehelix-chain/dsign/bhcrypto"
	"github.com/bluehelix-chain/dsign/bhcrypto/bhcheck"
	"github.com/bluehelix-chain/dsign/bhcrypto/bhs256k1"
	"github.com/bluehelix-chain/dsign/bhsssa"
	"math/big"
	"strconv"
	"testing"

	"github.com/bluehelix-chain/dsign/communicator"
	"github.com/bluehelix-chain/dsign/logger"

	"github.com/radicalrafi/gomorph/gaillier"
	"github.com/stretchr/testify/assert"
)

func TestSchnorrInKeySignWithCheater(t *testing.T) {
	T := 3
	P := 4
	N := 5
	str := "123456781234567845678123"
	hash := []byte(str)

	nodeList, dstSignNode := getNodes(N, P)
	signNodeList := nodeList[:P]

	cheater := 2
	done := make(chan string)
	for i := range dstSignNode {
		go func(label string) {
			var comm communicator.Communicator
			localComm := communicator.NewLocalCommunicator(dstSignNode, N, label)
			comm = localComm

			trueKeyGenerater := NewKeyGenerator(label, logger.DefaultLogger)
			nodeKey, _, err := trueKeyGenerater.KeyGen(nodeList, T, comm)
			if err != nil {
				fmt.Println(err)
			}

			var evidence *bhcheck.Evidence
			if label == nodeList[cheater] {
				fakeSchnorr := &DishonestSchnorr{}
				signer := NewSigner(label, logger.DefaultLogger).WithSchnorr(fakeSchnorr)
				_, _, _, evidence, err = signer.Sign(T, N, nodeKey, signNodeList, hash, comm)
			} else {
				signer := NewSigner(label, logger.DefaultLogger)
				_, _, _, evidence, err = signer.Sign(T, N, nodeKey, signNodeList, hash, comm)
			}
			if isInNodeList(label, signNodeList) {
				if label != nodeList[cheater] {
					re := nodeList[cheater] + " SCHNORR PROOF CHECK FAIL"
					assert.Equal(t, re, err.Error(), "Wrong cheater!")
					assert.NotNil(t, evidence, "No cheating evidence!")
					assert.Equal(t, bhcheck.SchnorrCheater, evidence.Type)
					for _, v := range evidence.SchnorrCheaterEvidences {
						assert.Equal(t, nodeList[cheater], v.Label, "Wrong cheater in evidenceList!")
						temp := bhcheck.CheckPubkeyProof(v.Proof, v.Pubkey, bhs256k1.S256())
						assert.Equal(t, false, temp, "Invalid evidence!")
					}
					done <- "Exit!"
					return
				}
			} else {
				done <- label + ":" + err.Error()
			}
		}(i)
	}

	doneNum := 0
	for v := range done {
		fmt.Println(v)
		doneNum++
		if doneNum == N-1 {
			break
		}
	}
}

func TestSenderRangeProofWithCheater(t *testing.T) {
	T := 3
	P := 4
	N := 5
	str := "123456781234567845678123"
	hash := []byte(str)

	nodeList, dstSignNode := getNodes(N, P)
	signNodeList := nodeList[:P]

	cheater := 2
	done := make(chan string)
	for i := range dstSignNode {
		go func(label string) {
			var comm communicator.Communicator
			localComm := communicator.NewLocalCommunicator(dstSignNode, N, label)
			comm = localComm
			var evidence *bhcheck.Evidence
			var node *Node

			keyGenerater := NewKeyGenerator(label, logger.DefaultLogger)
			nodeKey, _, err := keyGenerater.KeyGen(nodeList, T, comm)
			assert.Equal(t, nil, err, "GetPublicKey error!")

			if label == nodeList[cheater] {
				str := label
				for j := 0; j < 2; j++ {
					str = str + label
				}
				fakeRandom := &DishonestRandom{}
				signer := NewSigner(label, logger.DefaultLogger).WithRandom(fakeRandom)
				_, _, node, evidence, err = signer.Sign(T, N, nodeKey, signNodeList, hash, comm)
			} else {
				signer := NewSigner(label, logger.DefaultLogger)
				_, _, node, evidence, err = signer.Sign(T, N, nodeKey, signNodeList, hash, comm)
			}

			assert.True(t, err != nil, "Invalid range proof!")

			if isInNodeList(label, signNodeList) {
				if label != nodeList[cheater] {
					re := nodeList[cheater] + "K\n" + nodeList[cheater] + "R\n"
					assert.Equal(t, re, err.Error(), "Wrong cheater!")
					assert.NotEqual(t, nil, evidence, "No cheating evidence!")
					assert.Equal(t, bhcheck.SendingCheater, evidence.Type)
					for _, v := range evidence.SendingCheaterEvidences {
						assert.Equal(t, nodeList[cheater], v.Label, "Wrong cheater in evidenceList!")
						node.EccN = bhs256k1.S256().Params().N
						node.q = big.NewInt(0).Set(node.EccN)
						node.qCube = big.NewInt(0).Exp(node.q, big.NewInt(3), nil)
						temp := CheckSenderRangeProof(node.NTilde[node.label], node.h1[node.label], node.h2[node.label], node.qCube, node.qCube, v.Proof, v.Msg, v.Pubkey)
						assert.Equal(t, false, temp, "Invalid evidence!")
					}
					done <- "Exit!"
					return
				}
			} else {
				done <- label + ":" + err.Error()
			}
		}(i)
	}

	doneNum := 0
	for v := range done {
		fmt.Println(v)
		doneNum++
		if doneNum == N-1 {
			break
		}
	}
}

func TestReceiverRangeProofWithCheater(t *testing.T) {
	T := 3
	P := 4
	N := 5
	str := "123456781234567845678123"
	hash := []byte(str)

	nodeList, dstSignNode := getNodes(N, P)
	signNodeList := nodeList[:P]

	cheater := 2
	done := make(chan string)
	for i := range dstSignNode {
		go func(label string) {
			node := &Node{Logger: logger.DefaultLogger}
			var comm communicator.Communicator
			localComm := communicator.NewLocalCommunicator(dstSignNode, N, label)
			comm = localComm
			var evidence *bhcheck.Evidence

			keyGenerater := NewKeyGenerator(label, logger.DefaultLogger)
			nodeKey, _, err := keyGenerater.KeyGen(nodeList, T, comm)
			assert.Equal(t, nil, err, "GetPublicKey error!")

			if label == nodeList[cheater] {
				str := label
				for j := 0; j < 2; j++ {
					str = str + label
				}
				fakeResponse := &DishonestResponse{}
				signer := NewSigner(label, logger.DefaultLogger).WithResponse(fakeResponse)
				_, _, _, evidence, err = signer.Sign(T, N, nodeKey, signNodeList, hash, comm)
			} else {
				signer := NewSigner(label, logger.DefaultLogger)
				_, _, _, evidence, err = signer.Sign(T, N, nodeKey, signNodeList, hash, comm)
			}

			assert.True(t, err != nil, "Invalid range proof!")

			if isInNodeList(label, signNodeList) {
				if label != nodeList[cheater] {
					x := fmt.Sprintf("%s", err)
					re := nodeList[cheater] + "K\n" + nodeList[cheater] + "R\n"
					assert.Equal(t, re, x, "Wrong cheater!")
					assert.NotEqual(t, nil, evidence, "No cheating evidence!")
					assert.Equal(t, bhcheck.ReceivingCheater, evidence.Type)
					for _, v := range evidence.ReceivingCheaterEvidences {
						assert.Equal(t, nodeList[cheater], v.Label, "Wrong cheater in evidenceList!")
						node.EccN = bhs256k1.S256().Params().N
						node.q = big.NewInt(0).Set(node.EccN)
						node.qCube = big.NewInt(0).Exp(node.q, big.NewInt(3), nil)
						temp := node.CheckReceiverRangeProof(v.Proof, v.M1, v.M2, v.Pubkey)
						assert.Equal(t, false, temp, "Invalid evidence!")
					}
					done <- "Exit!"
					return
				}
			} else {
				done <- label + ":" + err.Error()
			}
		}(i)
	}

	doneNum := 0
	for v := range done {
		fmt.Println(v)
		doneNum++
		if doneNum == N-1 {
			break
		}
	}
}

func TestSiProofWithCheater(t *testing.T) {
	T := 3
	P := 4
	N := 5
	str := "123456781234567845678123"
	hash := []byte(str)

	nodeList, dstSignNode := getNodes(N, P)
	signNodeList := nodeList[:P]

	cheater := 2
	done := make(chan string)
	for i := range dstSignNode {
		go func(label string) {
			node := &Node{Logger: logger.DefaultLogger}
			var comm communicator.Communicator
			localComm := communicator.NewLocalCommunicator(dstSignNode, N, label)
			comm = localComm
			var evidence *bhcheck.Evidence

			keyGenerater := NewKeyGenerator(label, logger.DefaultLogger)
			nodeKey, _, err := keyGenerater.KeyGen(nodeList, T, comm)
			assert.Equal(t, nil, err, "GetPublicKey error!")

			if label == nodeList[cheater] {
				fakeSiProof := &DishonestSiProof{}
				signer := NewSigner(label, logger.DefaultLogger).WithSiProof(fakeSiProof)
				_, _, _, evidence, err = signer.Sign(T, N, nodeKey, signNodeList, hash, comm)
			} else {
				signer := NewSigner(label, logger.DefaultLogger)
				_, _, _, evidence, err = signer.Sign(T, N, nodeKey, signNodeList, hash, comm)
			}

			if isInNodeList(label, signNodeList) {
				if label != nodeList[cheater] {
					x := fmt.Sprintf("%s", err)
					re := nodeList[cheater] + " SiProof Fail"
					assert.Equal(t, re, x, "Wrong cheater!")
					assert.NotEqual(t, nil, evidence, "No cheating evidence!")
					assert.Equal(t, bhcheck.SiProofCheater, evidence.Type)
					for _, v := range evidence.SiProofCheaterEvidences {
						assert.Equal(t, nodeList[cheater], v.Label, "Wrong cheater in evidenceList!")
						node.EccN = v.EccN
						node.sigR = v.SigR
						node.SigRY = v.SigRY
						temp := node.CheckSiProof(v.Proof)
						assert.Equal(t, false, temp, "Invalid evidence!")
					}
					done <- "Exit!"
					return
				}
			} else {
				done <- label + ":" + err.Error()
			}
		}(i)
	}

	doneNum := 0
	for v := range done {
		fmt.Println(v)
		doneNum++
		if doneNum == N-1 {
			break
		}
	}
}

func TestSiCheckWithCheater(t *testing.T) {
	T := 3
	P := 4
	N := 5
	str := "123456781234567845678123"
	hash := []byte(str)

	nodeList, dstSignNode := getNodes(N, P)
	signNodeList := nodeList[:P]

	cheater := 2
	done := make(chan string)
	for i := range dstSignNode {
		go func(label string) {
			var comm communicator.Communicator
			localComm := communicator.NewLocalCommunicator(dstSignNode, N, label)
			comm = localComm
			var evidence *bhcheck.Evidence

			keyGenerater := NewKeyGenerator(label, logger.DefaultLogger)
			nodeKey, _, err := keyGenerater.KeyGen(nodeList, T, comm)
			assert.Equal(t, nil, err, "GetPublicKey error!")

			if label == nodeList[cheater] {
				fakeSiCheck := &DishonestSiCheck{}
				signer := NewSigner(label, logger.DefaultLogger).WithSiCheck(fakeSiCheck)
				_, _, _, evidence, err = signer.Sign(T, N, nodeKey, signNodeList, hash, comm)
			} else {
				signer := NewSigner(label, logger.DefaultLogger)
				_, _, _, evidence, err = signer.Sign(T, N, nodeKey, signNodeList, hash, comm)
			}

			if isInNodeList(label, signNodeList) {
				x := fmt.Sprintf("%s", err)
				re := "SiCheck Fail"
				assert.Equal(t, re, x, "Wrong cheater!")
				assert.NotNil(t, evidence, "No cheating evidence!")
				assert.Equal(t, bhcheck.SiCheckCheater, evidence.Type)
				assert.Equal(t, P, len(evidence.SiCheckCheaterEvidences), "Wrong evidence number!")
				done <- "Exit!"
				return
			}
			done <- label + ":" + err.Error()
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
}

func TestKeySign(t *testing.T) {
	T := 3
	P := 4
	N := 5
	testSign(T, P, N, t)
}

func TestLocalKeySign(t *testing.T) {
	T := 3
	P := 4
	N := 5
	testLocalSign(T, P, N, t)
}

func testLocalSign(T, P, N int, t *testing.T) {
	str := "123456781234567845678123"
	hash := []byte(str)

	nodeList, dstSignNode := getNodes(N, P)
	signNodeList := nodeList[:P]

	done := make(chan string)
	for i := range dstSignNode {
		go func(label string) {
			var comm communicator.Communicator
			localComm := communicator.NewLocalCommunicator(dstSignNode, N, label)
			comm = localComm

			keyGenerater := NewKeyGenerator(label, logger.DefaultLogger)
			nodeKey, _, err := keyGenerater.KeyGen(nodeList, T, comm)
			assert.Equal(t, nil, err, "GetPublicKey error!")

			signer := NewSigner(label, logger.DefaultLogger)
			sig, _, _, _, err := signer.Sign(T, N, nodeKey, signNodeList, hash, comm)
			if isInNodeList(label, signNodeList) {
				assert.Equal(t, nil, err, "GetSig error!")
				done <- label + ":" + strconv.FormatBool(sig.Verify(hash, nodeKey.PubkeySum))
				assert.True(t, sig.Verify(hash, nodeKey.PubkeySum), "Verification failure!")
			} else {
				done <- label + ":" + err.Error()
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
}

func isInNodeList(label string, nodelist []string) bool {
	for _, v := range nodelist {
		if label == v {
			return true
		}
	}
	return false
}

func testSign(T, P, N int, t *testing.T) {
	max := "11579208923731619542357098500868790"
	maxRand, _ := new(big.Int).SetString(max, 10)
	str := "123456781234567845678123"
	hash := []byte(str)

	var prtKey []*bhs256k1.PrivateKey = make([]*bhs256k1.PrivateKey, N)
	var pubKey []*bhs256k1.PublicKey = make([]*bhs256k1.PublicKey, N)
	var blindFactor []*big.Int = make([]*big.Int, N)
	var pubKeyCommit [][32]byte = make([][32]byte, N)

	var sig []bhs256k1.Signature = make([]bhs256k1.Signature, P)
	var k, r []*big.Int = make([]*big.Int, P), make([]*big.Int, P)
	var paillierPubKey []*gaillier.PubKey = make([]*gaillier.PubKey, P)
	var paillierPrtKey []*gaillier.PrivKey = make([]*gaillier.PrivKey, P)
	var combinedPrtKey []*big.Int = make([]*big.Int, P)
	var randNumArray [][]*big.Int = make([][]*big.Int, P)
	var messageK, messageR [][]byte = make([][]byte, P), make([][]byte, P)
	var sigOthersRX, sigOthersRY, sigLocalRX, sigLocalRY []*big.Int = make([]*big.Int, P), make([]*big.Int, P), make([]*big.Int, P), make([]*big.Int, P)
	var messageKResponse, messageRResponse [][][]byte = make([][][]byte, P), make([][][]byte, P)
	var thea []*big.Int = make([]*big.Int, P)
	var sigR, sigS, sigRY []*big.Int = make([]*big.Int, P), make([]*big.Int, P), make([]*big.Int, P)
	var theaInverse []*big.Int = make([]*big.Int, P)
	var v []byte = make([]byte, P)

	var coeff []*big.Int = make([]*big.Int, N)
	var tempShareArray []map[string]bhsssa.ShareXY = make([]map[string]bhsssa.ShareXY, N)
	var cofCommit [][]*bhs256k1.PublicKey = make([][]*bhs256k1.PublicKey, N)
	var shareReceived map[string][]bhsssa.ShareXY = make(map[string][]bhsssa.ShareXY, N)

	for i := range coeff {
		newPriKey, _ := bhs256k1.NewPrivateKey(bhs256k1.S256())
		re := newPriKey.PublicKey.X
		coeff[i] = big.NewInt(0).Set(re)
	}

	//GetPublicKey
	//rewrite InitNode
	for i := range coeff {
		tempShareArray[i] = make(map[string]bhsssa.ShareXY)
		shareReceived[coeff[i].String()] = make([]bhsssa.ShareXY, N)
		prtKey[i], tempShareArray[i], cofCommit[i] = genPkShares(T, N, coeff)

		blindFactor[i], _ = rand.Int(rand.Reader, maxRand)
		pubKey[i] = prtKey[i].PubKey()
		pubKeyCommit[i] = bhcheck.GetPubkeyCommit(pubKey[i], blindFactor[i], bhs256k1.S256())
	}
	for i := range prtKey {
		for j := range prtKey {
			shareReceived[coeff[j].String()][i] = tempShareArray[i][coeff[j].String()]
		}
	}
	//第pre-0轮消息:发送给所有的N个节点，包含自己
	//LabelFrom, PubKeyCommit, CofCommit
	//第0轮消息:发送给Round0MsgSent[]数组里所有LabelTo的节点，包含自己本身
	//LabelFrom, LabelTo, Share, PubKey, BlindFactor
	for i := 0; i < N; i++ {
		assert.True(t, bhcheck.CheckPubkeyCommit(pubKeyCommit[i], pubKey[i], blindFactor[i], bhs256k1.S256()), "The commitment of public key is wrong!")
		assert.True(t, checkShamirCommit(N, shareReceived[coeff[i].String()][i], shareReceived[coeff[i].String()], cofCommit, pubKey), "The commitment of shamir is wrong!")
	}
	pubKeySum := pKSum(pubKey)

	//GetSig
	//rewrite InitAll
	var participant []string
	for i := 0; i < P; i++ {
		participant = append(participant, coeff[i].String())
	}
	for i := 0; i < P; i++ {
		k[i], _ = rand.Int(rand.Reader, maxRand)
		r[i], _ = rand.Int(rand.Reader, maxRand)
		paillierPubKey[i], paillierPrtKey[i], _ = gaillier.GenerateKeyPair(rand.Reader, 2048)
		combinedPrtKey[i] = bhsssa.KeyCombine(participant, coeff[i].String(), shareReceived[coeff[i].String()], bhsssa.S256k1Prime)
		for j := 0; j < P-1; j++ {
			num, _ := rand.Int(rand.Reader, maxRand)
			randNumArray[i] = append(randNumArray[i], num)
		}
	}
	//第1轮消息:发送给不包含自身的所有其他节点
	//Label, Message_k, Message_r, SigOthersR, PaillierPubKey
	for i := 0; i < P; i++ {
		messageK[i], _ = bhcrypto.PaillierEnc(k[i], paillierPubKey[i])
		messageR[i], _ = bhcrypto.PaillierEnc(r[i], paillierPubKey[i])
		sigOthersRX[i], sigOthersRY[i] = elliptic.Curve.ScalarBaseMult(bhs256k1.S256(), k[i].Bytes())
	}
	//第2轮消息：发送给Round2MsgSent[]数组里所有LabelTo的节点，包含自己本身
	//LabelFrom, LabelTo, Message_k_response, Message_r_response
	for i := 0; i < P; i++ {
		messageKResponse[i] = make([][]byte, P)
		messageRResponse[i] = make([][]byte, P)
		for j := 0; j < P; j++ {
			if j == i {
				continue
			}
			jj := j
			if jj > i {
				jj--
			}
			oneCipher, oneR := bhcrypto.PaillierEnc(big.NewInt(1), paillierPubKey[j])
			messageKResponse[i][j], _ = getAnotherPart(messageK[j], paillierPubKey[j], randNumArray[i][jj], r[i], oneCipher, oneR)
			messageRResponse[i][j], _ = getAnotherPart(messageR[j], paillierPubKey[j], randNumArray[i][jj], combinedPrtKey[i], oneCipher, oneR)
		}
	}
	//第3轮消息：发送给不包含自身的所有其他节点
	//LabelFrom, Thea
	for i := 0; i < P; i++ {
		thea[i] = new(big.Int).Mul(k[i], r[i])
		for j := 0; j < P; j++ {
			if i == j {
				continue
			}
			temp := bhcrypto.PaillierDec(messageKResponse[j][i], paillierPrtKey[i])
			thea[i].Add(thea[i], temp)
		}
		for _, v := range randNumArray[i] {
			thea[i].Sub(thea[i], v)
		}
		thea[i].Mod(thea[i], bhs256k1.S256().Params().N)
	}
	//第4轮消息：发送给所有的节点，包含自己
	//Sigr, Sigs, V
	for i := 0; i < P; i++ {
		sigLocalRX[i], sigLocalRY[i], sigR[i], sigRY[i] = getSigR(i, P, k[i], sigOthersRX, sigOthersRY)
		theaInverse[i], sigS[i] = getSigS(i, P, hash, r[i], combinedPrtKey[i], messageRResponse, paillierPrtKey[i], randNumArray[i], thea, sigR[i])
		v[i] = byte(sigRY[i].Bit(0))
	}
	//signature
	for i := 0; i < P; i++ {
		recid := v[0]
		for j := 0; j < P; j++ {
			assert.Equal(t, recid, v[j], "V not equal!")
		}
		tempSig := bhs256k1.Signature{}
		tempSig.R, tempSig.S = big.NewInt(0), big.NewInt(0)
		for j := 0; j < P; j++ {
			tempSig.S.Add(tempSig.S, sigS[j])
		}
		tempSig.S.Mod(tempSig.S, bhs256k1.S256().Params().N)
		tempSig.R.Mod(sigR[0], bhs256k1.S256().Params().N)
		subS := new(big.Int).Sub(big.NewInt(0), tempSig.S)
		subS = subS.Mod(subS, bhs256k1.S256().Params().N)
		if tempSig.S.Cmp(subS) > 0 {
			tempSig.S = subS
		}
		sig[i] = tempSig
	}

	//Verify
	for i := 0; i < P; i++ {
		assert.True(t, sig[i].Verify(hash, pubKeySum), "Verification failure!")
	}
}

//modify CheckShamirCommit()
func checkShamirCommit(N int, shareOwn bhsssa.ShareXY, shareReceived []bhsssa.ShareXY, cofCommit [][]*bhs256k1.PublicKey,
	pubKey []*bhs256k1.PublicKey) bool {

	shareSum := bhsssa.ShareXY{}
	shareSum.X, shareSum.Y = big.NewInt(0), big.NewInt(0)
	shareSum.X.Add(shareSum.X, shareOwn.X)
	for i := 0; i < N; i++ {
		shareSum.Y.Add(shareSum.Y, shareReceived[i].Y)
	}
	finalCommit := make([]*bhs256k1.PublicKey, 0)
	for i := 0; i < N; i++ {
		if cofCommit[i][0].IsEqual(pubKey[i]) == false {
			return false
		}
	}
	for i := 0; i < len(cofCommit[1]); i++ {
		tempPubkey := &bhs256k1.PublicKey{}
		tempPubkey.Curve = bhs256k1.S256()
		tempPubkey.X, tempPubkey.Y = big.NewInt(0), big.NewInt(0)
		for j := 0; j < N; j++ {
			tempPubkey.X, tempPubkey.Y = tempPubkey.Add(tempPubkey.X, tempPubkey.Y, cofCommit[j][i].X, cofCommit[j][i].Y)
		}
		finalCommit = append(finalCommit, tempPubkey)
	}
	checkX := getCheckByX(shareSum.X, finalCommit)
	checkY := getCheckByY(shareSum.Y)
	return checkX.IsEqual(checkY)
}

//modify PubKeySum()
func pKSum(pubKey []*bhs256k1.PublicKey) *bhs256k1.PublicKey {
	pubKeySum := &bhs256k1.PublicKey{}
	pubKeySum.Curve = bhs256k1.S256()
	pubKeySum.X = big.NewInt(0)
	pubKeySum.Y = big.NewInt(0)
	for _, v := range pubKey {
		pubKeySum.X, pubKeySum.Y = pubKeySum.Add(pubKeySum.X, pubKeySum.Y, v.X, v.Y)
	}
	return pubKeySum
}

//modify GetSigR()
func getSigR(label, P int, k *big.Int, sigOthersRX, sigOthersRY []*big.Int) (*big.Int, *big.Int, *big.Int, *big.Int) {
	ecdsaPub := bhs256k1.PublicKey{}
	ecdsaPub.Curve = bhs256k1.S256()
	resultX, resultY := elliptic.Curve.ScalarBaseMult(bhs256k1.S256(), k.Bytes())
	sigLocalRX := resultX
	sigLocalRY := resultY

	for i := 0; i < P; i++ {
		if i == label {
			continue
		}
		resultX, resultY = ecdsaPub.Add(resultX, resultY, sigOthersRX[i], sigOthersRY[i])
	}
	sigR := resultX
	SigRY := resultY
	return sigLocalRX, sigLocalRY, sigR, SigRY
}

//modify GetSigs
func getSigS(label, P int, hash []byte, r, prtKey *big.Int, messageKResponse [][][]byte, paillierPrtKey *gaillier.PrivKey, randNumArray, thea []*big.Int, sigR *big.Int) (*big.Int, *big.Int) {
	rd := new(big.Int).Mul(r, prtKey)
	for i := 0; i < P; i++ {
		if i == label {
			continue
		}
		temp1 := bhcrypto.PaillierDec(messageKResponse[i][label], paillierPrtKey)
		rd.Add(rd, temp1)
	}
	for _, v := range randNumArray {
		rd.Sub(rd, v)
	}
	theaInverse := new(big.Int).Set(thea[label])

	for i := 0; i < P; i++ {
		if i == label {
			continue
		}
		theaInverse.Add(theaInverse, thea[i])
	}
	theaInverse.ModInverse(theaInverse, bhs256k1.S256().Params().N)
	e := bhcheck.HashToInt(hash, bhs256k1.S256())
	tempS := new(big.Int).Mul(e, r)
	rd.Mul(rd, sigR)
	rd.Add(rd, tempS)
	rd.Mul(rd, theaInverse)
	sigS := rd.Mod(rd, bhs256k1.S256().Params().N)
	return theaInverse, sigS
}
