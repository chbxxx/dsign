package dsign

import (
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"fmt"
	"github.com/bluehelix-chain/dsign/bhcrypto/bhcheck"
	"github.com/bluehelix-chain/dsign/bhcrypto/bhs256k1"
	"github.com/bluehelix-chain/dsign/bhsssa"
	"github.com/bluehelix-chain/dsign/logger"
	"math/big"
	"testing"

	"github.com/bluehelix-chain/dsign/communicator"
	"github.com/stretchr/testify/assert"
)

var max = "11579208923731619542357098500868790"

var _ bhcheck.Random = (*DishonestRandom)(nil)

type DishonestRandom struct{}

func (r *DishonestRandom) RandomNum(maxRand *big.Int) *big.Int {
	re, _ := new(big.Int).SetString("939043222490022847722933382741127312054584725638581422721867253727076463442149390432224900228477229333827411273120545847256385814227218672537270764634421493904322249002284772293338274112731205458472563858142272186725372707646344214", 10)
	return re
}

var _ bhcheck.Response = (*DishonestResponse)(nil)

type DishonestResponse struct{}

func (re *DishonestResponse) Respond(r, prtKey *big.Int) (*big.Int, *big.Int) {
	num, _ := new(big.Int).SetString("939043222490022847722933382741127312054584725638581422721867253727076463442149390432224900228477229333827411273120545847256385814227218672537270764634421493904322249002284772293338274112731205458472563858142272186725372707646344214", 10)
	return num, num
}

var _ bhcheck.Share = (*DishonestShare)(nil)

type DishonestShare struct{}

func (sh *DishonestShare) Share(pub *big.Int) *big.Int {
	num, _ := new(big.Int).SetString("939043222490022847722933382741127312054584725638581422721867253727076463442149390432224900228477229333827411273120545847256385814227218672537270764634421493904322249002284772293338274112731205458472563858142272186725372707646344214", 10)
	return num
}

var _ bhcheck.Schnorr = (*DishonestSchnorr)(nil)

type DishonestSchnorr struct{}

func (sh *DishonestSchnorr) Proof(x *big.Int, curve elliptic.Curve) bhcheck.SchnorrZKProof {
	num, _ := new(big.Int).SetString("939043222490022847722933382741127312054584725638581422721867253727076463442149390432224900228477229333827411273120545847256385814227218672537270764634421493904322249002284772293338274112731205458472563858142272186725372707646344214", 10)
	pub := bhs256k1.GetPubkeyByNum(num)
	return bhcheck.SchnorrZKProof{Pub: pub, Num: num}
}

var _ bhcheck.SiProof = (*DishonestSiProof)(nil)

type DishonestSiProof struct{}

func (si *DishonestSiProof) GetSiProof(siX, siY, s, l, rho *big.Int) bhcheck.SiZKProof {
	num, _ := new(big.Int).SetString("9390432224900228477229333827411273120545847", 10)
	return bhcheck.SiZKProof{VX: num, VY: num, AX: num, AY: num, BX: num, BY: num, AlphaX: num, AlphaY: num, BetaX: num, BetaY: num, T: num, U: num}
}

var _ bhcheck.SiCheck = (*DishonestSiCheck)(nil)

type DishonestSiCheck struct{}

func (si *DishonestSiCheck) GetSiCheck(siRho, siL, all5BSumX, all5BSumY, others5BSumX, others5BSumY, siY *big.Int, hash []byte, pubkey *bhs256k1.PublicKey) bhcheck.SiZKCheck {
	priKey, _ := bhs256k1.NewPrivateKey(bhs256k1.S256())
	return bhcheck.SiZKCheck{U: priKey.PubKey(), T: priKey.PubKey()}
}

var _ bhcheck.PQProof = (*DishonestPQProof)(nil)

type DishonestPQProof struct{}

func (pqProof *DishonestPQProof) GetPQProof(n, p, q *big.Int, PQProofK int) bhcheck.PQZKProof {
	newP, _ := new(big.Int).SetString("9390432224900228477229333827411273120545847", 10)
	newQ, _ := new(big.Int).SetString("9390432224900228477229333827411273120545847", 10)
	return bhcheck.GetPQProof(n, newP, newQ, PQProofK)
}

func getNodes(n, p int) ([]string, map[string]*communicator.ChanNode) {
	var nodeList []string = make([]string, n)
	var dstSignNode map[string]*communicator.ChanNode = make(map[string]*communicator.ChanNode)
	for i := range nodeList {
		newPriKey, _ := bhs256k1.NewPrivateKey(bhs256k1.S256())
		re := newPriKey.PublicKey.X
		label := big.NewInt(0).Set(re).String()
		nodeList[i] = label
		dstSignNode[label] = communicator.NewChanNode(n, p)
	}
	return nodeList, dstSignNode
}

func TestKeyGenData(t *testing.T) {
	nodeKey := &NodeKey{}
	nodeKey.SetLabel("12345")
	nodeKey.T, nodeKey.N = 3, 5
	var coeff = [5]string{"12345", "23451", "34512", "45123", "51234"}
	nodeKey.ShareReceived = make(map[string]bhsssa.ShareXY)
	nodeKey.NTilde = make(map[string]*big.Int)
	nodeKey.h1 = make(map[string]*big.Int)
	nodeKey.h2 = make(map[string]*big.Int)
	for k, v := range coeff {
		x, _ := big.NewInt(0).SetString(v, 10)
		y := big.NewInt(int64(k))
		tempShare := bhsssa.ShareXY{
			X: x,
			Y: y,
		}
		nodeKey.ShareReceived[v] = tempShare
		nodeKey.NTilde[v] = y
		nodeKey.h1[v] = y
		nodeKey.h2[v] = y
	}
	priKey, _ := bhs256k1.NewPrivateKey(bhs256k1.S256())
	nodeKey.PubkeySum, _ = bhs256k1.ParsePubKey(priKey.PubKey().SerializeCompressed(), bhs256k1.S256())

	data := GetKeyGenData(nodeKey)
	nodeKeyLoad := SetKeyGenData(data)

	assert.Equal(t, nodeKey.T, nodeKeyLoad.T)
	assert.Equal(t, nodeKey.N, nodeKeyLoad.N)
	for _, v := range coeff {
		assert.Equal(t, nodeKey.ShareReceived[v], nodeKeyLoad.ShareReceived[v])
		assert.Equal(t, nodeKey.NTilde[v], nodeKeyLoad.NTilde[v])
		assert.Equal(t, nodeKey.h1[v], nodeKeyLoad.h1[v])
		assert.Equal(t, nodeKey.h2[v], nodeKeyLoad.h2[v])
	}
}

func TestPubkeyProof(t *testing.T) {
	newPriKey, _ := bhs256k1.NewPrivateKey(bhs256k1.S256())
	newPriKey2, _ := bhs256k1.NewPrivateKey(bhs256k1.S256())
	trueProof := &bhcheck.HonestSchnorr{}
	proof := trueProof.Proof(newPriKey.D, bhs256k1.S256())
	assert.True(t, bhcheck.CheckPubkeyProof(proof, newPriKey.PubKey(), bhs256k1.S256()))
	assert.False(t, bhcheck.CheckPubkeyProof(proof, newPriKey2.PubKey(), bhs256k1.S256()))
}

func TestKeyGen(t *testing.T) {
	T := 3
	N := 5
	var coeff []*big.Int = make([]*big.Int, N)
	coeff[0], _ = big.NewInt(0).SetString("12345", 10)
	coeff[1], _ = big.NewInt(0).SetString("23451", 10)
	coeff[2], _ = big.NewInt(0).SetString("34512", 10)
	coeff[3], _ = big.NewInt(0).SetString("45123", 10)
	coeff[4], _ = big.NewInt(0).SetString("51234", 10)

	prtKey, tempShareArray, _ := genPkShares(T, N, coeff)
	combined, err := bhsssa.Combine(tempShareArray, bhsssa.S256k1Prime)

	if err != nil {
		t.Error("Fail to combine!")
	}
	assert.Equal(t, 0, combined.Cmp(prtKey.D), "The result is wrong!")
}

func TestKeyCombine(t *testing.T) {
	T := 3
	N := 5
	var coeff []*big.Int = make([]*big.Int, N)
	var prtKey []*bhs256k1.PrivateKey = make([]*bhs256k1.PrivateKey, N)
	var tempShareArray []map[string]bhsssa.ShareXY = make([]map[string]bhsssa.ShareXY, N)
	var shareReceived map[string][]bhsssa.ShareXY = make(map[string][]bhsssa.ShareXY)
	var particiShare []*big.Int = make([]*big.Int, N)
	var sum, combined *big.Int = big.NewInt(0), big.NewInt(0)
	coeff[0], _ = big.NewInt(0).SetString("12345", 10)
	coeff[1], _ = big.NewInt(0).SetString("2345678901234567890123456789012345678901", 10)
	coeff[2], _ = big.NewInt(0).SetString("34512", 10)
	prime, _ := big.NewInt(0).SetString(bhsssa.S256k1N, 10)
	re := big.NewInt(0).Set(prime)
	re = re.Sub(re, big.NewInt(1))
	re, _ = rand.Int(rand.Reader, re)
	coeff[3] = big.NewInt(0).Set(re)
	coeff[4], _ = big.NewInt(0).SetString("51234", 10)

	for i := range prtKey {
		tempShareArray[i] = make(map[string]bhsssa.ShareXY, N)
		shareReceived[coeff[i].String()] = make([]bhsssa.ShareXY, N)
		prtKey[i], tempShareArray[i], _ = genPkShares(T, N, coeff)
		sum = sum.Add(sum, prtKey[i].D)
		sum = sum.Mod(sum, prime)
	}
	for i := range prtKey {
		for j := range prtKey {
			shareReceived[coeff[j].String()][i] = tempShareArray[i][coeff[j].String()]
		}
	}

	for i := range prtKey {
		P := i + 1
		var participant []string
		for i := 0; i < P; i++ {
			participant = append(participant, coeff[i].String())
		}
		combined = big.NewInt(0)
		for j := 0; j < P; j++ {
			particiShare[j] = big.NewInt(0).Set(bhsssa.KeyCombine(participant, coeff[j].String(), shareReceived[coeff[j].String()], bhsssa.S256k1Prime))
			combined = combined.Add(combined, particiShare[j])
			combined = combined.Mod(combined, prime)
		}
		if P < T {
			assert.False(t, combined.Cmp(sum) == 0, "The result is wrong!")
		} else {
			assert.True(t, combined.Cmp(sum) == 0, "The result is wrong!")
		}
	}
}

func TestPQProofWithCheater(t *testing.T) {
	T := 3
	P := 4
	N := 5
	rsaLength = 512

	var nodeList []string = make([]string, N)
	var dstSignNode map[string]*communicator.ChanNode = make(map[string]*communicator.ChanNode)
	for i := range nodeList {
		newPriKey, _ := bhs256k1.NewPrivateKey(bhs256k1.S256())
		re := newPriKey.PublicKey.X
		label := big.NewInt(0).Set(re).String()
		nodeList[i] = label
		dstSignNode[label] = communicator.NewChanNode(N, P)
	}

	cheater := 2
	done := make(chan string)
	for i := range dstSignNode {
		go func(label string) {
			var comm communicator.Communicator
			localComm := communicator.NewLocalCommunicator(dstSignNode, N, label)
			comm = localComm
			var evidence *bhcheck.Evidence
			var err error
			if label == nodeList[cheater] {
				fakePQProof := &DishonestPQProof{}
				fakeKeyGenerater := NewKeyGenerator(label, logger.DefaultLogger).WithPQProof(fakePQProof)
				_, evidence, err = fakeKeyGenerater.KeyGen(nodeList, T, comm)
			} else {
				trueKeyGenerater := NewKeyGenerator(label, logger.DefaultLogger)
				_, evidence, err = trueKeyGenerater.KeyGen(nodeList, T, comm)
			}

			re := nodeList[cheater] + " PQProof Fail"
			assert.Equal(t, re, err.Error(), "Wrong cheater!")
			assert.NotEqual(t, nil, evidence, "No cheating evidence!")
			assert.Equal(t, bhcheck.PQProofCheater, evidence.Type, label, evidence)
			for _, v := range evidence.PQProofEvidences {
				assert.Equal(t, nodeList[cheater], v.Label, "Wrong cheater in evidenceList!")
			}
			done <- "Exit!"
		}(i)
	}

	doneNum := 0
	for range done {
		doneNum++
		if doneNum == N {
			break
		}
	}
}

func TestSchnorrInKeyGenWithCheater(t *testing.T) {
	T := 3
	P := 4
	N := 5
	rsaLength = 512

	var nodeList []string = make([]string, N)
	var dstSignNode map[string]*communicator.ChanNode = make(map[string]*communicator.ChanNode)
	for i := range nodeList {
		newPriKey, _ := bhs256k1.NewPrivateKey(bhs256k1.S256())
		re := newPriKey.PublicKey.X
		label := big.NewInt(0).Set(re).String()
		nodeList[i] = label
		dstSignNode[label] = communicator.NewChanNode(N, P)
	}

	cheater := 2
	done := make(chan string)
	for i := range dstSignNode {
		go func(label string) {
			var comm communicator.Communicator
			localComm := communicator.NewLocalCommunicator(dstSignNode, N, label)
			comm = localComm

			var evidence *bhcheck.Evidence
			var err error
			if label == nodeList[cheater] {
				fakeSchnorr := &DishonestSchnorr{}
				fakeKeyGenerater := NewKeyGenerator(label, logger.DefaultLogger).WithSchnorr(fakeSchnorr)
				_, evidence, err = fakeKeyGenerater.KeyGen(nodeList, T, comm)
			} else {
				trueKeyGenerater := NewKeyGenerator(label, logger.DefaultLogger)
				_, evidence, err = trueKeyGenerater.KeyGen(nodeList, T, comm)
			}

			re := nodeList[cheater] + " SCHNORR PROOF CHECK FAIL"
			assert.Equal(t, re, err.Error(), "Wrong cheater!")
			assert.NotEqual(t, nil, evidence, "No cheating evidence!")
			fmt.Println(evidence, err, label)
			assert.Equal(t, bhcheck.SchnorrCheater, evidence.Type)
			for _, v := range evidence.SchnorrCheaterEvidences {
				assert.Equal(t, nodeList[cheater], v.Label, "Wrong cheater in evidenceList!")
				temp := bhcheck.CheckPubkeyProof(v.Proof, v.Pubkey, bhs256k1.S256())
				assert.Equal(t, false, temp, "Invalid evidence!")
			}
			done <- "Exit!"
		}(i)
	}

	doneNum := 0
	for range done {
		doneNum++
		if doneNum == N {
			break
		}
	}
}

func TestShamirCheckWithCheater(t *testing.T) {
	T := 3
	P := 4
	N := 5
	rsaLength = 512

	nodeList, dstSignNode := getNodes(N, P)

	cheater := 2
	done := make(chan string)
	for i := range dstSignNode {
		go func(label string) {
			var comm communicator.Communicator
			localComm := communicator.NewLocalCommunicator(dstSignNode, N, label)
			comm = localComm

			var evidence *bhcheck.Evidence
			var err error
			if label == nodeList[cheater] {
				fakeShare := &DishonestShare{}
				keyGenerator := NewKeyGenerator(label, logger.DefaultLogger).WithShare(fakeShare)
				_, evidence, err = keyGenerator.KeyGen(nodeList, T, comm)
			} else {
				keyGenerator := NewKeyGenerator(label, logger.DefaultLogger)
				_, evidence, err = keyGenerator.KeyGen(nodeList, T, comm)
			}
			assert.Equal(t, errors.New("FINAL SHAMIR CHECK FAIL"), err, "Final shamir check error!")
			assert.NotNil(t, evidence, "No cheating evidence!")
			assert.Equal(t, bhcheck.ShamirCheck, evidence.Type)
			//这里面的Evidence的长度会是N*checkArray的数目，我们目前的checkArray为2，[0,1-t]，[t+1，N]
			assert.Equal(t, N*2, len(evidence.ShamirCheckEvidence), "Wrong evidence number!")
			done <- "Exit!"
		}(i)
	}

	doneNum := 0
	for range done {
		doneNum++
		if doneNum == N {
			break
		}
	}
}

func TestKeyGenTime(t *testing.T) {
	T := 3
	P := 4
	N := 5
	rsaLength = 512
	testKeyGenTime(T, P, N, t)
}

func testKeyGenTime(T, P, N int, t *testing.T) {

	nodeList, dstSignNode := getNodes(N, P)

	done := make(chan string)
	for i := range dstSignNode {
		go func(label string) {
			var comm communicator.Communicator
			localComm := communicator.NewLocalCommunicator(dstSignNode, N, label)
			comm = localComm

			keyGenerater := NewKeyGenerator(label, logger.DefaultLogger)
			_, _, err := keyGenerater.KeyGen(nodeList, T, comm)
			assert.Equal(t, nil, err, "GetPublicKey error!")
			done <- "Done!"
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
