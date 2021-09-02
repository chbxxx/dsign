package dsign

import (
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"
	"testing"

	"github.com/bluehelix-chain/dsign/communicator"
	"github.com/bluehelix-chain/dsign/types"
	sssa "github.com/bluehelix-chain/sssa-golang"
	"github.com/btcsuite/btcd/btcec"
	"github.com/stretchr/testify/assert"
)

var max = "11579208923731619542357098500868790"

var _ Random = (*DishonestRandom)(nil)

type DishonestRandom struct{}

func (r *DishonestRandom) randomNum(maxRand *big.Int) *big.Int {
	re, _ := new(big.Int).SetString("939043222490022847722933382741127312054584725638581422721867253727076463442149390432224900228477229333827411273120545847256385814227218672537270764634421493904322249002284772293338274112731205458472563858142272186725372707646344214", 10)
	return re
}

var _ Response = (*DishonestResponse)(nil)

type DishonestResponse struct{}

func (re *DishonestResponse) respond(r, prtKey *big.Int) (*big.Int, *big.Int) {
	num, _ := new(big.Int).SetString("939043222490022847722933382741127312054584725638581422721867253727076463442149390432224900228477229333827411273120545847256385814227218672537270764634421493904322249002284772293338274112731205458472563858142272186725372707646344214", 10)
	return num, num
}

var _ Share = (*DishonestShare)(nil)

type DishonestShare struct{}

func (sh *DishonestShare) share(pub *big.Int) *big.Int {
	num, _ := new(big.Int).SetString("939043222490022847722933382741127312054584725638581422721867253727076463442149390432224900228477229333827411273120545847256385814227218672537270764634421493904322249002284772293338274112731205458472563858142272186725372707646344214", 10)
	return num
}

var _ Schnorr = (*DishonestSchnorr)(nil)

type DishonestSchnorr struct{}

func (sh *DishonestSchnorr) proof(x *big.Int) types.SchnorrZKProof {
	num, _ := new(big.Int).SetString("939043222490022847722933382741127312054584725638581422721867253727076463442149390432224900228477229333827411273120545847256385814227218672537270764634421493904322249002284772293338274112731205458472563858142272186725372707646344214", 10)
	pub := getPubkeyByNum(num)
	return types.SchnorrZKProof{Pub: pub, Num: num}
}

var _ SiProof = (*DishonestSiProof)(nil)

type DishonestSiProof struct{}

func (si *DishonestSiProof) GetSiProof(t *Node, s, l, rho *big.Int) types.SiZKProof {
	num, _ := new(big.Int).SetString("9390432224900228477229333827411273120545847", 10)
	return types.SiZKProof{VX: num, VY: num, AX: num, AY: num, BX: num, BY: num, AlphaX: num, AlphaY: num, BetaX: num, BetaY: num, T: num, U: num}
}

var _ SiCheck = (*DishonestSiCheck)(nil)

type DishonestSiCheck struct{}

func (si *DishonestSiCheck) GetSiCheck(t *Node, hash []byte, pubkey *btcec.PublicKey) types.SiZKCheck {
	priKey, _ := btcec.NewPrivateKey(btcec.S256())
	return types.SiZKCheck{U: priKey.PubKey(), T: priKey.PubKey()}
}

var _ PQProof = (*DishonestPQProof)(nil)

type DishonestPQProof struct{}

func (pqProof *DishonestPQProof) GetPQProof(n, p, q *big.Int, PQProofK int) types.PQZKProof {
	newP, _ := new(big.Int).SetString("9390432224900228477229333827411273120545847", 10)
	newQ, _ := new(big.Int).SetString("9390432224900228477229333827411273120545847", 10)
	return GetPQProof(n, newP, newQ, PQProofK)
}

func getNodes(n, p int) ([]string, map[string]*communicator.ChanNode) {
	var nodeList []string = make([]string, n)
	var dstSignNode map[string]*communicator.ChanNode = make(map[string]*communicator.ChanNode)
	for i := range nodeList {
		newPriKey, _ := btcec.NewPrivateKey(btcec.S256())
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
	nodeKey.ShareReceived = make(map[string]sssa.ShareXY)
	nodeKey.NTilde = make(map[string]*big.Int)
	nodeKey.h1 = make(map[string]*big.Int)
	nodeKey.h2 = make(map[string]*big.Int)
	for k, v := range coeff {
		x, _ := big.NewInt(0).SetString(v, 10)
		y := big.NewInt(int64(k))
		tempShare := sssa.ShareXY{
			X: x,
			Y: y,
		}
		nodeKey.ShareReceived[v] = tempShare
		nodeKey.NTilde[v] = y
		nodeKey.h1[v] = y
		nodeKey.h2[v] = y
	}
	priKey, _ := btcec.NewPrivateKey(btcec.S256())
	nodeKey.PubkeySum, _ = btcec.ParsePubKey(priKey.PubKey().SerializeCompressed(), btcec.S256())

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
	newPriKey, _ := btcec.NewPrivateKey(btcec.S256())
	newPriKey2, _ := btcec.NewPrivateKey(btcec.S256())
	trueProof := &HonestSchnorr{}
	proof := trueProof.proof(newPriKey.D)
	assert.True(t, CheckPubkeyProof(proof, newPriKey.PubKey()))
	assert.False(t, CheckPubkeyProof(proof, newPriKey2.PubKey()))
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

	prtKey, tempShareArray, _ := keyGen(T, N, coeff)
	combined, err := sssa.Combine(tempShareArray)

	if err != nil {
		t.Error("Fail to combine!")
	}
	assert.Equal(t, 0, combined.Cmp(prtKey.D), "The result is wrong!")
}

func TestKeyCombine(t *testing.T) {
	T := 3
	N := 5
	var coeff []*big.Int = make([]*big.Int, N)
	var prtKey []*btcec.PrivateKey = make([]*btcec.PrivateKey, N)
	var tempShareArray []map[string]sssa.ShareXY = make([]map[string]sssa.ShareXY, N)
	var shareReceived map[string][]sssa.ShareXY = make(map[string][]sssa.ShareXY)
	var particiShare []*big.Int = make([]*big.Int, N)
	var sum, combined *big.Int = big.NewInt(0), big.NewInt(0)
	coeff[0], _ = big.NewInt(0).SetString("12345", 10)
	coeff[1], _ = big.NewInt(0).SetString("2345678901234567890123456789012345678901", 10)
	coeff[2], _ = big.NewInt(0).SetString("34512", 10)
	prime, _ := big.NewInt(0).SetString(sssa.DefaultPrimeStr, 10)
	re := big.NewInt(0).Set(prime)
	re = re.Sub(re, big.NewInt(1))
	re, _ = rand.Int(rand.Reader, re)
	coeff[3] = big.NewInt(0).Set(re)
	coeff[4], _ = big.NewInt(0).SetString("51234", 10)

	for i := range prtKey {
		tempShareArray[i] = make(map[string]sssa.ShareXY, N)
		shareReceived[coeff[i].String()] = make([]sssa.ShareXY, N)
		prtKey[i], tempShareArray[i], _ = keyGen(T, N, coeff)
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
			particiShare[j] = big.NewInt(0).Set(keyCombine(participant, coeff[j].String(), shareReceived[coeff[j].String()]))
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
		newPriKey, _ := btcec.NewPrivateKey(btcec.S256())
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
			var evidence *Evidence
			var err error
			if label == nodeList[cheater] {
				fakePQProof := &DishonestPQProof{}
				fakeKeyGenerater := NewKeyGenerator(label).WithPQProof(fakePQProof)
				_, evidence, err = fakeKeyGenerater.KeyGen(nodeList, T, comm)
			} else {
				trueKeyGenerater := NewKeyGenerator(label)
				_, evidence, err = trueKeyGenerater.KeyGen(nodeList, T, comm)
			}

			re := nodeList[cheater] + " PQProof Fail"
			assert.Equal(t, re, err.Error(), "Wrong cheater!")
			assert.NotEqual(t, nil, evidence, "No cheating evidence!")
			assert.Equal(t, PQProofCheater, evidence.Type, label, evidence)
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
		newPriKey, _ := btcec.NewPrivateKey(btcec.S256())
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

			var evidence *Evidence
			var err error
			if label == nodeList[cheater] {
				fakeSchnorr := &DishonestSchnorr{}
				fakeKeyGenerater := NewKeyGenerator(label).WithSchnorr(fakeSchnorr)
				_, evidence, err = fakeKeyGenerater.KeyGen(nodeList, T, comm)
			} else {
				trueKeyGenerater := NewKeyGenerator(label)
				_, evidence, err = trueKeyGenerater.KeyGen(nodeList, T, comm)
			}

			re := nodeList[cheater] + " SCHNORR PROOF CHECK FAIL"
			assert.Equal(t, re, err.Error(), "Wrong cheater!")
			assert.NotEqual(t, nil, evidence, "No cheating evidence!")
			fmt.Println(evidence, err, label)
			assert.Equal(t, SchnorrCheater, evidence.Type)
			for _, v := range evidence.SchnorrCheaterEvidences {
				assert.Equal(t, nodeList[cheater], v.Label, "Wrong cheater in evidenceList!")
				temp := CheckPubkeyProof(v.Proof, v.Pubkey)
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

			var evidence *Evidence
			var err error
			if label == nodeList[cheater] {
				fakeShare := &DishonestShare{}
				keyGenerater := NewKeyGenerator(label).WithShare(fakeShare)
				_, evidence, err = keyGenerater.KeyGen(nodeList, T, comm)
			} else {
				keyGenerater := NewKeyGenerator(label)
				_, evidence, err = keyGenerater.KeyGen(nodeList, T, comm)
			}
			assert.Equal(t, errors.New("FINAL SHAMIR CHECK FAIL"), err, "Final shamir check error!")
			assert.NotNil(t, evidence, "No cheating evidence!")
			assert.Equal(t, ShamirCheck, evidence.Type)
			assert.Equal(t, N, len(evidence.ShamirCheckEvidence.Evidence), "Wrong evidence number!")
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

			keyGenerater := NewKeyGenerator(label)
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
