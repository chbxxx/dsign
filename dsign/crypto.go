package dsign

import (
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"math/big"

	"github.com/bluehelix-chain/dsign/types"

	"github.com/btcsuite/btcd/btcec"
	"github.com/radicalrafi/gomorph/gaillier"
)

type Random interface {
	randomNum(maxRand *big.Int) *big.Int
}

var _ Random = (*HonestRandom)(nil)

type HonestRandom struct{}

func (r *HonestRandom) randomNum(maxRand *big.Int) *big.Int {
	re, _ := rand.Int(rand.Reader, maxRand)
	return re
}

type Response interface {
	respond(r, prtKey *big.Int) (*big.Int, *big.Int)
}

var _ Response = (*HonestResponse)(nil)

type HonestResponse struct{}

func (re *HonestResponse) respond(r, prtKey *big.Int) (*big.Int, *big.Int) {
	return r, prtKey
}

type Share interface {
	share(pub *big.Int) *big.Int
}

var _ Share = (*HonestShare)(nil)

type HonestShare struct{}

func (sh *HonestShare) share(pub *big.Int) *big.Int {
	return pub
}

type Schnorr interface {
	proof(x *big.Int) types.SchnorrZKProof
}

var _ Schnorr = (*HonestSchnorr)(nil)

type HonestSchnorr struct{}

//证明者生成自己知晓pubkey对应的私钥x的证据
func (sh *HonestSchnorr) proof(x *big.Int) types.SchnorrZKProof {
	pubkey := getPubkeyByNum(x)
	maxRand := btcec.S256().CurveParams.N
	randNum, _ := rand.Int(rand.Reader, maxRand)
	randPub := getPubkeyByNum(randNum)
	hash := sha256.New()
	_, _ = hash.Write(pubkey.SerializeUncompressed())
	_, _ = hash.Write(randPub.SerializeUncompressed())
	numByhash := big.NewInt(0).SetBytes(hash.Sum(nil))
	numByhash = numByhash.Mod(numByhash, maxRand)
	result := types.SchnorrZKProof{}
	num := big.NewInt(0).Set(randNum)
	temp := big.NewInt(0).Set(numByhash)
	temp = temp.Mul(temp, x)
	num = num.Add(num, temp)
	num = num.Mod(num, pubkey.Curve.Params().N)
	result.Num = num
	result.Pub = randPub
	return result
}

type SiProof interface {
	GetSiProof(t *Node, s, l, rho *big.Int) types.SiZKProof
}

var _ SiProof = (*HonestSiProof)(nil)

type HonestSiProof struct{}

func (si *HonestSiProof) GetSiProof(t *Node, s, l, rho *big.Int) types.SiZKProof {
	return t.GetSiProof(s, l, rho)
}

type SiCheck interface {
	GetSiCheck(t *Node, hash []byte, pubkey *btcec.PublicKey) types.SiZKCheck
}

var _ SiCheck = (*HonestSiCheck)(nil)

type HonestSiCheck struct{}

func (si *HonestSiCheck) GetSiCheck(t *Node, hash []byte, pubkey *btcec.PublicKey) types.SiZKCheck {
	return t.GetSiCheck(hash, pubkey)
}

type PQProof interface {
	GetPQProof(n, p, q *big.Int, PQProofK int) types.PQZKProof
}

var _ PQProof = (*HonestPQProof)(nil)

type HonestPQProof struct{}

func (pqProof *HonestPQProof) GetPQProof(n, p, q *big.Int, PQProofK int) types.PQZKProof {
	return GetPQProof(n, p, q, PQProofK)
}

func getPubkeyByNum(y *big.Int) *btcec.PublicKey {
	pub := &btcec.PublicKey{}
	pub.Curve = btcec.S256()
	pub.X, pub.Y = pub.ScalarBaseMult(y.Bytes())
	return pub
}

func copyPubkey(pub *btcec.PublicKey) *btcec.PublicKey {
	result := &btcec.PublicKey{}
	result.Curve = pub.Curve
	result.X, result.Y = big.NewInt(0).Set(pub.X), big.NewInt(0).Set(pub.Y)
	return result
}

//验证者验证根据公钥验证proof
func CheckPubkeyProof(proof types.SchnorrZKProof, pubkey *btcec.PublicKey) bool {
	P0 := getPubkeyByNum(proof.Num)
	maxRand := btcec.S256().CurveParams.N
	hash := sha256.New()
	_, _ = hash.Write(pubkey.SerializeUncompressed())
	_, _ = hash.Write(proof.Pub.SerializeUncompressed())
	numByhash := big.NewInt(0).SetBytes(hash.Sum(nil))
	numByhash = numByhash.Mod(numByhash, maxRand)
	P2 := copyPubkey(proof.Pub)
	x, y := pubkey.ScalarMult(pubkey.X, pubkey.Y, numByhash.Bytes())
	P2.X, P2.Y = pubkey.Add(P2.X, P2.Y, x, y)
	return P0.IsEqual(P2)
}

func GetPQProof(n, p, q *big.Int, PQProofK int) types.PQZKProof {
	strA := n.String() + n.String()
	A, _ := big.NewInt(0).SetString(strA, 10)
	r, _ := rand.Int(rand.Reader, A)
	hash := sha256.New()
	_, _ = hash.Write(n.Bytes())

	var z, x []*big.Int = make([]*big.Int, PQProofK), make([]*big.Int, PQProofK)
	fai := big.NewInt(0).Mul(big.NewInt(0).Sub(p, big.NewInt(1)), big.NewInt(0).Sub(q, big.NewInt(1)))
	for i := 0; i < PQProofK; i++ {
		temp, _ := rand.Int(rand.Reader, n)
		m1 := big.NewInt(0).Mod(temp, p)
		m2 := big.NewInt(0).Mod(temp, q)
		for m1.Cmp(big.NewInt(0)) == 0 || m2.Cmp(big.NewInt(0)) == 0 {
			temp, _ = rand.Int(rand.Reader, n)
			m1 = big.NewInt(0).Mod(temp, p)
			m2 = big.NewInt(0).Mod(temp, q)
		}
		z[i] = temp
		_, _ = hash.Write(temp.Bytes())
	}
	for k, v := range z {
		x[k] = big.NewInt(0).Exp(v, r, n)
	}
	e := big.NewInt(0).SetBytes(hash.Sum(nil))
	y := big.NewInt(0).Add(r, big.NewInt(0).Mul(big.NewInt(0).Sub(n, fai), e))
	return types.PQZKProof{Z: z, X: x, Y: y}
}

func PaillierEncrypt(pubkey *gaillier.PubKey, message []byte, r *big.Int) (*big.Int, error) {
	m := new(big.Int).SetBytes(message)
	if pubkey.N.Cmp(m) < 1 {
		return nil, errors.New("message too long")
	}
	//c = g^m * r^nmod n^2
	//g^m
	gm := new(big.Int).Exp(pubkey.G, m, pubkey.Nsq)
	//r^n
	rn := new(big.Int).Exp(r, pubkey.N, pubkey.Nsq)
	//prod = g^m * r^n
	prod := new(big.Int).Mul(gm, rn)
	c := new(big.Int).Mod(prod, pubkey.Nsq)
	return c, nil
}
