package bhcheck

import (
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"github.com/bluehelix-chain/dsign/bhcrypto"
	"github.com/bluehelix-chain/dsign/bhcrypto/bhed25519"
	"github.com/bluehelix-chain/dsign/bhcrypto/bhs256k1"
	"math/big"
	"reflect"
)

type SenderRangeProof struct {
	Z, W, Mu, S, S1, S2 *big.Int
}

type ReceiverRangeProof struct {
	MuX, MuY, Z, ZD, T, V, W, S, S1, S2, T1, T2, XX, XY *big.Int
}

type PQZKProof struct {
	Z []*big.Int
	X []*big.Int
	Y *big.Int
}

///

type Random interface {
	RandomNum(maxRand *big.Int) *big.Int
}

var _ Random = (*HonestRandom)(nil)

type HonestRandom struct{}

func (r *HonestRandom) RandomNum(maxRand *big.Int) *big.Int {
	re, _ := rand.Int(rand.Reader, maxRand)
	return re
}

type Response interface {
	Respond(r, prtKey *big.Int) (*big.Int, *big.Int)
}

var _ Response = (*HonestResponse)(nil)

type HonestResponse struct{}

func (re *HonestResponse) Respond(r, prtKey *big.Int) (*big.Int, *big.Int) {
	return r, prtKey
}

type Share interface {
	Share(pub *big.Int) *big.Int
}

var _ Share = (*HonestShare)(nil)

type HonestShare struct{}

func (sh *HonestShare) Share(pub *big.Int) *big.Int {
	return pub
}

type Schnorr interface {
	Proof(x *big.Int, curve elliptic.Curve) SchnorrZKProof
}

var _ Schnorr = (*HonestSchnorr)(nil)

type HonestSchnorr struct{}

//证明者生成自己知晓pubkey对应的私钥x的证据
func (sh *HonestSchnorr) Proof(x *big.Int, curve elliptic.Curve) SchnorrZKProof {
	if reflect.TypeOf(curve).Elem() == reflect.TypeOf(bhed25519.Edwards()).Elem() {
		pubkey := bhed25519.GetEdPubkeyByNum(x)
		maxRand := bhed25519.Edwards().N
		randNum, _ := rand.Int(rand.Reader, maxRand)
		randPub := bhed25519.GetEdPubkeyByNum(randNum)
		hash := sha256.New()
		_, _ = hash.Write(pubkey.SerializeUncompressed())
		_, _ = hash.Write(randPub.SerializeUncompressed())
		numByhash := big.NewInt(0).SetBytes(hash.Sum(nil))
		numByhash = numByhash.Mod(numByhash, maxRand)
		result := SchnorrZKProof{}
		num := big.NewInt(0).Set(randNum)
		temp := big.NewInt(0).Set(numByhash)
		temp = temp.Mul(temp, x)
		num = num.Add(num, temp)
		num = num.Mod(num, pubkey.GetCurve().Params().N)
		result.Num = num
		result.Pub = randPub
		return result
	} else {
		pubkey := bhs256k1.GetPubkeyByNum(x)
		maxRand := bhs256k1.S256().CurveParams.N
		randNum, _ := rand.Int(rand.Reader, maxRand)
		randPub := bhs256k1.GetPubkeyByNum(randNum)
		hash := sha256.New()
		_, _ = hash.Write(pubkey.SerializeUncompressed())
		_, _ = hash.Write(randPub.SerializeUncompressed())
		numByhash := big.NewInt(0).SetBytes(hash.Sum(nil))
		numByhash = numByhash.Mod(numByhash, maxRand)
		result := SchnorrZKProof{}
		num := big.NewInt(0).Set(randNum)
		temp := big.NewInt(0).Set(numByhash)
		temp = temp.Mul(temp, x)
		num = num.Add(num, temp)
		num = num.Mod(num, pubkey.Curve.Params().N)
		result.Num = num
		result.Pub = randPub
		return result
	}
}

type SiProof interface {
	GetSiProof(siX, siY, s, l, rho *big.Int) SiZKProof
}

var _ SiProof = (*HonestSiProof)(nil)

type HonestSiProof struct{}

func (si *HonestSiProof) GetSiProof(siX, siY, s, l, rho *big.Int) SiZKProof {
	return GetSiProof(siX, siY, s, l, rho)
}

type SiCheck interface {
	GetSiCheck(siRho, siL, all5BSumX, all5BSumY, others5BSumX, others5BSumY, sigR *big.Int, hash []byte, pubkey *bhs256k1.PublicKey) SiZKCheck
}

var _ SiCheck = (*HonestSiCheck)(nil)

type HonestSiCheck struct{}

func (si *HonestSiCheck) GetSiCheck(siRho, siL, all5BSumX, all5BSumY, others5BSumX, others5BSumY, sigR *big.Int, hash []byte, pubkey *bhs256k1.PublicKey) SiZKCheck {
	return GetSiCheck(siRho, siL, all5BSumX, all5BSumY, others5BSumX, others5BSumY, sigR, hash, pubkey)
}

type PQProof interface {
	GetPQProof(n, p, q *big.Int, PQProofK int) PQZKProof
}

var _ PQProof = (*HonestPQProof)(nil)

type HonestPQProof struct{}

func (pqProof *HonestPQProof) GetPQProof(n, p, q *big.Int, PQProofK int) PQZKProof {
	return GetPQProof(n, p, q, PQProofK)
}

func CopyPubkey(pub bhcrypto.BhPublicKey) *bhs256k1.PublicKey {
	result := &bhs256k1.PublicKey{}
	result.Curve = pub.GetCurve()
	result.X, result.Y = big.NewInt(0).Set(pub.GetX()), big.NewInt(0).Set(pub.GetY())
	return result
}

//验证者验证根据公钥验证proof
func CheckPubkeyProof(proof SchnorrZKProof, pubkey bhcrypto.BhPublicKey, curve elliptic.Curve) bool {

	if reflect.TypeOf(curve).Elem() == reflect.TypeOf(bhed25519.Edwards()).Elem() {
		P0 := bhed25519.GetEdPubkeyByNum(proof.Num)
		maxRand := bhed25519.Edwards().N
		hash := sha256.New()
		_, _ = hash.Write(pubkey.SerializeUncompressed())
		_, _ = hash.Write(proof.Pub.SerializeUncompressed())
		numByhash := big.NewInt(0).SetBytes(hash.Sum(nil))
		numByhash = numByhash.Mod(numByhash, maxRand)
		P2 := copyEdPubkey(proof.Pub)
		x, y := bhed25519.Edwards().ScalarMult(pubkey.GetX(), pubkey.GetY(), numByhash.Bytes())
		P2.X, P2.Y = bhed25519.Edwards().Add(P2.X, P2.Y, x, y)
		return P0.IsEqual(P2)

	} else {
		P0 := bhs256k1.GetPubkeyByNum(proof.Num)
		maxRand := bhs256k1.S256().CurveParams.N
		hash := sha256.New()
		_, _ = hash.Write(pubkey.SerializeUncompressed())
		_, _ = hash.Write(proof.Pub.SerializeUncompressed())
		numByhash := big.NewInt(0).SetBytes(hash.Sum(nil))
		numByhash = numByhash.Mod(numByhash, maxRand)
		P2 := CopyPubkey(proof.Pub)
		x, y := bhs256k1.S256().ScalarMult(pubkey.GetX(), pubkey.GetY(), numByhash.Bytes())
		P2.X, P2.Y = bhs256k1.S256().Add(P2.X, P2.Y, x, y)
		return P0.IsEqual(P2)
	}
}

func copyEdPubkey(pub bhcrypto.BhPublicKey) *bhed25519.PublicKey {
	result := &bhed25519.PublicKey{}
	result.Curve = pub.GetCurve()
	result.X, result.Y = big.NewInt(0).Set(pub.GetX()), big.NewInt(0).Set(pub.GetY())
	return result
}

func GetPQProof(n, p, q *big.Int, PQProofK int) PQZKProof {
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
	return PQZKProof{Z: z, X: x, Y: y}
}

//SI

//s为局部的签名的s,l,rho为随机生成的用于0知识证明的随机数
func GetSiProof(siX, siY, s, l, rho *big.Int) SiZKProof {
	//生成Vi,Ai,Bi
	localV := &bhs256k1.PublicKey{}
	localV.Curve = bhs256k1.S256()
	localV.X, localV.Y = localV.ScalarMult(siX, siY, s.Bytes())
	tempV := bhs256k1.GetPubkeyByNum(l)
	localV.X, localV.Y = localV.Add(localV.X, localV.Y, tempV.X, tempV.Y)
	localA := bhs256k1.GetPubkeyByNum(rho)
	localB := &bhs256k1.PublicKey{}
	localB.Curve = bhs256k1.S256()
	localB.X, localB.Y = tempV.ScalarMult(tempV.X, tempV.Y, rho.Bytes())
	//随机生成a,b
	a, _ := bhs256k1.NewPrivateKey(bhs256k1.S256())
	b, _ := bhs256k1.NewPrivateKey(bhs256k1.S256())
	//生成alpha,beta
	alpha, beta := &bhs256k1.PublicKey{}, &bhs256k1.PublicKey{}
	alpha.Curve = bhs256k1.S256()
	beta.Curve = bhs256k1.S256()
	tempAlpha := bhs256k1.GetPubkeyByNum(b.D)
	alpha.X, alpha.Y = alpha.ScalarMult(siX, siY, a.D.Bytes())
	alpha.X, alpha.Y = alpha.Add(alpha.X, alpha.Y, tempAlpha.X, tempAlpha.Y)
	beta.X, beta.Y = beta.ScalarMult(localA.X, localA.Y, b.D.Bytes())
	//生成c
	hash := sha256.New()
	_, _ = hash.Write(alpha.X.Bytes())
	_, _ = hash.Write(alpha.Y.Bytes())
	_, _ = hash.Write(beta.X.Bytes())
	_, _ = hash.Write(beta.Y.Bytes())
	c := big.NewInt(0).SetBytes(hash.Sum(nil))
	c = c.Mod(c, localV.Params().N)
	//生成T,u
	T := computeLinearSum(c, s, a.D)
	u := computeLinearSum(c, l, b.D)
	result := SiZKProof{
		VX:     localV.X,
		VY:     localV.Y,
		AX:     localA.X,
		AY:     localA.Y,
		BX:     localB.X,
		BY:     localB.Y,
		AlphaX: alpha.X,
		AlphaY: alpha.Y,
		BetaX:  beta.X,
		BetaY:  beta.Y,
		T:      T,
		U:      u,
	}
	return result
}

//hash为需要签名的对象，pubkey为最终的公钥
func GetSiCheck(siRho, siL, all5BSumX, all5BSumY, others5BSumX, others5BSumY, sigR *big.Int, hash []byte, pubkey *bhs256k1.PublicKey) SiZKCheck {
	//V:=sum(vi)- (e.G + r*da.G)
	//U := V*rho
	e := HashToInt(hash, pubkey.Curve)
	V := bhs256k1.GetPubkeyByNum(e)
	tempVx, tempVy := pubkey.ScalarMult(pubkey.X, pubkey.Y, sigR.Bytes())
	V.X, V.Y = V.Add(V.X, V.Y, tempVx, tempVy)
	V.Y = V.Y.Sub(bhs256k1.S256().P, V.Y)

	//Deal with siRho
	U := &bhs256k1.PublicKey{}
	U.Curve = bhs256k1.S256()
	U.X, U.Y = all5BSumX, all5BSumY
	U.X, U.Y = U.Add(U.X, U.Y, V.X, V.Y)
	U.X, U.Y = U.ScalarMult(U.X, U.Y, siRho.Bytes())

	//Deal with siL
	T := &bhs256k1.PublicKey{}
	T.Curve = bhs256k1.S256()
	T.X, T.Y = others5BSumX, others5BSumY
	T.X, T.Y = T.ScalarMult(T.X, T.Y, siL.Bytes())
	return SiZKCheck{
		U: U,
		T: T,
	}
}

//SI End
func HashToInt(hash []byte, c elliptic.Curve) *big.Int {
	orderBits := c.Params().N.BitLen()
	orderBytes := (orderBits + 7) / 8
	if len(hash) > orderBytes {
		hash = hash[:orderBytes]
	}

	ret := new(big.Int).SetBytes(hash)
	excess := len(hash)*8 - orderBits
	if excess > 0 {
		ret.Rsh(ret, uint(excess))
	}
	return ret
}

//return a*b+c
func computeLinearSum(a, b, c *big.Int) *big.Int {
	result := new(big.Int).Mul(a, b)
	result = result.Add(result, c)
	return result
}

//生成两个检查下标列表,[1-t][n-t,n]，可以覆盖所有参与分片的节点，一般情况下可以发现有节点在shamir分片中作弊
func GenerateCheckArrays(t, n int, coeff []*big.Int) [][]string {
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

func NewEdSignZKProof(x *big.Int, X *bhed25519.PublicKey) (*big.Int, *big.Int, *big.Int, error) {
	if x == nil || X == nil {
		return nil, nil, nil, errors.New("ZKProof constructor received nil or invalid value(s)")
	}
	a := big.NewInt(0)

	for a.Cmp(big.NewInt(0)) == 0 {
		a = bhed25519.GetRandomPositiveInt(X.Params().N)
	}

	alphaX, alphaY := X.Curve.ScalarBaseMult(a.Bytes())

	var c *big.Int
	{
		cHash := bhcrypto.SHA512_256i(X.X, X.Y, X.Curve.Params().Gx, X.Curve.Params().Gy, alphaX, alphaY)
		c = RejectionSample(X.Curve.Params().N, cHash)
	}
	t := new(big.Int).Mul(c, x)
	t = new(big.Int).Add(a, t)
	t = new(big.Int).Mod(t, X.Curve.Params().N)
	return alphaX, alphaY, t, nil
}

func Verify(alphaX *big.Int, alphaY *big.Int, t *big.Int, X *bhed25519.PublicKey) bool {

	var c *big.Int
	{
		cHash := bhcrypto.SHA512_256i(X.X, X.Y, X.Curve.Params().Gx, X.Curve.Params().Gy, alphaX, alphaY)
		c = RejectionSample(X.Curve.Params().N, cHash)
	}
	tGx, tGy := X.Curve.ScalarBaseMult(t.Bytes())
	Xcx, Xcy := X.Curve.ScalarMult(X.X, X.Y, c.Bytes())
	aXcX, aXcY := X.Curve.Add(alphaX, alphaY, Xcx, Xcy)

	return aXcX.Cmp(tGx) == 0 && aXcY.Cmp(tGy) == 0
}
