package bhcrypto

import (
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"
	"sync"
	"time"
)

var (
	one = big.NewInt(1)
	two = big.NewInt(2)
)

type RSAParameter struct {
	NTilde *big.Int
	PTilde *big.Int
	QTilde *big.Int
	H1     *big.Int
	H2     *big.Int
}

type RSAParameterGenerator struct {
	rsaCh                chan *RSAParameter
	rsaParameter         *RSAParameter
	rsaParameterUseTimes int
	rsaMaxReuseTimes     int
	rw                   sync.RWMutex

	bits int
}

func NewRSAParameterGenerator(bits, rsaMaxReuseTimes int) *RSAParameterGenerator {
	r := &RSAParameterGenerator{
		rsaCh:            make(chan *RSAParameter, 0),
		bits:             bits,
		rsaMaxReuseTimes: rsaMaxReuseTimes,
	}
	go r.gen()
	return r
}

func (r *RSAParameterGenerator) gen() {
	for {
		rsaParameter, err := genRSAParameter(r.bits)
		if err != nil {
			fmt.Println("GenRSAParameter error", err)
			continue
		}
		r.rsaCh <- rsaParameter
	}
}

func (r *RSAParameterGenerator) GetRSAParameter() (*RSAParameter, error) {
	r.rw.Lock()
	defer r.rw.Unlock()
	if r.rsaParameter != nil && r.rsaParameterUseTimes < r.rsaMaxReuseTimes {
		r.rsaParameterUseTimes++
		return r.rsaParameter, nil
	}

	select {
	case rsaParameter := <-r.rsaCh:
		r.rsaParameter = rsaParameter
		r.rsaParameterUseTimes = 1
		return r.rsaParameter, nil
	case <-time.After(5 * time.Minute):
		return nil, errors.New("gen rsa parameter timeout")
	}
}

func genRSAParameter(bits int) (*RSAParameter, error) {
	//gP^(PTilde-1)=gP^2p=1 mod PTilde
	PTilde, gP, err1 := safePrimeAndGenerator(bits)
	for err1 != nil {
		fmt.Println("SafePrimeAndGenerator 1 fail!")
		PTilde, gP, err1 = safePrimeAndGenerator(bits)
	}
	//gQ^(QTilde-1)=gQ^2q=1 mod QTilde
	QTilde, gQ, err2 := safePrimeAndGenerator(bits)
	for err2 != nil {
		fmt.Println("SafePrimeAndGenerator 2 fail!")
		QTilde, gQ, err2 = safePrimeAndGenerator(bits)
	}

	//Chinese Remainder Theorem requires gcd(m1,m2)=1
	pqMinDiff := big.NewInt(0).Exp(two, big.NewInt(int64(bits/2)), nil)
	for big.NewInt(0).Abs(big.NewInt(0).Sub(PTilde, QTilde)).Cmp(pqMinDiff) < 0 {
		fmt.Println("P Q too close", PTilde, QTilde)
		PTilde, gP, err1 = safePrimeAndGenerator(bits)
		for err1 != nil {
			fmt.Println("SafePrimeAndGenerator 1 fail!")
			PTilde, gP, err1 = safePrimeAndGenerator(bits)
		}
		QTilde, gQ, err2 = safePrimeAndGenerator(bits)
		for err2 != nil {
			fmt.Println("SafePrimeAndGenerator 2 fail!")
			QTilde, gQ, err2 = safePrimeAndGenerator(bits)
		}
	}
	p := big.NewInt(0).Rsh(big.NewInt(0).Sub(PTilde, one), 1)
	q := big.NewInt(0).Rsh(big.NewInt(0).Sub(QTilde, one), 1)

	NTilde := big.NewInt(0).Mul(PTilde, QTilde)
	t1 := big.NewInt(0).ModInverse(QTilde, PTilde)
	t2 := big.NewInt(0).ModInverse(PTilde, QTilde)
	b01 := big.NewInt(0).Mul(big.NewInt(0).Mul(gP, t1), QTilde)
	b02 := big.NewInt(0).Mul(big.NewInt(0).Mul(gQ, t2), PTilde)
	b0 := big.NewInt(0).Mod(big.NewInt(0).Add(b01, b02), NTilde)

	//gP^2pq=b0^2pq=1^q=1 mod P
	//gQ^2pq=b0^2pq=1^p=1 mod Q
	//gcd(P,Q)=1 -> b0^2pq=1 mod N
	pq := big.NewInt(0).Mul(p, q)
	pq = big.NewInt(0).Mul(pq, big.NewInt(2))
	test := big.NewInt(0).Exp(b0, pq, NTilde)
	if test.Cmp(one) != 0 {
		return nil, errors.New("invalid generator")
	}

	alpha, _ := rand.Int(rand.Reader, NTilde)
	for big.NewInt(0).Mod(NTilde, alpha).Cmp(big.NewInt(0)) == 0 {
		alpha, _ = rand.Int(rand.Reader, NTilde)
	}
	beta, _ := rand.Int(rand.Reader, NTilde)
	for big.NewInt(0).Mod(NTilde, beta).Cmp(big.NewInt(0)) == 0 {
		beta, _ = rand.Int(rand.Reader, NTilde)
	}
	h1 := big.NewInt(0).Exp(b0, alpha, NTilde)
	h2 := big.NewInt(0).Exp(b0, beta, NTilde)

	rsaParameter := &RSAParameter{
		NTilde: NTilde,
		PTilde: PTilde,
		QTilde: QTilde,
		H1:     h1,
		H2:     h2,
	}

	return rsaParameter, nil
}

func safePrimeAndGenerator(bits int) (*big.Int, *big.Int, error) {
	for i := 0; i < 100; i++ {
		p, err := safePrime(bits)
		if err != nil {
			return nil, nil, errors.New("safePrimeAndGenerator fail")
		}

		for _, g0 := range simplePrimes {
			g := big.NewInt(g0)
			if isGenerator(g, p) {
				return p, g, nil
			}
		}
	}
	return nil, nil, errors.New("safePrimeAndGenerator fail")
}

//safePrime, isGenerator and ok are quoted from https://github.com/opencoff/go-srp
//safePrime generates a safe prime; i.e., a prime 'p' such that 2p+1 is also prime.
func safePrime(bits int) (*big.Int, error) {
	a := new(big.Int)
	for {
		p, err := rand.Prime(rand.Reader, bits)
		if err != nil {
			return nil, err
		}
		// 2p+1
		a = a.Lsh(p, 1)
		a = a.Add(a, one)
		if a.ProbablyPrime(20) {
			return a, nil
		}
	}
}

// Return true if g is a generator for safe prime p
//
// From Cryptography Theory & Practive, Stinson and Paterson (Th. 6.8 pp 196):
//   If p > 2 is a prime and g is in Zp*, then
//   g is a primitive element modulo p iff g ^ (p-1)/q != 1 (mod p)
//   for all primes q such that q divides (p-1).
//
// "Primitive Element" and "Generator" are the same thing in Number Theory.
//
// Code below added as a result of bug pointed out by Dharmalingam G. (May 2019)
func isGenerator(g, p *big.Int) bool {
	p1 := big.NewInt(0).Sub(p, one)
	q := big.NewInt(0).Rsh(p1, 1) // q = p-1/2 = ((p-1) >> 1)

	// p is a safe prime. i.e., it is of the form 2q+1 where q is prime.
	//
	// => p-1 = 2q, where q is a prime.
	//
	// All factors of p-1 are: {2, q, 2q}
	//
	// So, our check really comes down to:
	//   1) g ^ (p-1/2q) != 1 mod p
	//		=> g ^ (2q/2q) != 1 mod p
	//		=> g != 1 mod p
	//	    Trivial case. We ignore this.
	//
	//   2) g ^ (p-1/2) != 1 mod p
	//      => g ^ (2q/2) != 1 mod p
	//      => g ^ q != 1 mod p
	//
	//   3) g ^ (p-1/q) != 1 mod p
	//      => g ^ (2q/q) != 1 mod p
	//      => g ^ 2 != 1 mod p
	//

	// g ^ 2 mod p
	if !ok(g, big.NewInt(0).Lsh(one, 1), p) {
		return false
	}

	// g ^ q mod p
	if !ok(g, q, p) {
		return false
	}

	//Fermat's little theorem -> g^(p-1)=1(mod p)
	return true
}

func ok(g, x *big.Int, p *big.Int) bool {
	z := big.NewInt(0).Exp(g, x, p)
	return z.Cmp(one) != 0
}

//TODO:优化生成元的查找
var simplePrimes = []int64{
	2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61,
	67, 71, 73, 79, 83, 89, 97, 101, 103, 107, 109, 113, 127, 131, 137,
	139, 149, 151, 157, 163, 167, 173, 179, 181, 191, 193, 197, 199, 211,
	223, 227, 229, 233, 239, 241, 251, 257, 263, 269, 271, 277, 281, 283,
	293, 307, 311, 313, 317, 331, 337, 347, 349, 353, 359, 367, 373, 379,
	383, 389, 397, 401, 409, 419, 421, 431, 433, 439, 443, 449, 457, 461,
	463, 467, 479, 487, 491, 499, 503, 509, 521, 523, 541,
}

// Generate a random element in the group of all the elements in Z/nZ that
// has a multiplicative inverse.
func GetRandomPositiveRelativelyPrimeInt(n *big.Int) *big.Int {
	if n == nil || one.Cmp(n) != -1 {
		return nil
	}
	max := new(big.Int)
	max = max.Exp(two, big.NewInt(int64(n.BitLen())), nil).Sub(max, one)

	var try *big.Int
	var err error
	for {
		try, err = rand.Int(rand.Reader, max)
		if err != nil {
			continue
		}
		if IsNumberInMultiplicativeGroup(n, try) {
			break
		}
	}
	return try
}

func IsNumberInMultiplicativeGroup(n, v *big.Int) bool {
	if n == nil || v == nil || big.NewInt(0).Cmp(n) != -1 {
		return false
	}
	gcd := big.NewInt(0)
	return v.Cmp(n) < 0 && v.Cmp(one) >= 0 &&
		gcd.GCD(nil, nil, v, n).Cmp(one) == 0
}
