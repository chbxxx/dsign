package bhcrypto

import (
	"errors"
	"github.com/radicalrafi/gomorph/gaillier"
	"math/big"
)

func PaillierEncWithR(msg []byte, r *big.Int, pubKey *gaillier.PubKey) (*big.Int, error) {
	m := new(big.Int).SetBytes(msg)
	if pubKey.N.Cmp(m) < 1 {
		return nil, errors.New("message too long")
	}
	//c = g^m * r^nmod n^2
	//g^m
	gm := new(big.Int).Exp(pubKey.G, m, pubKey.Nsq)
	//r^n
	rn := new(big.Int).Exp(r, pubKey.N, pubKey.Nsq)
	//prod = g^m * r^n
	prod := new(big.Int).Mul(gm, rn)
	c := new(big.Int).Mod(prod, pubKey.Nsq)
	return c, nil
}

func PaillierEnc(msg *big.Int, pubKey *gaillier.PubKey) ([]byte, *big.Int) {
	r := GetRandomPositiveRelativelyPrimeInt(pubKey.N)
	cipher, _ := PaillierEncWithR(msg.Bytes(), r, pubKey)
	return cipher.Bytes(), r
}

func PaillierDec(cipher []byte, prtKey *gaillier.PrivKey) *big.Int {
	msg, _ := gaillier.Decrypt(prtKey, cipher)
	result := new(big.Int).SetBytes(msg)
	return result
}
