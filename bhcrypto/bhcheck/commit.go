package bhcheck

import (
	"crypto/elliptic"
	"crypto/sha256"
	"github.com/bluehelix-chain/dsign/bhcrypto"
	"github.com/bluehelix-chain/dsign/bhcrypto/bhed25519"
	"github.com/bluehelix-chain/dsign/bhcrypto/bhs256k1"
	"math/big"
	"reflect"
)

//TODO: 用ECPoint
func GetPubkeyCommit(pubkey bhcrypto.BhPublicKey, blindFactor *big.Int, curve elliptic.Curve) [32]byte {

	if reflect.TypeOf(curve).Elem() == reflect.TypeOf(bhed25519.Edwards()).Elem() {
		temP := &bhed25519.PublicKey{}
		temP.Curve = bhed25519.Edwards()
		temP.X, temP.Y = big.NewInt(0), big.NewInt(0)
		temP.X = temP.X.Add(pubkey.GetX(), blindFactor)
		temP.Y = temP.Y.Add(pubkey.GetY(), blindFactor)
		return sha256.Sum256(temP.SerializeUncompressed())
	} else {
		temP := &bhs256k1.PublicKey{}
		temP.Curve = bhs256k1.S256()
		temP.X, temP.Y = big.NewInt(0), big.NewInt(0)
		temP.X = temP.X.Add(pubkey.GetX(), blindFactor)
		temP.Y = temP.Y.Add(pubkey.GetY(), blindFactor)
		return sha256.Sum256(temP.SerializeUncompressed())

	}
}

func CheckPubkeyCommit(commit [32]byte, pubkey bhcrypto.BhPublicKey, blindFactor *big.Int, curve elliptic.Curve) bool {
	a := commit
	b := GetPubkeyCommit(pubkey, blindFactor, curve)
	return a == b
}

func RejectionSample(q *big.Int, eHash *big.Int) *big.Int { // e' = eHash
	e := eHash.Mod(eHash, q)
	return e
}
