package commit

import (
	"crypto/sha256"
	"math/big"

	"github.com/btcsuite/btcd/btcec"
)

func GetPubkeyCommit(pubkey *btcec.PublicKey, blindFactor *big.Int) [32]byte {
	temP := &btcec.PublicKey{}
	temP.Curve = btcec.S256()
	temP.X, temP.Y = big.NewInt(0), big.NewInt(0)
	temP.X = temP.X.Add(pubkey.X, blindFactor)
	temP.Y = temP.Y.Add(pubkey.Y, blindFactor)
	return sha256.Sum256(temP.SerializeUncompressed())
}

func CheckPubkeyCommit(commit [32]byte, pubkey *btcec.PublicKey, blindFactor *big.Int) bool {
	return commit == GetPubkeyCommit(pubkey, blindFactor)
}
