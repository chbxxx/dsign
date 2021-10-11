package bhcheck

import (
	"crypto/rand"
	"github.com/bluehelix-chain/dsign/bhcrypto/bhs256k1"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCommit(t *testing.T) {
	priKey1, _ := bhs256k1.NewPrivateKey(bhs256k1.S256())
	priKey2, _ := bhs256k1.NewPrivateKey(bhs256k1.S256())
	pubKey1, pubKey2 := priKey1.PubKey(), priKey2.PubKey()

	blindFactor1, _ := rand.Int(rand.Reader, bhs256k1.S256().CurveParams.N)
	blindFactor2, _ := rand.Int(rand.Reader, bhs256k1.S256().CurveParams.N)

	commit1 := GetPubkeyCommit(pubKey1, blindFactor1)
	commit2 := GetPubkeyCommit(pubKey2, blindFactor2)

	assert.True(t, CheckPubkeyCommit(commit1, pubKey1, blindFactor1), "Invalid commitment!")
	assert.True(t, CheckPubkeyCommit(commit2, pubKey2, blindFactor2), "Invalid commitment!")
	assert.False(t, CheckPubkeyCommit(commit2, pubKey1, blindFactor1), "Invalid commitment!")
	assert.False(t, CheckPubkeyCommit(commit1, pubKey2, blindFactor2), "Invalid commitment!")
	assert.False(t, CheckPubkeyCommit(commit1, pubKey2, blindFactor1), "Invalid commitment!")
	assert.False(t, CheckPubkeyCommit(commit2, pubKey1, blindFactor2), "Invalid commitment!")
}
