package commit

import (
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/btcsuite/btcd/btcec"
)

func TestCommit(t *testing.T) {
	priKey1, _ := btcec.NewPrivateKey(btcec.S256())
	priKey2, _ := btcec.NewPrivateKey(btcec.S256())
	pubKey1, pubKey2 := priKey1.PubKey(), priKey2.PubKey()

	blindFactor1, _ := rand.Int(rand.Reader, btcec.S256().CurveParams.N)
	blindFactor2, _ := rand.Int(rand.Reader, btcec.S256().CurveParams.N)

	commit1 := GetPubkeyCommit(pubKey1, blindFactor1)
	commit2 := GetPubkeyCommit(pubKey2, blindFactor2)

	assert.True(t, CheckPubkeyCommit(commit1, pubKey1, blindFactor1), "Invalid commitment!")
	assert.True(t, CheckPubkeyCommit(commit2, pubKey2, blindFactor2), "Invalid commitment!")
	assert.False(t, CheckPubkeyCommit(commit2, pubKey1, blindFactor1), "Invalid commitment!")
	assert.False(t, CheckPubkeyCommit(commit1, pubKey2, blindFactor2), "Invalid commitment!")
	assert.False(t, CheckPubkeyCommit(commit1, pubKey2, blindFactor1), "Invalid commitment!")
	assert.False(t, CheckPubkeyCommit(commit2, pubKey1, blindFactor2), "Invalid commitment!")
}
