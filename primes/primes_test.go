package primes

import (
	"crypto/rand"
	"math/big"
	"testing"

	"github.com/radicalrafi/gomorph/gaillier"
	"github.com/stretchr/testify/assert"
)

const testBitLen = 1024

func TestGetRandomPositiveRelativelyPrimeInt(t *testing.T) {
	paillierPubKey, _, _ := gaillier.GenerateKeyPair(rand.Reader, testBitLen)
	rnd, _ := rand.Int(rand.Reader, paillierPubKey.N)
	rndPosRP := GetRandomPositiveRelativelyPrimeInt(rnd)
	assert.NotZero(t, rndPosRP, "rand int should not be zero")
	assert.True(t, IsNumberInMultiplicativeGroup(rnd, rndPosRP))
	assert.True(t, rndPosRP.Cmp(big.NewInt(0)) == 1, "rand int should be positive")
	// TODO test for relative primeness
}
