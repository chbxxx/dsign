package bhcrypto

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"math/big"
)

type BhPublicKey interface {
	ToECDSA() *ecdsa.PublicKey
	IsEqual(otherPubKey BhPublicKey) bool
	Serialize() []byte
	SerializeUncompressed() []byte
	SerializeCompressed() []byte
	GetCurve() elliptic.Curve
	GetX() *big.Int
	GetY() *big.Int
}

type BhPrivateKey interface {
	ToECDSA() *ecdsa.PrivateKey
	Serialize() []byte
}
