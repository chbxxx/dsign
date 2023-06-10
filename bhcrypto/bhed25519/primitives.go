package bhed25519

// Copyright (c) 2015-2018 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.
import (
	cryptorand "crypto/rand"
	"fmt"
	"math/big"

	"github.com/bluehelix-chain/ed25519/edwards25519"
)

// Some notes on primitives in Ed25519:
//   1) The integers themselves are stored as 32-byte little endian
//        representations. If the store value is a point, the bit in
//        the 31st byte, seventh position (b[31]>>7) represents whether
//        or not the X value retrieved from the Y value should be
//        negative or not. Remember, in affine EC space, the negative
//        is P - positiveX. The rest of the 255 bits then represent
//        the Y-value in little endian.
//   2) For high efficiency, 40 byte field elements (10x int32s) are
//        often used to represent integers.
//   3) For further increases in efficiency, the affine (cartesian)
//        coordinates are converted into projective (extended or non-
//        extended) formats, which include a Z and T or Z value
//        respectively.
//   4) Almost *everything* is encoded in little endian, with the
//        exception of ECDSA X and Y values of points in affine space.

// reverse reverses a byte string.
func reverse(s *[32]byte) {
	for i, j := 0, len(s)-1; i < j; i, j = i+1, j-1 {
		s[i], s[j] = s[j], s[i]
	}
}

// copyBytes copies a byte slice to a 32 byte array.
func copyBytes(aB []byte) *[32]byte {
	if aB == nil {
		return nil
	}
	s := new([32]byte)

	// If we have a short byte string, expand
	// it so that it's long enough.
	aBLen := len(aB)
	if aBLen < fieldIntSize {
		diff := fieldIntSize - aBLen
		for i := 0; i < diff; i++ {
			aB = append([]byte{0x00}, aB...)
		}
	}

	for i := 0; i < fieldIntSize; i++ {
		s[i] = aB[i]
	}

	return s
}

// copyBytes64 copies a byte slice to a 64 byte array.
func copyBytes64(aB []byte) *[64]byte {
	if aB == nil {
		return nil
	}

	s := new([64]byte)

	// If we have a short byte string, expand
	// it so that it's long enough.
	aBLen := len(aB)
	if aBLen < 64 {
		diff := 64 - aBLen
		for i := 0; i < diff; i++ {
			aB = append([]byte{0x00}, aB...)
		}
	}

	for i := 0; i < 64; i++ {
		s[i] = aB[i]
	}

	return s
}

func BigIntToEncodedBytes(a *big.Int) *[32]byte {
	return bigIntToEncodedBytes(a)
}

// bigIntToEncodedBytes converts a big integer into its corresponding
// 32 byte little endian representation.
func bigIntToEncodedBytes(a *big.Int) *[32]byte {
	s := new([32]byte)
	if a == nil {
		return s
	}
	// Caveat: a can be longer than 32 bytes.
	aB := a.Bytes()

	// If we have a short byte string, expand
	// it so that it's long enough.
	aBLen := len(aB)
	if aBLen < fieldIntSize {
		diff := fieldIntSize - aBLen
		for i := 0; i < diff; i++ {
			aB = append([]byte{0x00}, aB...)
		}
	}

	for i := 0; i < fieldIntSize; i++ {
		s[i] = aB[i]
	}

	// Reverse the byte string --> little endian after
	// encoding.
	reverse(s)

	return s
}

// bigIntToEncodedBytesNoReverse converts a big integer into its corresponding
// 32 byte big endian representation.
func bigIntToEncodedBytesNoReverse(a *big.Int) *[32]byte {
	s := new([32]byte)
	if a == nil {
		return s
	}
	// Caveat: a can be longer than 32 bytes.
	aB := a.Bytes()

	// If we have a short byte string, expand
	// it so that it's long enough.
	aBLen := len(aB)
	if aBLen < fieldIntSize {
		diff := fieldIntSize - aBLen
		for i := 0; i < diff; i++ {
			aB = append([]byte{0x00}, aB...)
		}
	}

	for i := 0; i < fieldIntSize; i++ {
		s[i] = aB[i]
	}

	return s
}

// bigIntToFieldElement converts a big little endian integer into its corresponding
// 40 byte field representation.
func bigIntToFieldElement(a *big.Int) *edwards25519.FieldElement {
	aB := bigIntToEncodedBytes(a)
	fe := new(edwards25519.FieldElement)
	edwards25519.FeFromBytes(fe, aB)
	return fe
}

// bigIntPointToEncodedBytes converts an affine point to a compressed
// 32 byte integer representation.
func bigIntPointToEncodedBytes(x *big.Int, y *big.Int) *[32]byte {
	s := bigIntToEncodedBytes(y)
	xB := bigIntToEncodedBytes(x)
	xFE := new(edwards25519.FieldElement)
	edwards25519.FeFromBytes(xFE, xB)
	isNegative := edwards25519.FeIsNegative(xFE) == 1

	if isNegative {
		s[31] |= (1 << 7)
	} else {
		s[31] &^= (1 << 7)
	}

	return s
}

func EncodedBytesToBigInt(s *[32]byte) *big.Int {
	return encodedBytesToBigInt(s)
}

// encodedBytesToBigInt converts a 32 byte little endian representation of
// an integer into a big, big endian integer.
func encodedBytesToBigInt(s *[32]byte) *big.Int {
	// Use a copy so we don't screw up our original
	// memory.
	sCopy := new([32]byte)
	for i := 0; i < fieldIntSize; i++ {
		sCopy[i] = s[i]
	}
	reverse(sCopy)

	bi := new(big.Int).SetBytes(sCopy[:])

	return bi
}

// extendedToBigAffine converts projective x, y, and z field elements into
// affine x and y coordinates, and returns whether or not the x value
// returned is negative.
func (curve TwistedEdwardsCurve) extendedToBigAffine(xi, yi,
	zi *edwards25519.FieldElement) (*big.Int, *big.Int, bool) {
	var recip, x, y edwards25519.FieldElement

	// Normalize to Z=1.
	edwards25519.FeInvert(&recip, zi)
	edwards25519.FeMul(&x, xi, &recip)
	edwards25519.FeMul(&y, yi, &recip)

	isNegative := edwards25519.FeIsNegative(&x) == 1

	return fieldElementToBigInt(&x), fieldElementToBigInt(&y), isNegative
}

// EncodedBytesToBigIntPoint converts a 32 byte representation of a point
// on the elliptical curve into a big integer point. It returns an error
// if the point does not fall on the curve.
func (curve TwistedEdwardsCurve) encodedBytesToBigIntPoint(s *[32]byte) (*big.Int, *big.Int, error) {
	sCopy := new([32]byte)
	for i := 0; i < fieldIntSize; i++ {
		sCopy[i] = s[i]
	}

	xIsNegBytes := sCopy[31]>>7 == 1
	p := new(edwards25519.ExtendedGroupElement)
	if !p.FromBytes(sCopy) {
		return nil, nil, fmt.Errorf("point not on curve")
	}

	// Normalize the X and Y coordinates in affine space.
	x, y, isNegative := curve.extendedToBigAffine(&p.X, &p.Y, &p.Z)

	// We got the wrong sign; flip the bit and recalculate.
	if xIsNegBytes != isNegative {
		x.Sub(curve.P, x)
	}

	// This should hopefully never happen, since the
	// library itself should never let us create a bad
	// point.
	if !curve.IsOnCurve(x, y) {
		return nil, nil, fmt.Errorf("point not on curve")
	}

	return x, y, nil
}

// encodedBytesToFieldElement converts a 32 byte little endian integer into
// a field element.
func encodedBytesToFieldElement(s *[32]byte) *edwards25519.FieldElement {
	fe := new(edwards25519.FieldElement)
	edwards25519.FeFromBytes(fe, s)
	return fe
}

// fieldElementToBigInt converts a 40 byte field element into a big int.
func fieldElementToBigInt(fe *edwards25519.FieldElement) *big.Int {
	s := new([32]byte)
	edwards25519.FeToBytes(s, fe)
	reverse(s)

	aBI := new(big.Int).SetBytes(s[:])

	return aBI
}

// fieldElementToEncodedBytes converts a 40 byte field element into a 32 byte
// little endian integer.
func fieldElementToEncodedBytes(fe *edwards25519.FieldElement) *[32]byte {
	s := new([32]byte)
	edwards25519.FeToBytes(s, fe)
	return s
}

// invert inverts a big integer over the Ed25519 curve.
func (curve *TwistedEdwardsCurve) invert(a *big.Int) *big.Int {
	sub2 := new(big.Int).Sub(curve.P, two)
	inv := new(big.Int).Exp(a, sub2, curve.P)
	return inv
}

func CombinePubkeys(pks []*PublicKey) *PublicKey {
	numPubKeys := len(pks)

	// Have to have at least two pubkeys.
	if numPubKeys < 1 {
		return nil
	}
	if numPubKeys == 1 {
		return pks[0]
	}
	if pks == nil {
		return nil
	}
	if pks[0] == nil || pks[1] == nil {
		return nil
	}

	curve := Edwards()
	var pkSumX *big.Int
	var pkSumY *big.Int

	pkSumX, pkSumY = curve.Add(pks[0].GetX(), pks[0].GetY(),
		pks[1].GetX(), pks[1].GetY())

	if numPubKeys > 2 {
		for i := 2; i < numPubKeys; i++ {
			pkSumX, pkSumY = curve.Add(pkSumX, pkSumY,
				pks[i].GetX(), pks[i].GetY())
		}
	}

	if !curve.IsOnCurve(pkSumX, pkSumY) {
		return nil
	}

	return NewPublicKey(pkSumX, pkSumY)
}

func GetRandomPositiveInt(lessThan *big.Int) *big.Int {
	if lessThan == nil || zero.Cmp(lessThan) != -1 {
		return nil
	}
	var try *big.Int
	for {
		try = MustGetRandomInt(lessThan.BitLen())
		if try.Cmp(lessThan) < 0 && try.Cmp(zero) >= 0 {
			break
		}
	}
	return try
}

// MustGetRandomInt panics if it is unable to gather entropy from `rand.Reader` or when `bits` is <= 0
func MustGetRandomInt(bits int) *big.Int {
	if bits <= 0 || 5000 < bits {
		panic(fmt.Errorf("MustGetRandomInt: bits should be positive, non-zero and less than %d", 5000))
	}
	// Max random value e.g. 2^256 - 1
	max := new(big.Int)
	max = max.Exp(two, big.NewInt(int64(bits)), nil).Sub(max, one)

	// Generate cryptographically strong pseudo-random int between 0 - max
	n, err := cryptorand.Int(cryptorand.Reader, max)
	if err != nil {
		panic("rand.Int failure in MustGetRandomInt!")
	}
	return n
}

func EcPointToExtendedElement(x *big.Int, y *big.Int) edwards25519.ExtendedGroupElement {

	return ecPointToExtendedElement(x, y)
}

func ecPointToExtendedElement(x *big.Int, y *big.Int) edwards25519.ExtendedGroupElement {
	curve := Edwards()
	encodedXBytes := bigIntToEncodedBytes(x)
	encodedYBytes := bigIntToEncodedBytes(y)

	z := GetRandomPositiveInt(curve.Params().N)
	encodedZBytes := bigIntToEncodedBytes(z)

	var fx, fy, fxy edwards25519.FieldElement
	edwards25519.FeFromBytes(&fx, encodedXBytes)
	edwards25519.FeFromBytes(&fy, encodedYBytes)

	var X, Y, Z, T edwards25519.FieldElement
	edwards25519.FeFromBytes(&Z, encodedZBytes)

	edwards25519.FeMul(&X, &fx, &Z)
	edwards25519.FeMul(&Y, &fy, &Z)
	edwards25519.FeMul(&fxy, &fx, &fy)
	edwards25519.FeMul(&T, &fxy, &Z)

	return edwards25519.ExtendedGroupElement{
		X: X,
		Y: Y,
		Z: Z,
		T: T,
	}
}

func AddExtendedElements(p, q edwards25519.ExtendedGroupElement) edwards25519.ExtendedGroupElement {
	return addExtendedElements(p, q)
}

func addExtendedElements(p, q edwards25519.ExtendedGroupElement) edwards25519.ExtendedGroupElement {
	var r edwards25519.CompletedGroupElement
	var qCached edwards25519.CachedGroupElement
	q.ToCached(&qCached)
	edwards25519.GeAdd(&r, &p, &qCached)
	var result edwards25519.ExtendedGroupElement
	r.ToExtended(&result)
	return result
}

func EcPointToEncodedBytes(x *big.Int, y *big.Int) *[32]byte {
	return ecPointToEncodedBytes(x, y)
}

func ecPointToEncodedBytes(x *big.Int, y *big.Int) *[32]byte {
	s := bigIntToEncodedBytes(y)
	xB := bigIntToEncodedBytes(x)
	xFE := new(edwards25519.FieldElement)
	edwards25519.FeFromBytes(xFE, xB)
	isNegative := edwards25519.FeIsNegative(xFE) == 1

	if isNegative {
		s[31] |= (1 << 7)
	} else {
		s[31] &^= (1 << 7)
	}

	return s
}
