package bhcrypto

import (
	"crypto"
	"encoding/binary"
	"math/big"
)

func SHA512_256(in ...[]byte) []byte {
	var data []byte
	state := crypto.SHA512_256.New()
	inLen := len(in)
	if inLen == 0 {
		return nil
	}
	bzSize := 0
	// prevent hash collisions with this prefix containing the block count
	inLenBz := make([]byte, 64/8)
	// converting between int and uint64 doesn't change the sign bit, but it may be interpreted as a larger value.
	// this prefix is never read/interpreted, so that doesn't matter.
	binary.LittleEndian.PutUint64(inLenBz, uint64(inLen))
	for _, bz := range in {
		bzSize += len(bz)
	}
	data = make([]byte, 0, len(inLenBz)+bzSize+inLen)
	data = append(data, inLenBz...)
	for _, bz := range in {
		data = append(data, bz...)
		data = append(data, byte('$')) // safety delimiter
	}
	// n < len(data) or an error will never happen.
	// see: https://golang.org/pkg/hash/#Hash and https://github.com/golang/go/wiki/Hashing#the-hashhash-interface
	if _, err := state.Write(data); err != nil {
		//Logger.Errorf("SHA512_256 Write() failed: %v", err)
		return nil
	}
	return state.Sum(nil)
}

func SHA512_256i(in ...*big.Int) *big.Int {
	var data []byte
	state := crypto.SHA512_256.New()
	inLen := len(in)
	if inLen == 0 {
		return nil
	}
	bzSize := 0
	// prevent hash collisions with this prefix containing the block count
	inLenBz := make([]byte, 64/8)
	// converting between int and uint64 doesn't change the sign bit, but it may be interpreted as a larger value.
	// this prefix is never read/interpreted, so that doesn't matter.
	binary.LittleEndian.PutUint64(inLenBz, uint64(inLen))
	ptrs := make([][]byte, inLen)
	for i, n := range in {
		ptrs[i] = n.Bytes()
		bzSize += len(ptrs[i])
	}
	data = make([]byte, 0, len(inLenBz)+bzSize+inLen)
	data = append(data, inLenBz...)
	for i := range in {
		data = append(data, ptrs[i]...)
		data = append(data, '$') // safety delimiter
	}
	// n < len(data) or an error will never happen.
	// see: https://golang.org/pkg/hash/#Hash and https://github.com/golang/go/wiki/Hashing#the-hashhash-interface
	if _, err := state.Write(data); err != nil {
		//Logger.Errorf("SHA512_256i Write() failed: %v", err)
		return nil
	}
	return new(big.Int).SetBytes(state.Sum(nil))
}
