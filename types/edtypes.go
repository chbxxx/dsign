package types

import (
	"fmt"
	"github.com/bluehelix-chain/dsign/bhcrypto"
	"github.com/bluehelix-chain/dsign/bhcrypto/bhcheck"
	"github.com/bluehelix-chain/dsign/bhcrypto/bhed25519"
	"github.com/bluehelix-chain/dsign/bhsssa"
	"math/big"
)

///
func (msg *EdKeyGenPhase1Msg) SetNativeCofCommit(commit []*bhed25519.PublicKey) {
	for _, v := range commit {
		msg.CofCommit = append(msg.CofCommit, v.SerializeCompressed())
	}
}

func (msg *EdKeyGenPhase1Msg) GetNativeCofCommit() []*bhed25519.PublicKey {
	data := make([]*bhed25519.PublicKey, 0)
	for _, v := range msg.CofCommit {
		temp, _ := bhed25519.ParsePubKey(v)
		data = append(data, temp)
	}
	return data
}

func (msg *EdKeyGenPhase1Msg) GetNativePubKeyCommit() [32]byte {
	data := [32]byte{}
	copy(data[:], msg.PubKeyCommit)
	return data
}

func (msg *EdKeyGenPhase1Msg) SetNativePubKeyCommit(commit [32]byte) {
	msg.PubKeyCommit = commit[:]
}

func (msg *EdKeyGenPhase1Msg) SetNativeShamirSharePubKey(pubkey *bhed25519.PublicKey) {
	msg.ShamirSharePubKey = pubkey.SerializeCompressed()
}

func (msg *EdKeyGenPhase1Msg) GetNativeShamirSharePubKey() *bhed25519.PublicKey {
	data, _ := bhed25519.ParsePubKey(msg.ShamirSharePubKey)
	return data
}

func (msg *EdKeyGenPhase2Msg) GetNativePubKey() *bhed25519.PublicKey {
	data, _ := bhed25519.ParsePubKey(msg.PubKey)
	return data
}
func (msg *EdKeyGenPhase2Msg) SetNativePubKey(pubkey *bhed25519.PublicKey) {
	msg.PubKey = pubkey.SerializeCompressed()
}

func (msg *EdKeyGenPhase2Msg) GetNativeBlindFactor() *big.Int {
	data := big.NewInt(0).SetBytes(msg.BlindFactor)
	return data
}
func (msg *EdKeyGenPhase2Msg) SetNativeBlindFactor(bf *big.Int) {
	msg.BlindFactor = bf.Bytes()
}

func (msg *EdKeyGenPhase2Msg) SetNativeShare(pubKey *bhed25519.PublicKey, share bhsssa.ShareXY) {
	msg.Share = &EdShareXY{}
	msg.Share.X = share.X.Bytes()
	ed25519pubKey := bhed25519.PublicKey{Curve: bhed25519.Edwards(), X: pubKey.X, Y: pubKey.Y}
	msg.Share.Y, _ = bhed25519.Encrypt(&ed25519pubKey, share.Y.Bytes())
}

func (msg *EdKeyGenPhase2Msg) GetNativeShare(priKey *bhed25519.PrivateKey) bhsssa.ShareXY {
	data := bhsssa.ShareXY{}
	data.X = big.NewInt(0).SetBytes(msg.Share.X)
	yBytes, err := bhed25519.Decrypt(priKey, msg.Share.Y)
	if err != nil {
		fmt.Println(err)
	}
	data.Y = big.NewInt(0).SetBytes(yBytes)
	return data
}

//Below func work for extending KeySign Type

func (msg *EdKeySignPhase1Msg) SetRPoint(rPoint bhed25519.PublicKey) {
	msg.ExtendedR = rPoint.Serialize()
}

func (msg *EdKeySignPhase3Msg) SetSigPartial(SigPartial [32]byte) {
	msg.SigPartial = SigPartial[:]
}

func (msg *EdKeyGenPhase3Msg) SetNativeShamirPubKey(pk bhcrypto.BhPublicKey) {
	msg.ShamirPub = pk.SerializeCompressed()
}

func (msg *EdKeyGenPhase3Msg) GetNativeShamirPubKey() *bhed25519.PublicKey {
	data, _ := bhed25519.ParsePubKey(msg.ShamirPub)
	return data
}

func (msg *EdKeyGenPhase3Msg) SetNativeSchnorrZKProof(p bhcheck.SchnorrZKProof) {
	msg.Proof = &KeyGenSchnorrProof{}
	msg.Proof.PubKey = p.Pub.SerializeCompressed()
	msg.Proof.Num = p.Num.Bytes()
}

func (msg *EdKeyGenPhase3Msg) GetNativeSchnorrZKProof() bhcheck.SchnorrZKProof {
	data := bhcheck.SchnorrZKProof{}
	data.Pub, _ = bhed25519.ParsePubKey(msg.Proof.PubKey)
	data.Num = big.NewInt(0).SetBytes(msg.Proof.Num)
	return data
}
