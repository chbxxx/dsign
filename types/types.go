package types

import (
	"math/big"

	sssa "github.com/bluehelix-chain/sssa-golang"
	"github.com/btcsuite/btcd/btcec"
	"github.com/decred/dcrd/dcrec/secp256k1"
	"github.com/radicalrafi/gomorph/gaillier"
)

type SigRNative struct {
	X, Y *big.Int
}

type SenderRangeProof struct {
	Z, W, Mu, S, S1, S2 *big.Int
}

type ReceiverRangeProof struct {
	MuX, MuY, Z, ZD, T, V, W, S, S1, S2, T1, T2, XX, XY *big.Int
}

type SchnorrZKProof struct {
	Pub *btcec.PublicKey
	Num *big.Int
}

//Si相关的零知识证明
type SiZKProof struct {
	VX, VY, AX, AY, BX, BY, AlphaX, AlphaY, BetaX, BetaY, T, U *big.Int
}

//在完成Si的零知识证明检查后，需要在不暴露Si的前提下进行S的正确性的检查
type SiZKCheck struct {
	U, T *btcec.PublicKey
}

type PQZKProof struct {
	Z []*big.Int
	X []*big.Int
	Y *big.Int
}

func (msg *KeyGenPhase1Msg) GetNativePubKeyCommit() [32]byte {
	data := [32]byte{}
	copy(data[:], msg.PubKeyCommit)
	return data
}

func (msg *KeyGenPhase1Msg) SetNativePubKeyCommit(commit [32]byte) {
	msg.PubKeyCommit = commit[:]
}

func (msg *KeyGenPhase1Msg) GetNativeCofCommit() []*btcec.PublicKey {
	data := make([]*btcec.PublicKey, 0)
	for _, v := range msg.CofCommit {
		temp, _ := btcec.ParsePubKey(v, btcec.S256())
		data = append(data, temp)
	}
	return data
}

func (msg *KeyGenPhase1Msg) SetNativeCofCommit(commit []*btcec.PublicKey) {
	for _, v := range commit {
		msg.CofCommit = append(msg.CofCommit, v.SerializeCompressed())
	}
}

func (msg *KeyGenPhase1Msg) GetNativeRSAParas() (*big.Int, *big.Int, *big.Int) {
	NTilde := big.NewInt(0).SetBytes(msg.NTilde)
	h1 := big.NewInt(0).SetBytes(msg.H1)
	h2 := big.NewInt(0).SetBytes(msg.H2)
	return NTilde, h1, h2
}

func (msg *KeyGenPhase1Msg) SetNativeRSAParas(N, h1, h2 *big.Int) {
	msg.NTilde = N.Bytes()
	msg.H1 = h1.Bytes()
	msg.H2 = h2.Bytes()
}

func (msg *KeyGenPhase1Msg) GetNativePQProof() PQZKProof {
	var z, x []*big.Int = make([]*big.Int, 0), make([]*big.Int, 0)
	for _, v := range msg.Proof.Zi {
		z = append(z, big.NewInt(0).SetBytes(v))
	}
	for _, v := range msg.Proof.Xi {
		x = append(x, big.NewInt(0).SetBytes(v))
	}
	temp := big.NewInt(0).SetBytes(msg.Proof.Y)
	re := PQZKProof{z, x, temp}
	return re
}

func (msg *KeyGenPhase1Msg) SetNativePQProof(p PQZKProof) {
	msg.Proof = &PQProof{}
	var z, x [][]byte = make([][]byte, 0), make([][]byte, 0)
	for _, v := range p.Z {
		z = append(z, v.Bytes())
	}
	for _, v := range p.X {
		x = append(x, v.Bytes())
	}
	msg.Proof.Zi = z
	msg.Proof.Xi = x
	msg.Proof.Y = p.Y.Bytes()
}

func (msg *KeyGenPhase1Msg) GetNativePubKey() *btcec.PublicKey {
	data, _ := btcec.ParsePubKey(msg.ShamirSharePubKey, btcec.S256())
	return data
}

func (msg *KeyGenPhase1Msg) SetNativePubKey(pk *btcec.PublicKey) {
	msg.ShamirSharePubKey = pk.SerializeCompressed()
}

func (msg *KeyGenPhase2Msg) GetNativePubKey() *btcec.PublicKey {
	data, _ := btcec.ParsePubKey(msg.PubKey, btcec.S256())
	return data
}

func (msg *KeyGenPhase2Msg) SetNativePubKey(pk *btcec.PublicKey) {
	msg.PubKey = pk.SerializeCompressed()
}

func (msg *KeyGenPhase2Msg) GetNativeBlindFactor() *big.Int {
	data := big.NewInt(0).SetBytes(msg.BlindFactor)
	return data
}

func (msg *KeyGenPhase2Msg) SetNativeBlindFactor(bf *big.Int) {
	msg.BlindFactor = bf.Bytes()
}

func (msg *KeyGenPhase2Msg) GetNativeShare(priKey *btcec.PrivateKey) sssa.ShareXY {
	data := sssa.ShareXY{}
	data.X = big.NewInt(0).SetBytes(msg.Share.X)
	secp256k1PrivKey := secp256k1.NewPrivateKey(priKey.D)
	yBytes, _ := secp256k1.Decrypt(secp256k1PrivKey, msg.Share.Y)
	data.Y = big.NewInt(0).SetBytes(yBytes)
	return data
}

func (msg *KeyGenPhase2Msg) SetNativeShare(pubKey *btcec.PublicKey, share sssa.ShareXY) {
	msg.Share = &ShareXY{}
	msg.Share.X = share.X.Bytes()
	secp256k1PubKey := secp256k1.PublicKey{Curve: btcec.S256(), X: pubKey.X, Y: pubKey.Y}
	msg.Share.Y, _ = secp256k1.Encrypt(&secp256k1PubKey, share.Y.Bytes())
}

func (msg *KeyGenPhase3Msg) GetNativeShamirPubKey() *btcec.PublicKey {
	data, _ := btcec.ParsePubKey(msg.ShamirPub, btcec.S256())
	return data
}

func (msg *KeyGenPhase3Msg) SetNativeShamirPubKey(pk *btcec.PublicKey) {
	msg.ShamirPub = pk.SerializeCompressed()
}

func (msg *KeyGenPhase3Msg) GetNativeSchnorrZKProof() SchnorrZKProof {
	data := SchnorrZKProof{}
	data.Pub, _ = btcec.ParsePubKey(msg.Proof.PubKey, btcec.S256())
	data.Num = big.NewInt(0).SetBytes(msg.Proof.Num)
	return data
}

func (msg *KeyGenPhase3Msg) SetNativeSchnorrZKProof(p SchnorrZKProof) {
	msg.Proof = &SchnorrProof{}
	msg.Proof.PubKey = p.Pub.SerializeCompressed()
	msg.Proof.Num = p.Num.Bytes()
}

func (msg *KeySignPhase1Msg) GetNativeSigRCommit() [32]byte {
	data := [32]byte{}
	copy(data[:], msg.SigOthersRCommit)
	return data
}

func (msg *KeySignPhase1Msg) SetNativeSigRCommit(commit [32]byte) {
	msg.SigOthersRCommit = commit[:]
}

func (msg *KeySignPhase1Msg) GetNativePaillierPubKey() *gaillier.PubKey {
	data := &gaillier.PubKey{}
	data.Len = int(msg.PaillierPubKey.Len)
	data.N = big.NewInt(0).SetBytes(msg.PaillierPubKey.N)
	data.G = big.NewInt(0).SetBytes(msg.PaillierPubKey.G)
	data.Nsq = big.NewInt(0).SetBytes(msg.PaillierPubKey.Nsq)
	return data
}

func (msg *KeySignPhase1Msg) SetNativePaillierPubKey(pk *gaillier.PubKey) {
	msg.PaillierPubKey = &PaillierPubKey{}
	msg.PaillierPubKey.Len = int64(pk.Len)
	msg.PaillierPubKey.N = pk.N.Bytes()
	msg.PaillierPubKey.G = pk.G.Bytes()
	msg.PaillierPubKey.Nsq = pk.Nsq.Bytes()
}

func GetNativeSenderRangeProof(p InitiatorRangeProof) SenderRangeProof {
	data := SenderRangeProof{}
	data.Z = big.NewInt(0).SetBytes(p.Z)
	data.W = big.NewInt(0).SetBytes(p.W)
	data.Mu = big.NewInt(0).SetBytes(p.Mu)
	data.S = big.NewInt(0).SetBytes(p.S)
	data.S1 = big.NewInt(0).SetBytes(p.S1)
	data.S2 = big.NewInt(0).SetBytes(p.S2)
	return data
}

func SetNativeSenderRangeProof(rp SenderRangeProof) *InitiatorRangeProof {
	p := &InitiatorRangeProof{}
	p.Z = rp.Z.Bytes()
	p.W = rp.W.Bytes()
	p.Mu = rp.Mu.Bytes()
	p.S = rp.S.Bytes()
	p.S1 = rp.S1.Bytes()
	p.S2 = rp.S2.Bytes()
	return p
}

func GetNativeReceiverRangeProof(p ResponderRangeProof) ReceiverRangeProof {
	data := ReceiverRangeProof{}
	data.MuX = big.NewInt(0).SetBytes(p.MuX)
	data.MuY = big.NewInt(0).SetBytes(p.MuY)
	data.Z = big.NewInt(0).SetBytes(p.Z)
	data.ZD = big.NewInt(0).SetBytes(p.ZD)
	data.T = big.NewInt(0).SetBytes(p.T)
	data.V = big.NewInt(0).SetBytes(p.V)
	data.W = big.NewInt(0).SetBytes(p.W)
	data.S = big.NewInt(0).SetBytes(p.S)
	data.S1 = big.NewInt(0).SetBytes(p.S1)
	data.S2 = big.NewInt(0).SetBytes(p.S2)
	data.T1 = big.NewInt(0).SetBytes(p.T1)
	data.T2 = big.NewInt(0).SetBytes(p.T2)
	data.XX = big.NewInt(0).SetBytes(p.XX)
	data.XY = big.NewInt(0).SetBytes(p.XY)
	return data
}

func SetNativeReceiverRangeProof(rp ReceiverRangeProof) *ResponderRangeProof {
	p := &ResponderRangeProof{}
	p.MuX = rp.MuX.Bytes()
	p.MuY = rp.MuY.Bytes()
	p.Z = rp.Z.Bytes()
	p.ZD = rp.ZD.Bytes()
	p.T = rp.T.Bytes()
	p.V = rp.V.Bytes()
	p.W = rp.W.Bytes()
	p.S = rp.S.Bytes()
	p.S1 = rp.S1.Bytes()
	p.S2 = rp.S2.Bytes()
	p.T1 = rp.T1.Bytes()
	p.T2 = rp.T2.Bytes()
	p.XX = rp.XX.Bytes()
	p.XY = rp.XY.Bytes()
	return p
}

func (msg *KeySignPhase1Msg) GetNativeSenderRangeProofK() SenderRangeProof {
	return GetNativeSenderRangeProof(*msg.PaillierRangeProofK)
}

func (msg *KeySignPhase1Msg) SetNativeSenderRangeProofK(p SenderRangeProof) {
	msg.PaillierRangeProofK = &InitiatorRangeProof{}
	msg.PaillierRangeProofK = SetNativeSenderRangeProof(p)
}

func (msg *KeySignPhase1Msg) GetNativeSenderRangeProofR() SenderRangeProof {
	return GetNativeSenderRangeProof(*msg.PaillierRangeProofR)
}

func (msg *KeySignPhase1Msg) SetNativeSenderRangeProofR(p SenderRangeProof) {
	msg.PaillierRangeProofR = &InitiatorRangeProof{}
	msg.PaillierRangeProofR = SetNativeSenderRangeProof(p)
}

func (msg *KeySignPhase2Msg) GetNativeReceiverRangeProofK() ReceiverRangeProof {
	return GetNativeReceiverRangeProof(*msg.PaillierRangeProofK)
}

func (msg *KeySignPhase2Msg) SetNativeReceiverRangeProofK(p ReceiverRangeProof) {
	msg.PaillierRangeProofK = &ResponderRangeProof{}
	msg.PaillierRangeProofK = SetNativeReceiverRangeProof(p)
}

func (msg *KeySignPhase2Msg) GetNativeReceiverRangeProofR() ReceiverRangeProof {
	return GetNativeReceiverRangeProof(*msg.PaillierRangeProofR)
}

func (msg *KeySignPhase2Msg) SetNativeReceiverRangeProofR(p ReceiverRangeProof) {
	msg.PaillierRangeProofR = &ResponderRangeProof{}
	msg.PaillierRangeProofR = SetNativeReceiverRangeProof(p)
}

func (msg *KeySignPhase3And4Msg) GetNativeThea() *big.Int {
	data := big.NewInt(0).SetBytes(msg.Thea)
	return data
}

func (msg *KeySignPhase3And4Msg) SetNativeThea(thea *big.Int) {
	msg.Thea = thea.Bytes()
}

func (msg *KeySignPhase3And4Msg) GetNativeSchnorrZKProof() SchnorrZKProof {
	data := SchnorrZKProof{}
	data.Pub, _ = btcec.ParsePubKey(msg.KiProof.PubKey, btcec.S256())
	data.Num = big.NewInt(0).SetBytes(msg.KiProof.Num)
	return data
}

func (msg *KeySignPhase3And4Msg) SetNativeSchnorrZKProof(p SchnorrZKProof) {
	msg.KiProof = &SchnorrProof{}
	msg.KiProof.PubKey = p.Pub.SerializeCompressed()
	msg.KiProof.Num = p.Num.Bytes()
}

func (msg *KeySignPhase3And4Msg) GetNativeSigOthersR() SigRNative {
	data := SigRNative{}
	data.X = big.NewInt(0).SetBytes(msg.SigOthersR.X)
	data.Y = big.NewInt(0).SetBytes(msg.SigOthersR.Y)
	return data
}

func (msg *KeySignPhase3And4Msg) SetNativeSigOthersR(sig SigRNative) {
	msg.SigOthersR = &SigR{}
	msg.SigOthersR.X = sig.X.Bytes()
	msg.SigOthersR.Y = sig.Y.Bytes()
}

func (msg *KeySignPhase3And4Msg) GetNativeBlindFactor() *big.Int {
	data := big.NewInt(0).SetBytes(msg.BlindFactor)
	return data
}

func (msg *KeySignPhase3And4Msg) SetNativeBlindFactor(bf *big.Int) {
	msg.BlindFactor = bf.Bytes()
}

func (msg *KeySignPhase5AMsg) GetNativeCommit() ([32]byte, [32]byte, [32]byte) {
	v := [32]byte{}
	copy(v[:], msg.VCommit)
	a := [32]byte{}
	copy(a[:], msg.ACommit)
	b := [32]byte{}
	copy(b[:], msg.BCommit)
	return v, a, b
}

func (msg *KeySignPhase5AMsg) SetNativeCommit(vCommit, aCommit, bCommit [32]byte) {
	msg.VCommit = vCommit[:]
	msg.ACommit = aCommit[:]
	msg.BCommit = bCommit[:]
}

func (msg *KeySignPhase5BMsg) GetNativeSiProof() SiZKProof {
	data := SiZKProof{}
	data.VX = big.NewInt(0).SetBytes(msg.Proof.VX)
	data.VY = big.NewInt(0).SetBytes(msg.Proof.VY)
	data.AX = big.NewInt(0).SetBytes(msg.Proof.AX)
	data.AY = big.NewInt(0).SetBytes(msg.Proof.AY)
	data.BX = big.NewInt(0).SetBytes(msg.Proof.BX)
	data.BY = big.NewInt(0).SetBytes(msg.Proof.BY)
	data.AlphaX = big.NewInt(0).SetBytes(msg.Proof.AlphaX)
	data.AlphaY = big.NewInt(0).SetBytes(msg.Proof.AlphaY)
	data.BetaX = big.NewInt(0).SetBytes(msg.Proof.BetaX)
	data.BetaY = big.NewInt(0).SetBytes(msg.Proof.BetaY)
	data.T = big.NewInt(0).SetBytes(msg.Proof.T)
	data.U = big.NewInt(0).SetBytes(msg.Proof.U)
	return data
}

func (msg *KeySignPhase5BMsg) SetNativeSiProof(p SiZKProof) {
	msg.Proof = &SiProof{}
	msg.Proof.VX = p.VX.Bytes()
	msg.Proof.VY = p.VY.Bytes()
	msg.Proof.AX = p.AX.Bytes()
	msg.Proof.AY = p.AY.Bytes()
	msg.Proof.BX = p.BX.Bytes()
	msg.Proof.BY = p.BY.Bytes()
	msg.Proof.AlphaX = p.AlphaX.Bytes()
	msg.Proof.AlphaY = p.AlphaY.Bytes()
	msg.Proof.BetaX = p.BetaX.Bytes()
	msg.Proof.BetaY = p.BetaY.Bytes()
	msg.Proof.T = p.T.Bytes()
	msg.Proof.U = p.U.Bytes()
}

func (msg *KeySignPhase5BMsg) GetNativeBlindFactor() (*big.Int, *big.Int, *big.Int) {
	v := big.NewInt(0).SetBytes(msg.VBlindFactor)
	a := big.NewInt(0).SetBytes(msg.ABlindFactor)
	b := big.NewInt(0).SetBytes(msg.BBlindFactor)
	return v, a, b
}

func (msg *KeySignPhase5BMsg) SetNativeBlindFactor(v, a, b *big.Int) {
	msg.VBlindFactor = v.Bytes()
	msg.ABlindFactor = a.Bytes()
	msg.BBlindFactor = b.Bytes()
}

func (msg *KeySignPhase5CMsg) GetNativeCommit() ([32]byte, [32]byte) {
	u := [32]byte{}
	copy(u[:], msg.UCommit)
	t := [32]byte{}
	copy(t[:], msg.TCommit)
	return u, t
}

func (msg *KeySignPhase5CMsg) SetNativeCommit(uCommit, tCommit [32]byte) {
	msg.UCommit = uCommit[:]
	msg.TCommit = tCommit[:]
}

func (msg *KeySignPhase5DMsg) GetNativeSiCheck() SiZKCheck {
	data := SiZKCheck{}
	data.T, _ = btcec.ParsePubKey(msg.Check.T, btcec.S256())
	data.U, _ = btcec.ParsePubKey(msg.Check.U, btcec.S256())
	return data
}

func (msg *KeySignPhase5DMsg) SetNativeSiCheck(p SiZKCheck) {
	msg.Check = &SiCheck{}
	msg.Check.T = p.T.SerializeCompressed()
	msg.Check.U = p.U.SerializeCompressed()
}

func (msg *KeySignPhase5DMsg) GetNativeBlindFactor() (*big.Int, *big.Int) {
	u := big.NewInt(0).SetBytes(msg.UBlindFactor)
	t := big.NewInt(0).SetBytes(msg.TBlindFactor)
	return u, t
}

func (msg *KeySignPhase5DMsg) SetNativeBlindFactor(u, t *big.Int) {
	msg.UBlindFactor = u.Bytes()
	msg.TBlindFactor = t.Bytes()
}

func (msg *KeySignPhase5EMsg) GetNativeSigr() *big.Int {
	data := big.NewInt(0).SetBytes(msg.Sigr)
	return data
}

func (msg *KeySignPhase5EMsg) SetNativeSigr(sigr *big.Int) {
	msg.Sigr = sigr.Bytes()
}

func (msg *KeySignPhase5EMsg) GetNativeSigs() *big.Int {
	data := big.NewInt(0).SetBytes(msg.Sigs)
	return data
}

func (msg *KeySignPhase5EMsg) SetNativeSigs(sigs *big.Int) {
	msg.Sigs = sigs.Bytes()
}

func (msg *KeySignPhase5EMsg) GetNativeV() byte {
	data := msg.V[0]
	return data
}

func (msg *KeySignPhase5EMsg) SetNativeV(v byte) {
	msg.V = make([]byte, 1)
	msg.V[0] = v
}
