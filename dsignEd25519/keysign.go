package dsigned25519

import (
	"bytes"
	"crypto/sha512"
	"errors"
	"github.com/bluehelix-chain/dsign/bhcrypto"
	"github.com/bluehelix-chain/dsign/bhcrypto/bhcheck"
	"github.com/bluehelix-chain/dsign/bhcrypto/bhed25519"
	"github.com/bluehelix-chain/dsign/bhsssa"
	"github.com/bluehelix-chain/dsign/communicator"
	"github.com/bluehelix-chain/dsign/logger"
	"github.com/bluehelix-chain/dsign/types"
	"github.com/bluehelix-chain/ed25519/edwards25519"
	"math/big"
	"strconv"
)

type Signer struct {
	label  string
	logger logger.Logger
}

func NewSigner(label string, logger logger.Logger) *Signer {
	return &Signer{
		label:  label,
		logger: logger,
	}
}

func (s *Signer) Sign(T, P, N int, label string, nodekey *NodeEdKeyGen, signNodeList []string, msg []byte,
	comm communicator.EdCommunicator) (*bhed25519.Signature, *NodeEdKeySign, *bhcheck.Evidence, error) {
	//T: Threshold
	//P: Participants
	//N: Total Number of key holders

	if !isInList(s.label, signNodeList) {
		return nil, nil, nil, nil
	}

	t := &NodeEdKeySign{}
	evidence := &bhcheck.Evidence{}
	t.comm = comm
	t.label = label
	t.T = T
	t.N = N
	t.P = P
	t.R = edwards25519.ExtendedGroupElement{}
	t.FullSig = bhed25519.Signature{}
	t.curve = bhed25519.Edwards()
	t.eight = big.NewInt(8)
	t.eightInv = new(big.Int).ModInverse(t.eight, t.curve.Params().N)
	t.signNodeList = signNodeList

	t.EdKeySignPhase1MsgMap = make(map[string]types.EdKeySignPhase1Msg)
	t.EdKeySignPhase2MsgMap = make(map[string]types.EdKeySignPhase2Msg)
	t.EdKeySignPhase3MsgMap = make(map[string]types.EdKeySignPhase3Msg)

	tempShares := []bhsssa.ShareXY{}
	for k := range nodekey.ShareReceived {
		tempShares = append(tempShares, nodekey.ShareReceived[k])
	}
	t.prtShares = tempShares
	//Use VSS to combine the additive serects
	t.prtKeyBigInt = bhsssa.KeyCombine(t.signNodeList, t.label, t.prtShares, bhsssa.Ed25519Prime)

	var rTemp *big.Int
	for rTemp == nil {
		rTemp = bhed25519.GetRandomPositiveInt(t.curve.Params().N)
	}
	t.r = rTemp

	//Get the local R
	edwards25519.GeScalarMultBase(&t.R, bhed25519.BigIntToEncodedBytes(t.r))

	//Get Local R's ecpoint, <<1，>>1 to make sure the most significant bit is 0
	t.rPoint = bhed25519.PublicKey{}
	t.rPoint.Curve = bhed25519.Edwards()
	t.rPoint.X, t.rPoint.Y = t.rPoint.ScalarBaseMult(t.r.Bytes())
	t.rPoint.X, t.rPoint.Y = t.rPoint.ScalarMult(t.rPoint.X, t.rPoint.Y, t.eight.Bytes())
	t.rPoint.X, t.rPoint.Y = t.rPoint.ScalarMult(t.rPoint.X, t.rPoint.Y, t.eightInv.Bytes())

	t.extendedR = bhed25519.EcPointToExtendedElement(t.rPoint.X, t.rPoint.Y)

	//Prepare Phase1 msg
	tempEdKeySignPhase1 := types.EdKeySignPhase1Msg{}
	tempEdKeySignPhase1.LabelFrom = t.label
	tempEdKeySignPhase1.CommitR = bhcrypto.SHA512_256(t.rPoint.Serialize())
	tempEdKeySignPhase1.SetRPoint(t.rPoint)

	t.EdKeySignPhase1MsgSent = tempEdKeySignPhase1

	t.comm.SendEdKeySignPhase1Msg(t.EdKeySignPhase1MsgSent)

	//Receive Broadcast
	for i := 0; i < P; i++ {
		msg, err := t.comm.GetEdKeySignPhase1Msg()
		if err != nil {
			//TODO: miss parts may not be an error evidences
			received := []string{s.label}
			for _, msg := range t.EdKeySignPhase1MsgReceived {
				received = append(received, msg.LabelFrom)
			}
			negativeNodes := getMissingStrings(received, signNodeList)
			evidence.SetNegativeNodes(negativeNodes)
			return nil, t, evidence, err
		}
		t.EdKeySignPhase1MsgReceived = append(t.EdKeySignPhase1MsgReceived, msg)
	}

	for _, v := range t.EdKeySignPhase1MsgReceived {
		t.EdKeySignPhase1MsgMap[v.LabelFrom] = v
		if v.LabelFrom == s.label {
			//We don't need to accumulate our self's R
			continue
		}

		if bytes.Compare(bhcrypto.SHA512_256(v.ExtendedR), v.CommitR) != 0 {
			s.logger.Error("%s open %s R's Commit failed", s.label, v.LabelFrom)
			return nil, t, nil, errors.New("R Commit failed to open")
		}

		rPointOhters, _ := bhed25519.ParsePubKey(v.ExtendedR)
		extendedR := bhed25519.EcPointToExtendedElement(rPointOhters.X, rPointOhters.Y)
		//Calculate the combined R
		t.R = bhed25519.AddExtendedElements(t.R, extendedR)
	}

	//Generate Partial Sig
	encodedPubKey := bhed25519.EcPointToEncodedBytes(nodekey.FullPubKey.GetX(), nodekey.FullPubKey.GetY())
	var encodedR [32]byte
	t.R.ToBytes(&encodedR)
	h := sha512.New()
	h.Reset()
	h.Write(encodedR[:])
	h.Write(encodedPubKey[:])
	h.Write(msg)

	var k [64]byte
	h.Sum(k[:0])
	var kReduced [32]byte
	edwards25519.ScReduce(&kReduced, &k)

	edwards25519.ScMulAdd(&t.sigLocalS, &kReduced,
		bhed25519.BigIntToEncodedBytes(t.prtKeyBigInt),
		bhed25519.BigIntToEncodedBytes(t.r))

	t.sigLocalR = encodedR

	//Prepare Phase2 Msg
	tempAlphaX, tempAlphaY, tempT, _ := bhcheck.NewEdSignZKProof(t.r, &t.rPoint)

	tempEdKeySignPhase2 := types.EdKeySignPhase2Msg{}
	tempEdKeySignPhase2.LabelFrom = s.label
	tempEdKeySignPhase2.ProofAlphaX = tempAlphaX.Bytes()
	tempEdKeySignPhase2.ProofAlphaY = tempAlphaY.Bytes()
	tempEdKeySignPhase2.ProofT = tempT.Bytes()
	t.EdKeySignPhase2MsgSent = tempEdKeySignPhase2
	t.comm.SendEdKeySignPhase2Msg(t.EdKeySignPhase2MsgSent)

	for i := 0; i < P; i++ {
		msg, err := t.comm.GetEdKeySignPhase2Msg()
		if err != nil {
			//TODO: miss parts may not be an error evidences
			received := []string{s.label}
			for _, msg := range t.EdKeySignPhase2MsgReceived {
				received = append(received, msg.LabelFrom)
			}
			negativeNodes := getMissingStrings(received, signNodeList)
			evidence.SetNegativeNodes(negativeNodes)
			return nil, t, evidence, err
		}
		t.EdKeySignPhase2MsgReceived = append(t.EdKeySignPhase2MsgReceived, msg)
	}

	for _, v := range t.EdKeySignPhase2MsgReceived {
		t.EdKeySignPhase2MsgMap[v.LabelFrom] = v

	}

	//Check Phase 2
	for _, v := range t.EdKeySignPhase2MsgMap {
		otherPointR, _ := bhed25519.ParsePubKey(t.EdKeySignPhase1MsgMap[v.LabelFrom].ExtendedR)
		s.logger.Error(s.label + " is verify ZK from " + v.LabelFrom + " : " + strconv.FormatBool(bhcheck.Verify(big.NewInt(0).SetBytes(v.ProofAlphaX), big.NewInt(0).SetBytes(v.ProofAlphaY), big.NewInt(0).SetBytes(v.ProofT), otherPointR)))
	}

	//Prepare Phase3 Msg
	tempEdKeySignPhase3 := types.EdKeySignPhase3Msg{}
	tempEdKeySignPhase3.LabelFrom = s.label
	tempEdKeySignPhase3.SetSigPartial(t.sigLocalS)

	t.EdKeySignPhase3MsgSent = tempEdKeySignPhase3
	t.comm.SendEdKeySignPhase3Msg(t.EdKeySignPhase3MsgSent)

	//Receive others msg
	for i := 0; i < P; i++ {
		msg, err := t.comm.GetEdKeySignPhase3Msg()
		if err != nil {
			//TODO: miss parts may not be an error evidences
			received := []string{s.label}
			for _, msg := range t.EdKeySignPhase3MsgReceived {
				received = append(received, msg.LabelFrom)
			}
			negativeNodes := getMissingStrings(received, signNodeList)
			evidence.SetNegativeNodes(negativeNodes)
			return nil, t, evidence, err
		}
		t.EdKeySignPhase3MsgReceived = append(t.EdKeySignPhase3MsgReceived, msg)
	}
	for _, v := range t.EdKeySignPhase3MsgReceived {
		t.EdKeySignPhase3MsgMap[v.LabelFrom] = v
	}

	//Sum Up final Sig
	var sums [32]byte
	edwards25519.ScMulAdd(&sums, byteTo32(t.EdKeySignPhase3MsgMap[t.signNodeList[0]].SigPartial),
		bhed25519.BigIntToEncodedBytes(big.NewInt(1)),
		byteTo32(t.EdKeySignPhase3MsgMap[t.signNodeList[1]].SigPartial))
	for i := 2; i < len(t.signNodeList); i++ {
		edwards25519.ScMulAdd(&sums, &sums,
			bhed25519.BigIntToEncodedBytes(big.NewInt(1)),
			byteTo32(t.EdKeySignPhase3MsgMap[t.signNodeList[i]].SigPartial))
	}

	t.sigS = bhed25519.EncodedBytesToBigInt(&sums)
	t.sigR = bhed25519.EncodedBytesToBigInt(&t.sigLocalR)

	t.FullSig.S = t.sigS
	t.FullSig.R = t.sigR

	return &t.FullSig, t, evidence, nil

}
