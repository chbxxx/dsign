package dsigned25519

import (
	"crypto/elliptic"
	"github.com/bluehelix-chain/dsign/bhcrypto/bhed25519"
	"github.com/bluehelix-chain/dsign/bhsssa"
	"github.com/bluehelix-chain/dsign/communicator"
	"github.com/bluehelix-chain/dsign/types"
	"github.com/bluehelix-chain/ed25519/edwards25519"
	"math/big"
)

type NodeEdKeySign struct {
	label                 string
	comm                  communicator.EdCommunicator
	T, N, P               int      //threashold、N
	signNodeList          []string //参与签名的节点列表
	EdKeySignPhase1MsgMap map[string]types.EdKeySignPhase1Msg
	EdKeySignPhase2MsgMap map[string]types.EdKeySignPhase2Msg
	EdKeySignPhase3MsgMap map[string]types.EdKeySignPhase3Msg

	prtShares    []bhsssa.ShareXY
	prtKeyBigInt *big.Int //分片并转换成本节点持有的Big Int

	r      *big.Int
	rPoint bhed25519.PublicKey

	R         edwards25519.ExtendedGroupElement
	extendedR edwards25519.ExtendedGroupElement

	curve     elliptic.Curve
	sigLocalS [32]byte
	sigLocalR [32]byte

	FullSig bhed25519.Signature
	sigR    *big.Int
	sigS    *big.Int

	eight    *big.Int
	eightInv *big.Int

	EdKeySignPhase1MsgSent     types.EdKeySignPhase1Msg
	EdKeySignPhase1MsgReceived []types.EdKeySignPhase1Msg
	EdKeySignPhase2MsgSent     types.EdKeySignPhase2Msg
	EdKeySignPhase2MsgReceived []types.EdKeySignPhase2Msg
	EdKeySignPhase3MsgSent     types.EdKeySignPhase3Msg
	EdKeySignPhase3MsgReceived []types.EdKeySignPhase3Msg
}
