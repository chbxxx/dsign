package communicator

import "github.com/bluehelix-chain/dsign/types"

type EdCommunicator interface {
	SendEdKeyGenPhase1Msg(msg types.EdKeyGenPhase1Msg)
	GetEdKeyGenPhase1Msg() (types.EdKeyGenPhase1Msg, error)
	SendEdKeyGenPhase2Msg(msg map[string]types.EdKeyGenPhase2Msg)
	GetEdKeyGenPhase2Msg() (types.EdKeyGenPhase2Msg, error)
	GetEdKeyGenPhase3Msg() (types.EdKeyGenPhase3Msg, error)
	SendEdKeyGenPhase3Msg(msg types.EdKeyGenPhase3Msg)

	SendEdKeySignPhase1Msg(msg types.EdKeySignPhase1Msg)
	GetEdKeySignPhase1Msg() (types.EdKeySignPhase1Msg, error)
	SendEdKeySignPhase2Msg(msg types.EdKeySignPhase2Msg)
	GetEdKeySignPhase2Msg() (types.EdKeySignPhase2Msg, error)
	SendEdKeySignPhase3Msg(msg types.EdKeySignPhase3Msg)
	GetEdKeySignPhase3Msg() (types.EdKeySignPhase3Msg, error)
}
