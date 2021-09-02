package communicator

import (
	"github.com/bluehelix-chain/dsign/types"
)

type Communicator interface {
	SendKeyGenPhase1Message(msg types.KeyGenPhase1Msg)
	SendKeyGenPhase2Message(msg map[string]types.KeyGenPhase2Msg)
	SendKeyGenPhase3Message(msg types.KeyGenPhase3Msg)
	SendKeySignPhase1Message(msg []types.KeySignPhase1Msg)
	SendKeySignPhase2Message(msg []types.KeySignPhase2Msg)
	SendKeySignPhase3And4Message(msg types.KeySignPhase3And4Msg, participants []string)
	SendKeySignPhase5AMessage(msg types.KeySignPhase5AMsg, participants []string)
	SendKeySignPhase5BMessage(msg types.KeySignPhase5BMsg, participants []string)
	SendKeySignPhase5CMessage(msg types.KeySignPhase5CMsg, participants []string)
	SendKeySignPhase5DMessage(msg types.KeySignPhase5DMsg, participants []string)
	SendKeySignPhase5EMessage(msg types.KeySignPhase5EMsg, participants []string)
	GetKeyGenPhase1Message() (types.KeyGenPhase1Msg, error)
	GetKeyGenPhase2Message() (types.KeyGenPhase2Msg, error)
	GetKeyGenPhase3Message() (types.KeyGenPhase3Msg, error)
	GetKeySignPhase1Message() (types.KeySignPhase1Msg, error)
	GetKeySignPhase2Message() (types.KeySignPhase2Msg, error)
	GetKeySignPhase3And4Message() (types.KeySignPhase3And4Msg, error)
	GetKeySignPhase5AMessage() (types.KeySignPhase5AMsg, error)
	GetKeySignPhase5BMessage() (types.KeySignPhase5BMsg, error)
	GetKeySignPhase5CMessage() (types.KeySignPhase5CMsg, error)
	GetKeySignPhase5DMessage() (types.KeySignPhase5DMsg, error)
	GetKeySignPhase5EMessage() (types.KeySignPhase5EMsg, error)
}
