package communicator

import (
	"fmt"

	"github.com/bluehelix-chain/dsign/types"
	"github.com/golang/protobuf/proto"
)

var _ Communicator = (*LocalCommunicator)(nil)

type LocalCommunicator struct {
	nodeMap map[string]*ChanNode
	n       int
	label   string
}

func NewLocalCommunicator(nodeMap map[string]*ChanNode, n int, label string) (l *LocalCommunicator) {
	l = &LocalCommunicator{}
	l.nodeMap = nodeMap
	l.n = n
	l.label = label
	return l
}

//第KeyGenPhase1轮消息:发送给所有的N个节点，包含自己
func (comm *LocalCommunicator) SendKeyGenPhase1Message(msg types.KeyGenPhase1Msg) {
	for _, v := range comm.nodeMap {
		str, _ := proto.Marshal(&msg) //need &!
		v.KeyGenPhase1Chan <- str
	}
}

//第KeyGenPhase2轮消息:发送给KeyGenPhase2MsgSent[]数组里所有LabelTo的节点，包含自己本身
func (comm *LocalCommunicator) SendKeyGenPhase2Message(msg map[string]types.KeyGenPhase2Msg) {
	for _, v := range msg {
		v := v
		str, _ := proto.Marshal(&v)
		comm.nodeMap[v.LabelTo].KeyGenPhase2Chan <- str
	}
}

//第KeyGenPhase3轮消息:发送给所有的N个节点，包含自己
func (comm *LocalCommunicator) SendKeyGenPhase3Message(msg types.KeyGenPhase3Msg) {
	for _, v := range comm.nodeMap {
		str, _ := proto.Marshal(&msg) //need &!
		v.KeyGenPhase3Chan <- str
	}
}

//第KeySignPhase1轮消息:发送给不包含自身的所有其他节点 toNodesLbael=participants-t.label
func (comm *LocalCommunicator) SendKeySignPhase1Message(msg []types.KeySignPhase1Msg) {
	for _, v := range msg {
		v := v
		str, _ := proto.Marshal(&v)
		comm.nodeMap[v.LabelTo].KeySignPhase1Chan <- str
	}
}

//第KeySignPhase2轮消息：发送给KeySignPhase2MsgSent[]数组里所有LabelTo的节点，包含自己本身
//不包含自身！！！
func (comm *LocalCommunicator) SendKeySignPhase2Message(msg []types.KeySignPhase2Msg) {
	for _, v := range msg {
		v := v
		str, _ := proto.Marshal(&v)
		comm.nodeMap[v.LabelTo].KeySignPhase2Chan <- str
	}
}

//第KeySignPhase3And4轮消息：发送给不包含自身的所有其他节点 toNodesLabel=participants-t.label
func (comm *LocalCommunicator) SendKeySignPhase3And4Message(msg types.KeySignPhase3And4Msg, participants []string) {
	for _, v := range participants {
		if v == comm.label {
			continue
		} //判断是不是自己，不需要发送给自己
		str, _ := proto.Marshal(&msg)
		comm.nodeMap[v].KeySignPhase3And4Chan <- str
	}
}

//第KeySignPhase5A轮消息：发送给所有的节点，包含自己 toNodesLabel = participants
func (comm *LocalCommunicator) SendKeySignPhase5AMessage(msg types.KeySignPhase5AMsg, participants []string) {
	for _, v := range participants {
		str, _ := proto.Marshal(&msg)
		comm.nodeMap[v].KeySignPhase5AChan <- str
	}
}

//第KeySignPhase5B轮消息：发送给所有的节点，包含自己 toNodesLabel = participants
func (comm *LocalCommunicator) SendKeySignPhase5BMessage(msg types.KeySignPhase5BMsg, participants []string) {
	for _, v := range participants {
		str, _ := proto.Marshal(&msg)
		comm.nodeMap[v].KeySignPhase5BChan <- str
	}
}

//第KeySignPhase5C轮消息：发送给所有的节点，包含自己 toNodesLabel = participants
func (comm *LocalCommunicator) SendKeySignPhase5CMessage(msg types.KeySignPhase5CMsg, participants []string) {
	for _, v := range participants {
		str, _ := proto.Marshal(&msg)
		comm.nodeMap[v].KeySignPhase5CChan <- str
	}
}

//第KeySignPhase5D轮消息：发送给所有的节点，包含自己 toNodesLabel = participants
func (comm *LocalCommunicator) SendKeySignPhase5DMessage(msg types.KeySignPhase5DMsg, participants []string) {
	for _, v := range participants {
		str, _ := proto.Marshal(&msg)
		comm.nodeMap[v].KeySignPhase5DChan <- str
	}
}

//第KeySignPhase5E轮消息：发送给所有的节点，包含自己 toNodesLabel = participants
func (comm *LocalCommunicator) SendKeySignPhase5EMessage(msg types.KeySignPhase5EMsg, participants []string) {
	for _, v := range participants {
		str, _ := proto.Marshal(&msg)
		comm.nodeMap[v].KeySignPhase5EChan <- str
	}
}

func (comm *LocalCommunicator) GetKeyGenPhase1Message() (types.KeyGenPhase1Msg, error) {
	re := &types.KeyGenPhase1Msg{}
	err := proto.Unmarshal(<-comm.nodeMap[comm.label].KeyGenPhase1Chan, re)
	if err != nil {
		fmt.Println(err)
	}
	return *re, nil
}

func (comm *LocalCommunicator) GetKeyGenPhase2Message() (types.KeyGenPhase2Msg, error) {
	re := &types.KeyGenPhase2Msg{}
	err := proto.Unmarshal(<-comm.nodeMap[comm.label].KeyGenPhase2Chan, re)
	if err != nil {
		fmt.Println(err)
	}
	return *re, nil
}

func (comm *LocalCommunicator) GetKeyGenPhase3Message() (types.KeyGenPhase3Msg, error) {
	re := &types.KeyGenPhase3Msg{}
	err := proto.Unmarshal(<-comm.nodeMap[comm.label].KeyGenPhase3Chan, re)
	if err != nil {
		fmt.Println(err)
	}
	return *re, nil
}

func (comm *LocalCommunicator) GetKeySignPhase1Message() (types.KeySignPhase1Msg, error) {
	re := &types.KeySignPhase1Msg{}
	err := proto.Unmarshal(<-comm.nodeMap[comm.label].KeySignPhase1Chan, re)
	if err != nil {
		fmt.Println(err)
	}
	return *re, nil
}

func (comm *LocalCommunicator) GetKeySignPhase2Message() (types.KeySignPhase2Msg, error) {
	re := &types.KeySignPhase2Msg{}
	err := proto.Unmarshal(<-comm.nodeMap[comm.label].KeySignPhase2Chan, re)
	if err != nil {
		fmt.Println(err)
	}
	return *re, nil
}

func (comm *LocalCommunicator) GetKeySignPhase3And4Message() (types.KeySignPhase3And4Msg, error) {
	re := &types.KeySignPhase3And4Msg{}
	err := proto.Unmarshal(<-comm.nodeMap[comm.label].KeySignPhase3And4Chan, re)
	if err != nil {
		fmt.Println(err)
	}
	return *re, nil
}

func (comm *LocalCommunicator) GetKeySignPhase5AMessage() (types.KeySignPhase5AMsg, error) {
	re := &types.KeySignPhase5AMsg{}
	err := proto.Unmarshal(<-comm.nodeMap[comm.label].KeySignPhase5AChan, re)
	if err != nil {
		fmt.Println(err)
	}
	return *re, nil
}

func (comm *LocalCommunicator) GetKeySignPhase5BMessage() (types.KeySignPhase5BMsg, error) {
	re := &types.KeySignPhase5BMsg{}
	err := proto.Unmarshal(<-comm.nodeMap[comm.label].KeySignPhase5BChan, re)
	if err != nil {
		fmt.Println(err)
	}
	return *re, nil
}

func (comm *LocalCommunicator) GetKeySignPhase5CMessage() (types.KeySignPhase5CMsg, error) {
	re := &types.KeySignPhase5CMsg{}
	err := proto.Unmarshal(<-comm.nodeMap[comm.label].KeySignPhase5CChan, re)
	if err != nil {
		fmt.Println(err)
	}
	return *re, nil
}

func (comm *LocalCommunicator) GetKeySignPhase5DMessage() (types.KeySignPhase5DMsg, error) {
	re := &types.KeySignPhase5DMsg{}
	err := proto.Unmarshal(<-comm.nodeMap[comm.label].KeySignPhase5DChan, re)
	if err != nil {
		fmt.Println(err)
	}
	return *re, nil
}

func (comm *LocalCommunicator) GetKeySignPhase5EMessage() (types.KeySignPhase5EMsg, error) {
	re := &types.KeySignPhase5EMsg{}
	err := proto.Unmarshal(<-comm.nodeMap[comm.label].KeySignPhase5EChan, re)
	if err != nil {
		fmt.Println(err)
	}
	return *re, nil
}

type ChanNode struct {
	KeyGenPhase1Chan      chan []byte
	KeyGenPhase2Chan      chan []byte
	KeyGenPhase3Chan      chan []byte
	KeySignPhase1Chan     chan []byte
	KeySignPhase2Chan     chan []byte
	KeySignPhase3And4Chan chan []byte
	KeySignPhase5AChan    chan []byte
	KeySignPhase5BChan    chan []byte
	KeySignPhase5CChan    chan []byte
	KeySignPhase5DChan    chan []byte
	KeySignPhase5EChan    chan []byte
}

func NewChanNode(n, p int) *ChanNode {
	return &ChanNode{
		KeyGenPhase1Chan:      make(chan []byte, n),
		KeyGenPhase2Chan:      make(chan []byte, n),
		KeyGenPhase3Chan:      make(chan []byte, n),
		KeySignPhase1Chan:     make(chan []byte, p-1),
		KeySignPhase2Chan:     make(chan []byte, p),
		KeySignPhase3And4Chan: make(chan []byte, p-1),
		KeySignPhase5AChan:    make(chan []byte, p),
		KeySignPhase5BChan:    make(chan []byte, p),
		KeySignPhase5CChan:    make(chan []byte, p),
		KeySignPhase5DChan:    make(chan []byte, p),
		KeySignPhase5EChan:    make(chan []byte, p),
	}
}
