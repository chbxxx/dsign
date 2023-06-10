package communicator

import (
	"fmt"
	"github.com/bluehelix-chain/dsign/types"
	"google.golang.org/protobuf/proto"
)

var _ EdCommunicator = (*LocalEdCommunicator)(nil)

type LocalEdCommunicator struct {
	nodeMap map[string]*EdChanNode
	n       int
	label   string
}

func (l LocalEdCommunicator) SendEdKeySignPhase1Msg(msg types.EdKeySignPhase1Msg) {
	for _, v := range l.nodeMap {

		//fmt.Printf("%s is sending msg: %s \n", l.label, hex.EncodeToString(msg.ShamirSharePubKey))
		bytes, _ := proto.Marshal(&msg) //need &!
		v.KeySignPhase1Chan <- bytes
	}
}

func (l LocalEdCommunicator) GetEdKeySignPhase1Msg() (types.EdKeySignPhase1Msg, error) {
	re := &types.EdKeySignPhase1Msg{}
	err := proto.Unmarshal(<-l.nodeMap[l.label].KeySignPhase1Chan, re)
	//fmt.Printf("%s is getting msg from %s about share pub key is : %s \n", l.label, re.LabelFrom, hex.EncodeToString(re.ShamirSharePubKey))
	if err != nil {
		fmt.Println(err)
	}
	return *re, nil
}

func (l LocalEdCommunicator) SendEdKeySignPhase2Msg(msg types.EdKeySignPhase2Msg) {
	for _, v := range l.nodeMap {

		//fmt.Printf("%s is sending msg: %s \n", l.label, hex.EncodeToString(msg.ShamirSharePubKey))
		bytes, _ := proto.Marshal(&msg) //need &!
		v.KeySignPhase2Chan <- bytes
	}
}

func (l LocalEdCommunicator) GetEdKeySignPhase2Msg() (types.EdKeySignPhase2Msg, error) {
	re := &types.EdKeySignPhase2Msg{}
	err := proto.Unmarshal(<-l.nodeMap[l.label].KeySignPhase2Chan, re)
	//fmt.Printf("%s is getting msg from %s about share pub key is : %s \n", l.label, re.LabelFrom, hex.EncodeToString(re.ShamirSharePubKey))
	if err != nil {
		fmt.Println(err)
	}
	return *re, nil
}

func (l LocalEdCommunicator) SendEdKeySignPhase3Msg(msg types.EdKeySignPhase3Msg) {
	for _, v := range l.nodeMap {

		//fmt.Printf("%s is sending msg: %s \n", l.label, hex.EncodeToString(msg.ShamirSharePubKey))
		bytes, _ := proto.Marshal(&msg) //need &!
		v.KeySignPhase3Chan <- bytes
	}
}

func (l LocalEdCommunicator) GetEdKeySignPhase3Msg() (types.EdKeySignPhase3Msg, error) {
	re := &types.EdKeySignPhase3Msg{}
	err := proto.Unmarshal(<-l.nodeMap[l.label].KeySignPhase3Chan, re)
	//fmt.Printf("%s is getting msg from %s about share pub key is : %s \n", l.label, re.LabelFrom, hex.EncodeToString(re.ShamirSharePubKey))
	if err != nil {
		fmt.Println(err)
	}
	return *re, nil
}

func (l LocalEdCommunicator) SendEdKeyGenPhase1Msg(msg types.EdKeyGenPhase1Msg) {
	for _, v := range l.nodeMap {

		//fmt.Printf("%s is sending msg: %s \n", l.label, hex.EncodeToString(msg.ShamirSharePubKey))
		bytes, _ := proto.Marshal(&msg) //need &!
		v.KeyGenPhase1Chan <- bytes
	}
}

func (l LocalEdCommunicator) SendEdKeyGenPhase2Msg(msg map[string]types.EdKeyGenPhase2Msg) {
	for _, v := range msg {
		v := v
		//fmt.Printf("%s is sending to %s: %s \n", l.label, v.LabelTo, v.String())
		bytes, _ := proto.Marshal(&v)
		l.nodeMap[v.LabelTo].KeyGenPhase2Chan <- bytes
	}

}

func (l LocalEdCommunicator) GetEdKeyGenPhase1Msg() (types.EdKeyGenPhase1Msg, error) {
	re := &types.EdKeyGenPhase1Msg{}
	err := proto.Unmarshal(<-l.nodeMap[l.label].KeyGenPhase1Chan, re)
	//fmt.Printf("%s is getting msg from %s about share pub key is : %s \n", l.label, re.LabelFrom, hex.EncodeToString(re.ShamirSharePubKey))
	if err != nil {
		fmt.Println(err)
	}
	return *re, nil
}

func (l LocalEdCommunicator) GetEdKeyGenPhase2Msg() (types.EdKeyGenPhase2Msg, error) {
	re := &types.EdKeyGenPhase2Msg{}
	err := proto.Unmarshal(<-l.nodeMap[l.label].KeyGenPhase2Chan, re)
	//fmt.Printf("%s is getting msg: %s \n", l.label, re.String())
	if err != nil {
		fmt.Println(err)
	}
	return *re, nil
}

func (l LocalEdCommunicator) GetEdKeyGenPhase3Msg() (types.EdKeyGenPhase3Msg, error) {
	re := &types.EdKeyGenPhase3Msg{}
	err := proto.Unmarshal(<-l.nodeMap[l.label].KeyGenPhase3Chan, re)
	//fmt.Printf("%s is getting msg: %s \n", l.label, re.String())
	if err != nil {
		fmt.Println(err)
	}
	return *re, nil
}

func (l LocalEdCommunicator) SendEdKeyGenPhase3Msg(msg types.EdKeyGenPhase3Msg) {
	for _, v := range l.nodeMap {

		//fmt.Printf("%s is sending msg: %s \n", l.label, hex.EncodeToString(msg.ShamirSharePubKey))
		bytes, _ := proto.Marshal(&msg) //need &!
		v.KeyGenPhase3Chan <- bytes
	}
}

func NewLocalEdCommunicator(nodeMap map[string]*EdChanNode, n int, label string) (l *LocalEdCommunicator) {
	l = &LocalEdCommunicator{}
	l.nodeMap = nodeMap
	l.n = n
	l.label = label
	return l
}

type EdChanNode struct {
	KeyGenPhase1Chan  chan []byte
	KeyGenPhase2Chan  chan []byte
	KeyGenPhase3Chan  chan []byte
	KeySignPhase1Chan chan []byte
	KeySignPhase2Chan chan []byte
	KeySignPhase3Chan chan []byte
}

func NewEdChanNode(n int) *EdChanNode {
	return &EdChanNode{
		KeyGenPhase1Chan:  make(chan []byte, n),
		KeyGenPhase2Chan:  make(chan []byte, n),
		KeyGenPhase3Chan:  make(chan []byte, n),
		KeySignPhase1Chan: make(chan []byte, n),
		KeySignPhase2Chan: make(chan []byte, n),
		KeySignPhase3Chan: make(chan []byte, n),
	}
}
