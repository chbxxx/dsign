// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.26.0
// 	protoc        v3.17.3
// source: edtypes.proto

package types

import (
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	reflect "reflect"
	sync "sync"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

type EdKeyGenPhase1Msg struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	LabelFrom         string   `protobuf:"bytes,1,opt,name=label_from,json=labelFrom,proto3" json:"label_from,omitempty"`                             //发送该消息的节点下标
	PubKeyCommit      []byte   `protobuf:"bytes,2,opt,name=pub_key_commit,json=pubKeyCommit,proto3" json:"pub_key_commit,omitempty"`                  //公钥commit
	CofCommit         [][]byte `protobuf:"bytes,3,rep,name=cof_commit,json=cofCommit,proto3" json:"cof_commit,omitempty"`                             //Shamir系数commit
	ShamirSharePubKey []byte   `protobuf:"bytes,4,opt,name=shamir_share_pub_key,json=shamirSharePubKey,proto3" json:"shamir_share_pub_key,omitempty"` //点对点加密Share用的公钥
}

func (x *EdKeyGenPhase1Msg) Reset() {
	*x = EdKeyGenPhase1Msg{}
	if protoimpl.UnsafeEnabled {
		mi := &file_edtypes_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *EdKeyGenPhase1Msg) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*EdKeyGenPhase1Msg) ProtoMessage() {}

func (x *EdKeyGenPhase1Msg) ProtoReflect() protoreflect.Message {
	mi := &file_edtypes_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use EdKeyGenPhase1Msg.ProtoReflect.Descriptor instead.
func (*EdKeyGenPhase1Msg) Descriptor() ([]byte, []int) {
	return file_edtypes_proto_rawDescGZIP(), []int{0}
}

func (x *EdKeyGenPhase1Msg) GetLabelFrom() string {
	if x != nil {
		return x.LabelFrom
	}
	return ""
}

func (x *EdKeyGenPhase1Msg) GetPubKeyCommit() []byte {
	if x != nil {
		return x.PubKeyCommit
	}
	return nil
}

func (x *EdKeyGenPhase1Msg) GetCofCommit() [][]byte {
	if x != nil {
		return x.CofCommit
	}
	return nil
}

func (x *EdKeyGenPhase1Msg) GetShamirSharePubKey() []byte {
	if x != nil {
		return x.ShamirSharePubKey
	}
	return nil
}

type EdKeyGenPhase2Msg struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	LabelFrom   string     `protobuf:"bytes,1,opt,name=label_from,json=labelFrom,proto3" json:"label_from,omitempty"`       //发送该消息的节点下标
	LabelTo     string     `protobuf:"bytes,2,opt,name=label_to,json=labelTo,proto3" json:"label_to,omitempty"`             //这个要记录发送目标，其他人才好从里面取出来属于自己的信息，用自己的私钥解密。
	Share       *EdShareXY `protobuf:"bytes,3,opt,name=share,proto3" json:"share,omitempty"`                                //加密过后的自己的密钥分片中发给别人保存的部分。
	PubKey      []byte     `protobuf:"bytes,4,opt,name=pub_key,json=pubKey,proto3" json:"pub_key,omitempty"`                //自己生成出来的私钥分片的
	BlindFactor []byte     `protobuf:"bytes,5,opt,name=blind_factor,json=blindFactor,proto3" json:"blind_factor,omitempty"` //给出我自己的pubkey blind_factor
}

func (x *EdKeyGenPhase2Msg) Reset() {
	*x = EdKeyGenPhase2Msg{}
	if protoimpl.UnsafeEnabled {
		mi := &file_edtypes_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *EdKeyGenPhase2Msg) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*EdKeyGenPhase2Msg) ProtoMessage() {}

func (x *EdKeyGenPhase2Msg) ProtoReflect() protoreflect.Message {
	mi := &file_edtypes_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use EdKeyGenPhase2Msg.ProtoReflect.Descriptor instead.
func (*EdKeyGenPhase2Msg) Descriptor() ([]byte, []int) {
	return file_edtypes_proto_rawDescGZIP(), []int{1}
}

func (x *EdKeyGenPhase2Msg) GetLabelFrom() string {
	if x != nil {
		return x.LabelFrom
	}
	return ""
}

func (x *EdKeyGenPhase2Msg) GetLabelTo() string {
	if x != nil {
		return x.LabelTo
	}
	return ""
}

func (x *EdKeyGenPhase2Msg) GetShare() *EdShareXY {
	if x != nil {
		return x.Share
	}
	return nil
}

func (x *EdKeyGenPhase2Msg) GetPubKey() []byte {
	if x != nil {
		return x.PubKey
	}
	return nil
}

func (x *EdKeyGenPhase2Msg) GetBlindFactor() []byte {
	if x != nil {
		return x.BlindFactor
	}
	return nil
}

type EdKeyGenPhase3Msg struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	LabelFrom string              `protobuf:"bytes,1,opt,name=label_from,json=labelFrom,proto3" json:"label_from,omitempty"`
	ShamirPub []byte              `protobuf:"bytes,2,opt,name=shamir_pub,json=shamirPub,proto3" json:"shamir_pub,omitempty"`
	Proof     *KeyGenSchnorrProof `protobuf:"bytes,3,opt,name=proof,proto3" json:"proof,omitempty"`
}

func (x *EdKeyGenPhase3Msg) Reset() {
	*x = EdKeyGenPhase3Msg{}
	if protoimpl.UnsafeEnabled {
		mi := &file_edtypes_proto_msgTypes[2]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *EdKeyGenPhase3Msg) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*EdKeyGenPhase3Msg) ProtoMessage() {}

func (x *EdKeyGenPhase3Msg) ProtoReflect() protoreflect.Message {
	mi := &file_edtypes_proto_msgTypes[2]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use EdKeyGenPhase3Msg.ProtoReflect.Descriptor instead.
func (*EdKeyGenPhase3Msg) Descriptor() ([]byte, []int) {
	return file_edtypes_proto_rawDescGZIP(), []int{2}
}

func (x *EdKeyGenPhase3Msg) GetLabelFrom() string {
	if x != nil {
		return x.LabelFrom
	}
	return ""
}

func (x *EdKeyGenPhase3Msg) GetShamirPub() []byte {
	if x != nil {
		return x.ShamirPub
	}
	return nil
}

func (x *EdKeyGenPhase3Msg) GetProof() *KeyGenSchnorrProof {
	if x != nil {
		return x.Proof
	}
	return nil
}

type KeyGenSchnorrProof struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	PubKey []byte `protobuf:"bytes,1,opt,name=pub_key,json=pubKey,proto3" json:"pub_key,omitempty"`
	Num    []byte `protobuf:"bytes,2,opt,name=num,proto3" json:"num,omitempty"`
}

func (x *KeyGenSchnorrProof) Reset() {
	*x = KeyGenSchnorrProof{}
	if protoimpl.UnsafeEnabled {
		mi := &file_edtypes_proto_msgTypes[3]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *KeyGenSchnorrProof) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*KeyGenSchnorrProof) ProtoMessage() {}

func (x *KeyGenSchnorrProof) ProtoReflect() protoreflect.Message {
	mi := &file_edtypes_proto_msgTypes[3]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use KeyGenSchnorrProof.ProtoReflect.Descriptor instead.
func (*KeyGenSchnorrProof) Descriptor() ([]byte, []int) {
	return file_edtypes_proto_rawDescGZIP(), []int{3}
}

func (x *KeyGenSchnorrProof) GetPubKey() []byte {
	if x != nil {
		return x.PubKey
	}
	return nil
}

func (x *KeyGenSchnorrProof) GetNum() []byte {
	if x != nil {
		return x.Num
	}
	return nil
}

type EdKeySignPhase1Msg struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	LabelFrom string `protobuf:"bytes,1,opt,name=label_from,json=labelFrom,proto3" json:"label_from,omitempty"` //发送该消息的节点下标
	ExtendedR []byte `protobuf:"bytes,2,opt,name=extendedR,proto3" json:"extendedR,omitempty"`                  //该节点的extendedR
	CommitR   []byte `protobuf:"bytes,3,opt,name=commitR,proto3" json:"commitR,omitempty"`
}

func (x *EdKeySignPhase1Msg) Reset() {
	*x = EdKeySignPhase1Msg{}
	if protoimpl.UnsafeEnabled {
		mi := &file_edtypes_proto_msgTypes[4]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *EdKeySignPhase1Msg) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*EdKeySignPhase1Msg) ProtoMessage() {}

func (x *EdKeySignPhase1Msg) ProtoReflect() protoreflect.Message {
	mi := &file_edtypes_proto_msgTypes[4]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use EdKeySignPhase1Msg.ProtoReflect.Descriptor instead.
func (*EdKeySignPhase1Msg) Descriptor() ([]byte, []int) {
	return file_edtypes_proto_rawDescGZIP(), []int{4}
}

func (x *EdKeySignPhase1Msg) GetLabelFrom() string {
	if x != nil {
		return x.LabelFrom
	}
	return ""
}

func (x *EdKeySignPhase1Msg) GetExtendedR() []byte {
	if x != nil {
		return x.ExtendedR
	}
	return nil
}

func (x *EdKeySignPhase1Msg) GetCommitR() []byte {
	if x != nil {
		return x.CommitR
	}
	return nil
}

type EdKeySignPhase2Msg struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	LabelFrom   string `protobuf:"bytes,1,opt,name=label_from,json=labelFrom,proto3" json:"label_from,omitempty"` //发送该消息的节点下标
	ProofAlphaX []byte `protobuf:"bytes,2,opt,name=proof_alpha_x,json=proofAlphaX,proto3" json:"proof_alpha_x,omitempty"`
	ProofAlphaY []byte `protobuf:"bytes,3,opt,name=proof_alpha_y,json=proofAlphaY,proto3" json:"proof_alpha_y,omitempty"`
	ProofT      []byte `protobuf:"bytes,4,opt,name=proof_t,json=proofT,proto3" json:"proof_t,omitempty"`
}

func (x *EdKeySignPhase2Msg) Reset() {
	*x = EdKeySignPhase2Msg{}
	if protoimpl.UnsafeEnabled {
		mi := &file_edtypes_proto_msgTypes[5]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *EdKeySignPhase2Msg) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*EdKeySignPhase2Msg) ProtoMessage() {}

func (x *EdKeySignPhase2Msg) ProtoReflect() protoreflect.Message {
	mi := &file_edtypes_proto_msgTypes[5]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use EdKeySignPhase2Msg.ProtoReflect.Descriptor instead.
func (*EdKeySignPhase2Msg) Descriptor() ([]byte, []int) {
	return file_edtypes_proto_rawDescGZIP(), []int{5}
}

func (x *EdKeySignPhase2Msg) GetLabelFrom() string {
	if x != nil {
		return x.LabelFrom
	}
	return ""
}

func (x *EdKeySignPhase2Msg) GetProofAlphaX() []byte {
	if x != nil {
		return x.ProofAlphaX
	}
	return nil
}

func (x *EdKeySignPhase2Msg) GetProofAlphaY() []byte {
	if x != nil {
		return x.ProofAlphaY
	}
	return nil
}

func (x *EdKeySignPhase2Msg) GetProofT() []byte {
	if x != nil {
		return x.ProofT
	}
	return nil
}

type EdKeySignPhase3Msg struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	LabelFrom  string `protobuf:"bytes,1,opt,name=label_from,json=labelFrom,proto3" json:"label_from,omitempty"` //发送该消息的节点下标
	SigPartial []byte `protobuf:"bytes,2,opt,name=sig_partial,json=sigPartial,proto3" json:"sig_partial,omitempty"`
}

func (x *EdKeySignPhase3Msg) Reset() {
	*x = EdKeySignPhase3Msg{}
	if protoimpl.UnsafeEnabled {
		mi := &file_edtypes_proto_msgTypes[6]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *EdKeySignPhase3Msg) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*EdKeySignPhase3Msg) ProtoMessage() {}

func (x *EdKeySignPhase3Msg) ProtoReflect() protoreflect.Message {
	mi := &file_edtypes_proto_msgTypes[6]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use EdKeySignPhase3Msg.ProtoReflect.Descriptor instead.
func (*EdKeySignPhase3Msg) Descriptor() ([]byte, []int) {
	return file_edtypes_proto_rawDescGZIP(), []int{6}
}

func (x *EdKeySignPhase3Msg) GetLabelFrom() string {
	if x != nil {
		return x.LabelFrom
	}
	return ""
}

func (x *EdKeySignPhase3Msg) GetSigPartial() []byte {
	if x != nil {
		return x.SigPartial
	}
	return nil
}

type EdKeyGenData struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Label         string            `protobuf:"bytes,1,opt,name=label,proto3" json:"label,omitempty"`
	SignThreshold uint64            `protobuf:"varint,2,opt,name=sign_threshold,json=signThreshold,proto3" json:"sign_threshold,omitempty"`
	Paras         []*EdParameterMap `protobuf:"bytes,3,rep,name=paras,proto3" json:"paras,omitempty"`
	PubKeySum     []byte            `protobuf:"bytes,4,opt,name=pub_key_sum,json=pubKeySum,proto3" json:"pub_key_sum,omitempty"`
	KeyNodes      []string          `protobuf:"bytes,5,rep,name=key_nodes,json=keyNodes,proto3" json:"key_nodes,omitempty"`
}

func (x *EdKeyGenData) Reset() {
	*x = EdKeyGenData{}
	if protoimpl.UnsafeEnabled {
		mi := &file_edtypes_proto_msgTypes[7]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *EdKeyGenData) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*EdKeyGenData) ProtoMessage() {}

func (x *EdKeyGenData) ProtoReflect() protoreflect.Message {
	mi := &file_edtypes_proto_msgTypes[7]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use EdKeyGenData.ProtoReflect.Descriptor instead.
func (*EdKeyGenData) Descriptor() ([]byte, []int) {
	return file_edtypes_proto_rawDescGZIP(), []int{7}
}

func (x *EdKeyGenData) GetLabel() string {
	if x != nil {
		return x.Label
	}
	return ""
}

func (x *EdKeyGenData) GetSignThreshold() uint64 {
	if x != nil {
		return x.SignThreshold
	}
	return 0
}

func (x *EdKeyGenData) GetParas() []*EdParameterMap {
	if x != nil {
		return x.Paras
	}
	return nil
}

func (x *EdKeyGenData) GetPubKeySum() []byte {
	if x != nil {
		return x.PubKeySum
	}
	return nil
}

func (x *EdKeyGenData) GetKeyNodes() []string {
	if x != nil {
		return x.KeyNodes
	}
	return nil
}

type EdParameterMap struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Label string     `protobuf:"bytes,1,opt,name=label,proto3" json:"label,omitempty"`
	Share *EdShareXY `protobuf:"bytes,2,opt,name=share,proto3" json:"share,omitempty"`
}

func (x *EdParameterMap) Reset() {
	*x = EdParameterMap{}
	if protoimpl.UnsafeEnabled {
		mi := &file_edtypes_proto_msgTypes[8]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *EdParameterMap) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*EdParameterMap) ProtoMessage() {}

func (x *EdParameterMap) ProtoReflect() protoreflect.Message {
	mi := &file_edtypes_proto_msgTypes[8]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use EdParameterMap.ProtoReflect.Descriptor instead.
func (*EdParameterMap) Descriptor() ([]byte, []int) {
	return file_edtypes_proto_rawDescGZIP(), []int{8}
}

func (x *EdParameterMap) GetLabel() string {
	if x != nil {
		return x.Label
	}
	return ""
}

func (x *EdParameterMap) GetShare() *EdShareXY {
	if x != nil {
		return x.Share
	}
	return nil
}

type EdShareXY struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	X []byte `protobuf:"bytes,1,opt,name=x,proto3" json:"x,omitempty"`
	Y []byte `protobuf:"bytes,2,opt,name=y,proto3" json:"y,omitempty"`
}

func (x *EdShareXY) Reset() {
	*x = EdShareXY{}
	if protoimpl.UnsafeEnabled {
		mi := &file_edtypes_proto_msgTypes[9]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *EdShareXY) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*EdShareXY) ProtoMessage() {}

func (x *EdShareXY) ProtoReflect() protoreflect.Message {
	mi := &file_edtypes_proto_msgTypes[9]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use EdShareXY.ProtoReflect.Descriptor instead.
func (*EdShareXY) Descriptor() ([]byte, []int) {
	return file_edtypes_proto_rawDescGZIP(), []int{9}
}

func (x *EdShareXY) GetX() []byte {
	if x != nil {
		return x.X
	}
	return nil
}

func (x *EdShareXY) GetY() []byte {
	if x != nil {
		return x.Y
	}
	return nil
}

var File_edtypes_proto protoreflect.FileDescriptor

var file_edtypes_proto_rawDesc = []byte{
	0x0a, 0x0d, 0x65, 0x64, 0x74, 0x79, 0x70, 0x65, 0x73, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12,
	0x05, 0x74, 0x79, 0x70, 0x65, 0x73, 0x22, 0xa8, 0x01, 0x0a, 0x11, 0x45, 0x64, 0x4b, 0x65, 0x79,
	0x47, 0x65, 0x6e, 0x50, 0x68, 0x61, 0x73, 0x65, 0x31, 0x4d, 0x73, 0x67, 0x12, 0x1d, 0x0a, 0x0a,
	0x6c, 0x61, 0x62, 0x65, 0x6c, 0x5f, 0x66, 0x72, 0x6f, 0x6d, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09,
	0x52, 0x09, 0x6c, 0x61, 0x62, 0x65, 0x6c, 0x46, 0x72, 0x6f, 0x6d, 0x12, 0x24, 0x0a, 0x0e, 0x70,
	0x75, 0x62, 0x5f, 0x6b, 0x65, 0x79, 0x5f, 0x63, 0x6f, 0x6d, 0x6d, 0x69, 0x74, 0x18, 0x02, 0x20,
	0x01, 0x28, 0x0c, 0x52, 0x0c, 0x70, 0x75, 0x62, 0x4b, 0x65, 0x79, 0x43, 0x6f, 0x6d, 0x6d, 0x69,
	0x74, 0x12, 0x1d, 0x0a, 0x0a, 0x63, 0x6f, 0x66, 0x5f, 0x63, 0x6f, 0x6d, 0x6d, 0x69, 0x74, 0x18,
	0x03, 0x20, 0x03, 0x28, 0x0c, 0x52, 0x09, 0x63, 0x6f, 0x66, 0x43, 0x6f, 0x6d, 0x6d, 0x69, 0x74,
	0x12, 0x2f, 0x0a, 0x14, 0x73, 0x68, 0x61, 0x6d, 0x69, 0x72, 0x5f, 0x73, 0x68, 0x61, 0x72, 0x65,
	0x5f, 0x70, 0x75, 0x62, 0x5f, 0x6b, 0x65, 0x79, 0x18, 0x04, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x11,
	0x73, 0x68, 0x61, 0x6d, 0x69, 0x72, 0x53, 0x68, 0x61, 0x72, 0x65, 0x50, 0x75, 0x62, 0x4b, 0x65,
	0x79, 0x22, 0xb1, 0x01, 0x0a, 0x11, 0x45, 0x64, 0x4b, 0x65, 0x79, 0x47, 0x65, 0x6e, 0x50, 0x68,
	0x61, 0x73, 0x65, 0x32, 0x4d, 0x73, 0x67, 0x12, 0x1d, 0x0a, 0x0a, 0x6c, 0x61, 0x62, 0x65, 0x6c,
	0x5f, 0x66, 0x72, 0x6f, 0x6d, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x09, 0x6c, 0x61, 0x62,
	0x65, 0x6c, 0x46, 0x72, 0x6f, 0x6d, 0x12, 0x19, 0x0a, 0x08, 0x6c, 0x61, 0x62, 0x65, 0x6c, 0x5f,
	0x74, 0x6f, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x52, 0x07, 0x6c, 0x61, 0x62, 0x65, 0x6c, 0x54,
	0x6f, 0x12, 0x26, 0x0a, 0x05, 0x73, 0x68, 0x61, 0x72, 0x65, 0x18, 0x03, 0x20, 0x01, 0x28, 0x0b,
	0x32, 0x10, 0x2e, 0x74, 0x79, 0x70, 0x65, 0x73, 0x2e, 0x45, 0x64, 0x53, 0x68, 0x61, 0x72, 0x65,
	0x58, 0x59, 0x52, 0x05, 0x73, 0x68, 0x61, 0x72, 0x65, 0x12, 0x17, 0x0a, 0x07, 0x70, 0x75, 0x62,
	0x5f, 0x6b, 0x65, 0x79, 0x18, 0x04, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x06, 0x70, 0x75, 0x62, 0x4b,
	0x65, 0x79, 0x12, 0x21, 0x0a, 0x0c, 0x62, 0x6c, 0x69, 0x6e, 0x64, 0x5f, 0x66, 0x61, 0x63, 0x74,
	0x6f, 0x72, 0x18, 0x05, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x0b, 0x62, 0x6c, 0x69, 0x6e, 0x64, 0x46,
	0x61, 0x63, 0x74, 0x6f, 0x72, 0x22, 0x82, 0x01, 0x0a, 0x11, 0x45, 0x64, 0x4b, 0x65, 0x79, 0x47,
	0x65, 0x6e, 0x50, 0x68, 0x61, 0x73, 0x65, 0x33, 0x4d, 0x73, 0x67, 0x12, 0x1d, 0x0a, 0x0a, 0x6c,
	0x61, 0x62, 0x65, 0x6c, 0x5f, 0x66, 0x72, 0x6f, 0x6d, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52,
	0x09, 0x6c, 0x61, 0x62, 0x65, 0x6c, 0x46, 0x72, 0x6f, 0x6d, 0x12, 0x1d, 0x0a, 0x0a, 0x73, 0x68,
	0x61, 0x6d, 0x69, 0x72, 0x5f, 0x70, 0x75, 0x62, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x09,
	0x73, 0x68, 0x61, 0x6d, 0x69, 0x72, 0x50, 0x75, 0x62, 0x12, 0x2f, 0x0a, 0x05, 0x70, 0x72, 0x6f,
	0x6f, 0x66, 0x18, 0x03, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x19, 0x2e, 0x74, 0x79, 0x70, 0x65, 0x73,
	0x2e, 0x4b, 0x65, 0x79, 0x47, 0x65, 0x6e, 0x53, 0x63, 0x68, 0x6e, 0x6f, 0x72, 0x72, 0x50, 0x72,
	0x6f, 0x6f, 0x66, 0x52, 0x05, 0x70, 0x72, 0x6f, 0x6f, 0x66, 0x22, 0x3f, 0x0a, 0x12, 0x4b, 0x65,
	0x79, 0x47, 0x65, 0x6e, 0x53, 0x63, 0x68, 0x6e, 0x6f, 0x72, 0x72, 0x50, 0x72, 0x6f, 0x6f, 0x66,
	0x12, 0x17, 0x0a, 0x07, 0x70, 0x75, 0x62, 0x5f, 0x6b, 0x65, 0x79, 0x18, 0x01, 0x20, 0x01, 0x28,
	0x0c, 0x52, 0x06, 0x70, 0x75, 0x62, 0x4b, 0x65, 0x79, 0x12, 0x10, 0x0a, 0x03, 0x6e, 0x75, 0x6d,
	0x18, 0x02, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x03, 0x6e, 0x75, 0x6d, 0x22, 0x6b, 0x0a, 0x12, 0x45,
	0x64, 0x4b, 0x65, 0x79, 0x53, 0x69, 0x67, 0x6e, 0x50, 0x68, 0x61, 0x73, 0x65, 0x31, 0x4d, 0x73,
	0x67, 0x12, 0x1d, 0x0a, 0x0a, 0x6c, 0x61, 0x62, 0x65, 0x6c, 0x5f, 0x66, 0x72, 0x6f, 0x6d, 0x18,
	0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x09, 0x6c, 0x61, 0x62, 0x65, 0x6c, 0x46, 0x72, 0x6f, 0x6d,
	0x12, 0x1c, 0x0a, 0x09, 0x65, 0x78, 0x74, 0x65, 0x6e, 0x64, 0x65, 0x64, 0x52, 0x18, 0x02, 0x20,
	0x01, 0x28, 0x0c, 0x52, 0x09, 0x65, 0x78, 0x74, 0x65, 0x6e, 0x64, 0x65, 0x64, 0x52, 0x12, 0x18,
	0x0a, 0x07, 0x63, 0x6f, 0x6d, 0x6d, 0x69, 0x74, 0x52, 0x18, 0x03, 0x20, 0x01, 0x28, 0x0c, 0x52,
	0x07, 0x63, 0x6f, 0x6d, 0x6d, 0x69, 0x74, 0x52, 0x22, 0x94, 0x01, 0x0a, 0x12, 0x45, 0x64, 0x4b,
	0x65, 0x79, 0x53, 0x69, 0x67, 0x6e, 0x50, 0x68, 0x61, 0x73, 0x65, 0x32, 0x4d, 0x73, 0x67, 0x12,
	0x1d, 0x0a, 0x0a, 0x6c, 0x61, 0x62, 0x65, 0x6c, 0x5f, 0x66, 0x72, 0x6f, 0x6d, 0x18, 0x01, 0x20,
	0x01, 0x28, 0x09, 0x52, 0x09, 0x6c, 0x61, 0x62, 0x65, 0x6c, 0x46, 0x72, 0x6f, 0x6d, 0x12, 0x22,
	0x0a, 0x0d, 0x70, 0x72, 0x6f, 0x6f, 0x66, 0x5f, 0x61, 0x6c, 0x70, 0x68, 0x61, 0x5f, 0x78, 0x18,
	0x02, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x0b, 0x70, 0x72, 0x6f, 0x6f, 0x66, 0x41, 0x6c, 0x70, 0x68,
	0x61, 0x58, 0x12, 0x22, 0x0a, 0x0d, 0x70, 0x72, 0x6f, 0x6f, 0x66, 0x5f, 0x61, 0x6c, 0x70, 0x68,
	0x61, 0x5f, 0x79, 0x18, 0x03, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x0b, 0x70, 0x72, 0x6f, 0x6f, 0x66,
	0x41, 0x6c, 0x70, 0x68, 0x61, 0x59, 0x12, 0x17, 0x0a, 0x07, 0x70, 0x72, 0x6f, 0x6f, 0x66, 0x5f,
	0x74, 0x18, 0x04, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x06, 0x70, 0x72, 0x6f, 0x6f, 0x66, 0x54, 0x22,
	0x54, 0x0a, 0x12, 0x45, 0x64, 0x4b, 0x65, 0x79, 0x53, 0x69, 0x67, 0x6e, 0x50, 0x68, 0x61, 0x73,
	0x65, 0x33, 0x4d, 0x73, 0x67, 0x12, 0x1d, 0x0a, 0x0a, 0x6c, 0x61, 0x62, 0x65, 0x6c, 0x5f, 0x66,
	0x72, 0x6f, 0x6d, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x09, 0x6c, 0x61, 0x62, 0x65, 0x6c,
	0x46, 0x72, 0x6f, 0x6d, 0x12, 0x1f, 0x0a, 0x0b, 0x73, 0x69, 0x67, 0x5f, 0x70, 0x61, 0x72, 0x74,
	0x69, 0x61, 0x6c, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x0a, 0x73, 0x69, 0x67, 0x50, 0x61,
	0x72, 0x74, 0x69, 0x61, 0x6c, 0x22, 0xb5, 0x01, 0x0a, 0x0c, 0x45, 0x64, 0x4b, 0x65, 0x79, 0x47,
	0x65, 0x6e, 0x44, 0x61, 0x74, 0x61, 0x12, 0x14, 0x0a, 0x05, 0x6c, 0x61, 0x62, 0x65, 0x6c, 0x18,
	0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x05, 0x6c, 0x61, 0x62, 0x65, 0x6c, 0x12, 0x25, 0x0a, 0x0e,
	0x73, 0x69, 0x67, 0x6e, 0x5f, 0x74, 0x68, 0x72, 0x65, 0x73, 0x68, 0x6f, 0x6c, 0x64, 0x18, 0x02,
	0x20, 0x01, 0x28, 0x04, 0x52, 0x0d, 0x73, 0x69, 0x67, 0x6e, 0x54, 0x68, 0x72, 0x65, 0x73, 0x68,
	0x6f, 0x6c, 0x64, 0x12, 0x2b, 0x0a, 0x05, 0x70, 0x61, 0x72, 0x61, 0x73, 0x18, 0x03, 0x20, 0x03,
	0x28, 0x0b, 0x32, 0x15, 0x2e, 0x74, 0x79, 0x70, 0x65, 0x73, 0x2e, 0x45, 0x64, 0x50, 0x61, 0x72,
	0x61, 0x6d, 0x65, 0x74, 0x65, 0x72, 0x4d, 0x61, 0x70, 0x52, 0x05, 0x70, 0x61, 0x72, 0x61, 0x73,
	0x12, 0x1e, 0x0a, 0x0b, 0x70, 0x75, 0x62, 0x5f, 0x6b, 0x65, 0x79, 0x5f, 0x73, 0x75, 0x6d, 0x18,
	0x04, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x09, 0x70, 0x75, 0x62, 0x4b, 0x65, 0x79, 0x53, 0x75, 0x6d,
	0x12, 0x1b, 0x0a, 0x09, 0x6b, 0x65, 0x79, 0x5f, 0x6e, 0x6f, 0x64, 0x65, 0x73, 0x18, 0x05, 0x20,
	0x03, 0x28, 0x09, 0x52, 0x08, 0x6b, 0x65, 0x79, 0x4e, 0x6f, 0x64, 0x65, 0x73, 0x22, 0x4e, 0x0a,
	0x0e, 0x45, 0x64, 0x50, 0x61, 0x72, 0x61, 0x6d, 0x65, 0x74, 0x65, 0x72, 0x4d, 0x61, 0x70, 0x12,
	0x14, 0x0a, 0x05, 0x6c, 0x61, 0x62, 0x65, 0x6c, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x05,
	0x6c, 0x61, 0x62, 0x65, 0x6c, 0x12, 0x26, 0x0a, 0x05, 0x73, 0x68, 0x61, 0x72, 0x65, 0x18, 0x02,
	0x20, 0x01, 0x28, 0x0b, 0x32, 0x10, 0x2e, 0x74, 0x79, 0x70, 0x65, 0x73, 0x2e, 0x45, 0x64, 0x53,
	0x68, 0x61, 0x72, 0x65, 0x58, 0x59, 0x52, 0x05, 0x73, 0x68, 0x61, 0x72, 0x65, 0x22, 0x27, 0x0a,
	0x09, 0x45, 0x64, 0x53, 0x68, 0x61, 0x72, 0x65, 0x58, 0x59, 0x12, 0x0c, 0x0a, 0x01, 0x78, 0x18,
	0x01, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x01, 0x78, 0x12, 0x0c, 0x0a, 0x01, 0x79, 0x18, 0x02, 0x20,
	0x01, 0x28, 0x0c, 0x52, 0x01, 0x79, 0x42, 0x0a, 0x5a, 0x08, 0x2e, 0x2e, 0x2f, 0x74, 0x79, 0x70,
	0x65, 0x73, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_edtypes_proto_rawDescOnce sync.Once
	file_edtypes_proto_rawDescData = file_edtypes_proto_rawDesc
)

func file_edtypes_proto_rawDescGZIP() []byte {
	file_edtypes_proto_rawDescOnce.Do(func() {
		file_edtypes_proto_rawDescData = protoimpl.X.CompressGZIP(file_edtypes_proto_rawDescData)
	})
	return file_edtypes_proto_rawDescData
}

var file_edtypes_proto_msgTypes = make([]protoimpl.MessageInfo, 10)
var file_edtypes_proto_goTypes = []interface{}{
	(*EdKeyGenPhase1Msg)(nil),  // 0: types.EdKeyGenPhase1Msg
	(*EdKeyGenPhase2Msg)(nil),  // 1: types.EdKeyGenPhase2Msg
	(*EdKeyGenPhase3Msg)(nil),  // 2: types.EdKeyGenPhase3Msg
	(*KeyGenSchnorrProof)(nil), // 3: types.KeyGenSchnorrProof
	(*EdKeySignPhase1Msg)(nil), // 4: types.EdKeySignPhase1Msg
	(*EdKeySignPhase2Msg)(nil), // 5: types.EdKeySignPhase2Msg
	(*EdKeySignPhase3Msg)(nil), // 6: types.EdKeySignPhase3Msg
	(*EdKeyGenData)(nil),       // 7: types.EdKeyGenData
	(*EdParameterMap)(nil),     // 8: types.EdParameterMap
	(*EdShareXY)(nil),          // 9: types.EdShareXY
}
var file_edtypes_proto_depIdxs = []int32{
	9, // 0: types.EdKeyGenPhase2Msg.share:type_name -> types.EdShareXY
	3, // 1: types.EdKeyGenPhase3Msg.proof:type_name -> types.KeyGenSchnorrProof
	8, // 2: types.EdKeyGenData.paras:type_name -> types.EdParameterMap
	9, // 3: types.EdParameterMap.share:type_name -> types.EdShareXY
	4, // [4:4] is the sub-list for method output_type
	4, // [4:4] is the sub-list for method input_type
	4, // [4:4] is the sub-list for extension type_name
	4, // [4:4] is the sub-list for extension extendee
	0, // [0:4] is the sub-list for field type_name
}

func init() { file_edtypes_proto_init() }
func file_edtypes_proto_init() {
	if File_edtypes_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_edtypes_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*EdKeyGenPhase1Msg); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_edtypes_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*EdKeyGenPhase2Msg); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_edtypes_proto_msgTypes[2].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*EdKeyGenPhase3Msg); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_edtypes_proto_msgTypes[3].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*KeyGenSchnorrProof); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_edtypes_proto_msgTypes[4].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*EdKeySignPhase1Msg); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_edtypes_proto_msgTypes[5].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*EdKeySignPhase2Msg); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_edtypes_proto_msgTypes[6].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*EdKeySignPhase3Msg); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_edtypes_proto_msgTypes[7].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*EdKeyGenData); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_edtypes_proto_msgTypes[8].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*EdParameterMap); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_edtypes_proto_msgTypes[9].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*EdShareXY); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_edtypes_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   10,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_edtypes_proto_goTypes,
		DependencyIndexes: file_edtypes_proto_depIdxs,
		MessageInfos:      file_edtypes_proto_msgTypes,
	}.Build()
	File_edtypes_proto = out.File
	file_edtypes_proto_rawDesc = nil
	file_edtypes_proto_goTypes = nil
	file_edtypes_proto_depIdxs = nil
}
