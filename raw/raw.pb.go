// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.26.0
// 	protoc        v3.21.11
// source: raw/raw.proto

package raw

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

// 簽名元信息
type Metadata struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// 簽名使用的 hash 算法名稱
	Hash string `protobuf:"bytes,1,opt,name=hash,proto3" json:"hash,omitempty"`
	// 使用此公鑰 驗證簽名，如果沒有表示它是自簽名的
	Parent []byte `protobuf:"bytes,2,opt,name=parent,proto3" json:"parent,omitempty"`
	// 公鑰，驗證它簽名的數據是否有效
	PublicKey []byte `protobuf:"bytes,3,opt,name=publicKey,proto3" json:"publicKey,omitempty"`
	// unix 表示此簽名有效起始時間，<1 則表示沒有此限制
	Afrer int64 `protobuf:"varint,4,opt,name=afrer,proto3" json:"afrer,omitempty"`
	// unix 表示此簽名有效截止時間，<1 則表示沒有此限制
	Before int64 `protobuf:"varint,5,opt,name=before,proto3" json:"before,omitempty"`
	// 可選的 國家名稱
	Country string `protobuf:"bytes,6,opt,name=country,proto3" json:"country,omitempty"`
	// 可選的 /州 名稱
	State string `protobuf:"bytes,7,opt,name=state,proto3" json:"state,omitempty"`
	// 可選的 地點或城市名稱
	Locality string `protobuf:"bytes,8,opt,name=locality,proto3" json:"locality,omitempty"`
	// 可選的 組織或公司名稱
	Organization string `protobuf:"bytes,9,opt,name=organization,proto3" json:"organization,omitempty"`
	// 可選的 組織單位或公司部門
	Organizational string `protobuf:"bytes,10,opt,name=organizational,proto3" json:"organizational,omitempty"`
	// 可選的 被簽名的附帶內容
	Content []byte `protobuf:"bytes,11,opt,name=content,proto3" json:"content,omitempty"`
}

func (x *Metadata) Reset() {
	*x = Metadata{}
	if protoimpl.UnsafeEnabled {
		mi := &file_raw_raw_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Metadata) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Metadata) ProtoMessage() {}

func (x *Metadata) ProtoReflect() protoreflect.Message {
	mi := &file_raw_raw_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Metadata.ProtoReflect.Descriptor instead.
func (*Metadata) Descriptor() ([]byte, []int) {
	return file_raw_raw_proto_rawDescGZIP(), []int{0}
}

func (x *Metadata) GetHash() string {
	if x != nil {
		return x.Hash
	}
	return ""
}

func (x *Metadata) GetParent() []byte {
	if x != nil {
		return x.Parent
	}
	return nil
}

func (x *Metadata) GetPublicKey() []byte {
	if x != nil {
		return x.PublicKey
	}
	return nil
}

func (x *Metadata) GetAfrer() int64 {
	if x != nil {
		return x.Afrer
	}
	return 0
}

func (x *Metadata) GetBefore() int64 {
	if x != nil {
		return x.Before
	}
	return 0
}

func (x *Metadata) GetCountry() string {
	if x != nil {
		return x.Country
	}
	return ""
}

func (x *Metadata) GetState() string {
	if x != nil {
		return x.State
	}
	return ""
}

func (x *Metadata) GetLocality() string {
	if x != nil {
		return x.Locality
	}
	return ""
}

func (x *Metadata) GetOrganization() string {
	if x != nil {
		return x.Organization
	}
	return ""
}

func (x *Metadata) GetOrganizational() string {
	if x != nil {
		return x.Organizational
	}
	return ""
}

func (x *Metadata) GetContent() []byte {
	if x != nil {
		return x.Content
	}
	return nil
}

// 公鑰用於驗證簽名
type PublicKey struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// 元信息
	Metadata []byte `protobuf:"bytes,1,opt,name=metadata,proto3" json:"metadata,omitempty"`
	// 本身的簽名用於驗證自身有效
	// * 對於自己簽名的使用 metadata -> hash+publicKey 驗證
	// * 否則使用 metadata -> hash+parent 進行驗證
	Signature []byte `protobuf:"bytes,2,opt,name=signature,proto3" json:"signature,omitempty"`
}

func (x *PublicKey) Reset() {
	*x = PublicKey{}
	if protoimpl.UnsafeEnabled {
		mi := &file_raw_raw_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *PublicKey) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*PublicKey) ProtoMessage() {}

func (x *PublicKey) ProtoReflect() protoreflect.Message {
	mi := &file_raw_raw_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use PublicKey.ProtoReflect.Descriptor instead.
func (*PublicKey) Descriptor() ([]byte, []int) {
	return file_raw_raw_proto_rawDescGZIP(), []int{1}
}

func (x *PublicKey) GetMetadata() []byte {
	if x != nil {
		return x.Metadata
	}
	return nil
}

func (x *PublicKey) GetSignature() []byte {
	if x != nil {
		return x.Signature
	}
	return nil
}

// 公鑰鏈，用於回溯簽發源
type PublicChain struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// 這個鏈條是由 誰簽發的，沒有則表示自己簽名的
	Parent []byte `protobuf:"bytes,1,opt,name=parent,proto3" json:"parent,omitempty"`
	// 公鑰用於驗證簽名
	PublicKey *PublicKey `protobuf:"bytes,2,opt,name=publicKey,proto3" json:"publicKey,omitempty"`
}

func (x *PublicChain) Reset() {
	*x = PublicChain{}
	if protoimpl.UnsafeEnabled {
		mi := &file_raw_raw_proto_msgTypes[2]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *PublicChain) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*PublicChain) ProtoMessage() {}

func (x *PublicChain) ProtoReflect() protoreflect.Message {
	mi := &file_raw_raw_proto_msgTypes[2]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use PublicChain.ProtoReflect.Descriptor instead.
func (*PublicChain) Descriptor() ([]byte, []int) {
	return file_raw_raw_proto_rawDescGZIP(), []int{2}
}

func (x *PublicChain) GetParent() []byte {
	if x != nil {
		return x.Parent
	}
	return nil
}

func (x *PublicChain) GetPublicKey() *PublicKey {
	if x != nil {
		return x.PublicKey
	}
	return nil
}

// 私鑰鏈，用於簽名
type PrivateChain struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	PublicChain []byte `protobuf:"bytes,1,opt,name=publicChain,proto3" json:"publicChain,omitempty"`
	// 私鑰用於簽名
	PrivateKey []byte `protobuf:"bytes,2,opt,name=privateKey,proto3" json:"privateKey,omitempty"`
}

func (x *PrivateChain) Reset() {
	*x = PrivateChain{}
	if protoimpl.UnsafeEnabled {
		mi := &file_raw_raw_proto_msgTypes[3]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *PrivateChain) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*PrivateChain) ProtoMessage() {}

func (x *PrivateChain) ProtoReflect() protoreflect.Message {
	mi := &file_raw_raw_proto_msgTypes[3]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use PrivateChain.ProtoReflect.Descriptor instead.
func (*PrivateChain) Descriptor() ([]byte, []int) {
	return file_raw_raw_proto_rawDescGZIP(), []int{3}
}

func (x *PrivateChain) GetPublicChain() []byte {
	if x != nil {
		return x.PublicChain
	}
	return nil
}

func (x *PrivateChain) GetPrivateKey() []byte {
	if x != nil {
		return x.PrivateKey
	}
	return nil
}

var File_raw_raw_proto protoreflect.FileDescriptor

var file_raw_raw_proto_rawDesc = []byte{
	0x0a, 0x0d, 0x72, 0x61, 0x77, 0x2f, 0x72, 0x61, 0x77, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x22,
	0xb4, 0x02, 0x0a, 0x08, 0x4d, 0x65, 0x74, 0x61, 0x64, 0x61, 0x74, 0x61, 0x12, 0x12, 0x0a, 0x04,
	0x68, 0x61, 0x73, 0x68, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x04, 0x68, 0x61, 0x73, 0x68,
	0x12, 0x16, 0x0a, 0x06, 0x70, 0x61, 0x72, 0x65, 0x6e, 0x74, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0c,
	0x52, 0x06, 0x70, 0x61, 0x72, 0x65, 0x6e, 0x74, 0x12, 0x1c, 0x0a, 0x09, 0x70, 0x75, 0x62, 0x6c,
	0x69, 0x63, 0x4b, 0x65, 0x79, 0x18, 0x03, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x09, 0x70, 0x75, 0x62,
	0x6c, 0x69, 0x63, 0x4b, 0x65, 0x79, 0x12, 0x14, 0x0a, 0x05, 0x61, 0x66, 0x72, 0x65, 0x72, 0x18,
	0x04, 0x20, 0x01, 0x28, 0x03, 0x52, 0x05, 0x61, 0x66, 0x72, 0x65, 0x72, 0x12, 0x16, 0x0a, 0x06,
	0x62, 0x65, 0x66, 0x6f, 0x72, 0x65, 0x18, 0x05, 0x20, 0x01, 0x28, 0x03, 0x52, 0x06, 0x62, 0x65,
	0x66, 0x6f, 0x72, 0x65, 0x12, 0x18, 0x0a, 0x07, 0x63, 0x6f, 0x75, 0x6e, 0x74, 0x72, 0x79, 0x18,
	0x06, 0x20, 0x01, 0x28, 0x09, 0x52, 0x07, 0x63, 0x6f, 0x75, 0x6e, 0x74, 0x72, 0x79, 0x12, 0x14,
	0x0a, 0x05, 0x73, 0x74, 0x61, 0x74, 0x65, 0x18, 0x07, 0x20, 0x01, 0x28, 0x09, 0x52, 0x05, 0x73,
	0x74, 0x61, 0x74, 0x65, 0x12, 0x1a, 0x0a, 0x08, 0x6c, 0x6f, 0x63, 0x61, 0x6c, 0x69, 0x74, 0x79,
	0x18, 0x08, 0x20, 0x01, 0x28, 0x09, 0x52, 0x08, 0x6c, 0x6f, 0x63, 0x61, 0x6c, 0x69, 0x74, 0x79,
	0x12, 0x22, 0x0a, 0x0c, 0x6f, 0x72, 0x67, 0x61, 0x6e, 0x69, 0x7a, 0x61, 0x74, 0x69, 0x6f, 0x6e,
	0x18, 0x09, 0x20, 0x01, 0x28, 0x09, 0x52, 0x0c, 0x6f, 0x72, 0x67, 0x61, 0x6e, 0x69, 0x7a, 0x61,
	0x74, 0x69, 0x6f, 0x6e, 0x12, 0x26, 0x0a, 0x0e, 0x6f, 0x72, 0x67, 0x61, 0x6e, 0x69, 0x7a, 0x61,
	0x74, 0x69, 0x6f, 0x6e, 0x61, 0x6c, 0x18, 0x0a, 0x20, 0x01, 0x28, 0x09, 0x52, 0x0e, 0x6f, 0x72,
	0x67, 0x61, 0x6e, 0x69, 0x7a, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x61, 0x6c, 0x12, 0x18, 0x0a, 0x07,
	0x63, 0x6f, 0x6e, 0x74, 0x65, 0x6e, 0x74, 0x18, 0x0b, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x07, 0x63,
	0x6f, 0x6e, 0x74, 0x65, 0x6e, 0x74, 0x22, 0x45, 0x0a, 0x09, 0x50, 0x75, 0x62, 0x6c, 0x69, 0x63,
	0x4b, 0x65, 0x79, 0x12, 0x1a, 0x0a, 0x08, 0x6d, 0x65, 0x74, 0x61, 0x64, 0x61, 0x74, 0x61, 0x18,
	0x01, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x08, 0x6d, 0x65, 0x74, 0x61, 0x64, 0x61, 0x74, 0x61, 0x12,
	0x1c, 0x0a, 0x09, 0x73, 0x69, 0x67, 0x6e, 0x61, 0x74, 0x75, 0x72, 0x65, 0x18, 0x02, 0x20, 0x01,
	0x28, 0x0c, 0x52, 0x09, 0x73, 0x69, 0x67, 0x6e, 0x61, 0x74, 0x75, 0x72, 0x65, 0x22, 0x4f, 0x0a,
	0x0b, 0x50, 0x75, 0x62, 0x6c, 0x69, 0x63, 0x43, 0x68, 0x61, 0x69, 0x6e, 0x12, 0x16, 0x0a, 0x06,
	0x70, 0x61, 0x72, 0x65, 0x6e, 0x74, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x06, 0x70, 0x61,
	0x72, 0x65, 0x6e, 0x74, 0x12, 0x28, 0x0a, 0x09, 0x70, 0x75, 0x62, 0x6c, 0x69, 0x63, 0x4b, 0x65,
	0x79, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x0a, 0x2e, 0x50, 0x75, 0x62, 0x6c, 0x69, 0x63,
	0x4b, 0x65, 0x79, 0x52, 0x09, 0x70, 0x75, 0x62, 0x6c, 0x69, 0x63, 0x4b, 0x65, 0x79, 0x22, 0x50,
	0x0a, 0x0c, 0x50, 0x72, 0x69, 0x76, 0x61, 0x74, 0x65, 0x43, 0x68, 0x61, 0x69, 0x6e, 0x12, 0x20,
	0x0a, 0x0b, 0x70, 0x75, 0x62, 0x6c, 0x69, 0x63, 0x43, 0x68, 0x61, 0x69, 0x6e, 0x18, 0x01, 0x20,
	0x01, 0x28, 0x0c, 0x52, 0x0b, 0x70, 0x75, 0x62, 0x6c, 0x69, 0x63, 0x43, 0x68, 0x61, 0x69, 0x6e,
	0x12, 0x1e, 0x0a, 0x0a, 0x70, 0x72, 0x69, 0x76, 0x61, 0x74, 0x65, 0x4b, 0x65, 0x79, 0x18, 0x02,
	0x20, 0x01, 0x28, 0x0c, 0x52, 0x0a, 0x70, 0x72, 0x69, 0x76, 0x61, 0x74, 0x65, 0x4b, 0x65, 0x79,
	0x42, 0x20, 0x5a, 0x1e, 0x67, 0x69, 0x74, 0x68, 0x75, 0x62, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x7a,
	0x75, 0x69, 0x77, 0x75, 0x63, 0x68, 0x61, 0x6e, 0x67, 0x2f, 0x73, 0x65, 0x61, 0x6c, 0x2f, 0x72,
	0x61, 0x77, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_raw_raw_proto_rawDescOnce sync.Once
	file_raw_raw_proto_rawDescData = file_raw_raw_proto_rawDesc
)

func file_raw_raw_proto_rawDescGZIP() []byte {
	file_raw_raw_proto_rawDescOnce.Do(func() {
		file_raw_raw_proto_rawDescData = protoimpl.X.CompressGZIP(file_raw_raw_proto_rawDescData)
	})
	return file_raw_raw_proto_rawDescData
}

var file_raw_raw_proto_msgTypes = make([]protoimpl.MessageInfo, 4)
var file_raw_raw_proto_goTypes = []interface{}{
	(*Metadata)(nil),     // 0: Metadata
	(*PublicKey)(nil),    // 1: PublicKey
	(*PublicChain)(nil),  // 2: PublicChain
	(*PrivateChain)(nil), // 3: PrivateChain
}
var file_raw_raw_proto_depIdxs = []int32{
	1, // 0: PublicChain.publicKey:type_name -> PublicKey
	1, // [1:1] is the sub-list for method output_type
	1, // [1:1] is the sub-list for method input_type
	1, // [1:1] is the sub-list for extension type_name
	1, // [1:1] is the sub-list for extension extendee
	0, // [0:1] is the sub-list for field type_name
}

func init() { file_raw_raw_proto_init() }
func file_raw_raw_proto_init() {
	if File_raw_raw_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_raw_raw_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Metadata); i {
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
		file_raw_raw_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*PublicKey); i {
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
		file_raw_raw_proto_msgTypes[2].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*PublicChain); i {
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
		file_raw_raw_proto_msgTypes[3].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*PrivateChain); i {
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
			RawDescriptor: file_raw_raw_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   4,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_raw_raw_proto_goTypes,
		DependencyIndexes: file_raw_raw_proto_depIdxs,
		MessageInfos:      file_raw_raw_proto_msgTypes,
	}.Build()
	File_raw_raw_proto = out.File
	file_raw_raw_proto_rawDesc = nil
	file_raw_raw_proto_goTypes = nil
	file_raw_raw_proto_depIdxs = nil
}
