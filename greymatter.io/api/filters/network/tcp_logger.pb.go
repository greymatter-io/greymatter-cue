// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.25.0
// 	protoc        v3.7.1
// source: source/filters/network/proto/tcp_logger.proto

package proto

import (
	proto "github.com/golang/protobuf/proto"
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

// This is a compile-time assertion that a sufficiently up-to-date version
// of the legacy proto package is being used.
const _ = proto.ProtoPackageIsVersion4

type TcpLoggerConfig struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	WarnWindow        string `protobuf:"bytes,1,opt,name=warnWindow,proto3" json:"warnWindow,omitempty"`
	LogConnect        bool   `protobuf:"varint,2,opt,name=logConnect,proto3" json:"logConnect,omitempty"`
	OmitSSLFailure    bool   `protobuf:"varint,3,opt,name=omitSSLFailure,proto3" json:"omitSSLFailure,omitempty"`
	LogRawTcp         bool   `protobuf:"varint,4,opt,name=logRawTcp,proto3" json:"logRawTcp,omitempty"`
	FailureCheckDelay string `protobuf:"bytes,5,opt,name=failureCheckDelay,proto3" json:"failureCheckDelay,omitempty"`
}

func (x *TcpLoggerConfig) Reset() {
	*x = TcpLoggerConfig{}
	if protoimpl.UnsafeEnabled {
		mi := &file_source_filters_network_proto_tcp_logger_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *TcpLoggerConfig) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*TcpLoggerConfig) ProtoMessage() {}

func (x *TcpLoggerConfig) ProtoReflect() protoreflect.Message {
	mi := &file_source_filters_network_proto_tcp_logger_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use TcpLoggerConfig.ProtoReflect.Descriptor instead.
func (*TcpLoggerConfig) Descriptor() ([]byte, []int) {
	return file_source_filters_network_proto_tcp_logger_proto_rawDescGZIP(), []int{0}
}

func (x *TcpLoggerConfig) GetWarnWindow() string {
	if x != nil {
		return x.WarnWindow
	}
	return ""
}

func (x *TcpLoggerConfig) GetLogConnect() bool {
	if x != nil {
		return x.LogConnect
	}
	return false
}

func (x *TcpLoggerConfig) GetOmitSSLFailure() bool {
	if x != nil {
		return x.OmitSSLFailure
	}
	return false
}

func (x *TcpLoggerConfig) GetLogRawTcp() bool {
	if x != nil {
		return x.LogRawTcp
	}
	return false
}

func (x *TcpLoggerConfig) GetFailureCheckDelay() string {
	if x != nil {
		return x.FailureCheckDelay
	}
	return ""
}

var File_source_filters_network_proto_tcp_logger_proto protoreflect.FileDescriptor

var file_source_filters_network_proto_tcp_logger_proto_rawDesc = []byte{
	0x0a, 0x2d, 0x73, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x2f, 0x66, 0x69, 0x6c, 0x74, 0x65, 0x72, 0x73,
	0x2f, 0x6e, 0x65, 0x74, 0x77, 0x6f, 0x72, 0x6b, 0x2f, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x2f, 0x74,
	0x63, 0x70, 0x5f, 0x6c, 0x6f, 0x67, 0x67, 0x65, 0x72, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12,
	0x2d, 0x67, 0x72, 0x65, 0x79, 0x6d, 0x61, 0x74, 0x74, 0x65, 0x72, 0x5f, 0x69, 0x6f, 0x2e, 0x67,
	0x6d, 0x5f, 0x70, 0x72, 0x6f, 0x78, 0x79, 0x2e, 0x73, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x2e, 0x66,
	0x69, 0x6c, 0x74, 0x65, 0x72, 0x73, 0x2e, 0x6e, 0x65, 0x74, 0x77, 0x6f, 0x72, 0x6b, 0x22, 0xc5,
	0x01, 0x0a, 0x0f, 0x74, 0x63, 0x70, 0x4c, 0x6f, 0x67, 0x67, 0x65, 0x72, 0x43, 0x6f, 0x6e, 0x66,
	0x69, 0x67, 0x12, 0x1e, 0x0a, 0x0a, 0x77, 0x61, 0x72, 0x6e, 0x57, 0x69, 0x6e, 0x64, 0x6f, 0x77,
	0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x0a, 0x77, 0x61, 0x72, 0x6e, 0x57, 0x69, 0x6e, 0x64,
	0x6f, 0x77, 0x12, 0x1e, 0x0a, 0x0a, 0x6c, 0x6f, 0x67, 0x43, 0x6f, 0x6e, 0x6e, 0x65, 0x63, 0x74,
	0x18, 0x02, 0x20, 0x01, 0x28, 0x08, 0x52, 0x0a, 0x6c, 0x6f, 0x67, 0x43, 0x6f, 0x6e, 0x6e, 0x65,
	0x63, 0x74, 0x12, 0x26, 0x0a, 0x0e, 0x6f, 0x6d, 0x69, 0x74, 0x53, 0x53, 0x4c, 0x46, 0x61, 0x69,
	0x6c, 0x75, 0x72, 0x65, 0x18, 0x03, 0x20, 0x01, 0x28, 0x08, 0x52, 0x0e, 0x6f, 0x6d, 0x69, 0x74,
	0x53, 0x53, 0x4c, 0x46, 0x61, 0x69, 0x6c, 0x75, 0x72, 0x65, 0x12, 0x1c, 0x0a, 0x09, 0x6c, 0x6f,
	0x67, 0x52, 0x61, 0x77, 0x54, 0x63, 0x70, 0x18, 0x04, 0x20, 0x01, 0x28, 0x08, 0x52, 0x09, 0x6c,
	0x6f, 0x67, 0x52, 0x61, 0x77, 0x54, 0x63, 0x70, 0x12, 0x2c, 0x0a, 0x11, 0x66, 0x61, 0x69, 0x6c,
	0x75, 0x72, 0x65, 0x43, 0x68, 0x65, 0x63, 0x6b, 0x44, 0x65, 0x6c, 0x61, 0x79, 0x18, 0x05, 0x20,
	0x01, 0x28, 0x09, 0x52, 0x11, 0x66, 0x61, 0x69, 0x6c, 0x75, 0x72, 0x65, 0x43, 0x68, 0x65, 0x63,
	0x6b, 0x44, 0x65, 0x6c, 0x61, 0x79, 0x42, 0x40, 0x5a, 0x3e, 0x67, 0x69, 0x74, 0x68, 0x75, 0x62,
	0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x67, 0x72, 0x65, 0x79, 0x6d, 0x61, 0x74, 0x74, 0x65, 0x72, 0x2d,
	0x69, 0x6f, 0x2f, 0x67, 0x6d, 0x2d, 0x70, 0x72, 0x6f, 0x78, 0x79, 0x2f, 0x73, 0x6f, 0x75, 0x72,
	0x63, 0x65, 0x2f, 0x66, 0x69, 0x6c, 0x74, 0x65, 0x72, 0x73, 0x2f, 0x6e, 0x65, 0x74, 0x77, 0x6f,
	0x72, 0x6b, 0x2f, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_source_filters_network_proto_tcp_logger_proto_rawDescOnce sync.Once
	file_source_filters_network_proto_tcp_logger_proto_rawDescData = file_source_filters_network_proto_tcp_logger_proto_rawDesc
)

func file_source_filters_network_proto_tcp_logger_proto_rawDescGZIP() []byte {
	file_source_filters_network_proto_tcp_logger_proto_rawDescOnce.Do(func() {
		file_source_filters_network_proto_tcp_logger_proto_rawDescData = protoimpl.X.CompressGZIP(file_source_filters_network_proto_tcp_logger_proto_rawDescData)
	})
	return file_source_filters_network_proto_tcp_logger_proto_rawDescData
}

var file_source_filters_network_proto_tcp_logger_proto_msgTypes = make([]protoimpl.MessageInfo, 1)
var file_source_filters_network_proto_tcp_logger_proto_goTypes = []interface{}{
	(*TcpLoggerConfig)(nil), // 0: greymatter_io.gm_proxy.source.filters.network.tcpLoggerConfig
}
var file_source_filters_network_proto_tcp_logger_proto_depIdxs = []int32{
	0, // [0:0] is the sub-list for method output_type
	0, // [0:0] is the sub-list for method input_type
	0, // [0:0] is the sub-list for extension type_name
	0, // [0:0] is the sub-list for extension extendee
	0, // [0:0] is the sub-list for field type_name
}

func init() { file_source_filters_network_proto_tcp_logger_proto_init() }
func file_source_filters_network_proto_tcp_logger_proto_init() {
	if File_source_filters_network_proto_tcp_logger_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_source_filters_network_proto_tcp_logger_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*TcpLoggerConfig); i {
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
			RawDescriptor: file_source_filters_network_proto_tcp_logger_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   1,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_source_filters_network_proto_tcp_logger_proto_goTypes,
		DependencyIndexes: file_source_filters_network_proto_tcp_logger_proto_depIdxs,
		MessageInfos:      file_source_filters_network_proto_tcp_logger_proto_msgTypes,
	}.Build()
	File_source_filters_network_proto_tcp_logger_proto = out.File
	file_source_filters_network_proto_tcp_logger_proto_rawDesc = nil
	file_source_filters_network_proto_tcp_logger_proto_goTypes = nil
	file_source_filters_network_proto_tcp_logger_proto_depIdxs = nil
}
