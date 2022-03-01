package v3

// Thrift transport types supported by Envoy.
#TransportType: "AUTO_TRANSPORT" | "FRAMED" | "UNFRAMED" | "HEADER"

TransportType_AUTO_TRANSPORT: "AUTO_TRANSPORT"
TransportType_FRAMED:         "FRAMED"
TransportType_UNFRAMED:       "UNFRAMED"
TransportType_HEADER:         "HEADER"

// Thrift Protocol types supported by Envoy.
#ProtocolType: "AUTO_PROTOCOL" | "BINARY" | "LAX_BINARY" | "COMPACT" | "TWITTER"

ProtocolType_AUTO_PROTOCOL: "AUTO_PROTOCOL"
ProtocolType_BINARY:        "BINARY"
ProtocolType_LAX_BINARY:    "LAX_BINARY"
ProtocolType_COMPACT:       "COMPACT"
ProtocolType_TWITTER:       "TWITTER"

// [#next-free-field: 8]
#ThriftProxy: {
	// Supplies the type of transport that the Thrift proxy should use. Defaults to
	// :ref:`AUTO_TRANSPORT<envoy_v3_api_enum_value_extensions.filters.network.thrift_proxy.v3.TransportType.AUTO_TRANSPORT>`.
	transport?: #TransportType
	// Supplies the type of protocol that the Thrift proxy should use. Defaults to
	// :ref:`AUTO_PROTOCOL<envoy_v3_api_enum_value_extensions.filters.network.thrift_proxy.v3.ProtocolType.AUTO_PROTOCOL>`.
	protocol?: #ProtocolType
	// The human readable prefix to use when emitting statistics.
	stat_prefix?: string
	// The route table for the connection manager is static and is specified in this property.
	route_config?: #RouteConfiguration
	// A list of individual Thrift filters that make up the filter chain for requests made to the
	// Thrift proxy. Order matters as the filters are processed sequentially. For backwards
	// compatibility, if no thrift_filters are specified, a default Thrift router filter
	// (`envoy.filters.thrift.router`) is used.
	// [#extension-category: envoy.thrift_proxy.filters]
	thrift_filters?: [...#ThriftFilter]
	// If set to true, Envoy will try to skip decode data after metadata in the Thrift message.
	// This mode will only work if the upstream and downstream protocols are the same and the transports
	// are Framed or Header, and the protocol is not Twitter. Otherwise Envoy will
	// fallback to decode the data.
	payload_passthrough?: bool
	// Optional maximum requests for a single downstream connection. If not specified, there is no limit.
	max_requests_per_connection?: uint32
}

// ThriftFilter configures a Thrift filter.
#ThriftFilter: {
	// The name of the filter to instantiate. The name must match a supported
	// filter. The built-in filters are:
	//
	// [#comment:TODO(zuercher): Auto generate the following list]
	// * :ref:`envoy.filters.thrift.router <config_thrift_filters_router>`
	// * :ref:`envoy.filters.thrift.rate_limit <config_thrift_filters_rate_limit>`
	name?:         string
	typed_config?: _
}

// ThriftProtocolOptions specifies Thrift upstream protocol options. This object is used in
// in
// :ref:`typed_extension_protocol_options<envoy_v3_api_field_config.cluster.v3.Cluster.typed_extension_protocol_options>`,
// keyed by the name `envoy.filters.network.thrift_proxy`.
#ThriftProtocolOptions: {
	// Supplies the type of transport that the Thrift proxy should use for upstream connections.
	// Selecting
	// :ref:`AUTO_TRANSPORT<envoy_v3_api_enum_value_extensions.filters.network.thrift_proxy.v3.TransportType.AUTO_TRANSPORT>`,
	// which is the default, causes the proxy to use the same transport as the downstream connection.
	transport?: #TransportType
	// Supplies the type of protocol that the Thrift proxy should use for upstream connections.
	// Selecting
	// :ref:`AUTO_PROTOCOL<envoy_v3_api_enum_value_extensions.filters.network.thrift_proxy.v3.ProtocolType.AUTO_PROTOCOL>`,
	// which is the default, causes the proxy to use the same protocol as the downstream connection.
	protocol?: #ProtocolType
}
