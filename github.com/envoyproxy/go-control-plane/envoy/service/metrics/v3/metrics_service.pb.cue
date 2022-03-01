package v3

import (
	v3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	_go "github.com/prometheus/client_model/go"
)

#StreamMetricsResponse: {
}

#StreamMetricsMessage: {
	// Identifier data effectively is a structured metadata. As a performance optimization this will
	// only be sent in the first message on the stream.
	identifier?: #StreamMetricsMessage_Identifier
	// A list of metric entries
	envoy_metrics?: [..._go.#MetricFamily]
}

#StreamMetricsMessage_Identifier: {
	// The node sending metrics over the stream.
	node?: v3.#Node
}

// MetricsServiceClient is the client API for MetricsService service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://godoc.org/google.golang.org/grpc#ClientConn.NewStream.
#MetricsServiceClient: _

#MetricsService_StreamMetricsClient: _

// MetricsServiceServer is the server API for MetricsService service.
#MetricsServiceServer: _

// UnimplementedMetricsServiceServer can be embedded to have forward compatible implementations.
#UnimplementedMetricsServiceServer: {
}

#MetricsService_StreamMetricsServer: _
