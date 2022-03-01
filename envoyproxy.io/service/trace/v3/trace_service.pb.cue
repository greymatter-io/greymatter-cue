package v3

import (
	v1 "envoyproxy.io/deps/census-instrumentation/opencensus-proto/gen-go/trace/v1"
	v3 "envoyproxy.io/config/core/v3"
)

#StreamTracesResponse: {
}

#StreamTracesMessage: {
	// Identifier data effectively is a structured metadata.
	// As a performance optimization this will only be sent in the first message
	// on the stream.
	identifier?: #StreamTracesMessage_Identifier
	// A list of Span entries
	spans?: [...v1.#Span]
}

#StreamTracesMessage_Identifier: {
	// The node sending the access log messages over the stream.
	node?: v3.#Node
}

// TraceServiceClient is the client API for TraceService service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://godoc.org/google.golang.org/grpc#ClientConn.NewStream.
#TraceServiceClient: _

#TraceService_StreamTracesClient: _

// TraceServiceServer is the server API for TraceService service.
#TraceServiceServer: _

// UnimplementedTraceServiceServer can be embedded to have forward compatible implementations.
#UnimplementedTraceServiceServer: {
}

#TraceService_StreamTracesServer: _
