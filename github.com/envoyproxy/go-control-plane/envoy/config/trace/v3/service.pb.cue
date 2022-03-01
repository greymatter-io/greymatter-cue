package v3

import (
	v3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
)

// Configuration structure.
#TraceServiceConfig: {
	// The upstream gRPC cluster that hosts the metrics service.
	grpc_service?: v3.#GrpcService
}
