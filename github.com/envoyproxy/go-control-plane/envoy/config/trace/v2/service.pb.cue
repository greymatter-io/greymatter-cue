package v2

import (
	core "github.com/envoyproxy/go-control-plane/envoy/api/v2/core"
)

// Configuration structure.
#TraceServiceConfig: {
	// The upstream gRPC cluster that hosts the metrics service.
	grpc_service?: core.#GrpcService
}
