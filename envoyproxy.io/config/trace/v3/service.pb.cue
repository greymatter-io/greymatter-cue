package v3

import (
	v3 "envoyproxy.io/config/core/v3"
)

// Configuration structure.
#TraceServiceConfig: {
	// The upstream gRPC cluster that hosts the metrics service.
	grpc_service?: v3.#GrpcService
}
