package v2

import (
	core "envoyproxy.io/api/v2/core"
)

// Configuration structure.
#TraceServiceConfig: {
	// The upstream gRPC cluster that hosts the metrics service.
	grpc_service?: core.#GrpcService
}
