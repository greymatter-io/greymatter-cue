package v3

import (
	v3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
)

// Rate limit :ref:`configuration overview <config_rate_limit_service>`.
#RateLimitServiceConfig: {
	// Specifies the gRPC service that hosts the rate limit service. The client
	// will connect to this cluster when it needs to make rate limit service
	// requests.
	grpc_service?: v3.#GrpcService
	// API version for rate limit transport protocol. This describes the rate limit gRPC endpoint and
	// version of messages used on the wire.
	transport_api_version?: v3.#ApiVersion
}
