package v3

import (
	v3 "envoyproxy.io/config/core/v3"
)

// Configuration for the OpenTelemetry tracer.
//  [#extension: envoy.tracers.opentelemetry]
#OpenTelemetryConfig: {
	// The upstream gRPC cluster that will receive OTLP traces.
	// Note that the tracer drops traces if the server does not read data fast enough.
	grpc_service?: v3.#GrpcService
}
