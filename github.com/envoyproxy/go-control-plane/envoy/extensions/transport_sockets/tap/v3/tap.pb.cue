package v3

import (
	v31 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	v3 "github.com/envoyproxy/go-control-plane/envoy/extensions/common/tap/v3"
)

// Configuration for tap transport socket. This wraps another transport socket, providing the
// ability to interpose and record in plain text any traffic that is surfaced to Envoy.
#Tap: {
	// Common configuration for the tap transport socket.
	common_config?: v3.#CommonExtensionConfig
	// The underlying transport socket being wrapped.
	transport_socket?: v31.#TransportSocket
}
