package v3

import (
	v3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
)

// Configuration for PROXY protocol socket
#ProxyProtocolUpstreamTransport: {
	// The PROXY protocol settings
	config?: v3.#ProxyProtocolConfig
	// The underlying transport socket being wrapped.
	transport_socket?: v3.#TransportSocket
}
