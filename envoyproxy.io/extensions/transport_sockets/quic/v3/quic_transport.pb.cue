package v3

import (
	v3 "envoyproxy.io/extensions/transport_sockets/tls/v3"
)

// Configuration for Downstream QUIC transport socket. This provides Google's implementation of Google QUIC and IETF QUIC to Envoy.
#QuicDownstreamTransport: {
	downstream_tls_context?: v3.#DownstreamTlsContext
}

// Configuration for Upstream QUIC transport socket. This provides Google's implementation of Google QUIC and IETF QUIC to Envoy.
#QuicUpstreamTransport: {
	upstream_tls_context?: v3.#UpstreamTlsContext
}
