package v3

import (
	v3 "envoyproxy.io/config/core/v3"
)

// [#next-free-field: 8]
#UdpListenerConfig: {
	// UDP socket configuration for the listener. The default for
	// :ref:`prefer_gro <envoy_v3_api_field_config.core.v3.UdpSocketConfig.prefer_gro>` is false for
	// listener sockets. If receiving a large amount of datagrams from a small number of sources, it
	// may be worthwhile to enable this option after performance testing.
	downstream_socket_config?: v3.#UdpSocketConfig
	// Configuration for QUIC protocol. If empty, QUIC will not be enabled on this listener. Set
	// to the default object to enable QUIC without modifying any additional options.
	quic_options?: #QuicProtocolOptions
}

#ActiveRawUdpListenerConfig: {
}
