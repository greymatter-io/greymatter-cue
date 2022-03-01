package v2

import (
	core "github.com/envoyproxy/go-control-plane/envoy/api/v2/core"
	v21 "github.com/envoyproxy/go-control-plane/envoy/config/filter/accesslog/v2"
	listener "github.com/envoyproxy/go-control-plane/envoy/api/v2/listener"
	v2 "github.com/envoyproxy/go-control-plane/envoy/config/listener/v2"
)

#Listener_DrainType: "DEFAULT" | "MODIFY_ONLY"

Listener_DrainType_DEFAULT:     "DEFAULT"
Listener_DrainType_MODIFY_ONLY: "MODIFY_ONLY"

// [#next-free-field: 23]
#Listener: {
	// The unique name by which this listener is known. If no name is provided,
	// Envoy will allocate an internal UUID for the listener. If the listener is to be dynamically
	// updated or removed via :ref:`LDS <config_listeners_lds>` a unique name must be provided.
	name?: string
	// The address that the listener should listen on. In general, the address must be unique, though
	// that is governed by the bind rules of the OS. E.g., multiple listeners can listen on port 0 on
	// Linux as the actual port will be allocated by the OS.
	address?: core.#Address
	// A list of filter chains to consider for this listener. The
	// :ref:`FilterChain <envoy_api_msg_listener.FilterChain>` with the most specific
	// :ref:`FilterChainMatch <envoy_api_msg_listener.FilterChainMatch>` criteria is used on a
	// connection.
	//
	// Example using SNI for filter chain selection can be found in the
	// :ref:`FAQ entry <faq_how_to_setup_sni>`.
	filter_chains?: [...listener.#FilterChain]
	// If a connection is redirected using *iptables*, the port on which the proxy
	// receives it might be different from the original destination address. When this flag is set to
	// true, the listener hands off redirected connections to the listener associated with the
	// original destination address. If there is no listener associated with the original destination
	// address, the connection is handled by the listener that receives it. Defaults to false.
	//
	// .. attention::
	//
	//   This field is deprecated. Use :ref:`an original_dst <config_listener_filters_original_dst>`
	//   :ref:`listener filter <envoy_api_field_Listener.listener_filters>` instead.
	//
	//   Note that hand off to another listener is *NOT* performed without this flag. Once
	//   :ref:`FilterChainMatch <envoy_api_msg_listener.FilterChainMatch>` is implemented this flag
	//   will be removed, as filter chain matching can be used to select a filter chain based on the
	//   restored destination address.
	//
	// Deprecated: Do not use.
	use_original_dst?: bool
	// Soft limit on size of the listener’s new connection read and write buffers.
	// If unspecified, an implementation defined default is applied (1MiB).
	per_connection_buffer_limit_bytes?: uint32
	// Listener metadata.
	metadata?: core.#Metadata
	// [#not-implemented-hide:]
	deprecated_v1?: #Listener_DeprecatedV1
	// The type of draining to perform at a listener-wide level.
	drain_type?: #Listener_DrainType
	// Listener filters have the opportunity to manipulate and augment the connection metadata that
	// is used in connection filter chain matching, for example. These filters are run before any in
	// :ref:`filter_chains <envoy_api_field_Listener.filter_chains>`. Order matters as the
	// filters are processed sequentially right after a socket has been accepted by the listener, and
	// before a connection is created.
	// UDP Listener filters can be specified when the protocol in the listener socket address in
	// :ref:`protocol <envoy_api_field_core.SocketAddress.protocol>` is :ref:`UDP
	// <envoy_api_enum_value_core.SocketAddress.Protocol.UDP>`.
	// UDP listeners currently support a single filter.
	listener_filters?: [...listener.#ListenerFilter]
	// The timeout to wait for all listener filters to complete operation. If the timeout is reached,
	// the accepted socket is closed without a connection being created unless
	// `continue_on_listener_filters_timeout` is set to true. Specify 0 to disable the
	// timeout. If not specified, a default timeout of 15s is used.
	listener_filters_timeout?: string
	// Whether a connection should be created when listener filters timeout. Default is false.
	//
	// .. attention::
	//
	//   Some listener filters, such as :ref:`Proxy Protocol filter
	//   <config_listener_filters_proxy_protocol>`, should not be used with this option. It will cause
	//   unexpected behavior when a connection is created.
	continue_on_listener_filters_timeout?: bool
	// Whether the listener should be set as a transparent socket.
	// When this flag is set to true, connections can be redirected to the listener using an
	// *iptables* *TPROXY* target, in which case the original source and destination addresses and
	// ports are preserved on accepted connections. This flag should be used in combination with
	// :ref:`an original_dst <config_listener_filters_original_dst>` :ref:`listener filter
	// <envoy_api_field_Listener.listener_filters>` to mark the connections' local addresses as
	// "restored." This can be used to hand off each redirected connection to another listener
	// associated with the connection's destination address. Direct connections to the socket without
	// using *TPROXY* cannot be distinguished from connections redirected using *TPROXY* and are
	// therefore treated as if they were redirected.
	// When this flag is set to false, the listener's socket is explicitly reset as non-transparent.
	// Setting this flag requires Envoy to run with the *CAP_NET_ADMIN* capability.
	// When this flag is not set (default), the socket is not modified, i.e. the transparent option
	// is neither set nor reset.
	transparent?: bool
	// Whether the listener should set the *IP_FREEBIND* socket option. When this
	// flag is set to true, listeners can be bound to an IP address that is not
	// configured on the system running Envoy. When this flag is set to false, the
	// option *IP_FREEBIND* is disabled on the socket. When this flag is not set
	// (default), the socket is not modified, i.e. the option is neither enabled
	// nor disabled.
	freebind?: bool
	// Additional socket options that may not be present in Envoy source code or
	// precompiled binaries.
	socket_options?: [...core.#SocketOption]
	// Whether the listener should accept TCP Fast Open (TFO) connections.
	// When this flag is set to a value greater than 0, the option TCP_FASTOPEN is enabled on
	// the socket, with a queue length of the specified size
	// (see `details in RFC7413 <https://tools.ietf.org/html/rfc7413#section-5.1>`_).
	// When this flag is set to 0, the option TCP_FASTOPEN is disabled on the socket.
	// When this flag is not set (default), the socket is not modified,
	// i.e. the option is neither enabled nor disabled.
	//
	// On Linux, the net.ipv4.tcp_fastopen kernel parameter must include flag 0x2 to enable
	// TCP_FASTOPEN.
	// See `ip-sysctl.txt <https://www.kernel.org/doc/Documentation/networking/ip-sysctl.txt>`_.
	//
	// On macOS, only values of 0, 1, and unset are valid; other values may result in an error.
	// To set the queue length on macOS, set the net.inet.tcp.fastopen_backlog kernel parameter.
	tcp_fast_open_queue_length?: uint32
	// Specifies the intended direction of the traffic relative to the local Envoy.
	// This property is required on Windows for listeners using the original destination filter,
	// see :ref:`Original Destination <config_listener_filters_original_dst>`.
	traffic_direction?: core.#TrafficDirection
	// If the protocol in the listener socket address in :ref:`protocol
	// <envoy_api_field_core.SocketAddress.protocol>` is :ref:`UDP
	// <envoy_api_enum_value_core.SocketAddress.Protocol.UDP>`, this field specifies the actual udp
	// listener to create, i.e. :ref:`udp_listener_name
	// <envoy_api_field_listener.UdpListenerConfig.udp_listener_name>` = "raw_udp_listener" for
	// creating a packet-oriented UDP listener. If not present, treat it as "raw_udp_listener".
	udp_listener_config?: listener.#UdpListenerConfig
	// Used to represent an API listener, which is used in non-proxy clients. The type of API
	// exposed to the non-proxy application depends on the type of API listener.
	// When this field is set, no other field except for :ref:`name<envoy_api_field_Listener.name>`
	// should be set.
	//
	// .. note::
	//
	//  Currently only one ApiListener can be installed; and it can only be done via bootstrap config,
	//  not LDS.
	//
	// [#next-major-version: In the v3 API, instead of this messy approach where the socket
	// listener fields are directly in the top-level Listener message and the API listener types
	// are in the ApiListener message, the socket listener messages should be in their own message,
	// and the top-level Listener should essentially be a oneof that selects between the
	// socket listener and the various types of API listener. That way, a given Listener message
	// can structurally only contain the fields of the relevant type.]
	api_listener?: v2.#ApiListener
	// The listener's connection balancer configuration, currently only applicable to TCP listeners.
	// If no configuration is specified, Envoy will not attempt to balance active connections between
	// worker threads.
	connection_balance_config?: #Listener_ConnectionBalanceConfig
	// When this flag is set to true, listeners set the *SO_REUSEPORT* socket option and
	// create one socket for each worker thread. This makes inbound connections
	// distribute among worker threads roughly evenly in cases where there are a high number
	// of connections. When this flag is set to false, all worker threads share one socket.
	//
	// Before Linux v4.19-rc1, new TCP connections may be rejected during hot restart
	// (see `3rd paragraph in 'soreuseport' commit message
	// <https://github.com/torvalds/linux/commit/c617f398edd4db2b8567a28e89>`_).
	// This issue was fixed by `tcp: Avoid TCP syncookie rejected by SO_REUSEPORT socket
	// <https://github.com/torvalds/linux/commit/40a1227ea845a37ab197dd1caffb60b047fa36b1>`_.
	reuse_port?: bool
	// Configuration for :ref:`access logs <arch_overview_access_logs>`
	// emitted by this listener.
	access_log?: [...v21.#AccessLog]
}

// [#not-implemented-hide:]
#Listener_DeprecatedV1: {
	// Whether the listener should bind to the port. A listener that doesn't
	// bind can only receive connections redirected from other listeners that
	// set use_original_dst parameter to true. Default is true.
	//
	// This is deprecated in v2, all Listeners will bind to their port. An
	// additional filter chain must be created for every original destination
	// port this listener may redirect to in v2, with the original port
	// specified in the FilterChainMatch destination_port field.
	//
	// [#comment:TODO(PiotrSikora): Remove this once verified that we no longer need it.]
	bind_to_port?: bool
}

// Configuration for listener connection balancing.
#Listener_ConnectionBalanceConfig: {
	// If specified, the listener will use the exact connection balancer.
	exact_balance?: #Listener_ConnectionBalanceConfig_ExactBalance
}

// A connection balancer implementation that does exact balancing. This means that a lock is
// held during balancing so that connection counts are nearly exactly balanced between worker
// threads. This is "nearly" exact in the sense that a connection might close in parallel thus
// making the counts incorrect, but this should be rectified on the next accept. This balancer
// sacrifices accept throughput for accuracy and should be used when there are a small number of
// connections that rarely cycle (e.g., service mesh gRPC egress).
#Listener_ConnectionBalanceConfig_ExactBalance: {
}
