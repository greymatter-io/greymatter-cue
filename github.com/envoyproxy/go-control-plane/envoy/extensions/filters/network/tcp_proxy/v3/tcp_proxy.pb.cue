package v3

import (
	v32 "github.com/envoyproxy/go-control-plane/envoy/type/v3"
	v31 "github.com/envoyproxy/go-control-plane/envoy/config/accesslog/v3"
	v3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
)

// [#next-free-field: 14]
#TcpProxy: {
	// The prefix to use when emitting :ref:`statistics
	// <config_network_filters_tcp_proxy_stats>`.
	stat_prefix?: string
	// The upstream cluster to connect to.
	cluster?: string
	// Multiple upstream clusters can be specified for a given route. The
	// request is routed to one of the upstream clusters based on weights
	// assigned to each cluster.
	weighted_clusters?: #TcpProxy_WeightedCluster
	// Optional endpoint metadata match criteria. Only endpoints in the upstream
	// cluster with metadata matching that set in metadata_match will be
	// considered. The filter name should be specified as *envoy.lb*.
	metadata_match?: v3.#Metadata
	// The idle timeout for connections managed by the TCP proxy filter. The idle timeout
	// is defined as the period in which there are no bytes sent or received on either
	// the upstream or downstream connection. If not set, the default idle timeout is 1 hour. If set
	// to 0s, the timeout will be disabled.
	//
	// .. warning::
	//   Disabling this timeout has a highly likelihood of yielding connection leaks due to lost TCP
	//   FIN packets, etc.
	idle_timeout?: string
	// [#not-implemented-hide:] The idle timeout for connections managed by the TCP proxy
	// filter. The idle timeout is defined as the period in which there is no
	// active traffic. If not set, there is no idle timeout. When the idle timeout
	// is reached the connection will be closed. The distinction between
	// downstream_idle_timeout/upstream_idle_timeout provides a means to set
	// timeout based on the last byte sent on the downstream/upstream connection.
	downstream_idle_timeout?: string
	// [#not-implemented-hide:]
	upstream_idle_timeout?: string
	// Configuration for :ref:`access logs <arch_overview_access_logs>`
	// emitted by the this tcp_proxy.
	access_log?: [...v31.#AccessLog]
	// The maximum number of unsuccessful connection attempts that will be made before
	// giving up. If the parameter is not specified, 1 connection attempt will be made.
	max_connect_attempts?: uint32
	// Optional configuration for TCP proxy hash policy. If hash_policy is not set, the hash-based
	// load balancing algorithms will select a host randomly. Currently the number of hash policies is
	// limited to 1.
	hash_policy?: [...v32.#HashPolicy]
	// If set, this configures tunneling, e.g. configuration options to tunnel TCP payload over
	// HTTP CONNECT. If this message is absent, the payload will be proxied upstream as per usual.
	tunneling_config?: #TcpProxy_TunnelingConfig
	// The maximum duration of a connection. The duration is defined as the period since a connection
	// was established. If not set, there is no max duration. When max_downstream_connection_duration
	// is reached the connection will be closed. Duration must be at least 1ms.
	max_downstream_connection_duration?: string
}

// Allows for specification of multiple upstream clusters along with weights
// that indicate the percentage of traffic to be forwarded to each cluster.
// The router selects an upstream cluster based on these weights.
#TcpProxy_WeightedCluster: {
	// Specifies one or more upstream clusters associated with the route.
	clusters?: [...#TcpProxy_WeightedCluster_ClusterWeight]
}

// Configuration for tunneling TCP over other transports or application layers.
// Tunneling is supported over both HTTP/1.1 and HTTP/2. Upstream protocol is
// determined by the cluster configuration.
#TcpProxy_TunnelingConfig: {
	// The hostname to send in the synthesized CONNECT headers to the upstream proxy.
	hostname?: string
	// Use POST method instead of CONNECT method to tunnel the TCP stream.
	// The 'protocol: bytestream' header is also NOT set for HTTP/2 to comply with the spec.
	//
	// The upstream proxy is expected to convert POST payload as raw TCP.
	use_post?: bool
	// Additional request headers to upstream proxy. This is mainly used to
	// trigger upstream to convert POST requests back to CONNECT requests.
	//
	// Neither *:-prefixed* pseudo-headers nor the Host: header can be overridden.
	headers_to_add?: [...v3.#HeaderValueOption]
}

#TcpProxy_WeightedCluster_ClusterWeight: {
	// Name of the upstream cluster.
	name?: string
	// When a request matches the route, the choice of an upstream cluster is
	// determined by its weight. The sum of weights across all entries in the
	// clusters array determines the total weight.
	weight?: uint32
	// Optional endpoint metadata match criteria used by the subset load balancer. Only endpoints
	// in the upstream cluster with metadata matching what is set in this field will be considered
	// for load balancing. Note that this will be merged with what's provided in
	// :ref:`TcpProxy.metadata_match
	// <envoy_v3_api_field_extensions.filters.network.tcp_proxy.v3.TcpProxy.metadata_match>`, with values
	// here taking precedence. The filter name should be specified as *envoy.lb*.
	metadata_match?: v3.#Metadata
}
