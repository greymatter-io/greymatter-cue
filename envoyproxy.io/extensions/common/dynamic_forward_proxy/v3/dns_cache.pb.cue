package v3

import (
	v3 "envoyproxy.io/config/cluster/v3"
	v31 "envoyproxy.io/config/core/v3"
	v32 "envoyproxy.io/config/common/key_value/v3"
)

// Configuration of circuit breakers for resolver.
#DnsCacheCircuitBreakers: {
	"@type": "type.googleapis.com/envoy.extensions.common.dynamic_forward_proxy.v3.DnsCacheCircuitBreakers"
	// The maximum number of pending requests that Envoy will allow to the
	// resolver. If not specified, the default is 1024.
	max_pending_requests?: uint32
}

// Configuration for the dynamic forward proxy DNS cache. See the :ref:`architecture overview
// <arch_overview_http_dynamic_forward_proxy>` for more information.
// [#next-free-field: 15]
#DnsCacheConfig: {
	"@type": "type.googleapis.com/envoy.extensions.common.dynamic_forward_proxy.v3.DnsCacheConfig"
	// The name of the cache. Multiple named caches allow independent dynamic forward proxy
	// configurations to operate within a single Envoy process using different configurations. All
	// configurations with the same name *must* otherwise have the same settings when referenced
	// from different configuration components. Configuration will fail to load if this is not
	// the case.
	name?: string
	// The DNS lookup family to use during resolution.
	//
	// [#comment:TODO(mattklein123): Figure out how to support IPv4/IPv6 "happy eyeballs" mode. The
	// way this might work is a new lookup family which returns both IPv4 and IPv6 addresses, and
	// then configures a host to have a primary and fall back address. With this, we could very
	// likely build a "happy eyeballs" connection pool which would race the primary / fall back
	// address and return the one that wins. This same method could potentially also be used for
	// QUIC to TCP fall back.]
	dns_lookup_family?: v3.#Cluster_DnsLookupFamily
	// The DNS refresh rate for unresolved DNS hosts. If not specified defaults to 60s.
	//
	// The refresh rate is rounded to the closest millisecond, and must be at least 1ms.
	//
	// Once a host has been resolved, the refresh rate will be the DNS TTL, capped
	// at a minimum of `dns_min_refresh_rate`.
	dns_refresh_rate?: string
	// The minimum rate that DNS resolution will occur. Per `dns_refresh_rate`, once a host is
	// resolved, the DNS TTL will be used, with a minimum set by `dns_min_refresh_rate`.
	// `dns_min_refresh_rate` defaults to 5s and must also be >= 5s.
	dns_min_refresh_rate?: string
	// The TTL for hosts that are unused. Hosts that have not been used in the configured time
	// interval will be purged. If not specified defaults to 5m.
	//
	// .. note:
	//
	//   The TTL is only checked at the time of DNS refresh, as specified by *dns_refresh_rate*. This
	//   means that if the configured TTL is shorter than the refresh rate the host may not be removed
	//   immediately.
	//
	//  .. note:
	//
	//   The TTL has no relation to DNS TTL and is only used to control Envoy's resource usage.
	host_ttl?: string
	// The maximum number of hosts that the cache will hold. If not specified defaults to 1024.
	//
	// .. note:
	//
	//   The implementation is approximate and enforced independently on each worker thread, thus
	//   it is possible for the maximum hosts in the cache to go slightly above the configured
	//   value depending on timing. This is similar to how other circuit breakers work.
	max_hosts?: uint32
	// If the DNS failure refresh rate is specified,
	// this is used as the cache's DNS refresh rate when DNS requests are failing. If this setting is
	// not specified, the failure refresh rate defaults to the dns_refresh_rate.
	dns_failure_refresh_rate?: v3.#Cluster_RefreshRate
	// The config of circuit breakers for resolver. It provides a configurable threshold.
	// Envoy will use dns cache circuit breakers with default settings even if this value is not set.
	dns_cache_circuit_breaker?: #DnsCacheCircuitBreakers
	// Always use TCP queries instead of UDP queries for DNS lookups.
	// This field is deprecated in favor of *dns_resolution_config*
	// which aggregates all of the DNS resolver configuration in a single message.
	//
	// Deprecated: Do not use.
	use_tcp_for_dns_lookups?: bool
	// DNS resolution configuration which includes the underlying dns resolver addresses and options.
	// This field is deprecated in favor of
	// :ref:`typed_dns_resolver_config <envoy_v3_api_field_extensions.common.dynamic_forward_proxy.v3.DnsCacheConfig.typed_dns_resolver_config>`.
	//
	// Deprecated: Do not use.
	dns_resolution_config?: v31.#DnsResolutionConfig
	// DNS resolver type configuration extension. This extension can be used to configure c-ares, apple,
	// or any other DNS resolver types and the related parameters.
	// For example, an object of
	// :ref:`CaresDnsResolverConfig <envoy_v3_api_msg_extensions.network.dns_resolver.cares.v3.CaresDnsResolverConfig>`
	// can be packed into this *typed_dns_resolver_config*. This configuration replaces the
	// :ref:`dns_resolution_config <envoy_v3_api_field_extensions.common.dynamic_forward_proxy.v3.DnsCacheConfig.dns_resolution_config>`
	// configuration.
	// During the transition period when both *dns_resolution_config* and *typed_dns_resolver_config* exists,
	// when *typed_dns_resolver_config* is in place, Envoy will use it and ignore *dns_resolution_config*.
	// When *typed_dns_resolver_config* is missing, the default behavior is in place.
	// [#extension-category: envoy.network.dns_resolver]
	typed_dns_resolver_config?: v31.#TypedExtensionConfig
	// Hostnames that should be preresolved into the cache upon creation. This might provide a
	// performance improvement, in the form of cache hits, for hostnames that are going to be
	// resolved during steady state and are known at config load time.
	preresolve_hostnames?: [...v31.#SocketAddress]
	// The timeout used for DNS queries. This timeout is independent of any timeout and retry policy
	// used by the underlying DNS implementation (e.g., c-areas and Apple DNS) which are opaque.
	// Setting this timeout will ensure that queries succeed or fail within the specified time frame
	// and are then retried using the standard refresh rates. Defaults to 5s if not set.
	dns_query_timeout?: string
	// [#not-implemented-hide:]
	// Configuration to flush the DNS cache to long term storage.
	key_value_config?: v32.#KeyValueStoreConfig
}
