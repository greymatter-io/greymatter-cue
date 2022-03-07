package v3

import (
	v3 "envoyproxy.io/config/core/v3"
)

// [#not-implemented-hide:]
// [#next-free-field: 6]
#MetaProtocolProxy: {
	// The human readable prefix to use when emitting statistics.
	stat_prefix?: string
	// The application protocol built on top of the meta protocol proxy.
	application_protocol?: #ApplicationProtocol
	// The meta protocol proxies route table will be dynamically loaded via the meta RDS API.
	rds?: #MetaRds
	// The route table for the meta protocol proxy is static and is specified in this property.
	route_config?: #RouteConfiguration
	// A list of individual Layer-7 filters that make up the filter chain for requests made to the
	// meta protocol proxy. Order matters as the filters are processed sequentially as request events
	// happen.
	meta_protocol_filters?: [...v3.#TypedExtensionConfig]
}

// [#not-implemented-hide:]
#ApplicationProtocol: {
	// The name of the application protocol.
	name?: string
	// The codec which encodes and decodes the application protocol.
	codec?: v3.#TypedExtensionConfig
}

// [#not-implemented-hide:]
#MetaRds: {
	// Configuration source specifier for RDS.
	config_source?: v3.#ConfigSource
	// The name of the route configuration. This name will be passed to the RDS API. This allows an
	// Envoy configuration with multiple meta protocol proxies to use different route configurations.
	route_config_name?: string
}
