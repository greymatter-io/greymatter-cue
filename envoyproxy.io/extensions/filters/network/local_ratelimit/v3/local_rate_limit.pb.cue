package v3

import (
	v31 "envoyproxy.io/config/core/v3"
	v3 "envoyproxy.io/type/v3"
)

#LocalRateLimit: {
	// The prefix to use when emitting :ref:`statistics
	// <config_network_filters_local_rate_limit_stats>`.
	stat_prefix?: string
	// The token bucket configuration to use for rate limiting connections that are processed by the
	// filter's filter chain. Each incoming connection processed by the filter consumes a single
	// token. If the token is available, the connection will be allowed. If no tokens are available,
	// the connection will be immediately closed.
	//
	// .. note::
	//   In the current implementation each filter and filter chain has an independent rate limit.
	//
	// .. note::
	//   In the current implementation the token bucket's :ref:`fill_interval
	//   <envoy_v3_api_field_type.v3.TokenBucket.fill_interval>` must be >= 50ms to avoid too aggressive
	//   refills.
	token_bucket?: v3.#TokenBucket
	// Runtime flag that controls whether the filter is enabled or not. If not specified, defaults
	// to enabled.
	runtime_enabled?: v31.#RuntimeFeatureFlag
}
