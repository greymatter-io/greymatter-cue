package v3

import (
	v3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
)

// Configuration for the alternate protocols cache HTTP filter.
// [#extension: envoy.filters.http.alternate_protocols_cache]
#FilterConfig: {
	// If set, causes the use of the alternate protocols cache, which is responsible for
	// parsing and caching HTTP Alt-Svc headers. This enables the use of HTTP/3 for upstream
	// servers that advertise supporting it.
	// TODO(RyanTheOptimist): Make this field required when HTTP/3 is enabled via auto_http.
	alternate_protocols_cache_options?: v3.#AlternateProtocolsCacheOptions
}
