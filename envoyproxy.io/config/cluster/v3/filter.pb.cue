package v3

import (
	any "envoyproxy.io/deps/golang/protobuf/ptypes/any"
)

#Filter: {
	// The name of the filter configuration.
	name?: string
	// Filter specific configuration which depends on the filter being
	// instantiated. See the supported filters for further documentation.
	// Note that Envoy's :ref:`downstream network
	// filters <config_network_filters>` are not valid upstream filters.
	typed_config?: any.#Any
}
