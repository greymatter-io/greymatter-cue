package v3

#Filter: {
	// The name of the filter to instantiate. The name must match a
	// supported upstream filter. Note that Envoy's :ref:`downstream network
	// filters <config_network_filters>` are not valid upstream filters.
	name?: string
	// Filter specific configuration which depends on the filter being
	// instantiated. See the supported filters for further documentation.
	typed_config?: _
}
