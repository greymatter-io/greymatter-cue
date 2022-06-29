package v3

// Used to match request service of the downstream request. Only applicable if a service provided
// by the application protocol.
// [#not-implemented-hide:]
#ServiceMatchInput: {
	"@type": "type.googleapis.com/envoy.extensions.filters.network.meta_protocol_proxy.matcher.v3.ServiceMatchInput"
}

// Used to match request method of the downstream request. Only applicable if a method provided
// by the application protocol.
// [#not-implemented-hide:]
#MethodMatchInput: {
	"@type": "type.googleapis.com/envoy.extensions.filters.network.meta_protocol_proxy.matcher.v3.MethodMatchInput"
}

// Used to match an arbitrary property of the downstream request.
// These properties are populated by the codecs of application protocols.
// [#not-implemented-hide:]
#PropertyMatchInput: {
	"@type": "type.googleapis.com/envoy.extensions.filters.network.meta_protocol_proxy.matcher.v3.PropertyMatchInput"
	// The property name to match on.
	property_name?: string
}
