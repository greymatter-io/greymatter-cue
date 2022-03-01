package v3

// Used to match request service of the downstream request. Only applicable if a service provided
// by the application protocol.
// [#not-implemented-hide:]
#ServiceMatchInput: {
}

// Used to match request method of the downstream request. Only applicable if a method provided
// by the application protocol.
// [#not-implemented-hide:]
#MethodMatchInput: {
}

// Used to match an arbitrary property of the downstream request.
// These properties are populated by the codecs of application protocols.
// [#not-implemented-hide:]
#PropertyMatchInput: {
	// The property name to match on.
	property_name?: string
}
