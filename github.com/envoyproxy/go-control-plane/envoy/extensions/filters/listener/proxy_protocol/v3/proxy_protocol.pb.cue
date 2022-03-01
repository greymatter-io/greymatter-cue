package v3

#ProxyProtocol: {
	// The list of rules to apply to requests.
	rules?: [...#ProxyProtocol_Rule]
}

#ProxyProtocol_KeyValuePair: {
	// The namespace — if this is empty, the filter's namespace will be used.
	metadata_namespace?: string
	// The key to use within the namespace.
	key?: string
}

// A Rule defines what metadata to apply when a header is present or missing.
#ProxyProtocol_Rule: {
	// The type that triggers the rule - required
	// TLV type is defined as uint8_t in proxy protocol. See `the spec
	// <https://www.haproxy.org/download/2.1/doc/proxy-protocol.txt>`_ for details.
	tlv_type?: uint32
	// If the TLV type is present, apply this metadata KeyValuePair.
	on_tlv_present?: #ProxyProtocol_KeyValuePair
}
