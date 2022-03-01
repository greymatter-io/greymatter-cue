package v1

// AnyValue is used to represent any type of attribute value. AnyValue may contain a
// primitive value such as a string or integer or it may contain an arbitrary nested
// object containing arrays, key-value lists and primitives.
#AnyValue: {
	string_value?: string
	bool_value?:   bool
	int_value?:    int64
	double_value?: float64
	array_value?:  #ArrayValue
	kvlist_value?: #KeyValueList
}

// ArrayValue is a list of AnyValue messages. We need ArrayValue as a message
// since oneof in AnyValue does not allow repeated fields.
#ArrayValue: {
	// Array of values. The array may be empty (contain 0 elements).
	values?: [...#AnyValue]
}

// KeyValueList is a list of KeyValue messages. We need KeyValueList as a message
// since `oneof` in AnyValue does not allow repeated fields. Everywhere else where we need
// a list of KeyValue messages (e.g. in Span) we use `repeated KeyValue` directly to
// avoid unnecessary extra wrapping (which slows down the protocol). The 2 approaches
// are semantically equivalent.
#KeyValueList: {
	// A collection of key/value pairs of key-value pairs. The list may be empty (may
	// contain 0 elements).
	values?: [...#KeyValue]
}

// KeyValue is a key-value pair that is used to store Span attributes, Link
// attributes, etc.
#KeyValue: {
	key?:   string
	value?: #AnyValue
}

// StringKeyValue is a pair of key/value strings. This is the simpler (and faster) version
// of KeyValue that only supports string values.
#StringKeyValue: {
	key?:   string
	value?: string
}

// InstrumentationLibrary is a message representing the instrumentation library information
// such as the fully qualified name and version.
#InstrumentationLibrary: {
	// An empty instrumentation library name means the name is unknown.
	name?:    string
	version?: string
}
