package matcher

import (
	_type "github.com/envoyproxy/go-control-plane/envoy/type"
)

// Specifies the way to match a double value.
#DoubleMatcher: {
	// If specified, the input double value must be in the range specified here.
	// Note: The range is using half-open interval semantics [start, end).
	range?: _type.#DoubleRange
	// If specified, the input double value must be equal to the value specified here.
	exact?: float64
}
