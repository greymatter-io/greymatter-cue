package v3

import (
	v3 "envoyproxy.io/deps/cncf/xds/go/xds/type/v3"
)

#Int64RangeMatcher: {
	range_matchers?: [...#Int64RangeMatcher_RangeMatcher]
}

#Int32RangeMatcher: {
	range_matchers?: [...#Int32RangeMatcher_RangeMatcher]
}

#DoubleRangeMatcher: {
	range_matchers?: [...#DoubleRangeMatcher_RangeMatcher]
}

#Int64RangeMatcher_RangeMatcher: {
	ranges?: [...v3.#Int64Range]
	on_match?: #Matcher_OnMatch
}

#Int32RangeMatcher_RangeMatcher: {
	ranges?: [...v3.#Int32Range]
	on_match?: #Matcher_OnMatch
}

#DoubleRangeMatcher_RangeMatcher: {
	ranges?: [...v3.#DoubleRange]
	on_match?: #Matcher_OnMatch
}
