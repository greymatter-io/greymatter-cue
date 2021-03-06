package v3

import (
	v3 "envoyproxy.io/deps/cncf/xds/go/xds/core/v3"
)

#IPMatcher: {
	range_matchers?: [...#IPMatcher_IPRangeMatcher]
}

#IPMatcher_IPRangeMatcher: {
	ranges?: [...v3.#CidrRange]
	on_match?:  #Matcher_OnMatch
	exclusive?: bool
}
