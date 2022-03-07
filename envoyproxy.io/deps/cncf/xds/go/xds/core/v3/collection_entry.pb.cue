package v3

import (
	any "envoyproxy.io/deps/golang/protobuf/ptypes/any"
)

#CollectionEntry: {
	locator?:      #ResourceLocator
	inline_entry?: #CollectionEntry_InlineEntry
}

#CollectionEntry_InlineEntry: {
	name?:     string
	version?:  string
	resource?: any.#Any
}
