package v3

import (
)

#CollectionEntry: {
	locator?:      #ResourceLocator
	inline_entry?: #CollectionEntry_InlineEntry
}

#CollectionEntry_InlineEntry: {
	name?:     string
	version?:  string
	resource?: _
}
