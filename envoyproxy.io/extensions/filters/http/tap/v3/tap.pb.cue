package v3

import (
	v3 "envoyproxy.io/extensions/common/tap/v3"
)

// Top level configuration for the tap filter.
#Tap: {
	// Common configuration for the HTTP tap filter.
	common_config?: v3.#CommonExtensionConfig
}
