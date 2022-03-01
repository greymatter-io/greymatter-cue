package v2alpha

import (
	v2alpha "envoyproxy.io/config/common/tap/v2alpha"
)

// Top level configuration for the tap filter.
#Tap: {
	// Common configuration for the HTTP tap filter.
	common_config?: v2alpha.#CommonExtensionConfig
}
