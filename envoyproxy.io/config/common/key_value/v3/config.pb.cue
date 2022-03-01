package v3

import (
	v3 "envoyproxy.io/config/core/v3"
)

// This shared configuration for Envoy key value stores.
#KeyValueStoreConfig: {
	// [#extension-category: envoy.common.key_value]
	config?: v3.#TypedExtensionConfig
}
