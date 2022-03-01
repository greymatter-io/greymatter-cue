package v3

import (
	v3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
)

// This shared configuration for Envoy key value stores.
#KeyValueStoreConfig: {
	// [#extension-category: envoy.common.key_value]
	config?: v3.#TypedExtensionConfig
}
