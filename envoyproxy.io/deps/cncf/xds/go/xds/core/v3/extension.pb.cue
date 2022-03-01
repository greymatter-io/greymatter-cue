package v3

import (
	any "envoyproxy.io/deps/golang/protobuf/ptypes/any"
)

#TypedExtensionConfig: {
	name?:         string
	typed_config?: any.#Any
}
