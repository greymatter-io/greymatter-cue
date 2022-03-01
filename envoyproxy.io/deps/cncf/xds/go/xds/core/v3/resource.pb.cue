package v3

import (
	any "envoyproxy.io/deps/golang/protobuf/ptypes/any"
)

#Resource: {
	name?:     #ResourceName
	version?:  string
	resource?: any.#Any
}
