package v2

import (
	_type "github.com/envoyproxy/go-control-plane/envoy/type"
	status "google.golang.org/genproto/googleapis/rpc/status"
	core "github.com/envoyproxy/go-control-plane/envoy/api/v2/core"
)

#CheckRequest: {
	// The request attributes.
	attributes?: #AttributeContext
}

// HTTP attributes for a denied response.
#DeniedHttpResponse: {
	// This field allows the authorization service to send a HTTP response status
	// code to the downstream client other than 403 (Forbidden).
	status?: _type.#HttpStatus
	// This field allows the authorization service to send HTTP response headers
	// to the downstream client. Note that the `append` field in `HeaderValueOption` defaults to
	// false when used in this message.
	headers?: [...core.#HeaderValueOption]
	// This field allows the authorization service to send a response body data
	// to the downstream client.
	body?: string
}

// HTTP attributes for an ok response.
#OkHttpResponse: {
	// HTTP entity headers in addition to the original request headers. This allows the authorization
	// service to append, to add or to override headers from the original request before
	// dispatching it to the upstream. Note that the `append` field in `HeaderValueOption` defaults to
	// false when used in this message. By setting the `append` field to `true`,
	// the filter will append the correspondent header value to the matched request header.
	// By leaving `append` as false, the filter will either add a new header, or override an existing
	// one if there is a match.
	headers?: [...core.#HeaderValueOption]
}

// Intended for gRPC and Network Authorization servers `only`.
#CheckResponse: {
	// Status `OK` allows the request. Any other status indicates the request should be denied.
	status?: status.#Status
	// Supplies http attributes for a denied response.
	denied_response?: #DeniedHttpResponse
	// Supplies http attributes for an ok response.
	ok_response?: #OkHttpResponse
}

// AuthorizationClient is the client API for Authorization service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://godoc.org/google.golang.org/grpc#ClientConn.NewStream.
#AuthorizationClient: _

// AuthorizationServer is the server API for Authorization service.
#AuthorizationServer: _

// UnimplementedAuthorizationServer can be embedded to have forward compatible implementations.
#UnimplementedAuthorizationServer: {
}
