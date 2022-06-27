package v3

// The Original Src filter binds upstream connections to the original source address determined
// for the connection. This address could come from something like the Proxy Protocol filter, or it
// could come from trusted http headers.
#OriginalSrc: {
	"@type": "type.googleapis.com/envoy.extensions.filters.listener.original_src.v3.OriginalSrc"
	// Whether to bind the port to the one used in the original downstream connection.
	// [#not-implemented-hide:]
	bind_port?: bool
	// Sets the SO_MARK option on the upstream connection's socket to the provided value. Used to
	// ensure that non-local addresses may be routed back through envoy when binding to the original
	// source address. The option will not be applied if the mark is 0.
	mark?: uint32
}
