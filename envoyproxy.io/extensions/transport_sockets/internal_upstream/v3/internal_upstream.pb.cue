package v3

import (
	v3 "envoyproxy.io/config/core/v3"
	v31 "envoyproxy.io/type/metadata/v3"
)

// Configuration for the internal upstream address. An internal address defines
// a loopback user space socket residing in the same proxy instance. This
// extension allows passing additional structured state across the user space
// socket in addition to the regular byte stream. The purpose is to facilitate
// communication between filters on the downstream and the upstream internal
// connections.
//
// Because the passthrough state is transferred once per the upstream
// connection before the bytes payload, every passthrough filter state object
// is included in the hash key used to select an upstream connection if it
// implements a hashing interface.
//
// .. note::
//
//  Using internal upstream transport affects load balancing decisions if the
//  passthrough state is derived from the downstream connection attributes. As
//  an example, using the downstream source IP in the passthrough state will
//  prevent sharing of an upstream internal connection between different source
//  IPs.
#InternalUpstreamTransport: {
	// Specifies the metadata namespaces and values to insert into the downstream
	// internal connection dynamic metadata when an internal address is used as a
	// host. If the destination name is repeated across two metadata source
	// locations, and both locations contain the metadata with the given name,
	// then the latter in the list overrides the former.
	passthrough_metadata?: [...#InternalUpstreamTransport_MetadataValueSource]
	// Specifies the list of the filter state object names to insert into the
	// server internal connection from the downstream connection when an internal
	// address is used as a host. The filter state objects must be mutable. These
	// objects participate in the connection hashing decisions if they implement a
	// hashing function.
	passthrough_filter_state_objects?: [...#InternalUpstreamTransport_FilterStateSource]
	// The underlying transport socket being wrapped.
	transport_socket?: v3.#TransportSocket
}

// Describes the location of the imported metadata value.
// If the metadata with the given name is not present at the source location,
// then no metadata is passed through for this particular instance.
#InternalUpstreamTransport_MetadataValueSource: {
	// Specifies what kind of metadata.
	kind?: v31.#MetadataKind
	// Name is the filter namespace used in the dynamic metadata.
	name?: string
}

// Describes the location of the imported filter state object from the downstream connection.
#InternalUpstreamTransport_FilterStateSource: {
	// Name is the imported filter state object name.
	name?: string
}
