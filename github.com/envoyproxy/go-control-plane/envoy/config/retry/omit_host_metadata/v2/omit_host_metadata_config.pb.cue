package v2

import (
	core "github.com/envoyproxy/go-control-plane/envoy/api/v2/core"
)

// A retry host predicate that can be used to reject a host based on
// predefined metadata match criteria.
// [#extension: envoy.retry_host_predicates.omit_host_metadata]
#OmitHostMetadataConfig: {
	// Retry host predicate metadata match criteria. The hosts in
	// the upstream cluster with matching metadata will be omitted while
	// attempting a retry of a failed request. The metadata should be specified
	// under the *envoy.lb* key.
	metadata_match?: core.#Metadata
}
