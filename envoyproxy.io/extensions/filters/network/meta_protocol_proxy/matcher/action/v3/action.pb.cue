package v3

import (
	v3 "envoyproxy.io/config/route/v3"
)

// Configuration for the route match action.
// [#not-implemented-hide:]
#RouteAction: {
	// Indicates the upstream cluster to which the request should be routed.
	cluster?: string
	// Multiple upstream clusters can be specified for a given route. The request is routed to one
	// of the upstream clusters based on weights assigned to each cluster.
	// Currently ClusterWeight only supports the name and weight fields.
	weighted_clusters?: v3.#WeightedCluster
}
