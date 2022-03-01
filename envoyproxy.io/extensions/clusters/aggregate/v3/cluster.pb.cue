package v3

// Configuration for the aggregate cluster. See the :ref:`architecture overview
// <arch_overview_aggregate_cluster>` for more information.
// [#extension: envoy.clusters.aggregate]
#ClusterConfig: {
	// Load balancing clusters in aggregate cluster. Clusters are prioritized based on the order they
	// appear in this list.
	clusters?: [...string]
}
