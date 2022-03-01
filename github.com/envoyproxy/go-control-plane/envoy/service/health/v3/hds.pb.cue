package v3

import (
	v31 "github.com/envoyproxy/go-control-plane/envoy/config/endpoint/v3"
	v32 "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	v3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
)

// Different Envoy instances may have different capabilities (e.g. Redis)
// and/or have ports enabled for different protocols.
#Capability_Protocol: "HTTP" | "TCP" | "REDIS"

Capability_Protocol_HTTP:  "HTTP"
Capability_Protocol_TCP:   "TCP"
Capability_Protocol_REDIS: "REDIS"

// Defines supported protocols etc, so the management server can assign proper
// endpoints to healthcheck.
#Capability: {
	health_check_protocols?: [...#Capability_Protocol]
}

#HealthCheckRequest: {
	node?:       v3.#Node
	capability?: #Capability
}

#EndpointHealth: {
	endpoint?:      v31.#Endpoint
	health_status?: v3.#HealthStatus
}

// Group endpoint health by locality under each cluster.
#LocalityEndpointsHealth: {
	locality?: v3.#Locality
	endpoints_health?: [...#EndpointHealth]
}

// The health status of endpoints in a cluster. The cluster name and locality
// should match the corresponding fields in ClusterHealthCheck message.
#ClusterEndpointsHealth: {
	cluster_name?: string
	locality_endpoints_health?: [...#LocalityEndpointsHealth]
}

#EndpointHealthResponse: {
	// Deprecated - Flat list of endpoint health information.
	//
	// Deprecated: Do not use.
	endpoints_health?: [...#EndpointHealth]
	// Organize Endpoint health information by cluster.
	cluster_endpoints_health?: [...#ClusterEndpointsHealth]
}

#HealthCheckRequestOrEndpointHealthResponse: {
	health_check_request?:     #HealthCheckRequest
	endpoint_health_response?: #EndpointHealthResponse
}

#LocalityEndpoints: {
	locality?: v3.#Locality
	endpoints?: [...v31.#Endpoint]
}

// The cluster name and locality is provided to Envoy for the endpoints that it
// health checks to support statistics reporting, logging and debugging by the
// Envoy instance (outside of HDS). For maximum usefulness, it should match the
// same cluster structure as that provided by EDS.
#ClusterHealthCheck: {
	cluster_name?: string
	health_checks?: [...v3.#HealthCheck]
	locality_endpoints?: [...#LocalityEndpoints]
	// Optional map that gets filtered by :ref:`health_checks.transport_socket_match_criteria <envoy_v3_api_field_config.core.v3.HealthCheck.transport_socket_match_criteria>`
	// on connection when health checking. For more details, see
	// :ref:`config.cluster.v3.Cluster.transport_socket_matches <envoy_v3_api_field_config.cluster.v3.Cluster.transport_socket_matches>`.
	transport_socket_matches?: [...v32.#Cluster_TransportSocketMatch]
}

#HealthCheckSpecifier: {
	cluster_health_checks?: [...#ClusterHealthCheck]
	// The default is 1 second.
	interval?: string
}

// [#not-implemented-hide:] Not configuration. Workaround c++ protobuf issue with importing
// services: https://github.com/google/protobuf/issues/4221 and protoxform to upgrade the file.
#HdsDummy: {
}

// HealthDiscoveryServiceClient is the client API for HealthDiscoveryService service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://godoc.org/google.golang.org/grpc#ClientConn.NewStream.
#HealthDiscoveryServiceClient: _

#HealthDiscoveryService_StreamHealthCheckClient: _

// HealthDiscoveryServiceServer is the server API for HealthDiscoveryService service.
#HealthDiscoveryServiceServer: _

// UnimplementedHealthDiscoveryServiceServer can be embedded to have forward compatible implementations.
#UnimplementedHealthDiscoveryServiceServer: {
}

#HealthDiscoveryService_StreamHealthCheckServer: _
