package v3

// Available Zipkin collector endpoint versions.
#ZipkinConfig_CollectorEndpointVersion: "DEPRECATED_AND_UNAVAILABLE_DO_NOT_USE" | "HTTP_JSON" | "HTTP_PROTO" | "GRPC"

ZipkinConfig_CollectorEndpointVersion_DEPRECATED_AND_UNAVAILABLE_DO_NOT_USE: "DEPRECATED_AND_UNAVAILABLE_DO_NOT_USE"
ZipkinConfig_CollectorEndpointVersion_HTTP_JSON:                             "HTTP_JSON"
ZipkinConfig_CollectorEndpointVersion_HTTP_PROTO:                            "HTTP_PROTO"
ZipkinConfig_CollectorEndpointVersion_GRPC:                                  "GRPC"

// Configuration for the Zipkin tracer.
// [#extension: envoy.tracers.zipkin]
// [#next-free-field: 7]
#ZipkinConfig: {
	// The cluster manager cluster that hosts the Zipkin collectors.
	collector_cluster?: string
	// The API endpoint of the Zipkin service where the spans will be sent. When
	// using a standard Zipkin installation.
	collector_endpoint?: string
	// Determines whether a 128bit trace id will be used when creating a new
	// trace instance. The default value is false, which will result in a 64 bit trace id being used.
	trace_id_128bit?: bool
	// Determines whether client and server spans will share the same span context.
	// The default value is true.
	shared_span_context?: bool
	// Determines the selected collector endpoint version.
	collector_endpoint_version?: #ZipkinConfig_CollectorEndpointVersion
	// Optional hostname to use when sending spans to the collector_cluster. Useful for collectors
	// that require a specific hostname. Defaults to :ref:`collector_cluster <envoy_v3_api_field_config.trace.v3.ZipkinConfig.collector_cluster>` above.
	collector_hostname?: string
}
