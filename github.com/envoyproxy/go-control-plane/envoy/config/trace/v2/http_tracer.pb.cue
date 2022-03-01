package v2

// The tracing configuration specifies settings for an HTTP tracer provider used by Envoy.
//
// Envoy may support other tracers in the future, but right now the HTTP tracer is the only one
// supported.
//
// .. attention::
//
//   Use of this message type has been deprecated in favor of direct use of
//   :ref:`Tracing.Http <envoy_api_msg_config.trace.v2.Tracing.Http>`.
#Tracing: {
	// Provides configuration for the HTTP tracer.
	http?: #Tracing_Http
}

// Configuration for an HTTP tracer provider used by Envoy.
//
// The configuration is defined by the
// :ref:`HttpConnectionManager.Tracing <envoy_api_msg_config.filter.network.http_connection_manager.v2.HttpConnectionManager.Tracing>`
// :ref:`provider <envoy_api_field_config.filter.network.http_connection_manager.v2.HttpConnectionManager.Tracing.provider>`
// field.
#Tracing_Http: {
	// The name of the HTTP trace driver to instantiate. The name must match a
	// supported HTTP trace driver. Built-in trace drivers:
	//
	// - *envoy.tracers.lightstep*
	// - *envoy.tracers.zipkin*
	// - *envoy.tracers.dynamic_ot*
	// - *envoy.tracers.datadog*
	// - *envoy.tracers.opencensus*
	// - *envoy.tracers.xray*
	name?: string
	// Deprecated: Do not use.
	config?:       _
	typed_config?: _
}
