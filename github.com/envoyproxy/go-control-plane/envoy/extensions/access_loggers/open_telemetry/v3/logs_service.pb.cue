package v3

import (
	v3 "github.com/envoyproxy/go-control-plane/envoy/extensions/access_loggers/grpc/v3"
	v1 "go.opentelemetry.io/proto/otlp/common/v1"
)

// Configuration for the built-in *envoy.access_loggers.open_telemetry*
// :ref:`AccessLog <envoy_v3_api_msg_config.accesslog.v3.AccessLog>`. This configuration will
// populate `opentelemetry.proto.collector.v1.logs.ExportLogsServiceRequest.resource_logs <https://github.com/open-telemetry/opentelemetry-proto/blob/main/opentelemetry/proto/collector/logs/v1/logs_service.proto>`_.
// OpenTelemetry `Resource <https://github.com/open-telemetry/opentelemetry-proto/blob/main/opentelemetry/proto/resource/v1/resource.proto>`_
// attributes are filled with Envoy node info. In addition, the request start time is set in the
// dedicated field.
// [#extension: envoy.access_loggers.open_telemetry]
// [#comment:TODO(itamarkam): allow configuration for resource attributes.]
#OpenTelemetryAccessLogConfig: {
	// [#comment:TODO(itamarkam): add 'filter_state_objects_to_log' to logs.]
	common_config?: v3.#CommonGrpcAccessLogConfig
	// OpenTelemetry `LogResource <https://github.com/open-telemetry/opentelemetry-proto/blob/main/opentelemetry/proto/logs/v1/logs.proto>`_
	// fields, following `Envoy access logging formatting <https://www.envoyproxy.io/docs/envoy/latest/configuration/observability/access_log/usage>`_.
	//
	// See 'body' in the LogResource proto for more details.
	// Example: ``body { string_value: "%PROTOCOL%" }``.
	body?: v1.#AnyValue
	// See 'attributes' in the LogResource proto for more details.
	// Example: ``attributes { values { key: "user_agent" value { string_value: "%REQ(USER-AGENT)%" } } }``.
	attributes?: v1.#KeyValueList
}
