package v3

#Config_InvocationMode: "SYNCHRONOUS" | "ASYNCHRONOUS"

Config_InvocationMode_SYNCHRONOUS:  "SYNCHRONOUS"
Config_InvocationMode_ASYNCHRONOUS: "ASYNCHRONOUS"

// AWS Lambda filter config
#Config: {
	// The ARN of the AWS Lambda to invoke when the filter is engaged
	// Must be in the following format:
	// arn:<partition>:lambda:<region>:<account-number>:function:<function-name>
	arn?: string
	// Whether to transform the request (headers and body) to a JSON payload or pass it as is.
	payload_passthrough?: bool
	// Determines the way to invoke the Lambda function.
	invocation_mode?: #Config_InvocationMode
}

// Per-route configuration for AWS Lambda. This can be useful when invoking a different Lambda function or a different
// version of the same Lambda depending on the route.
#PerRouteConfig: {
	invoke_config?: #Config
}
