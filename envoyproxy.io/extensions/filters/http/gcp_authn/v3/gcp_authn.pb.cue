package v3

import (
	v3 "envoyproxy.io/config/core/v3"
)

// Filter configuration.
#GcpAuthnFilterConfig: {
	// The HTTP URI to fetch tokens from GCE Metadata Server(https://cloud.google.com/compute/docs/metadata/overview).
	// The URL format is "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/identity?audience=[AUDIENCE]"
	http_uri?: v3.#HttpUri
	// Retry policy for fetching tokens.
	// This field is optional. If it is not configured, the filter will be fail-closed (i.e., reject the requests).
	retry_policy?: v3.#RetryPolicy
}

// Audience is the URL of the receiving service that performs token authentication.
// It will be provided to the filter through cluster's typed_filter_metadata.
#Audience: {
	url?: string
}
