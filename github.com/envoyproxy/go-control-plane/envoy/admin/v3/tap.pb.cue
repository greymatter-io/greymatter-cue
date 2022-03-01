package v3

import (
	v3 "github.com/envoyproxy/go-control-plane/envoy/config/tap/v3"
)

// The /tap admin request body that is used to configure an active tap session.
#TapRequest: {
	// The opaque configuration ID used to match the configuration to a loaded extension.
	// A tap extension configures a similar opaque ID that is used to match.
	config_id?: string
	// The tap configuration to load.
	tap_config?: v3.#TapConfig
}
