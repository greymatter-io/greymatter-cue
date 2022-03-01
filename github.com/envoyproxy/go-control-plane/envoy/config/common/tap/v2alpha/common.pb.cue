package v2alpha

import (
	v2alpha "github.com/envoyproxy/go-control-plane/envoy/service/tap/v2alpha"
)

// Common configuration for all tap extensions.
#CommonExtensionConfig: {
	// If specified, the tap filter will be configured via an admin handler.
	admin_config?: #AdminConfig
	// If specified, the tap filter will be configured via a static configuration that cannot be
	// changed.
	static_config?: v2alpha.#TapConfig
}

// Configuration for the admin handler. See :ref:`here <config_http_filters_tap_admin_handler>` for
// more information.
#AdminConfig: {
	// Opaque configuration ID. When requests are made to the admin handler, the passed opaque ID is
	// matched to the configured filter opaque ID to determine which filter to configure.
	config_id?: string
}
