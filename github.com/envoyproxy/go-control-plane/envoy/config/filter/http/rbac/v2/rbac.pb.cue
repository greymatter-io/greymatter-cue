package v2

import (
	v2 "github.com/envoyproxy/go-control-plane/envoy/config/rbac/v2"
)

// RBAC filter config.
#RBAC: {
	// Specify the RBAC rules to be applied globally.
	// If absent, no enforcing RBAC policy will be applied.
	rules?: v2.#RBAC
	// Shadow rules are not enforced by the filter (i.e., returning a 403)
	// but will emit stats and logs and can be used for rule testing.
	// If absent, no shadow RBAC policy will be applied.
	shadow_rules?: v2.#RBAC
}

#RBACPerRoute: {
	// Override the global configuration of the filter with this new config.
	// If absent, the global RBAC policy will be disabled for this route.
	rbac?: #RBAC
}
