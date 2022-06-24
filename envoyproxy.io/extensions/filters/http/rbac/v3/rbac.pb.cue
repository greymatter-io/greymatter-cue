package v3

import (
	v3 "envoyproxy.io/config/rbac/v3"
)

// RBAC filter config.
#RBAC: {
	"@type": "type.googleapis.com/envoy.extensions.filters.http.rbac.v3.RBAC"
	// Specify the RBAC rules to be applied globally.
	// If absent, no enforcing RBAC policy will be applied.
	// If present and empty, DENY.
	rules?: v3.#RBAC
	// Shadow rules are not enforced by the filter (i.e., returning a 403)
	// but will emit stats and logs and can be used for rule testing.
	// If absent, no shadow RBAC policy will be applied.
	shadow_rules?: v3.#RBAC
	// If specified, shadow rules will emit stats with the given prefix.
	// This is useful to distinguish the stat when there are more than 1 RBAC filter configured with
	// shadow rules.
	shadow_rules_stat_prefix?: string
}

#RBACPerRoute: {
	"@type": "type.googleapis.com/envoy.extensions.filters.http.rbac.v3.RBACPerRoute"
	// Override the global configuration of the filter with this new config.
	// If absent, the global RBAC policy will be disabled for this route.
	rbac?: #RBAC
}
