package v3

import (
	v3 "envoyproxy.io/config/rbac/v3"
)

#RBAC_EnforcementType: "ONE_TIME_ON_FIRST_BYTE" | "CONTINUOUS"

RBAC_EnforcementType_ONE_TIME_ON_FIRST_BYTE: "ONE_TIME_ON_FIRST_BYTE"
RBAC_EnforcementType_CONTINUOUS:             "CONTINUOUS"

// RBAC network filter config.
//
// Header should not be used in rules/shadow_rules in RBAC network filter as
// this information is only available in :ref:`RBAC http filter <config_http_filters_rbac>`.
// [#next-free-field: 6]
#RBAC: {
	// Specify the RBAC rules to be applied globally.
	// If absent, no enforcing RBAC policy will be applied.
	// If present and empty, DENY.
	rules?: v3.#RBAC
	// Shadow rules are not enforced by the filter but will emit stats and logs
	// and can be used for rule testing.
	// If absent, no shadow RBAC policy will be applied.
	shadow_rules?: v3.#RBAC
	// If specified, shadow rules will emit stats with the given prefix.
	// This is useful to distinguish the stat when there are more than 1 RBAC filter configured with
	// shadow rules.
	shadow_rules_stat_prefix?: string
	// The prefix to use when emitting statistics.
	stat_prefix?: string
	// RBAC enforcement strategy. By default RBAC will be enforced only once
	// when the first byte of data arrives from the downstream. When used in
	// conjunction with filters that emit dynamic metadata after decoding
	// every payload (e.g., Mongo, MySQL, Kafka) set the enforcement type to
	// CONTINUOUS to enforce RBAC policies on every message boundary.
	enforcement_type?: #RBAC_EnforcementType
}
