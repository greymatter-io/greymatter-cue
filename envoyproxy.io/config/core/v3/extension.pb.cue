package v3

// Message type for extension configuration.
// [#next-major-version: revisit all existing typed_config that doesn't use this wrapper.].
#TypedExtensionConfig: {
	// The name of an extension. This is not used to select the extension, instead
	// it serves the role of an opaque identifier.
	name?: string
	// The typed config for the extension. The type URL will be used to identify
	// the extension. In the case that the type URL is *xds.type.v3.TypedStruct*
	// (or, for historical reasons, *udpa.type.v1.TypedStruct*), the inner type
	// URL of *TypedStruct* will be utilized. See the
	// :ref:`extension configuration overview
	// <config_overview_extension_configuration>` for further details.
	typed_config?: _
}

// Configuration source specifier for a late-bound extension configuration. The
// parent resource is warmed until all the initial extension configurations are
// received, unless the flag to apply the default configuration is set.
// Subsequent extension updates are atomic on a per-worker basis. Once an
// extension configuration is applied to a request or a connection, it remains
// constant for the duration of processing. If the initial delivery of the
// extension configuration fails, due to a timeout for example, the optional
// default configuration is applied. Without a default configuration, the
// extension is disabled, until an extension configuration is received. The
// behavior of a disabled extension depends on the context. For example, a
// filter chain with a disabled extension filter rejects all incoming streams.
#ExtensionConfigSource: {
	config_source?: #ConfigSource
	// Optional default configuration to use as the initial configuration if
	// there is a failure to receive the initial extension configuration or if
	// `apply_default_config_without_warming` flag is set.
	default_config?: _
	// Use the default config as the initial configuration without warming and
	// waiting for the first discovery response. Requires the default configuration
	// to be supplied.
	apply_default_config_without_warming?: bool
	// A set of permitted extension type URLs. Extension configuration updates are rejected
	// if they do not match any type URL in the set.
	type_urls?: [...string]
}
