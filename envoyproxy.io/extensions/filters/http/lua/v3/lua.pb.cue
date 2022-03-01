package v3

import (
	v3 "envoyproxy.io/config/core/v3"
)

#Lua: {
	// The Lua code that Envoy will execute. This can be a very small script that
	// further loads code from disk if desired. Note that if JSON configuration is used, the code must
	// be properly escaped. YAML configuration may be easier to read since YAML supports multi-line
	// strings so complex scripts can be easily expressed inline in the configuration.
	inline_code?: string
	// Map of named Lua source codes that can be referenced in :ref:`LuaPerRoute
	// <envoy_v3_api_msg_extensions.filters.http.lua.v3.LuaPerRoute>`. The Lua source codes can be
	// loaded from inline string or local files.
	//
	// Example:
	//
	// .. code-block:: yaml
	//
	//   source_codes:
	//     hello.lua:
	//       inline_string: |
	//         function envoy_on_response(response_handle)
	//           -- Do something.
	//         end
	//     world.lua:
	//       filename: /etc/lua/world.lua
	//
	source_codes?: [string]: v3.#DataSource
}

#LuaPerRoute: {
	// Disable the Lua filter for this particular vhost or route. If disabled is specified in
	// multiple per-filter-configs, the most specific one will be used.
	disabled?: bool
	// A name of a Lua source code stored in
	// :ref:`Lua.source_codes <envoy_v3_api_field_extensions.filters.http.lua.v3.Lua.source_codes>`.
	name?: string
	// A configured per-route Lua source code that can be served by RDS or provided inline.
	source_code?: v3.#DataSource
}
