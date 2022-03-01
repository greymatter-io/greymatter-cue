package v3

import (
	v3 "github.com/envoyproxy/go-control-plane/envoy/type/v3"
)

// This extension allows for the original downstream remote IP to be detected
// by reading the value from a configured header name. If the value is successfully parsed
// as an IP, it'll be treated as the effective downstream remote address and seen as such
// by all filters. See :ref:`original_ip_detection_extensions
// <envoy_v3_api_field_extensions.filters.network.http_connection_manager.v3.HttpConnectionManager.original_ip_detection_extensions>`
// for an overview of how extensions operate and what happens when an extension fails
// to detect the remote IP.
//
// [#extension: envoy.http.original_ip_detection.custom_header]
#CustomHeaderConfig: {
	// The header name containing the original downstream remote address, if present.
	//
	// Note: in the case of a multi-valued header, only the first value is tried and the rest are ignored.
	header_name?: string
	// If set to true, the extension could decide that the detected address should be treated as
	// trusted by the HCM. If the address is considered :ref:`trusted<config_http_conn_man_headers_x-forwarded-for_trusted_client_address>`,
	// it might be used as input to determine if the request is internal (among other things).
	allow_extension_to_set_address_as_trusted?: bool
	// If this is set, the request will be rejected when detection fails using it as the HTTP response status.
	//
	// .. note::
	//   If this is set to < 400 or > 511, the default status 403 will be used instead.
	reject_with_status?: v3.#HttpStatus
}
