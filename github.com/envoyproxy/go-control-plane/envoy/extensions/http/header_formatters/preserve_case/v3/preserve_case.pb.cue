package v3

// Configuration for the preserve case header formatter.
// See the :ref:`header casing <config_http_conn_man_header_casing>` configuration guide for more
// information.
#PreserveCaseFormatterConfig: {
	// Allows forwarding reason phrase text.
	// This is off by default, and a standard reason phrase is used for a corresponding HTTP response code.
	forward_reason_phrase?: bool
}
