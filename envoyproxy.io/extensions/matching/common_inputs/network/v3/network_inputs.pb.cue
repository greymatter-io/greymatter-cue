package v3

// Specifies that matching should be performed by the destination IP address.
#DestinationIPInput: {
}

// Specifies that matching should be performed by the destination port.
#DestinationPortInput: {
}

// Specifies that matching should be performed by the source IP address.
#SourceIPInput: {
}

// Specifies that matching should be performed by the source port.
#SourcePortInput: {
}

// Input that matches by the directly connected source IP address (this
// will only be different from the source IP address when using a listener
// filter that overrides the source address, such as the :ref:`Proxy Protocol
// listener filter <config_listener_filters_proxy_protocol>`).
#DirectSourceIPInput: {
}

// Input that matches by the source IP type.
// Specifies the source IP match type. The values include:
//
// * ``local`` - matches a connection originating from the same host,
#SourceTypeInput: {
}

// Input that matches by the requested server name (e.g. SNI in TLS).
//
// :ref:`TLS Inspector <config_listener_filters_tls_inspector>` provides the requested server name based on SNI,
// when TLS protocol is detected.
#ServerNameInput: {
}

// Input that matches by the transport protocol.
//
// Suggested values include:
//
// * ``raw_buffer`` - default, used when no transport protocol is detected,
// * ``tls`` - set by :ref:`envoy.filters.listener.tls_inspector <config_listener_filters_tls_inspector>`
//   when TLS protocol is detected.
#TransportProtocolInput: {
}

// List of quoted and comma-separated requested application protocols. The list consists of a
// single negotiated application protocol once the network stream is established.
//
// Examples:
//
// * ``'h2','http/1.1'``
// * ``'h2c'```
//
// Suggested values in the list include:
//
// * ``http/1.1`` - set by :ref:`envoy.filters.listener.tls_inspector
//   <config_listener_filters_tls_inspector>` and :ref:`envoy.filters.listener.http_inspector
//   <config_listener_filters_http_inspector>`,
// * ``h2`` - set by :ref:`envoy.filters.listener.tls_inspector <config_listener_filters_tls_inspector>`
// * ``h2c`` - set by :ref:`envoy.filters.listener.http_inspector <config_listener_filters_http_inspector>`
//
// .. attention::
//
//   Currently, :ref:`TLS Inspector <config_listener_filters_tls_inspector>` provides
//   application protocol detection based on the requested
//   `ALPN <https://en.wikipedia.org/wiki/Application-Layer_Protocol_Negotiation>`_ values.
//
//   However, the use of ALPN is pretty much limited to the HTTP/2 traffic on the Internet,
//   and matching on values other than ``h2`` is going to lead to a lot of false negatives,
//   unless all connecting clients are known to use ALPN.
#ApplicationProtocolInput: {
}