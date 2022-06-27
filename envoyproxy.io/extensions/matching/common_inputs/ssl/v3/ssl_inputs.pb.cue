package v3

// List of comma-delimited URIs in the SAN field of the peer certificate for a downstream.
// [#extension: envoy.matching.inputs.uri_san]
#UriSanInput: {
}

// List of comma-delimited DNS entries in the SAN field of the peer certificate for a downstream.
// [#extension: envoy.matching.inputs.dns_san]
#DnsSanInput: {
}

// Input that matches the subject field of the peer certificate in RFC 2253 format for a
// downstream.
// [#extension: envoy.matching.inputs.subject]
#SubjectInput: {
}
