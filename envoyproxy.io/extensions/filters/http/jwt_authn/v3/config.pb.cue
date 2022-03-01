package v3

import (
	emptypb "envoyproxy.io/deps/protobuf/types/known/emptypb"
	v3 "envoyproxy.io/config/core/v3"
	v31 "envoyproxy.io/config/route/v3"
)

// Please see following for JWT authentication flow:
//
// * `JSON Web Token (JWT) <https://tools.ietf.org/html/rfc7519>`_
// * `The OAuth 2.0 Authorization Framework <https://tools.ietf.org/html/rfc6749>`_
// * `OpenID Connect <http://openid.net/connect>`_
//
// A JwtProvider message specifies how a JSON Web Token (JWT) can be verified. It specifies:
//
// * issuer: the principal that issues the JWT. If specified, it has to match the *iss* field in JWT.
// * allowed audiences: the ones in the token have to be listed here.
// * how to fetch public key JWKS to verify the token signature.
// * how to extract JWT token in the request.
// * how to pass successfully verified token payload.
//
// Example:
//
// .. code-block:: yaml
//
//     issuer: https://example.com
//     audiences:
//     - bookstore_android.apps.googleusercontent.com
//     - bookstore_web.apps.googleusercontent.com
//     remote_jwks:
//       http_uri:
//         uri: https://example.com/.well-known/jwks.json
//         cluster: example_jwks_cluster
//         timeout: 1s
//       cache_duration:
//         seconds: 300
//
// [#next-free-field: 15]
#JwtProvider: {
	// Specify the `principal <https://tools.ietf.org/html/rfc7519#section-4.1.1>`_ that issued
	// the JWT, usually a URL or an email address.
	//
	// It is optional. If specified, it has to match the *iss* field in JWT.
	//
	// If a JWT has *iss* field and this field is specified, they have to match, otherwise the
	// JWT *iss* field is not checked.
	//
	// Note: *JwtRequirement* :ref:`allow_missing <envoy_v3_api_field_extensions.filters.http.jwt_authn.v3.JwtRequirement.allow_missing>`
	// and :ref:`allow_missing_or_failed <envoy_v3_api_field_extensions.filters.http.jwt_authn.v3.JwtRequirement.allow_missing_or_failed>`
	// are implemented differently than other *JwtRequirements*. Hence the usage of this field
	// is different as follows if *allow_missing* or *allow_missing_or_failed* is used:
	//
	// * If a JWT has *iss* field, it needs to be specified by this field in one of *JwtProviders*.
	// * If a JWT doesn't have *iss* field, one of *JwtProviders* should fill this field empty.
	// * Multiple *JwtProviders* should not have same value in this field.
	//
	// Example: https://securetoken.google.com
	// Example: 1234567-compute@developer.gserviceaccount.com
	//
	issuer?: string
	// The list of JWT `audiences <https://tools.ietf.org/html/rfc7519#section-4.1.3>`_ are
	// allowed to access. A JWT containing any of these audiences will be accepted. If not specified,
	// will not check audiences in the token.
	//
	// Example:
	//
	// .. code-block:: yaml
	//
	//     audiences:
	//     - bookstore_android.apps.googleusercontent.com
	//     - bookstore_web.apps.googleusercontent.com
	//
	audiences?: [...string]
	// JWKS can be fetched from remote server via HTTP/HTTPS. This field specifies the remote HTTP
	// URI and how the fetched JWKS should be cached.
	//
	// Example:
	//
	// .. code-block:: yaml
	//
	//    remote_jwks:
	//      http_uri:
	//        uri: https://www.googleapis.com/oauth2/v1/certs
	//        cluster: jwt.www.googleapis.com|443
	//        timeout: 1s
	//      cache_duration:
	//        seconds: 300
	//
	remote_jwks?: #RemoteJwks
	// JWKS is in local data source. It could be either in a local file or embedded in the
	// inline_string.
	//
	// Example: local file
	//
	// .. code-block:: yaml
	//
	//    local_jwks:
	//      filename: /etc/envoy/jwks/jwks1.txt
	//
	// Example: inline_string
	//
	// .. code-block:: yaml
	//
	//    local_jwks:
	//      inline_string: ACADADADADA
	//
	local_jwks?: v3.#DataSource
	// If false, the JWT is removed in the request after a success verification. If true, the JWT is
	// not removed in the request. Default value is false.
	// caveat: only works for from_header & has no effect for JWTs extracted through from_params & from_cookies.
	forward?: bool
	// Two fields below define where to extract the JWT from an HTTP request.
	//
	// If no explicit location is specified, the following default locations are tried in order:
	//
	// 1. The Authorization header using the `Bearer schema
	// <https://tools.ietf.org/html/rfc6750#section-2.1>`_. Example::
	//
	//    Authorization: Bearer <token>.
	//
	// 2. `access_token <https://tools.ietf.org/html/rfc6750#section-2.3>`_ query parameter.
	//
	// Multiple JWTs can be verified for a request. Each JWT has to be extracted from the locations
	// its provider specified or from the default locations.
	//
	// Specify the HTTP headers to extract JWT token. For examples, following config:
	//
	// .. code-block:: yaml
	//
	//   from_headers:
	//   - name: x-goog-iap-jwt-assertion
	//
	// can be used to extract token from header::
	//
	//   ``x-goog-iap-jwt-assertion: <JWT>``.
	//
	from_headers?: [...#JwtHeader]
	// JWT is sent in a query parameter. `jwt_params` represents the query parameter names.
	//
	// For example, if config is:
	//
	// .. code-block:: yaml
	//
	//   from_params:
	//   - jwt_token
	//
	// The JWT format in query parameter is::
	//
	//    /path?jwt_token=<JWT>
	//
	from_params?: [...string]
	// JWT is sent in a cookie. `from_cookies` represents the cookie names to extract from.
	//
	// For example, if config is:
	//
	// .. code-block:: yaml
	//
	//   from_cookies:
	//   - auth-token
	//
	// Then JWT will be extracted from `auth-token` cookie in the request.
	//
	from_cookies?: [...string]
	// This field specifies the header name to forward a successfully verified JWT payload to the
	// backend. The forwarded data is::
	//
	//    base64url_encoded(jwt_payload_in_JSON)
	//
	// If it is not specified, the payload will not be forwarded.
	forward_payload_header?: string
	// When :ref:`forward_payload_header <envoy_v3_api_field_extensions.filters.http.jwt_authn.v3.JwtProvider.forward_payload_header>`
	// is specified, the base64 encoded payload will be added to the headers.
	// Normally JWT based64 encode doesn't add padding. If this field is true,
	// the header will be padded.
	//
	// This field is only relevant if :ref:`forward_payload_header <envoy_v3_api_field_extensions.filters.http.jwt_authn.v3.JwtProvider.forward_payload_header>`
	// is specified.
	pad_forward_payload_header?: bool
	// If non empty, successfully verified JWT payloads will be written to StreamInfo DynamicMetadata
	// in the format as: *namespace* is the jwt_authn filter name as **envoy.filters.http.jwt_authn**
	// The value is the *protobuf::Struct*. The value of this field will be the key for its *fields*
	// and the value is the *protobuf::Struct* converted from JWT JSON payload.
	//
	// For example, if payload_in_metadata is *my_payload*:
	//
	// .. code-block:: yaml
	//
	//   envoy.filters.http.jwt_authn:
	//     my_payload:
	//       iss: https://example.com
	//       sub: test@example.com
	//       aud: https://example.com
	//       exp: 1501281058
	//
	payload_in_metadata?: string
	// If not empty, similar to :ref:`payload_in_metadata <envoy_v3_api_field_extensions.filters.http.jwt_authn.v3.JwtProvider.payload_in_metadata>`,
	// a successfully verified JWT header will be written to :ref:`Dynamic State <arch_overview_data_sharing_between_filters>`
	// as an entry (``protobuf::Struct``) in **envoy.filters.http.jwt_authn** *namespace* with the
	// value of this field as the key.
	//
	// For example, if ``header_in_metadata`` is *my_header*:
	//
	// .. code-block:: yaml
	//
	//   envoy.filters.http.jwt_authn:
	//     my_header:
	//       alg: JWT
	//       kid: EF71iSaosbC5C4tC6Syq1Gm647M
	//       alg: PS256
	//
	// When the metadata has **envoy.filters.http.jwt_authn** entry already (for example if
	// :ref:`payload_in_metadata <envoy_v3_api_field_extensions.filters.http.jwt_authn.v3.JwtProvider.payload_in_metadata>`
	// is not empty), it will be inserted as a new entry in the same *namespace* as shown below:
	//
	// .. code-block:: yaml
	//
	//   envoy.filters.http.jwt_authn:
	//     my_payload:
	//       iss: https://example.com
	//       sub: test@example.com
	//       aud: https://example.com
	//       exp: 1501281058
	//     my_header:
	//       alg: JWT
	//       kid: EF71iSaosbC5C4tC6Syq1Gm647M
	//       alg: PS256
	//
	// .. warning::
	//   Using the same key name for :ref:`header_in_metadata <envoy_v3_api_field_extensions.filters.http.jwt_authn.v3.JwtProvider.payload_in_metadata>`
	//   and :ref:`payload_in_metadata <envoy_v3_api_field_extensions.filters.http.jwt_authn.v3.JwtProvider.payload_in_metadata>`
	//   is not suggested due to potential override of existing entry, while it is not enforced during
	//   config validation.
	//
	header_in_metadata?: string
	// Specify the clock skew in seconds when verifying JWT time constraint,
	// such as `exp`, and `nbf`. If not specified, default is 60 seconds.
	clock_skew_seconds?: uint32
	// Enables JWT cache, its size is specified by *jwt_cache_size*.
	// Only valid JWT tokens are cached.
	jwt_cache_config?: #JwtCacheConfig
}

// This message specifies JWT Cache configuration.
#JwtCacheConfig: {
	// The unit is number of JWT tokens, default to 100.
	jwt_cache_size?: uint32
}

// This message specifies how to fetch JWKS from remote and how to cache it.
#RemoteJwks: {
	// The HTTP URI to fetch the JWKS. For example:
	//
	// .. code-block:: yaml
	//
	//    http_uri:
	//      uri: https://www.googleapis.com/oauth2/v1/certs
	//      cluster: jwt.www.googleapis.com|443
	//      timeout: 1s
	//
	http_uri?: v3.#HttpUri
	// Duration after which the cached JWKS should be expired. If not specified, default cache
	// duration is 5 minutes.
	cache_duration?: string
	// Fetch Jwks asynchronously in the main thread before the listener is activated.
	// Fetched Jwks can be used by all worker threads.
	//
	// If this feature is not enabled:
	//
	// * The Jwks is fetched on-demand when the requests come. During the fetching, first
	//   few requests are paused until the Jwks is fetched.
	// * Each worker thread fetches its own Jwks since Jwks cache is per worker thread.
	//
	// If this feature is enabled:
	//
	// * Fetched Jwks is done in the main thread before the listener is activated. Its fetched
	//   Jwks can be used by all worker threads. Each worker thread doesn't need to fetch its own.
	// * Jwks is ready when the requests come, not need to wait for the Jwks fetching.
	//
	async_fetch?: #JwksAsyncFetch
	// Retry policy for fetching Jwks. optional. turned off by default.
	//
	// For example:
	//
	// .. code-block:: yaml
	//
	//   retry_policy:
	//     retry_back_off:
	//       base_interval: 0.01s
	//       max_interval: 20s
	//     num_retries: 10
	//
	// will yield a randomized truncated exponential backoff policy with an initial delay of 10ms
	// 10 maximum attempts spaced at most 20s seconds.
	//
	// .. code-block:: yaml
	//
	//   retry_policy:
	//     num_retries:1
	//
	// uses the default :ref:`retry backoff strategy <envoy_v3_api_msg_config.core.v3.BackoffStrategy>`.
	// with the default base interval is 1000 milliseconds. and the default maximum interval of 10 times the base interval.
	//
	// if num_retries is omitted, the default is to allow only one retry.
	//
	//
	// If enabled, the retry policy will apply to all Jwks fetching approaches, e.g. on demand or asynchronously in background.
	//
	//
	retry_policy?: v3.#RetryPolicy
}

// Fetch Jwks asynchronously in the main thread when the filter config is parsed.
// The listener is activated only after the Jwks is fetched.
// When the Jwks is expired in the cache, it is fetched again in the main thread.
// The fetched Jwks from the main thread can be used by all worker threads.
#JwksAsyncFetch: {
	// If false, the listener is activated after the initial fetch is completed.
	// The initial fetch result can be either successful or failed.
	// If true, it is activated without waiting for the initial fetch to complete.
	// Default is false.
	fast_listener?: bool
}

// This message specifies a header location to extract JWT token.
#JwtHeader: {
	// The HTTP header name.
	name?: string
	// The value prefix. The value format is "value_prefix<token>"
	// For example, for "Authorization: Bearer <token>", value_prefix="Bearer " with a space at the
	// end.
	value_prefix?: string
}

// Specify a required provider with audiences.
#ProviderWithAudiences: {
	// Specify a required provider name.
	provider_name?: string
	// This field overrides the one specified in the JwtProvider.
	audiences?: [...string]
}

// This message specifies a Jwt requirement. An empty message means JWT verification is not
// required. Here are some config examples:
//
// .. code-block:: yaml
//
//  # Example 1: not required with an empty message
//
//  # Example 2: require A
//  provider_name: provider-A
//
//  # Example 3: require A or B
//  requires_any:
//    requirements:
//      - provider_name: provider-A
//      - provider_name: provider-B
//
//  # Example 4: require A and B
//  requires_all:
//    requirements:
//      - provider_name: provider-A
//      - provider_name: provider-B
//
//  # Example 5: require A and (B or C)
//  requires_all:
//    requirements:
//      - provider_name: provider-A
//      - requires_any:
//        requirements:
//          - provider_name: provider-B
//          - provider_name: provider-C
//
//  # Example 6: require A or (B and C)
//  requires_any:
//    requirements:
//      - provider_name: provider-A
//      - requires_all:
//        requirements:
//          - provider_name: provider-B
//          - provider_name: provider-C
//
//  # Example 7: A is optional (if token from A is provided, it must be valid, but also allows
//  missing token.)
//  requires_any:
//    requirements:
//    - provider_name: provider-A
//    - allow_missing: {}
//
//  # Example 8: A is optional and B is required.
//  requires_all:
//    requirements:
//    - requires_any:
//        requirements:
//        - provider_name: provider-A
//        - allow_missing: {}
//    - provider_name: provider-B
//
// [#next-free-field: 7]
#JwtRequirement: {
	// Specify a required provider name.
	provider_name?: string
	// Specify a required provider with audiences.
	provider_and_audiences?: #ProviderWithAudiences
	// Specify list of JwtRequirement. Their results are OR-ed.
	// If any one of them passes, the result is passed.
	requires_any?: #JwtRequirementOrList
	// Specify list of JwtRequirement. Their results are AND-ed.
	// All of them must pass, if one of them fails or missing, it fails.
	requires_all?: #JwtRequirementAndList
	// The requirement is always satisfied even if JWT is missing or the JWT
	// verification fails. A typical usage is: this filter is used to only verify
	// JWTs and pass the verified JWT payloads to another filter, the other filter
	// will make decision. In this mode, all JWT tokens will be verified.
	allow_missing_or_failed?: emptypb.#Empty
	// The requirement is satisfied if JWT is missing, but failed if JWT is
	// presented but invalid. Similar to allow_missing_or_failed, this is used
	// to only verify JWTs and pass the verified payload to another filter. The
	// different is this mode will reject requests with invalid tokens.
	allow_missing?: emptypb.#Empty
}

// This message specifies a list of RequiredProvider.
// Their results are OR-ed; if any one of them passes, the result is passed
#JwtRequirementOrList: {
	// Specify a list of JwtRequirement.
	requirements?: [...#JwtRequirement]
}

// This message specifies a list of RequiredProvider.
// Their results are AND-ed; all of them must pass, if one of them fails or missing, it fails.
#JwtRequirementAndList: {
	// Specify a list of JwtRequirement.
	requirements?: [...#JwtRequirement]
}

// This message specifies a Jwt requirement for a specific Route condition.
// Example 1:
//
// .. code-block:: yaml
//
//    - match:
//        prefix: /healthz
//
// In above example, "requires" field is empty for /healthz prefix match,
// it means that requests matching the path prefix don't require JWT authentication.
//
// Example 2:
//
// .. code-block:: yaml
//
//    - match:
//        prefix: /
//      requires: { provider_name: provider-A }
//
// In above example, all requests matched the path prefix require jwt authentication
// from "provider-A".
#RequirementRule: {
	// The route matching parameter. Only when the match is satisfied, the "requires" field will
	// apply.
	//
	// For example: following match will match all requests.
	//
	// .. code-block:: yaml
	//
	//    match:
	//      prefix: /
	//
	match?: v31.#RouteMatch
	// Specify a Jwt requirement. Please see detail comment in message JwtRequirement.
	requires?: #JwtRequirement
	// Use requirement_name to specify a Jwt requirement.
	// This requirement_name MUST be specified at the
	// :ref:`requirement_map <envoy_v3_api_field_extensions.filters.http.jwt_authn.v3.JwtAuthentication.requirement_map>`
	// in `JwtAuthentication`.
	requirement_name?: string
}

// This message specifies Jwt requirements based on stream_info.filterState.
// This FilterState should use `Router::StringAccessor` object to set a string value.
// Other HTTP filters can use it to specify Jwt requirements dynamically.
//
// Example:
//
// .. code-block:: yaml
//
//    name: jwt_selector
//    requires:
//      issuer_1:
//        provider_name: issuer1
//      issuer_2:
//        provider_name: issuer2
//
// If a filter set "jwt_selector" with "issuer_1" to FilterState for a request,
// jwt_authn filter will use JwtRequirement{"provider_name": "issuer1"} to verify.
#FilterStateRule: {
	// The filter state name to retrieve the `Router::StringAccessor` object.
	name?: string
	// A map of string keys to requirements. The string key is the string value
	// in the FilterState with the name specified in the *name* field above.
	requires?: [string]: #JwtRequirement
}

// This is the Envoy HTTP filter config for JWT authentication.
//
// For example:
//
// .. code-block:: yaml
//
//   providers:
//      provider1:
//        issuer: issuer1
//        audiences:
//        - audience1
//        - audience2
//        remote_jwks:
//          http_uri:
//            uri: https://example.com/.well-known/jwks.json
//            cluster: example_jwks_cluster
//            timeout: 1s
//      provider2:
//        issuer: issuer2
//        local_jwks:
//          inline_string: jwks_string
//
//   rules:
//      # Not jwt verification is required for /health path
//      - match:
//          prefix: /health
//
//      # Jwt verification for provider1 is required for path prefixed with "prefix"
//      - match:
//          prefix: /prefix
//        requires:
//          provider_name: provider1
//
//      # Jwt verification for either provider1 or provider2 is required for all other requests.
//      - match:
//          prefix: /
//        requires:
//          requires_any:
//            requirements:
//              - provider_name: provider1
//              - provider_name: provider2
//
// [#next-free-field: 6]
#JwtAuthentication: {
	// Map of provider names to JwtProviders.
	//
	// .. code-block:: yaml
	//
	//   providers:
	//     provider1:
	//        issuer: issuer1
	//        audiences:
	//        - audience1
	//        - audience2
	//        remote_jwks:
	//          http_uri:
	//            uri: https://example.com/.well-known/jwks.json
	//            cluster: example_jwks_cluster
	//            timeout: 1s
	//      provider2:
	//        issuer: provider2
	//        local_jwks:
	//          inline_string: jwks_string
	//
	providers?: [string]: #JwtProvider
	// Specifies requirements based on the route matches. The first matched requirement will be
	// applied. If there are overlapped match conditions, please put the most specific match first.
	//
	// Examples
	//
	// .. code-block:: yaml
	//
	//   rules:
	//     - match:
	//         prefix: /healthz
	//     - match:
	//         prefix: /baz
	//       requires:
	//         provider_name: provider1
	//     - match:
	//         prefix: /foo
	//       requires:
	//         requires_any:
	//           requirements:
	//             - provider_name: provider1
	//             - provider_name: provider2
	//     - match:
	//         prefix: /bar
	//       requires:
	//         requires_all:
	//           requirements:
	//             - provider_name: provider1
	//             - provider_name: provider2
	//
	rules?: [...#RequirementRule]
	// This message specifies Jwt requirements based on stream_info.filterState.
	// Other HTTP filters can use it to specify Jwt requirements dynamically.
	// The *rules* field above is checked first, if it could not find any matches,
	// check this one.
	filter_state_rules?: #FilterStateRule
	// When set to true, bypass the `CORS preflight request
	// <http://www.w3.org/TR/cors/#cross-origin-request-with-preflight>`_ regardless of JWT
	// requirements specified in the rules.
	bypass_cors_preflight?: bool
	// A map of unique requirement_names to JwtRequirements.
	// :ref:`requirement_name <envoy_v3_api_field_extensions.filters.http.jwt_authn.v3.PerRouteConfig.requirement_name>`
	// in `PerRouteConfig` uses this map to specify a JwtRequirement.
	requirement_map?: [string]: #JwtRequirement
}

// Specify per-route config.
#PerRouteConfig: {
	// Disable Jwt Authentication for this route.
	disabled?: bool
	// Use requirement_name to specify a JwtRequirement.
	// This requirement_name MUST be specified at the
	// :ref:`requirement_map <envoy_v3_api_field_extensions.filters.http.jwt_authn.v3.JwtAuthentication.requirement_map>`
	// in `JwtAuthentication`. If no, the requests using this route will be rejected with 403.
	requirement_name?: string
}
