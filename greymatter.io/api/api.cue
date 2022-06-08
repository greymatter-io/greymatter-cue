package api

import (
	"greymatter.io/api/filters/http"
	"greymatter.io/api/filters/network"
)

// Cluster

#Cluster: {
	name:         string
	cluster_key:  string
	zone_key:     string
	require_tls?: bool
	instances?: [...#Instance]
	health_checks?: [...#HealthCheck]
	outlier_detection?:     #OutlierDetection
	circuit_breakers?:      #CircuitBreakersThresholds
	ring_hash_lb_conf?:     #RingHashLbConfig
	original_dst_lb_conf?:  #OriginalDstLbConfig
	least_request_lb_conf?: #LeastRequestLbConfig
	common_lb_conf?:        #CommonLbConfig

	// common.cue
	secret?:                 #Secret
	ssl_config?:             #SSLConfig
	http_protocol_options?:  #HTTPProtocolOptions
	http2_protocol_options?: #HTTP2ProtocolOptions
}

#Instance: {
	host: string
	port: int32
	metadata?: [...#Metadata]
}

#HealthCheck: {
	timeout_msec?:                 int64
	interval_msec?:                int64
	interval_jitter_msec?:         int64
	unhealthy_threshold?:          int64
	healthy_threshold?:            int64
	reuse_connection?:             bool
	no_traffic_interval_msec?:     int64
	unhealthy_interval_msec?:      int64
	unhealthy_edge_interval_msec?: int64
	healthy_edge_interval_msec?:   int64
	health_checker?:               #HealthChecker
}

#HealthChecker: {
	http_health_check?: #HTTPHealthCheck
	tcp_health_check?:  #TCPHealthCheck
}

#TCPHealthCheck: {
	send?: string
	receive?: [...string]
}

#HTTPHealthCheck: {
	host?:         string
	path?:         string
	service_name?: string
	request_headers_to_add?: [...#Metadata]
}

#OutlierDetection: {
	interval_msec?:                         int64
	base_ejection_time_msec?:               int64
	max_ejection_percent?:                  int64
	consecutive5xx?:                        int64
	enforcing_consecutive5xx?:              int64
	enforcing_success_rate?:                int64
	success_rate_minimum_hosts?:            int64
	success_rate_request_volume?:           int64
	success_rate_stdev_factor?:             int64
	consecutive_gateway_failure?:           int64
	enforcing_consecutive_gateway_failure?: int64
}

#CircuitBreakersThresholds: {
	#CircuitBreakers
	high?: #CircuitBreakers
}

#CircuitBreakers: {
	max_connections?:      int64
	max_pending_requests?: int64
	max_requests?:         int64
	max_retries?:          int64
	max_connection_pools?: int64
	track_remaining?:      bool
}

#RingHashLbConfig: {
	minimum_ring_size?: uint64
	hash_func?:         uint32
	maximum_ring_size?: uint64
}

#OriginalDstLbConfig: use_http_header?: bool

#LeastRequestLbConfig: choice_count?: uint32

#CommonLbConfig: {
	healthy_panic_threshold?:              #Percent
	zone_aware_lb_conf?:                   #ZoneAwareLbConfig
	locality_weighted_lb_conf?:            #LocalityWeightedLbConfig
	consistent_hashing_lb_conf?:           #ConsistentHashingLbConfig
	update_merge_window?:                  #Duration
	ignore_new_hosts_until_first_hc?:      bool
	close_connections_on_host_set_change?: bool
}

#Percent: value?: float64

#ZoneAwareLbConfig: {
	routing_enabled?:       #Percent
	min_cluster_size?:      uint64
	fail_traffic_on_panic?: bool
}

#LocalityWeightedLbConfig: {
}

#ConsistentHashingLbConfig: use_hostname_for_hashing?: bool

#Duration: {
	seconds?: int64
	nanos?:   int32
}

// Route

#Route: {
	route_key:       string
	domain_key:      string
	zone_key:        string
	prefix_rewrite?: string
	cohort_seed?:    string
	high_priority?:  bool
	timeout?:        string
	idle_timeout?:   string
	rules: [...#Rule]
	route_match:    #RouteMatch
	response_data?: #ResponseData
	retry_policy?:  #RetryPolicy
	filter_metadata?: [string]: #Metadata
	filter_configs?: [string]: {...}
	request_headers_to_add?: [...#Metadatum]
	response_headers_to_add?: [...#Metadatum]
	request_headers_to_remove?: [...string]
	response_headers_to_remove?: [...string]
	redirects: [...#Redirect]
	shared_rules_key?: string
}

#RouteMatch: {
	path:       string
	match_type: string
}

#Rule: {
	rule_key?: string
	methods?: [...string]
	matches?: [...#Match]
	constraints?: #Constraints
	cohort_seed?: string
}

#Match: {
	kind?:     string
	behavior?: string
	from?:     #Metadatum
	to?:       #Metadatum
}

#Constraints: {
	light: [...#Constraint]
	dark?: [...#Constraint]
	tap?: [...#Constraint]
}

#Constraint: {
	cluster_key: string
	metadata?: [...#Metadata]
	properties?: [...#Metadata]
	response_data?: #ResponseData
	weight:         uint32
}

#ResponseData: {
	headers?: [...#HeaderDatum]
	cookies?: [...#CookieDatum]
}

#HeaderDatum: response_datum?: #ResponseDatum

#ResponseDatum: {
	name?:             string
	value?:            string
	value_is_literal?: bool
}

#CookieDatum: {
	response_datum?: #ResponseDatum
	expires_in_sec?: uint32
	domain?:         string
	path?:           string
	secure?:         bool
	http_only?:      bool
	same_site?:      string
}

#RetryPolicy: {
	num_retries?:                       int64
	per_try_timeout_msec?:              int64
	timeout_msec?:                      int64
	retry_on?:                          string
	retry_priority?:                    string
	retry_host_predicate?:              string
	host_selection_retry_max_attempts?: int64
	retriable_status_codes?:            int64
	retry_back_off?:                    #BackOff
	retriable_headers?:                 #HeaderMatcher
	retriable_request_headers?:         #HeaderMatcher
}

#BackOff: {
	base_interval?: string
	max_interval?:  string
}

#HeaderMatcher: {
	name?:             string
	exact_match?:      string
	regex_match?:      string
	safe_regex_match?: #RegexMatcher
	range_match?:      #RangeMatch
	present_match?:    bool
	prefix_match?:     string
	suffix_match?:     string
	invert_match?:     bool
}

#RegexMatcher: {
	google_re2?: #GoogleRe2
	regex?:      string
}

#GoogleRe2: max_program_size?: int64

#RangeMatch: {
	start?: int64
	end?:   int64
}

// Domain

#Domain: {
	domain_key:   string
	zone_key:     string
	name:         string
	port:         int32
	force_https?: bool
	cors_config?: #CorsConfig
	aliases?: [...string]

	// common.cue
	ssl_config?: #SSLConfig
	redirects?: [...#Redirect]
	custom_headers?: [...#Metadatum]
}

#CorsConfig: {
	allowed_origins?: [...#AllowOriginStringMatchItem]
	allow_credentials?: bool
	exposed_headers?: [...string]
	max_age?: int64
	allowed_methods?: [...string]
	allowed_headers?: [...string]
}

#AllowOriginStringMatchItem: {
	match_type?: string
	value?:      string
}

// Listener

#Listener: {
	name:         string
	listener_key: name
	zone_key:     string
	ip:           string
	port:         int32
	protocol:     string
	domain_keys: [...string]
	active_http_filters?: [...string]
	http_filters?: #HTTPFilters
	active_network_filters?: [...string]
	network_filters?:       #NetworkFilters
	stream_idle_timeout?:   string
	request_timeout?:       string
	drain_timeout?:         string
	delayed_close_timeout?: string
	use_remote_address?:    bool
	tracing_config?:        #TracingConfig
	access_loggers?:        #AccessLoggers

	// common.cue
	secret?:                 #Secret
	http_protocol_options?:  #HTTPProtocolOptions
	http2_protocol_options?: #HTTP2ProtocolOptions
}

#HTTPFilters: {
	gm_metrics?:             http.#MetricsConfig
	gm_impersonation?:       http.#ImpersonationConfig
	gm_inheaders?:           http.#InheadersConfig
	gm_listauth?:            http.#ListAuthConfig
	gm_observables?:         http.#ObservablesConfig
	gm_ensure_variables?:    http.#EnsureVariablesConfig
	gm_keycloak?:            http.#GmJwtKeycloakConfig
	gm_oauth?:               http.#OauthConfig
	gm_oidc_authenticaiton?: http.#AuthenticationConfig
	gm_oidc_validation?:     http.#ValidationConfig
	...
}

#NetworkFilters: {
	envoy_tcp_proxy?: {
		cluster:     string
		stat_prefix: string
	}
	gm_tcp_metrics?:      network.#tcpMetricsConfig
	gm_tcp_logger?:       network.#tcpLoggerConfig
	gm_tcp_observables?:  network.#ObservablesTCPConfig
	gm_tcp_jwt_security?: network.#jwtSecurityTcpConfig
}

#TracingConfig: {
	ingress?: bool
	request_headers_for_tags?: [...string]
}

#AccessLoggers: {
	http_connection_loggers?: #Loggers
	http_upstream_loggers?:   #Loggers
}

#Loggers: {
	disabled?: bool
	file_loggers?: [...#FileAccessLog]
	h_ttpgrpc_access_loggers?: [...#HTTPGRPCAccessLog]
}

#FileAccessLog: {
	path?:   string
	format?: string
	json_format?: [string]:       string
	typed_json_format?: [string]: string
}

#HTTPGRPCAccessLog: {
	common_config?: #GRPCCommonConfig
	additional_request_headers?: [...string]
	additional_response_headers?: [...string]
	additional_response_trailers?: [...string]
}

#GRPCCommonConfig: {
	log_name?:      string
	g_rpc_service?: #GRPCService
}

#GRPCService: {
	cluster_name?: string
}

// Proxy

#Proxy: {
	name:      string
	proxy_key: string
	zone_key:  string
	domain_keys: [...string]
	listener_keys: [...string]
	upgrades?: string
}

// CatalogService

#CatalogService: {
	mesh_id:                   string
	service_id:                string
	name:                      string
	api_endpoint?:             string
	api_spec_endpoint?:        string
	description?:              string
	enable_instance_metrics:   bool
	enable_historical_metrics: bool
	business_impact: string
	version?: string
}

// Common

#Metadata: [...#Metadatum]

#Metadatum: {
	key:   string
	value: string
}

#Secret: {
	secret_key?:             string
	secret_name?:            string
	secret_validation_name?: string
	subject_names?: [...string]
	ecdh_curves?: [...string]
	forward_client_cert_details?:     string
	set_current_client_cert_details?: #SetCurrentClientCertDetails
}

#SetCurrentClientCertDetails: uri: bool

#SSLConfig: {
	cipher_filter?: string
	protocols?: [...string]
	cert_key_pairs?: [...#CertKeyPathPair]
	require_client_certs?: bool
	trust_file?:           string
	sni?: [...string]
	crl?: #DataSource
}

#CertKeyPathPair: {
	certificate_path?: string
	key_path?:         string
}

#DataSource: {
	filename?:      string
	inline_string?: string
}

#HTTPProtocolOptions: {
	allow_absolute_url?:      bool
	accept_http10?:           bool
	default_host_for_http10?: string
	header_key_format?:       #HeaderKeyFormat
	enable_trailers?:         bool
}

#HeaderKeyFormat: proper_case_words?: bool

#HTTP2ProtocolOptions: {
	hpack_table_size?:                                     uint32
	max_concurrent_streams?:                               uint32
	initial_stream_window_size?:                           uint32
	initial_connection_window_size?:                       uint32
	allow_connect?:                                        bool
	max_outbound_frames?:                                  uint32
	max_outbound_control_frames?:                          uint32
	max_consecutive_inbound_frames_with_empty_payload?:    uint32
	max_inbound_priority_frames_per_stream?:               uint32
	max_inbound_window_update_frames_per_data_frame_sent?: uint32
	stream_error_on_invalid_http_messaging?:               bool
}

#Redirect: {
	name?:          string
	from?:          string
	to?:            string
	redirect_type?: string
	header_constraints?: [...#HeaderConstraint]
}

#HeaderConstraint: {
	name?:           string
	value?:          string
	case_sensitive?: bool
	invert?:         bool
}

// Shared Rules

#AllConstraints: {
	light?: [...#ClusterConstraint] | *null
	dark?:  [...#ClusterConstraint] | *null
	tap?:   [...#ClusterConstraint] | *null
}

#Constraints: {
	light?: [...#ClusterConstraint]
	dark?: [...#ClusterConstraint]
	tap?: [...#ClusterConstraint]
}

#ClusterConstraint: {
	constraint_key?: string
	cluster_key:     string
	metadata?:       [...#Metadata] | *null
	properties?:     [...#Metadata] | *null
	response_data?:  #ResponseData
	// We probably do not want to default the weight value
	weight: uint32
}

#SharedRules: {
	shared_rules_key: string
	name?:            string
	zone_key:         string
	default:          #AllConstraints
	rules:            [...#Rule] | *null
	response_data:    #ResponseData
	cohort_seed?:     string | *null
	properties?:      [...#Metadata] | *null
	retry_policy?:    #RetryPolicy | *null
	org_key?:         string
}
