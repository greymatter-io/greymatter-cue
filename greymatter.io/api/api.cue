package api

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

#CircuitBreakersThresholds: #CircuitBreakers & {
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
	gm_metrics?:			 #MetricsConfig
	gm_impersonation?:       #ImpersonationConfig
	gm_inheaders?:           #InheadersConfig
	gm_listauth?:            #ListAuthConfig
	gm_observables?:         #ObservablesConfig
	gm_ensure_variables?:    #EnsureVariablesConfig
	gm_keycloak?:            #GmJwtKeycloakConfig
	gm_oauth?:               #OauthConfig
	gm_oidc_authenticaiton?: #AuthenticationConfig
	gm_oidc_validation?:     #ValidationConfig
}

#NetworkFilters: {
	envoy_tcp_proxy?: {
		cluster:     string
		stat_prefix: string
	}
	gm_tcp_metrics?: 		#tcpMetricsConfig
	gm_tcp_logger?: 		#tcpLoggerConfig
	gm_tcp_observables?: 	#ObservablesTCPConfig
	gm_tcp_jwt_security?: 	#jwtSecurityTcpConfig
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
}

// Common

#Metadata: metadata?: [...#Metadatum]

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

#LocationType: {"header", #enumValue: 0} |
	{"cookie", #enumValue: 1} |
	{"queryString", #enumValue: 2} |
	{"metadata", #enumValue: 3}

#LocationType_value: {
	"header":      0
	"cookie":      1
	"queryString": 2
	"metadata":    3
}

#CookieOptions: {
	httpOnly?: bool   @protobuf(1,bool)
	secure?:   bool   @protobuf(2,bool)
	domain?:   string @protobuf(3,string)
	path?:     string @protobuf(4,string)
	maxAge?:   string @protobuf(5,string)
}

#EnsureVariablesConfig: {

	#Rule: {

		#Value: {
			#MatchType: {"exact", #enumValue: 0} |
				{"prefix", #enumValue: 1} |
				{"suffix", #enumValue: 2} |
				{"regex", #enumValue: 3}

			#MatchType_value: {
				"exact":  0
				"prefix": 1
				"suffix": 2
				"regex":  3
			}
			matchType?:   #MatchType @protobuf(1,MatchType)
			matchString?: string     @protobuf(2,string)
		}

		#CopyTo: {
			location?: #LocationType @protobuf(1,LocationType)
			key?:      string        @protobuf(2,string)

			#Direction: {"default", #enumValue: 0} |
				{"request", #enumValue: 1} |
				{"response", #enumValue: 2} |
				{"both", #enumValue: 3}

			#Direction_value: {
				"default":  0
				"request":  1
				"response": 2
				"both":     3
			}
			direction?:     #Direction     @protobuf(3,Direction)
			cookieOptions?: #CookieOptions @protobuf(4,CookieOptions)
		}
		key?:                 string        @protobuf(1,string)
		location?:            #LocationType @protobuf(2,LocationType)
		metadataFilter?:      string        @protobuf(3,string)
		enforce?:             bool          @protobuf(4,bool)
		enforceResponseCode?: int32         @protobuf(5,int32)
		removeOriginal?:      bool          @protobuf(6,bool)
		value?:               #Value        @protobuf(7,Value)
		copyTo?: [...#CopyTo] @protobuf(8,CopyTo)
	}
	rules?: [...#Rule] @protobuf(1,Rule)
}

#GmJwtKeycloakConfig: {
	clientSecret?:    string @protobuf(1,string)
	endpoint?:        string @protobuf(2,string)
	authnHeaderName?: string @protobuf(3,string)

	// tls
	useTLS?:             bool   @protobuf(4,bool)
	certPath?:           string @protobuf(5,string)
	keyPath?:            string @protobuf(6,string)
	caPath?:             string @protobuf(7,string)
	insecureSkipVerify?: bool   @protobuf(8,bool)

	// request config
	timeoutMs?:    int32 @protobuf(9,int32)
	maxRetries?:   int32 @protobuf(10,int32)
	retryDelayMs?: int32 @protobuf(11,int32)

	// cache config
	cachedTokenExp?: int32 @protobuf(12,int32)
	cacheLimit?:     int32 @protobuf(13,int32)

	// keycloak-specifc
	writeBody?:               bool   @protobuf(14,bool)
	fetchFullToken?:          bool   @protobuf(15,bool)
	clientID?:                string @protobuf(16,string)
	realm?:                   string @protobuf(17,string)
	jwtPrivateKeyPath?:       string @protobuf(18,string)
	authzHeaderName?:         string @protobuf(19,string)
	jwks?:                    string @protobuf(20,string)
	authenticateOnly?:        bool   @protobuf(21,bool)
	sharedJwtKeycloakSecret?: string @protobuf(22,string)
}

#GmJwtSecurityConfig: {
	apiKey?:        string @protobuf(1,string)
	endpoint?:      string @protobuf(2,string)
	jwtHeaderName?: string @protobuf(3,string)

	// tls
	useTls?:             bool   @protobuf(4,bool)
	certPath?:           string @protobuf(5,string)
	keyPath?:            string @protobuf(6,string)
	caPath?:             string @protobuf(7,string)
	insecureSkipVerify?: bool   @protobuf(8,bool)

	// request config
	timeoutMs?:    int32 @protobuf(9,int32)
	maxRetries?:   int32 @protobuf(10,int32)
	retryDelayMs?: int32 @protobuf(11,int32)

	// cache config
	cachedTokenExp?: int32 @protobuf(12,int32)
	cacheLimit?:     int32 @protobuf(13,int32)
}

#ImpersonationConfig: {
	servers?:       string @protobuf(1,string)
	caseSensitive?: bool   @protobuf(2,bool)
}

#InheadersConfig: {
	debug?: bool @protobuf(1,bool)
}

#ListAuthConfig: {
	blacklist?: string @protobuf(1,string)
	whitelist?: string @protobuf(2,string)
	denylist?:  string @protobuf(3,string)
	allowlist?: string @protobuf(4,string)
}

#MetricsConfig: {
	metricsPort?:                            int32  @protobuf(1,int32,name=metrics_port)
	metricsHost?:                            string @protobuf(2,string,name=metrics_host)
	metricsDashboardUriPath?:                string @protobuf(3,string,name=metrics_dashboard_uri_path)
	metricsPrometheusUriPath?:               string @protobuf(4,string,name=metrics_prometheus_uri_path)
	prometheusSystemMetricsIntervalSeconds?: int32  @protobuf(5,int32,name=prometheus_system_metrics_interval_seconds)
	metricsRingBufferSize?:                  int32  @protobuf(6,int32,name=metrics_ring_buffer_size)
	metricsKeyFunction?:                     string @protobuf(7,string,name=metrics_key_function)
	metricsKeyDepth?:                        string @protobuf(8,string,name=metrics_key_depth)
	throughputTimeoutDuration?:              string @protobuf(9,string,name=throughput_timeout_duration)
	useMetricsTls?:                          bool   @protobuf(10,bool,name=use_metrics_tls)
	serverCaCertPath?:                       string @protobuf(11,string,name=server_ca_cert_path)
	serverCertPath?:                         string @protobuf(12,string,name=server_cert_path)
	serverKeyPath?:                          string @protobuf(13,string,name=server_key_path)
	enableCloudwatch?:                       bool   @protobuf(14,bool,name=enable_cloudwatch)
	cwNamespace?:                            string @protobuf(15,string,name=cw_namespace)
	cwDimensions?:                           string @protobuf(16,string,name=cw_dimensions)
	cwMetricsRoutes?:                        string @protobuf(17,string,name=cw_metrics_routes)
	cwMetricsValues?:                        string @protobuf(18,string,name=cw_metrics_values)
	cwDebug?:                                bool   @protobuf(19,bool,name=cw_debug)
	cwReportingIntervalSeconds?:             int32  @protobuf(20,int32,name=cw_reporting_interval_seconds)
	awsRegion?:                              string @protobuf(21,string,name=aws_region)
	awsAccessKeyId?:                         string @protobuf(22,string,name=aws_access_key_id)
	awsSecretAccessKey?:                     string @protobuf(23,string,name=aws_secret_access_key)
	awsSessionToken?:                        string @protobuf(24,string,name=aws_session_token)
	awsProfile?:                             string @protobuf(25,string,name=aws_profile)
	awsConfigFile?:                          string @protobuf(26,string,name=aws_config_file)

	#MetricsReceiver: {
		redisConnectionString?: string @protobuf(1,string,name=redis_connection_string)
		natsConnectionString?:  string @protobuf(2,string,name=nats_connection_string)
		pushIntervalSeconds?:   int32  @protobuf(3,int32,name=push_interval_seconds)
	}
	metricsReceiver?: #MetricsReceiver @protobuf(27,MetricsReceiver,name=metrics_receiver)
}

#MetricsRouteConfig: {
	metricsKeyFunction?: string @protobuf(1,string,name=metrics_key_function)
	metricsKeyDepth?:    string @protobuf(2,string,name=metrics_key_depth)
}

#OauthConfig: {
	provider?:       string @protobuf(1,string)
	clientId?:       string @protobuf(2,string,name=client_id)
	clientSecret?:   string @protobuf(3,string,name=client_secret)
	serverName?:     string @protobuf(4,string,name=server_name)
	serverInsecure?: bool   @protobuf(5,bool,name=server_insecure)
	sessionSecret?:  string @protobuf(6,string,name=session_secret)
	domain?:         string @protobuf(7,string)
}

#OauthRouteConfig: {
	domain?: string @protobuf(1,string)
}

#ObservablesConfig: {
	emitFullResponse?: bool @protobuf(1,bool)
	useKafka?:         bool @protobuf(2,bool)

	// Kafka TLS configuration
	useKafkaTLS?:           bool   @protobuf(3,bool)
	kafkaCAs?:              string @protobuf(4,string)
	kafkaCertificate?:      string @protobuf(5,string)
	kafkaCertificateKey?:   string @protobuf(6,string)
	kafkaServerName?:       string @protobuf(7,string)
	enforceAudit?:          bool   @protobuf(8,bool)
	topic?:                 string @protobuf(9,string)
	eventTopic?:            string @protobuf(10,string)
	kafkaZKDiscover?:       bool   @protobuf(11,bool)
	kafkaServerConnection?: string @protobuf(12,string)
	fileName?:              string @protobuf(13,string)
	logLevel?:              string @protobuf(14,string)
	encryptionAlgorithm?:   string @protobuf(15,string)

	// Bas64 encrypted bytes
	encryptionKey?:   string @protobuf(16,string)
	encryptionKeyID?: uint32 @protobuf(17,uint32)

	// Kafka timeout
	timeoutMs?: int32 @protobuf(18,int32)
}

#ObservablesRouteConfig: {
	emitFullResponse?: bool @protobuf(1,bool)
}

#LocationType: {"header", #enumValue: 0} |
	{"cookie", #enumValue: 1} |
	{"queryString", #enumValue: 2} |
	{"metadata", #enumValue: 3}

#LocationType_value: {
	"header":      0
	"cookie":      1
	"queryString": 2
	"metadata":    3
}

#CookieOptions: {
	httpOnly?: bool   @protobuf(1,bool)
	secure?:   bool   @protobuf(2,bool)
	domain?:   string @protobuf(3,string)
	path?:     string @protobuf(4,string)
	maxAge?:   string @protobuf(5,string)
}

#AuthenticationConfig: {

	#TokenStorage: {
		location?:       #LocationType  @protobuf(1,LocationType)
		key?:            string         @protobuf(2,string)
		cookieOptions?:  #CookieOptions @protobuf(3,CookieOptions)
		metadataFilter?: string         @protobuf(4,string)
	}
	accessToken?:  #TokenStorage @protobuf(1,TokenStorage)
	idToken?:      #TokenStorage @protobuf(2,TokenStorage)
	serviceUrl?:   string        @protobuf(3,string)
	callbackPath?: string        @protobuf(4,string)
	provider?:     string        @protobuf(5,string)
	clientId?:     string        @protobuf(6,string)
	clientSecret?: string        @protobuf(7,string)
	additionalScopes?: [...string] @protobuf(8,string)

	#TokenRefreshConfig: {
		enabled?:            bool   @protobuf(1,bool)
		endpoint?:           string @protobuf(2,string)
		realm?:              string @protobuf(3,string)
		useTLS?:             bool   @protobuf(4,bool)
		certPath?:           string @protobuf(5,string)
		keyPath?:            string @protobuf(6,string)
		caPath?:             string @protobuf(7,string)
		insecureSkipVerify?: bool   @protobuf(8,bool)
		timeoutMs?:          int32  @protobuf(9,int32)
	}
	tokenRefresh?: #TokenRefreshConfig @protobuf(9,TokenRefreshConfig)
}

#LocationType: {"header", #enumValue: 0} |
	{"cookie", #enumValue: 1} |
	{"queryString", #enumValue: 2} |
	{"metadata", #enumValue: 3}

#LocationType_value: {
	"header":      0
	"cookie":      1
	"queryString": 2
	"metadata":    3
}

#CookieOptions: {
	httpOnly?: bool   @protobuf(1,bool)
	secure?:   bool   @protobuf(2,bool)
	domain?:   string @protobuf(3,string)
	path?:     string @protobuf(4,string)
	maxAge?:   string @protobuf(5,string)
}

#ValidationConfig: {
	provider?:            string @protobuf(1,string)
	enforce?:             bool   @protobuf(2,bool)
	enforceResponseCode?: int32  @protobuf(3,int32)

	#AccessToken: {
		location?:       #LocationType @protobuf(1,LocationType)
		key?:            string        @protobuf(2,string)
		metadataFilter?: string        @protobuf(3,string)
	}
	accessToken?: #AccessToken @protobuf(4,AccessToken)

	#UserInfo: {
		claims?: [...string] @protobuf(1,string)
		location?:      #LocationType  @protobuf(2,LocationType)
		key?:           string         @protobuf(3,string)
		cookieOptions?: #CookieOptions @protobuf(4,CookieOptions)
	}
	userInfo?: #UserInfo @protobuf(5,UserInfo)

	#FilterTLSConfig: {
		useTLS?:             bool   @protobuf(1,bool)
		certPath?:           string @protobuf(2,string)
		keyPath?:            string @protobuf(3,string)
		caPath?:             string @protobuf(4,string)
		insecureSkipVerify?: bool   @protobuf(5,bool)
	}
	TLSConfig?: #FilterTLSConfig @protobuf(6,FilterTLSConfig)
}

#ValidationRouteConfig: {
	enforce?:             bool  @protobuf(1,bool)
	enforceResponseCode?: int32 @protobuf(2,int32)
	userInfoClaims?: [...string] @protobuf(3,string)
	overwriteClaims?: bool @protobuf(4,bool)
}

#PolicyConfig: {
	inboundPolicy?:     string @protobuf(1,string)
	outboundPolicy?:    string @protobuf(2,string)
	inboundPolicyRaw?:  string @protobuf(13,string)
	outboundPolicyRaw?: string @protobuf(4,string)
}

#DemoConfig: {
	message?: string @protobuf(1,string)
}

#jwtSecurityTcpConfig: {
	apiKey?:   string @protobuf(1,string)
	endpoint?: string @protobuf(2,string)

	// tls
	useTls?:             bool   @protobuf(3,bool)
	certPath?:           string @protobuf(4,string)
	keyPath?:            string @protobuf(5,string)
	caPath?:             string @protobuf(6,string)
	insecureSkipVerify?: bool   @protobuf(7,bool)

	// request config
	timeoutMs?:    int32 @protobuf(8,int32)
	maxRetries?:   int32 @protobuf(9,int32)
	retryDelayMs?: int32 @protobuf(10,int32)

	// cache config
	cachedTokenExp?: int32 @protobuf(11,int32)
	cacheLimit?:     int32 @protobuf(12,int32)

	// Connection handling
	closeOnFail?: bool @protobuf(13,bool)

	// jwt decode
	skipDecode?: bool   @protobuf(14,bool)
	jwks?:       string @protobuf(15,string)
	issuer?:     string @protobuf(16,string)
}

#ObservablesTCPConfig: {
	// Whether to emit response (or otherwise just request)
	emitFullResponse?: bool @protobuf(1,bool)

	// Whether to use Kafka
	useKafka?: bool @protobuf(2,bool)

	// Kafka TLS configuration
	// -----------------------
	// Whether to use TLS when connecting to Kafka
	useKafkaTLS?: bool @protobuf(3,bool)

	// Kafka Certificate Authorities
	kafkaCAs?: string @protobuf(4,string)

	// Kafka TLC cert key
	kafkaCertificate?: string @protobuf(5,string)

	// Kafka TLC cert key
	kafkaCertificateKey?: string @protobuf(6,string)

	// Name of Kafka server
	kafkaServerName?: string @protobuf(7,string)

	// The topic name to embed in the event.
	topic?: string @protobuf(8,string)

	// Kafka topic to publish to.
	eventTopic?: string @protobuf(9,string)

	// Whether to use Zookeeper for Kafka discovery (if not using file storage)
	kafkaZKDiscover?: bool @protobuf(10,bool)

	// Kafka connection string (if not using file storage)
	kafkaServerConnection?: string @protobuf(11,string)

	// File to store event to use (if not using Kafka)
	fileName?: string @protobuf(12,string)

	// Log level to use ("warn", "debug" or "info")
	logLevel?: string @protobuf(13,string)

	// Algorithm used to encrypt
	encryptionAlgorithm?: string @protobuf(14,string)

	// Key to encrypt event
	encryptionKey?:   string @protobuf(15,string)
	encryptionKeyID?: uint32 @protobuf(16,uint32)

	// Kafka timeout
	timeoutMs?:    int32 @protobuf(17,int32)
	enforceAudit?: bool  @protobuf(18,bool)

	// Decode
	decodeToProtocol?: string @protobuf(19,string)
	decodeSkipFail?:   bool   @protobuf(20,bool)
}

#tcpLoggerConfig: {
	warnWindow?:        string @protobuf(1,string)
	logConnect?:        bool   @protobuf(2,bool)
	omitSSLFailure?:    bool   @protobuf(3,bool)
	logRawTcp?:         bool   @protobuf(4,bool)
	failureCheckDelay?: string @protobuf(5,string)
}

#tcpMetricsConfig: {
	metricsPort?:                            int32  @protobuf(1,int32,name=metrics_port)
	metricsHost?:                            string @protobuf(2,string,name=metrics_host)
	metricsDashboardUriPath?:                string @protobuf(3,string,name=metrics_dashboard_uri_path)
	metricsPrometheusUriPath?:               string @protobuf(4,string,name=metrics_prometheus_uri_path)
	prometheusSystemMetricsIntervalSeconds?: int32  @protobuf(5,int32,name=prometheus_system_metrics_interval_seconds)
	metricsRingBufferSize?:                  int32  @protobuf(6,int32,name=metrics_ring_buffer_size)
	metricsKeyFunction?:                     string @protobuf(7,string,name=metrics_key_function)
	metricsKeyDepth?:                        string @protobuf(8,string,name=metrics_key_depth)
	throughputTimeoutDuration?:              string @protobuf(9,string,name=throughput_timeout_duration)
	useMetricsTls?:                          bool   @protobuf(10,bool,name=use_metrics_tls)
	serverCaCertPath?:                       string @protobuf(11,string,name=server_ca_cert_path)
	serverCertPath?:                         string @protobuf(12,string,name=server_cert_path)
	serverKeyPath?:                          string @protobuf(13,string,name=server_key_path)
	enableCloudwatch?:                       bool   @protobuf(14,bool,name=enable_cloudwatch)
	cwNamespace?:                            string @protobuf(15,string,name=cw_namespace)
	cwDimensions?:                           string @protobuf(16,string,name=cw_dimensions)
	cwMetricsRoutes?:                        string @protobuf(17,string,name=cw_metrics_routes)
	cwMetricsValues?:                        string @protobuf(18,string,name=cw_metrics_values)
	cwDebug?:                                bool   @protobuf(19,bool,name=cw_debug)
	cwReportingIntervalSeconds?:             int32  @protobuf(20,int32,name=cw_reporting_interval_seconds)
	awsRegion?:                              string @protobuf(21,string,name=aws_region)
	awsAccessKeyId?:                         string @protobuf(22,string,name=aws_access_key_id)
	awsSecretAccessKey?:                     string @protobuf(23,string,name=aws_secret_access_key)
	awsSessionToken?:                        string @protobuf(24,string,name=aws_session_token)
	awsProfile?:                             string @protobuf(25,string,name=aws_profile)
	awsConfigFile?:                          string @protobuf(26,string,name=aws_config_file)
	decodeToProtocol?:                       string @protobuf(27,string,name=decode_to_protocol)
	internalTopics?:                         bool   @protobuf(28,bool,name=internal_topics)
}
