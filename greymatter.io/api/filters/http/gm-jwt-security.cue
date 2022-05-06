package http

#GmJwtSecurityConfig: {
	apiKey?:        string
	endpoint?:      string
	jwtHeaderName?: string
	// tls
	useTls?:             bool
	certPath?:           string
	keyPath?:            string
	caPath?:             string
	insecureSkipVerify?: bool
	// request config
	timeoutMs?:    int32
	maxRetries?:   int32
	retryDelayMs?: int32
	// cache config
	cachedTokenExp?: int32
	cacheLimit?:     int32
}
