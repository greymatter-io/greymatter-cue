package network

#JwtSecurityTcpConfig: {
	apiKey?:   string
	endpoint?: string
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
	// Connection handling
	closeOnFail?: bool
	// jwt decode
	skipDecode?: bool
	jwks?:       string
	issuer?:     string
}
