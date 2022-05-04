package http

#GmJwtKeycloakConfig: {
	clientSecret?:    string
	endpoint?:        string
	authnHeaderName?: string
	// tls
	useTLS?:             bool
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
	// keycloak-specifc
	writeBody?:               bool
	fetchFullToken?:          bool
	clientID?:                string
	realm?:                   string
	jwtPrivateKeyPath?:       string
	authzHeaderName?:         string
	jwks?:                    string
	authenticateOnly?:        bool
	sharedJwtKeycloakSecret?: string
}
