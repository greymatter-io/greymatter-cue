package http

#AuthenticationConfig: {
	accessToken?:  #AuthenticationConfig_TokenStorage
	idToken?:      #AuthenticationConfig_TokenStorage
	serviceUrl?:   string
	callbackPath?: string
	provider?:     string
	clientId?:     string
	clientSecret?: string
	additionalScopes?: [...string]
	tokenRefresh?: #AuthenticationConfig_TokenRefreshConfig
}

#AuthenticationConfig_TokenStorage: {
	location?:       #LocationType
	key?:            string
	cookieOptions?:  #CookieOptions
	metadataFilter?: string
}

#AuthenticationConfig_TokenRefreshConfig: {
	enabled?:            bool
	endpoint?:           string
	realm?:              string
	useTLS?:             bool
	certPath?:           string
	keyPath?:            string
	caPath?:             string
	insecureSkipVerify?: bool
	timeoutMs?:          int32
}
