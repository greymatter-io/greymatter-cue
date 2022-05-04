package http

#ValidationConfig: {
	provider?:            string
	enforce?:             bool
	enforceResponseCode?: int32
	accessToken?:         #ValidationConfig_AccessToken
	userInfo?:            #ValidationConfig_UserInfo
	TLSConfig?:           #ValidationConfig_FilterTLSConfig
}

#ValidationRouteConfig: {
	enforce?:             bool
	enforceResponseCode?: int32
	userInfoClaims?: [...string]
	overwriteClaims?: bool
}

#ValidationConfig_AccessToken: {
	location?:       #LocationType
	key?:            string
	metadataFilter?: string
}

#ValidationConfig_UserInfo: {
	claims?: [...string]
	location?:      #LocationType
	key?:           string
	cookieOptions?: #CookieOptions
}

#ValidationConfig_FilterTLSConfig: {
	useTLS?:             bool
	certPath?:           string
	keyPath?:            string
	caPath?:             string
	insecureSkipVerify?: bool
}
