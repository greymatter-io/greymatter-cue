package http

#LocationType: "header" | "cookie" | "queryString" | "metadata"

LocationType_header:      "header"
LocationType_cookie:      "cookie"
LocationType_queryString: "queryString"
LocationType_metadata:    "metadata"

#EnsureVariablesConfig_Rule_Value_MatchType: "exact" | "prefix" | "suffix" | "regex"

EnsureVariablesConfig_Rule_Value_MatchType_exact:  "exact"
EnsureVariablesConfig_Rule_Value_MatchType_prefix: "prefix"
EnsureVariablesConfig_Rule_Value_MatchType_suffix: "suffix"
EnsureVariablesConfig_Rule_Value_MatchType_regex:  "regex"

#EnsureVariablesConfig_Rule_CopyTo_Direction: "default" | "request" | "response" | "both"

EnsureVariablesConfig_Rule_CopyTo_Direction_default:  "default"
EnsureVariablesConfig_Rule_CopyTo_Direction_request:  "request"
EnsureVariablesConfig_Rule_CopyTo_Direction_response: "response"
EnsureVariablesConfig_Rule_CopyTo_Direction_both:     "both"

#CookieOptions: {
	httpOnly?: bool
	secure?:   bool
	domain?:   string
	path?:     string
	maxAge?:   string
}

#EnsureVariablesConfig: {
	rules?: [...#EnsureVariablesConfig_Rule]
}

#EnsureVariablesConfig_Rule: {
	key?:                 string
	location?:            #LocationType
	metadataFilter?:      string
	enforce?:             bool
	enforceResponseCode?: int32
	removeOriginal?:      bool
	value?:               #EnsureVariablesConfig_Rule_Value
	copyTo?: [...#EnsureVariablesConfig_Rule_CopyTo]
}

#EnsureVariablesConfig_Rule_Value: {
	matchType?:   #EnsureVariablesConfig_Rule_Value_MatchType
	matchString?: string
}

#EnsureVariablesConfig_Rule_CopyTo: {
	location?:      #LocationType
	key?:           string
	direction?:     #EnsureVariablesConfig_Rule_CopyTo_Direction
	cookieOptions?: #CookieOptions
}
