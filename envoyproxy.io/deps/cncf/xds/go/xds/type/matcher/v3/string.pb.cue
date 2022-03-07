package v3

#StringMatcher: {
	exact?:       string
	prefix?:      string
	suffix?:      string
	safe_regex?:  #RegexMatcher
	contains?:    string
	ignore_case?: bool
}

#ListStringMatcher: {
	patterns?: [...#StringMatcher]
}
