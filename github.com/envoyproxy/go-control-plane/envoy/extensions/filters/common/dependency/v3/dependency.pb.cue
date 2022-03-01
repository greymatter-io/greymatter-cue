package v3

#Dependency_DependencyType: "HEADER" | "FILTER_STATE_KEY" | "DYNAMIC_METADATA"

Dependency_DependencyType_HEADER:           "HEADER"
Dependency_DependencyType_FILTER_STATE_KEY: "FILTER_STATE_KEY"
Dependency_DependencyType_DYNAMIC_METADATA: "DYNAMIC_METADATA"

// Dependency specification and string identifier.
#Dependency: {
	// The kind of dependency.
	type?: #Dependency_DependencyType
	// The string identifier for the dependency.
	name?: string
}

// Dependency specification for a filter. For a filter chain to be valid, any
// dependency that is required must be provided by an earlier filter.
#FilterDependencies: {
	// A list of dependencies required on the decode path.
	decode_required?: [...#Dependency]
	// A list of dependencies provided on the encode path.
	decode_provided?: [...#Dependency]
	// A list of dependencies required on the decode path.
	encode_required?: [...#Dependency]
	// A list of dependencies provided on the encode path.
	encode_provided?: [...#Dependency]
}

// Matching requirements for a filter. For a match tree to be used with a filter, the match
// requirements must be satisfied.
//
// This protobuf is provided by the filter implementation as a way to communicate the matching
// requirements to the filter factories, allowing for config rejection if the requirements are
// not satisfied.
#MatchingRequirements: {
	data_input_allow_list?: #MatchingRequirements_DataInputAllowList
}

#MatchingRequirements_DataInputAllowList: {
	// An explicit list of data inputs that are allowed to be used with this filter.
	type_url?: [...string]
}
