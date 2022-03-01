package v1alpha1

import (
	status "google.golang.org/genproto/googleapis/rpc/status"
)

// Severities of issues.
#IssueDetails_Severity: int32

// Request message for the Parse method.
#ParseRequest: {
	// Required. Source text in CEL syntax.
	cel_source?: string
	// Tag for version of CEL syntax, for future use.
	syntax_version?: string
	// File or resource for source text, used in [SourceInfo][google.api.expr.v1alpha1.SourceInfo].
	source_location?: string
	// Prevent macro expansion.  See "Macros" in Language Defiinition.
	disable_macros?: bool
}

// Response message for the Parse method.
#ParseResponse: {
	// The parsed representation, or unset if parsing failed.
	parsed_expr?: #ParsedExpr
	// Any number of issues with [StatusDetails][] as the details.
	issues?: [...status.#Status]
}

// Request message for the Check method.
#CheckRequest: {
	// Required. The parsed representation of the CEL program.
	parsed_expr?: #ParsedExpr
	// Declarations of types for external variables and functions.
	// Required if program uses external variables or functions
	// not in the default environment.
	type_env?: [...#Decl]
	// The protocol buffer context.  See "Name Resolution" in the
	// Language Definition.
	container?: string
	// If true, use only the declarations in [type_env][google.api.expr.v1alpha1.CheckRequest.type_env].  If false (default),
	// add declarations for the standard definitions to the type environment.  See
	// "Standard Definitions" in the Language Definition.
	no_std_env?: bool
}

// Response message for the Check method.
#CheckResponse: {
	// The annotated representation, or unset if checking failed.
	checked_expr?: #CheckedExpr
	// Any number of issues with [StatusDetails][] as the details.
	issues?: [...status.#Status]
}

// Request message for the Eval method.
#EvalRequest: {
	parsed_expr?:  #ParsedExpr
	checked_expr?: #CheckedExpr
	// Bindings for the external variables.  The types SHOULD be compatible
	// with the type environment in [CheckRequest][google.api.expr.v1alpha1.CheckRequest], if checked.
	bindings?: [string]: #ExprValue
	// SHOULD be the same container as used in [CheckRequest][google.api.expr.v1alpha1.CheckRequest], if checked.
	container?: string
}

// Response message for the Eval method.
#EvalResponse: {
	// The execution result, or unset if execution couldn't start.
	result?: #ExprValue
	// Any number of issues with [StatusDetails][] as the details.
	// Note that CEL execution errors are reified into [ExprValue][google.api.expr.v1alpha1.ExprValue].
	// Nevertheless, we'll allow out-of-band issues to be raised,
	// which also makes the replies more regular.
	issues?: [...status.#Status]
}

// Warnings or errors in service execution are represented by
// [google.rpc.Status][google.rpc.Status] messages, with the following message
// in the details field.
#IssueDetails: {
	// The severity of the issue.
	severity?: #IssueDetails_Severity
	// Position in the source, if known.
	position?: #SourcePosition
	// Expression ID from [Expr][google.api.expr.v1alpha1.Expr], 0 if unknown.
	id?: int64
}

// ConformanceServiceClient is the client API for ConformanceService service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://godoc.org/google.golang.org/grpc#ClientConn.NewStream.
#ConformanceServiceClient: _

// ConformanceServiceServer is the server API for ConformanceService service.
#ConformanceServiceServer: _

// UnimplementedConformanceServiceServer can be embedded to have forward compatible implementations.
#UnimplementedConformanceServiceServer: {
}
