package v3

// Specifies the int64 start and end of the range using half-open interval semantics [start,
// end).
#Int64Range: {
	// start of the range (inclusive)
	start?: int64
	// end of the range (exclusive)
	end?: int64
}

// Specifies the int32 start and end of the range using half-open interval semantics [start,
// end).
#Int32Range: {
	// start of the range (inclusive)
	start?: int32
	// end of the range (exclusive)
	end?: int32
}

// Specifies the double start and end of the range using half-open interval semantics [start,
// end).
#DoubleRange: {
	// start of the range (inclusive)
	start?: float64
	// end of the range (exclusive)
	end?: float64
}
