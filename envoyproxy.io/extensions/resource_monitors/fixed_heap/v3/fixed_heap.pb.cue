package v3

// The fixed heap resource monitor reports the Envoy process memory pressure, computed as a
// fraction of currently reserved heap memory divided by a statically configured maximum
// specified in the FixedHeapConfig.
#FixedHeapConfig: {
	max_heap_size_bytes?: uint64
}
