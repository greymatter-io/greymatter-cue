package v3

// [#extension: envoy.key_value.file_based]
// This is configuration to flush a key value store out to disk.
#FileBasedKeyValueStoreConfig: {
	// The filename to read the keys and values from, and write the keys and
	// values to.
	filename?: string
	// The interval at which the key value store should be flushed to the file.
	flush_interval?: string
}
