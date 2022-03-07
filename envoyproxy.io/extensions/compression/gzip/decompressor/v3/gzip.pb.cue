package v3

#Gzip: {
	// Value from 9 to 15 that represents the base two logarithmic of the decompressor's window size.
	// The decompression window size needs to be equal or larger than the compression window size.
	// The default window size is 15.
	// This is so that the decompressor can decompress a response compressed by a compressor with any compression window size.
	// For more details about this parameter, please refer to `zlib manual <https://www.zlib.net/manual.html>`_ > inflateInit2.
	window_bits?: uint32
	// Value for zlib's decompressor output buffer. If not set, defaults to 4096.
	// See https://www.zlib.net/manual.html for more details.
	chunk_size?: uint32
}
