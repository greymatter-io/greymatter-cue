package http

#ObservablesConfig: {
	emitFullResponse?: bool
	useKafka?:         bool
	// Kafka TLS configuration
	useKafkaTLS?:           bool
	kafkaCAs?:              string
	kafkaCertificate?:      string
	kafkaCertificateKey?:   string
	kafkaServerName?:       string
	enforceAudit?:          bool
	topic?:                 string
	eventTopic?:            string
	kafkaZKDiscover?:       bool
	kafkaServerConnection?: string
	fileName?:              string
	logLevel?:              string
	encryptionAlgorithm?:   string
	// Bas64 encrypted bytes
	encryptionKey?:   string
	encryptionKeyID?: uint32
	// Kafka timeout
	timeoutMs?: int32
}

#ObservablesRouteConfig: {
	emitFullResponse?: bool
}
