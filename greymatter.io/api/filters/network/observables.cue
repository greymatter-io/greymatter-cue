package network

#ObservablesTCPConfig: {
	// Whether to emit response (or otherwise just request)
	emitFullResponse?: bool
	// Whether to use Kafka
	useKafka?: bool
	// Kafka TLS configuration
	// -----------------------
	// Whether to use TLS when connecting to Kafka
	useKafkaTLS?: bool
	// Kafka Certificate Authorities
	kafkaCAs?: string
	// Kafka TLC cert key
	kafkaCertificate?: string
	// Kafka TLC cert key
	kafkaCertificateKey?: string
	// Name of Kafka server
	kafkaServerName?: string
	// The topic name to embed in the event.
	topic?: string
	// Kafka topic to publish to.
	eventTopic?: string
	// Whether to use Zookeeper for Kafka discovery (if not using file storage)
	kafkaZKDiscover?: bool
	// Kafka connection string (if not using file storage)
	kafkaServerConnection?: string
	// File to store event to use (if not using Kafka)
	fileName?: string
	// Log level to use ("warn", "debug" or "info")
	logLevel?: string
	// Algorithm used to encrypt
	encryptionAlgorithm?: string
	// Key to encrypt event
	encryptionKey?:   string
	encryptionKeyID?: uint32
	// Kafka timeout
	timeoutMs?:    int32
	enforceAudit?: bool
	// Decode
	decodeToProtocol?: string
	decodeSkipFail?:   bool
}
