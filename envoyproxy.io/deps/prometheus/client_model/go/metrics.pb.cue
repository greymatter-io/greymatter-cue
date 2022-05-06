package go

#MetricType: int32

#LabelPair: {
	name?:  string
	value?: string
}

#Gauge: {
	value?: float64
}

#Counter: {
	value?:    float64
	exemplar?: #Exemplar
}

#Quantile: {
	quantile?: float64
	value?:    float64
}

#Summary: {
	sample_count?: uint64
	sample_sum?:   float64
	quantile?: [...#Quantile]
}

#Untyped: {
	value?: float64
}

#Histogram: {
	sample_count?: uint64
	sample_sum?:   float64
	bucket?: [...#Bucket]
}

#Bucket: {
	cumulative_count?: uint64
	upper_bound?:      float64
	exemplar?:         #Exemplar
}

#Exemplar: {
	label?: [...#LabelPair]
	value?:     float64
	timestamp?: string
}

#Metric: {
	label?: [...#LabelPair]
	gauge?:        #Gauge
	counter?:      #Counter
	summary?:      #Summary
	untyped?:      #Untyped
	histogram?:    #Histogram
	timestamp_ms?: int64
}

#MetricFamily: {
	name?: string
	help?: string
	type?: #MetricType
	metric?: [...#Metric]
}
