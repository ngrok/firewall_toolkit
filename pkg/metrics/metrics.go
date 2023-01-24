package metrics

import (
	"time"
)

// Metrics interface, a subset of the [datadog-go statsd client]
//
// [datadog-go statsd client]: https://pkg.go.dev/github.com/DataDog/datadog-go/v5/statsd#ClientInterface
type Metrics interface {
	Count(name string, value int64, tags []string, rate float64) error
	Distribution(name string, value float64, tags []string, rate float64) error
	Gauge(name string, value float64, tags []string, rate float64) error
	Histogram(name string, value float64, tags []string, rate float64) error
	Set(name string, value string, tags []string, rate float64) error
	Timing(name string, d time.Duration, tags []string, rate float64) error
	Flush() error
}

func Prefix(metricName string) string {
	return "fwtk." + metricName
}
