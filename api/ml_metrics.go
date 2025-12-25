package api

import (
	"math"
	"sort"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

const (
	// DefaultAggregationWindow is the default time window for metrics aggregation
	DefaultAggregationWindow = 5 * time.Minute

	// DefaultMetricsBufferSize is the default initial capacity for metrics buffers
	DefaultMetricsBufferSize = 1000

	// P95Percentile is the percentile value for P95 calculations
	P95Percentile = 0.95
)

// MLMetricsCollector handles Prometheus metrics collection for ML operations
type MLMetricsCollector struct {
	// Detection metrics
	detectionRequests prometheus.Counter
	detectionLatency  prometheus.Histogram
	detectionErrors   prometheus.Counter
	anomaliesDetected prometheus.Counter

	// Training metrics
	trainingRequests prometheus.Counter
	trainingDuration prometheus.Histogram
	trainingErrors   prometheus.Counter
	modelUpdates     prometheus.Counter

	// System metrics
	activeGoroutines prometheus.Gauge
	memoryUsage      prometheus.Gauge
	sampleCount      prometheus.Gauge

	// Performance metrics
	averageLatency prometheus.Gauge
	p95Latency     prometheus.Gauge
	throughput     prometheus.Gauge
	errorRate      prometheus.Gauge

	// Aggregation data
	mu                  sync.RWMutex
	detectionLatencies  []time.Duration
	requestTimestamps   []time.Time
	errorCount          int64
	totalRequests       int64
	aggregationWindow   time.Duration
	lastAggregationTime time.Time

	// Cached performance values
	currentAvgLatency float64
	currentP95Latency float64
	currentThroughput float64
	currentErrorRate  float64
}

var (
	mlMetricsOnce     sync.Once
	mlMetricsInstance *MLMetricsCollector
)

// NewMLMetricsCollector creates a new ML metrics collector
func NewMLMetricsCollector() *MLMetricsCollector {
	mlMetricsOnce.Do(func() {
		mlMetricsInstance = &MLMetricsCollector{
			// Detection metrics
			detectionRequests: promauto.NewCounter(prometheus.CounterOpts{
				Name: "cerberus_ml_detection_requests_total",
				Help: "Total number of ML detection requests",
			}),
			detectionLatency: promauto.NewHistogram(prometheus.HistogramOpts{
				Name:    "cerberus_ml_detection_latency_seconds",
				Help:    "Latency of ML detection operations",
				Buckets: prometheus.DefBuckets,
			}),
			detectionErrors: promauto.NewCounter(prometheus.CounterOpts{
				Name: "cerberus_ml_detection_errors_total",
				Help: "Total number of ML detection errors",
			}),

			// Training metrics
			trainingRequests: promauto.NewCounter(prometheus.CounterOpts{
				Name: "cerberus_ml_training_requests_total",
				Help: "Total number of ML training requests",
			}),
			trainingDuration: promauto.NewHistogram(prometheus.HistogramOpts{
				Name:    "cerberus_ml_training_duration_seconds",
				Help:    "Duration of ML training operations",
				Buckets: []float64{1, 5, 10, 30, 60, 120, 300, 600},
			}),
			trainingErrors: promauto.NewCounter(prometheus.CounterOpts{
				Name: "cerberus_ml_training_errors_total",
				Help: "Total number of ML training errors",
			}),
			modelUpdates: promauto.NewCounter(prometheus.CounterOpts{
				Name: "cerberus_ml_model_updates_total",
				Help: "Total number of ML model updates",
			}),

			// System metrics
			activeGoroutines: promauto.NewGauge(prometheus.GaugeOpts{
				Name: "cerberus_ml_active_goroutines",
				Help: "Number of active goroutines in ML system",
			}),
			memoryUsage: promauto.NewGauge(prometheus.GaugeOpts{
				Name: "cerberus_ml_memory_usage_bytes",
				Help: "Memory usage of ML system in bytes",
			}),
			sampleCount: promauto.NewGauge(prometheus.GaugeOpts{
				Name: "cerberus_ml_sample_count",
				Help: "Number of training samples processed",
			}),

			// Performance metrics
			averageLatency: promauto.NewGauge(prometheus.GaugeOpts{
				Name: "cerberus_ml_average_latency_seconds",
				Help: "Average latency of ML detection operations",
			}),
			p95Latency: promauto.NewGauge(prometheus.GaugeOpts{
				Name: "cerberus_ml_p95_latency_seconds",
				Help: "95th percentile latency of ML detection operations",
			}),
			throughput: promauto.NewGauge(prometheus.GaugeOpts{
				Name: "cerberus_ml_throughput_per_second",
				Help: "ML detection throughput in operations per second",
			}),
			errorRate: promauto.NewGauge(prometheus.GaugeOpts{
				Name: "cerberus_ml_error_rate_percent",
				Help: "ML error rate as percentage",
			}),

			// Initialize aggregation data
			detectionLatencies:  make([]time.Duration, 0, DefaultMetricsBufferSize),
			requestTimestamps:   make([]time.Time, 0, DefaultMetricsBufferSize),
			aggregationWindow:   DefaultAggregationWindow,
			lastAggregationTime: time.Now(),
		}
	})
	return mlMetricsInstance
}

// RecordDetection records a detection operation
func (m *MLMetricsCollector) RecordDetection(duration time.Duration, isAnomaly bool, hadError bool) {
	m.detectionRequests.Inc()
	m.detectionLatency.Observe(duration.Seconds())

	if hadError {
		m.detectionErrors.Inc()
	}

	if isAnomaly {
		m.anomaliesDetected.Inc()
	}

	// Store data for aggregation
	now := time.Now()
	m.mu.Lock()
	m.detectionLatencies = append(m.detectionLatencies, duration)
	m.requestTimestamps = append(m.requestTimestamps, now)
	if hadError {
		m.errorCount++
	}
	m.totalRequests++
	m.mu.Unlock()

	// Trigger aggregation if needed
	m.aggregateMetricsIfNeeded()
}

// RecordTraining records a training operation
func (m *MLMetricsCollector) RecordTraining(duration time.Duration, hadError bool) {
	m.trainingRequests.Inc()
	m.trainingDuration.Observe(duration.Seconds())

	if hadError {
		m.trainingErrors.Inc()
	} else {
		m.modelUpdates.Inc()
	}
}

// UpdateSystemMetrics updates system-level metrics
func (m *MLMetricsCollector) UpdateSystemMetrics(goroutines int, memoryBytes float64, samples int64) {
	m.activeGoroutines.Set(float64(goroutines))
	m.memoryUsage.Set(memoryBytes)
	m.sampleCount.Set(float64(samples))
}

// UpdatePerformanceMetrics updates performance metrics
func (m *MLMetricsCollector) UpdatePerformanceMetrics(avgLatency, p95Latency, throughput, errorRate float64) {
	m.averageLatency.Set(avgLatency)
	m.p95Latency.Set(p95Latency)
	m.throughput.Set(throughput)
	m.errorRate.Set(errorRate)
}

// aggregateMetricsIfNeeded checks if aggregation should run and executes it
func (m *MLMetricsCollector) aggregateMetricsIfNeeded() {
	m.mu.Lock()
	defer m.mu.Unlock()

	now := time.Now()
	if now.Sub(m.lastAggregationTime) >= m.aggregationWindow {
		m.aggregateMetrics()
		m.lastAggregationTime = now
	}
}

// aggregateMetrics calculates performance metrics from recent data
func (m *MLMetricsCollector) aggregateMetrics() {
	if len(m.detectionLatencies) == 0 {
		return
	}

	avgLatency := m.calculateAverageLatency()
	p95Latency := m.calculateP95Latency()
	throughput := m.calculateThroughput()
	errorRate := m.calculateErrorRate()

	m.updatePerformanceMetrics(avgLatency, p95Latency, throughput, errorRate)
	m.cachePerformanceValues(avgLatency, p95Latency, throughput, errorRate)
	m.cleanupOldData()
}

// calculateAverageLatency computes the average latency from recent detections
// Returns 0 if no detections have been recorded
func (m *MLMetricsCollector) calculateAverageLatency() float64 {
	var totalLatency time.Duration
	for _, latency := range m.detectionLatencies {
		totalLatency += latency
	}
	return totalLatency.Seconds() / float64(len(m.detectionLatencies))
}

// calculateP95Latency computes the 95th percentile latency
// from recent detection operations
func (m *MLMetricsCollector) calculateP95Latency() float64 {
	sortedLatencies := make([]time.Duration, len(m.detectionLatencies))
	copy(sortedLatencies, m.detectionLatencies)
	sort.Slice(sortedLatencies, func(i, j int) bool {
		return sortedLatencies[i] < sortedLatencies[j]
	})

	p95Index := int(math.Ceil(float64(len(sortedLatencies))*P95Percentile)) - 1
	if p95Index < 0 {
		p95Index = 0
	}
	if p95Index >= len(sortedLatencies) {
		p95Index = len(sortedLatencies) - 1
	}

	return sortedLatencies[p95Index].Seconds()
}

// calculateThroughput computes requests per second over the aggregation window
// Returns 0 if the time window is invalid
func (m *MLMetricsCollector) calculateThroughput() float64 {
	timeSpan := m.aggregationWindow.Seconds()
	if timeSpan <= 0 {
		return 0
	}

	throughput := float64(len(m.requestTimestamps)) / timeSpan
	m.throughput.Set(throughput)
	return throughput
}

// calculateErrorRate computes the error rate as a percentage
// Returns 0 if no requests have been recorded
func (m *MLMetricsCollector) calculateErrorRate() float64 {
	if m.totalRequests == 0 {
		return 0
	}
	return float64(m.errorCount) / float64(m.totalRequests) * 100.0
}

// updatePerformanceMetrics updates the Prometheus metrics gauges
// with the calculated performance values
func (m *MLMetricsCollector) updatePerformanceMetrics(avgLatency, p95Latency, throughput, errorRate float64) {
	m.averageLatency.Set(avgLatency)
	m.p95Latency.Set(p95Latency)
	m.errorRate.Set(errorRate)
}

// cachePerformanceValues stores current performance values for quick access
// without querying Prometheus metrics
func (m *MLMetricsCollector) cachePerformanceValues(avgLatency, p95Latency, throughput, errorRate float64) {
	m.currentAvgLatency = avgLatency
	m.currentP95Latency = p95Latency
	m.currentThroughput = throughput
	m.currentErrorRate = errorRate
}

// cleanupOldData removes latency and timestamp data older than the aggregation window
// to prevent unbounded memory growth
func (m *MLMetricsCollector) cleanupOldData() {
	cutoffTime := time.Now().Add(-m.aggregationWindow)
	validLatencies := make([]time.Duration, 0, len(m.detectionLatencies))
	validTimestamps := make([]time.Time, 0, len(m.requestTimestamps))

	for i, timestamp := range m.requestTimestamps {
		if timestamp.After(cutoffTime) {
			validTimestamps = append(validTimestamps, timestamp)
			if i < len(m.detectionLatencies) {
				validLatencies = append(validLatencies, m.detectionLatencies[i])
			}
		}
	}

	m.detectionLatencies = validLatencies
	m.requestTimestamps = validTimestamps
	m.errorCount = 0
	m.totalRequests = 0
}

// GetPerformanceMetrics returns the current performance metrics
func (m *MLMetricsCollector) GetPerformanceMetrics() (avgLatency, p95Latency, throughput, errorRate float64) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.currentAvgLatency, m.currentP95Latency, m.currentThroughput, m.currentErrorRate
}
