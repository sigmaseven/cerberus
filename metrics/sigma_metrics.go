package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// SIGMA-specific Prometheus metrics for observability.
//
// These metrics provide insight into SIGMA rule evaluation performance,
// cache efficiency, and error rates. Use these for:
//   - Performance monitoring and alerting
//   - Capacity planning (cache sizing, rule complexity analysis)
//   - Debugging rule evaluation issues
//
// All metrics are automatically registered with Prometheus.

var (
	// SigmaRuleEvaluationsTotal counts total SIGMA rule evaluations.
	// Labels:
	//   - rule_id: The ID of the evaluated rule
	//   - result: "match", "no_match", or "error"
	SigmaRuleEvaluationsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "cerberus",
			Subsystem: "sigma",
			Name:      "rule_evaluations_total",
			Help:      "Total number of SIGMA rule evaluations",
		},
		[]string{"rule_id", "result"},
	)

	// SigmaRuleEvaluationDuration measures rule evaluation time.
	// This histogram helps identify slow rules for optimization.
	// Buckets are tuned for typical SIGMA evaluation times (microseconds to milliseconds).
	SigmaRuleEvaluationDuration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: "cerberus",
			Subsystem: "sigma",
			Name:      "rule_evaluation_duration_seconds",
			Help:      "Time spent evaluating SIGMA rules",
			// Buckets: 10μs to 1s with geometric progression
			Buckets: []float64{
				0.00001, // 10μs
				0.00005, // 50μs
				0.0001,  // 100μs
				0.0005,  // 500μs
				0.001,   // 1ms
				0.005,   // 5ms
				0.01,    // 10ms
				0.05,    // 50ms
				0.1,     // 100ms
				0.5,     // 500ms
				1.0,     // 1s
			},
		},
		[]string{"rule_id"},
	)

	// SigmaCacheHitsTotal counts cache hits for parsed rules.
	SigmaCacheHitsTotal = promauto.NewCounter(
		prometheus.CounterOpts{
			Namespace: "cerberus",
			Subsystem: "sigma",
			Name:      "cache_hits_total",
			Help:      "Total number of SIGMA rule cache hits",
		},
	)

	// SigmaCacheMissesTotal counts cache misses requiring YAML parsing.
	SigmaCacheMissesTotal = promauto.NewCounter(
		prometheus.CounterOpts{
			Namespace: "cerberus",
			Subsystem: "sigma",
			Name:      "cache_misses_total",
			Help:      "Total number of SIGMA rule cache misses",
		},
	)

	// SigmaCacheEvictionsTotal counts LRU evictions from the cache.
	SigmaCacheEvictionsTotal = promauto.NewCounter(
		prometheus.CounterOpts{
			Namespace: "cerberus",
			Subsystem: "sigma",
			Name:      "cache_evictions_total",
			Help:      "Total number of SIGMA rule cache evictions",
		},
	)

	// SigmaCacheExpirationsTotal counts TTL-based expirations from the cache.
	SigmaCacheExpirationsTotal = promauto.NewCounter(
		prometheus.CounterOpts{
			Namespace: "cerberus",
			Subsystem: "sigma",
			Name:      "cache_expirations_total",
			Help:      "Total number of SIGMA rule cache TTL expirations",
		},
	)

	// SigmaCacheSize is the current number of cached rules.
	SigmaCacheSize = promauto.NewGauge(
		prometheus.GaugeOpts{
			Namespace: "cerberus",
			Subsystem: "sigma",
			Name:      "cache_size",
			Help:      "Current number of SIGMA rules in cache",
		},
	)

	// SigmaModifierEvaluationsTotal counts modifier evaluations by type.
	// Labels:
	//   - modifier: The modifier name (e.g., "contains", "endswith", "base64")
	SigmaModifierEvaluationsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "cerberus",
			Subsystem: "sigma",
			Name:      "modifier_evaluations_total",
			Help:      "Total number of SIGMA modifier evaluations by type",
		},
		[]string{"modifier"},
	)

	// SigmaParseErrorsTotal counts YAML/condition parsing errors.
	// Labels:
	//   - error_type: "yaml_parse", "condition_parse", "validation"
	SigmaParseErrorsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "cerberus",
			Subsystem: "sigma",
			Name:      "parse_errors_total",
			Help:      "Total number of SIGMA rule parsing errors",
		},
		[]string{"error_type"},
	)

	// SigmaFieldMappingLookups counts field mapping operations.
	// Labels:
	//   - source: "logsource", "generic", "alias", "passthrough"
	SigmaFieldMappingLookups = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "cerberus",
			Subsystem: "sigma",
			Name:      "field_mapping_lookups_total",
			Help:      "Total number of SIGMA field mapping lookups by resolution source",
		},
		[]string{"source"},
	)

	// SigmaConditionEvaluations counts condition AST evaluations.
	// Labels:
	//   - operator: "and", "or", "not", "all_of", "any_of", "count_of"
	SigmaConditionEvaluations = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "cerberus",
			Subsystem: "sigma",
			Name:      "condition_evaluations_total",
			Help:      "Total number of SIGMA condition operator evaluations",
		},
		[]string{"operator"},
	)

	// SigmaActiveRules is the current count of enabled SIGMA rules.
	SigmaActiveRules = promauto.NewGauge(
		prometheus.GaugeOpts{
			Namespace: "cerberus",
			Subsystem: "sigma",
			Name:      "active_rules",
			Help:      "Number of currently active (enabled) SIGMA rules",
		},
	)

	// SigmaRuleLoadDuration measures time to load/parse rules.
	SigmaRuleLoadDuration = promauto.NewHistogram(
		prometheus.HistogramOpts{
			Namespace: "cerberus",
			Subsystem: "sigma",
			Name:      "rule_load_duration_seconds",
			Help:      "Time spent loading and parsing SIGMA rules",
			Buckets:   prometheus.ExponentialBuckets(0.001, 2, 10), // 1ms to ~1s
		},
	)
)

// RecordRuleEvaluation records a SIGMA rule evaluation with result and timing.
// This is the primary entry point for recording evaluation metrics.
//
// Parameters:
//   - ruleID: The ID of the evaluated rule
//   - matched: Whether the rule matched
//   - durationSec: Evaluation duration in seconds
func RecordRuleEvaluation(ruleID string, matched bool, durationSec float64) {
	result := "no_match"
	if matched {
		result = "match"
	}
	SigmaRuleEvaluationsTotal.WithLabelValues(ruleID, result).Inc()
	SigmaRuleEvaluationDuration.WithLabelValues(ruleID).Observe(durationSec)
}

// RecordRuleEvaluationError records a failed rule evaluation.
func RecordRuleEvaluationError(ruleID string) {
	SigmaRuleEvaluationsTotal.WithLabelValues(ruleID, "error").Inc()
}

// RecordCacheHit records a cache hit.
func RecordCacheHit() {
	SigmaCacheHitsTotal.Inc()
}

// RecordCacheMiss records a cache miss.
func RecordCacheMiss() {
	SigmaCacheMissesTotal.Inc()
}

// RecordCacheEviction records an LRU cache eviction.
func RecordCacheEviction() {
	SigmaCacheEvictionsTotal.Inc()
}

// RecordCacheExpiration records a TTL-based cache expiration.
func RecordCacheExpiration() {
	SigmaCacheExpirationsTotal.Inc()
}

// UpdateCacheSize updates the current cache size gauge.
func UpdateCacheSize(size int) {
	SigmaCacheSize.Set(float64(size))
}

// RecordModifierEvaluation records a modifier evaluation.
func RecordModifierEvaluation(modifier string) {
	SigmaModifierEvaluationsTotal.WithLabelValues(modifier).Inc()
}

// RecordParseError records a parsing error by type.
func RecordParseError(errorType string) {
	SigmaParseErrorsTotal.WithLabelValues(errorType).Inc()
}

// RecordFieldMappingLookup records a field mapping lookup.
func RecordFieldMappingLookup(source string) {
	SigmaFieldMappingLookups.WithLabelValues(source).Inc()
}

// RecordConditionEvaluation records a condition operator evaluation.
func RecordConditionEvaluation(operator string) {
	SigmaConditionEvaluations.WithLabelValues(operator).Inc()
}

// UpdateActiveRules updates the count of active SIGMA rules.
func UpdateActiveRules(count int) {
	SigmaActiveRules.Set(float64(count))
}

// RecordRuleLoadDuration records the time to load a rule.
func RecordRuleLoadDuration(durationSec float64) {
	SigmaRuleLoadDuration.Observe(durationSec)
}
