package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	EventsIngested = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "cerberus_events_ingested_total",
			Help: "Total number of events ingested",
		},
		[]string{"source"},
	)

	AlertsGenerated = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "cerberus_alerts_generated_total",
			Help: "Total number of alerts generated",
		},
		[]string{"severity"},
	)

	ActionsExecuted = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "cerberus_actions_executed_total",
			Help: "Total number of actions executed",
		},
		[]string{"type"},
	)

	EventProcessingDuration = promauto.NewHistogram(
		prometheus.HistogramOpts{
			Name:    "cerberus_event_processing_duration_seconds",
			Help:    "Time taken to process events",
			Buckets: prometheus.DefBuckets,
		},
	)

	DeadLetterInsertFailures = promauto.NewCounter(
		prometheus.CounterOpts{
			Name: "cerberus_dead_letter_insert_failures_total",
			Help: "Total number of dead letter insertion failures",
		},
	)

	CacheHits = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "cerberus_cache_hits_total",
			Help: "Total number of cache hits",
		},
		[]string{"cache_type"},
	)

	CacheMisses = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "cerberus_cache_misses_total",
			Help: "Total number of cache misses",
		},
		[]string{"cache_type"},
	)

	CacheErrors = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "cerberus_cache_errors_total",
			Help: "Total number of cache errors",
		},
		[]string{"cache_type", "operation"},
	)

	WorkerPoolActiveWorkers = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "cerberus_worker_pool_active_workers",
			Help: "Number of active workers in worker pool",
		},
		[]string{"pool_type"},
	)

	WorkerPoolQueueSize = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "cerberus_worker_pool_queue_size",
			Help: "Current size of worker pool queue",
		},
		[]string{"pool_type"},
	)

	WorkerPoolTasksProcessed = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "cerberus_worker_pool_tasks_processed_total",
			Help: "Total number of tasks processed by worker pool",
		},
		[]string{"pool_type"},
	)

	// Circuit breaker metrics for monitoring external service health
	CircuitBreakerState = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "cerberus_circuit_breaker_state",
			Help: "Circuit breaker state (0=closed, 1=half-open, 2=open)",
		},
		[]string{"endpoint"},
	)

	CircuitBreakerStateTransitions = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "cerberus_circuit_breaker_state_transitions_total",
			Help: "Total number of circuit breaker state transitions",
		},
		[]string{"endpoint", "from_state", "to_state"},
	)

	CircuitBreakerRequestsBlocked = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "cerberus_circuit_breaker_requests_blocked_total",
			Help: "Total number of requests blocked by circuit breaker",
		},
		[]string{"endpoint"},
	)

	// TCP connection pool metrics for monitoring resource utilization
	TCPConnectionPoolActive = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "cerberus_tcp_connection_pool_active",
			Help: "Number of active TCP connections in pool",
		},
		[]string{"listener_type"},
	)

	TCPConnectionPoolRejected = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "cerberus_tcp_connection_pool_rejected_total",
			Help: "Total number of TCP connections rejected due to pool limit",
		},
		[]string{"listener_type"},
	)

	// FluentdPanics tracks panic recoveries in Fluentd message processing
	// SECURITY: Monitor for malformed messages causing panics
	FluentdPanics = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "cerberus_fluentd_panics_total",
			Help: "Total panics in Fluentd message processing",
		},
		[]string{"listener"},
	)

	// RegexValidationFailures tracks regex patterns rejected by validation
	// SECURITY: Monitor for potentially malicious ReDoS patterns
	RegexValidationFailures = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "cerberus_regex_validation_failures_total",
			Help: "Regex patterns rejected by validation",
		},
		[]string{"reason"},
	)

	// TASK 2.5: Regex timeout and ReDoS protection metrics
	// RegexTimeouts tracks regex evaluation timeouts
	// SECURITY: Monitor for ReDoS attack attempts
	RegexTimeouts = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "cerberus_regex_timeout_total",
			Help: "Total number of regex evaluation timeouts",
		},
		[]string{"rule_id", "pattern_hash"},
	)

	// RegexExecutionDuration tracks time taken for regex evaluation
	// SECURITY: Monitor for performance degradation
	RegexExecutionDuration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "cerberus_regex_execution_duration_seconds",
			Help:    "Time taken to execute regex patterns",
			Buckets: []float64{0.001, 0.005, 0.01, 0.05, 0.1, 0.25, 0.5, 1.0}, // ms to seconds
		},
		[]string{"rule_id"},
	)

	// RegexComplexityRejections tracks patterns rejected due to complexity
	// SECURITY: Monitor for malicious patterns during rule loading
	RegexComplexityRejections = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "cerberus_regex_complexity_rejections_total",
			Help: "Total number of regex patterns rejected due to complexity analysis",
		},
		[]string{"risk_level", "issue_type"},
	)

	// TASK 7.6: DLQ metrics for malformed event tracking
	// DLQEventsTotal tracks total DLQ events written
	DLQEventsTotal = promauto.NewCounter(
		prometheus.CounterOpts{
			Name: "cerberus_dlq_events_total",
			Help: "Total number of events written to dead-letter queue",
		},
	)

	// DLQEventsByReason tracks DLQ events by error reason
	DLQEventsByReason = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "cerberus_dlq_events_by_reason_total",
			Help: "Total number of DLQ events by error reason",
		},
		[]string{"reason"},
	)

	// DLQEventsByProtocol tracks DLQ events by protocol
	DLQEventsByProtocol = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "cerberus_dlq_events_by_protocol_total",
			Help: "Total number of DLQ events by protocol",
		},
		[]string{"protocol"},
	)

	// DLQReplaySuccess tracks successful DLQ event replays
	DLQReplaySuccess = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "cerberus_dlq_replay_success_total",
			Help: "Total number of successful DLQ event replays",
		},
		[]string{"protocol"},
	)

	// DLQReplayFailure tracks failed DLQ event replays
	DLQReplayFailure = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "cerberus_dlq_replay_failure_total",
			Help: "Total number of failed DLQ event replays",
		},
		[]string{"protocol", "reason"},
	)

	// TASK 25.5: Playbook execution metrics
	// PlaybookExecutionsTotal tracks total playbook executions
	PlaybookExecutionsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "cerberus_playbook_executions_total",
			Help: "Total number of playbook executions",
		},
		[]string{"playbook_id", "status"},
	)

	// PlaybookExecutionDuration tracks playbook execution duration
	PlaybookExecutionDuration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "cerberus_playbook_execution_duration_seconds",
			Help:    "Time taken to execute playbooks",
			Buckets: prometheus.DefBuckets,
		},
		[]string{"playbook_id"},
	)

	// PlaybookStepFailures tracks failed playbook steps
	PlaybookStepFailures = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "cerberus_playbook_step_failures_total",
			Help: "Total number of failed playbook steps",
		},
		[]string{"playbook_id", "step_id", "action_type"},
	)

	// PlaybookQueueDepth tracks queued playbook executions
	PlaybookQueueDepth = promauto.NewGauge(
		prometheus.GaugeOpts{
			Name: "cerberus_playbook_queue_depth",
			Help: "Current number of playbook executions in queue",
		},
	)

	// TASK 131.5: SIGMA Engine Rollout Metrics
	// Track native vs legacy engine usage for gradual rollout monitoring

	// SigmaEngineEvaluations tracks rule evaluations by engine type
	// Labels: engine_type (native|legacy), rule_id
	// OBSERVABILITY: Monitor rollout percentage and distribution
	SigmaEngineEvaluations = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "cerberus_sigma_engine_evaluations_total",
			Help: "Total number of rule evaluations by engine type",
		},
		[]string{"engine_type", "rule_id"},
	)

	// SigmaRolloutDecisions tracks feature flag decision reasons
	// Labels: decision (native|legacy), reason (master_switch_off|explicit_whitelist|explicit_blocklist|hash_routing)
	// OBSERVABILITY: Debug rollout decision logic and verify expected behavior
	SigmaRolloutDecisions = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "cerberus_sigma_rollout_decisions_total",
			Help: "Total number of SIGMA rollout decisions by reason",
		},
		[]string{"decision", "reason"},
	)

	// SigmaEngineErrors tracks errors in SIGMA engine evaluation
	// Labels: error_type (parse_error|evaluation_error|field_mapping_error)
	// OBSERVABILITY: Monitor native engine health and identify problematic rules
	SigmaEngineErrors = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "cerberus_sigma_engine_errors_total",
			Help: "Total number of SIGMA engine evaluation errors",
		},
		[]string{"error_type", "rule_id"},
	)

	// TASK 143.3: SQLite Connection Pool Metrics
	// Track connection pool health, utilization, and performance characteristics

	// SQLitePoolOpenConnections tracks current open connections
	// Labels: pool_type (read|write)
	// OBSERVABILITY: Monitor connection pool utilization
	SQLitePoolOpenConnections = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "cerberus_sqlite_pool_open_connections",
			Help: "Current number of open connections in SQLite pool",
		},
		[]string{"pool_type"},
	)

	// SQLitePoolInUse tracks connections currently in use
	// Labels: pool_type (read|write)
	// OBSERVABILITY: Monitor active query load
	SQLitePoolInUse = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "cerberus_sqlite_pool_in_use",
			Help: "Number of connections currently in use",
		},
		[]string{"pool_type"},
	)

	// SQLitePoolIdle tracks idle connections in pool
	// Labels: pool_type (read|write)
	// OBSERVABILITY: Monitor connection pool efficiency
	SQLitePoolIdle = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "cerberus_sqlite_pool_idle",
			Help: "Number of idle connections in pool",
		},
		[]string{"pool_type"},
	)

	// SQLitePoolWaitCount tracks total waits for a connection
	// Labels: pool_type (read|write)
	// OBSERVABILITY: Monitor connection contention
	SQLitePoolWaitCount = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "cerberus_sqlite_pool_wait_count_total",
			Help: "Total number of times waited for a connection",
		},
		[]string{"pool_type"},
	)

	// SQLitePoolWaitDuration tracks total time waited for connections
	// Labels: pool_type (read|write)
	// OBSERVABILITY: Monitor connection pool latency impact
	SQLitePoolWaitDuration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "cerberus_sqlite_pool_wait_duration_seconds",
			Help:    "Time spent waiting for a connection from pool",
			Buckets: []float64{0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0},
		},
		[]string{"pool_type"},
	)

	// SQLitePoolMaxOpenConnections tracks configured max connections
	// Labels: pool_type (read|write)
	// OBSERVABILITY: Configuration visibility for capacity planning
	SQLitePoolMaxOpenConnections = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "cerberus_sqlite_pool_max_open_connections",
			Help: "Maximum number of open connections allowed",
		},
		[]string{"pool_type"},
	)

	// SQLitePoolMaxIdleClosed tracks connections closed due to max idle limit
	// Labels: pool_type (read|write)
	// OBSERVABILITY: Monitor connection churn
	SQLitePoolMaxIdleClosed = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "cerberus_sqlite_pool_max_idle_closed_total",
			Help: "Total connections closed due to max idle limit",
		},
		[]string{"pool_type"},
	)

	// SQLitePoolMaxLifetimeClosed tracks connections closed due to max lifetime
	// Labels: pool_type (read|write)
	// OBSERVABILITY: Monitor connection recycling
	SQLitePoolMaxLifetimeClosed = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "cerberus_sqlite_pool_max_lifetime_closed_total",
			Help: "Total connections closed due to max lifetime limit",
		},
		[]string{"pool_type"},
	)

	// TASK 137.4: API panic recovery metrics
	// APIPanicsRecovered tracks panics recovered by the error recovery middleware
	// Labels: method (HTTP method), path (sanitized path)
	// SECURITY: Monitor for unexpected panics in API handlers
	APIPanicsRecovered = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "cerberus_api_panics_recovered_total",
			Help: "Total number of panics recovered in API handlers",
		},
		[]string{"method", "path"},
	)

	// TASK 171: Rule Performance Tracking Metrics
	// RuleEvaluationDuration tracks time spent evaluating rules
	// Labels: rule_id, rule_type (sigma|cql|correlation)
	// OBSERVABILITY: Monitor rule performance for optimization
	RuleEvaluationDuration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "cerberus_rule_evaluation_duration_seconds",
			Help:    "Time spent evaluating rules",
			Buckets: []float64{0.0001, 0.0005, 0.001, 0.005, 0.01, 0.05, 0.1},
		},
		[]string{"rule_id", "rule_type"},
	)

	// RuleEvaluationsTotal tracks total number of rule evaluations
	// Labels: rule_id, result (match|no_match|error)
	// OBSERVABILITY: Monitor rule evaluation counts and success rates
	RuleEvaluationsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "cerberus_rule_evaluations_total",
			Help: "Total number of rule evaluations",
		},
		[]string{"rule_id", "result"},
	)

	// RuleMatchesTotal tracks total number of rule matches
	// Labels: rule_id, severity
	// OBSERVABILITY: Monitor detection rates by rule and severity
	RuleMatchesTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "cerberus_rule_matches_total",
			Help: "Total number of rule matches",
		},
		[]string{"rule_id", "severity"},
	)

	// RuleFalsePositivesTotal tracks user-reported false positives
	// Labels: rule_id
	// OBSERVABILITY: Track rule accuracy and tuning needs
	RuleFalsePositivesTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "cerberus_rule_false_positives_total",
			Help: "Total number of user-reported false positives",
		},
		[]string{"rule_id"},
	)
)
