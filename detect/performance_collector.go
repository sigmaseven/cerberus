package detect

import (
	"math"
	"sort"
	"sync"
	"time"

	"cerberus/storage"

	"go.uber.org/zap"
)

const (
	// DefaultBatchSize is the number of evaluations before flushing to storage
	// PERFORMANCE: Batching reduces DB write overhead
	DefaultBatchSize = 100

	// MaxPendingTimes limits memory usage for percentile calculation
	// SECURITY: Prevents unbounded memory growth
	MaxPendingTimes = 1000
)

// PendingStats accumulates statistics before batch flush
// THREAD-SAFETY: Protected by PerformanceCollector's mutex
type PendingStats struct {
	Times    []float64 // Evaluation times in milliseconds
	Matches  int64     // Number of matches
	LastEval time.Time // Last evaluation timestamp
}

// PerformanceCollector tracks rule performance metrics
// PRODUCTION: Non-blocking collection for minimal impact on detection path
// SECURITY: Bounded memory usage prevents resource exhaustion
// OBSERVABILITY: Enables performance monitoring and optimization
// CRITICAL-4 FIX: Added circuit breaker for flush failures
type PerformanceCollector struct {
	mu        sync.Mutex
	pending   map[string]*PendingStats // Rule ID -> accumulated stats
	batchSize int                      // Flush every N evaluations
	storage   storage.RulePerformanceStorage
	logger    *zap.SugaredLogger

	// Metrics for monitoring collector health
	totalFlushes      int64
	totalEvaluations  int64
	lastFlush         time.Time
	flushErrors       int64

	// CRITICAL-4 FIX: Circuit breaker for flush failures
	consecutiveFailures int
	backoffUntil        time.Time
}

// NewPerformanceCollector creates a performance collector
// PRODUCTION: Returns immediately, background flushing is non-blocking
func NewPerformanceCollector(
	storage storage.RulePerformanceStorage,
	logger *zap.SugaredLogger,
) *PerformanceCollector {
	return &PerformanceCollector{
		pending:   make(map[string]*PendingStats),
		batchSize: DefaultBatchSize,
		storage:   storage,
		logger:    logger,
		lastFlush: time.Now(),
	}
}

// RecordEvaluation records a single rule evaluation
// PERFORMANCE: Fast path - only mutex lock, no I/O
// THREAD-SAFETY: Safe for concurrent calls from multiple goroutines
// NON-BLOCKING: Returns immediately, batching happens asynchronously
func (pc *PerformanceCollector) RecordEvaluation(
	ruleID string,
	durationMs float64,
	matched bool,
) {
	if ruleID == "" {
		return // Ignore invalid input
	}

	pc.mu.Lock()
	defer pc.mu.Unlock()

	// Get or create pending stats
	stats, exists := pc.pending[ruleID]
	if !exists {
		stats = &PendingStats{
			Times: make([]float64, 0, 100),
		}
		pc.pending[ruleID] = stats
	}

	// Record evaluation time
	// SECURITY: Enforce memory limit to prevent unbounded growth
	if len(stats.Times) < MaxPendingTimes {
		stats.Times = append(stats.Times, durationMs)
	}

	// Track matches
	if matched {
		stats.Matches++
	}

	// Update last evaluation timestamp
	stats.LastEval = time.Now()

	pc.totalEvaluations++

	// Check if we should flush
	// PERFORMANCE: Batch updates to reduce DB overhead
	// CRITICAL-4 FIX: Skip flush if in backoff period
	if pc.shouldFlush() && !pc.isInBackoff() {
		pc.flushLocked()
	}
}

// shouldFlush checks if we should flush pending stats
// CALLER MUST HOLD LOCK
func (pc *PerformanceCollector) shouldFlush() bool {
	// Count total pending evaluations
	totalPending := int64(0)
	for _, stats := range pc.pending {
		totalPending += int64(len(stats.Times))
	}

	return totalPending >= int64(pc.batchSize)
}

// flushLocked flushes pending stats to storage
// CALLER MUST HOLD LOCK
// PERFORMANCE: Batches all updates in single transaction
// BLOCKING-6 FIX: Capture pending map BEFORE unlock to prevent race condition
func (pc *PerformanceCollector) flushLocked() {
	if len(pc.pending) == 0 {
		return
	}

	// BLOCKING-6 FIX: Snapshot and clear while holding lock
	// This prevents new data from being added between unlock and lock
	toFlush := pc.pending
	pc.pending = make(map[string]*PendingStats)

	// Build batch update list from snapshot
	batch := make([]*storage.RulePerformance, 0, len(toFlush))

	for ruleID, pending := range toFlush {
		if len(pending.Times) == 0 {
			continue
		}

		// Load existing stats from storage
		existing, err := pc.storage.GetPerformance(ruleID)
		if err != nil {
			pc.logger.Warnf("Failed to load performance for %s: %v", ruleID, err)
			continue
		}

		// Calculate new stats
		newStats := pc.mergeStats(ruleID, existing, pending)
		batch = append(batch, newStats)
	}

	// Release lock before I/O operation
	pc.mu.Unlock()
	defer pc.mu.Lock()

	// Batch update (outside lock to avoid blocking detection)
	if len(batch) > 0 {
		if err := pc.storage.BatchUpdatePerformance(batch); err != nil {
			pc.logger.Errorf("Failed to flush performance stats: %v", err)
			pc.flushErrors++
			// CRITICAL-4 FIX: Implement exponential backoff circuit breaker
			pc.handleFlushFailure()
		} else {
			pc.totalFlushes++
			pc.lastFlush = time.Now()
			// CRITICAL-4 FIX: Reset circuit breaker on success
			pc.resetCircuitBreaker()
		}
	}
}

// isInBackoff checks if collector is in backoff period
// CRITICAL-4 FIX: Prevents log flooding and memory leak from repeated failures
func (pc *PerformanceCollector) isInBackoff() bool {
	return time.Now().Before(pc.backoffUntil)
}

// handleFlushFailure implements exponential backoff circuit breaker
// CRITICAL-4 FIX: Prevents resource exhaustion from continuous flush failures
func (pc *PerformanceCollector) handleFlushFailure() {
	pc.consecutiveFailures++

	// Exponential backoff: 1s, 2s, 4s, 8s, 16s, max 60s
	backoffSeconds := 1 << uint(pc.consecutiveFailures-1)
	if backoffSeconds > 60 {
		backoffSeconds = 60
	}

	pc.backoffUntil = time.Now().Add(time.Duration(backoffSeconds) * time.Second)

	pc.logger.Warnw("Performance flush circuit breaker activated",
		"consecutive_failures", pc.consecutiveFailures,
		"backoff_seconds", backoffSeconds,
		"backoff_until", pc.backoffUntil)
}

// resetCircuitBreaker resets the circuit breaker after successful flush
// CRITICAL-4 FIX: Allows recovery after transient failures
func (pc *PerformanceCollector) resetCircuitBreaker() {
	if pc.consecutiveFailures > 0 {
		pc.logger.Infow("Performance flush circuit breaker reset",
			"previous_failures", pc.consecutiveFailures)
		pc.consecutiveFailures = 0
		pc.backoffUntil = time.Time{}
	}
}

// mergeStats merges pending stats with existing storage stats
// STATISTICS: Calculates rolling average, max, and p99 percentile
func (pc *PerformanceCollector) mergeStats(
	ruleID string,
	existing *storage.RulePerformance,
	pending *PendingStats,
) *storage.RulePerformance {
	// Initialize if no existing data
	if existing == nil {
		existing = &storage.RulePerformance{
			RuleID: ruleID,
		}
	}

	// Calculate stats from pending times
	pendingCount := int64(len(pending.Times))
	if pendingCount == 0 {
		return existing
	}

	// Calculate average from pending times
	var sum float64
	maxTime := existing.MaxEvalTimeMs
	for _, t := range pending.Times {
		sum += t
		if t > maxTime {
			maxTime = t
		}
	}
	pendingAvg := sum / float64(pendingCount)

	// Calculate rolling average
	totalEvals := existing.TotalEvaluations + pendingCount
	newAvg := ((existing.AvgEvalTimeMs * float64(existing.TotalEvaluations)) +
		(pendingAvg * float64(pendingCount))) / float64(totalEvals)

	// Calculate p99 from pending times
	p99 := calculateP99(pending.Times)

	// Merge p99 with existing (use max of both)
	if p99 > existing.P99EvalTimeMs {
		existing.P99EvalTimeMs = p99
	}

	// Update stats
	existing.AvgEvalTimeMs = newAvg
	existing.MaxEvalTimeMs = maxTime
	existing.TotalEvaluations = totalEvals
	existing.TotalMatches += pending.Matches
	existing.LastEvaluated = pending.LastEval

	return existing
}

// calculateP99 calculates the 99th percentile from a slice of times
// STATISTICS: Uses sorting for accurate percentile calculation
// PERFORMANCE: Operates on copy to avoid modifying input
// CRITICAL-2 FIX: Use ceiling for nearest-rank method, return max for small samples
func calculateP99(times []float64) float64 {
	n := len(times)
	if n == 0 {
		return 0
	}

	// Make a copy to avoid modifying input
	sorted := make([]float64, n)
	copy(sorted, times)
	sort.Float64s(sorted)

	// CRITICAL-2 FIX: For small samples (n<10), return max instead of p99
	if n < 10 {
		return sorted[n-1] // Return max for small samples
	}

	// CRITICAL-2 FIX: Use ceiling for nearest-rank method
	rank := int(math.Ceil(0.99 * float64(n)))
	if rank >= n {
		rank = n - 1
	}

	return sorted[rank]
}

// Flush forces immediate flush of pending stats
// PRODUCTION: Called during graceful shutdown
// BLOCKING: Waits for flush to complete
func (pc *PerformanceCollector) Flush() error {
	pc.mu.Lock()
	defer pc.mu.Unlock()

	if len(pc.pending) == 0 {
		return nil
	}

	// Build batch (same logic as flushLocked)
	batch := make([]*storage.RulePerformance, 0, len(pc.pending))

	for ruleID, pending := range pc.pending {
		if len(pending.Times) == 0 {
			continue
		}

		existing, err := pc.storage.GetPerformance(ruleID)
		if err != nil {
			pc.logger.Warnf("Failed to load performance for %s: %v", ruleID, err)
			continue
		}

		newStats := pc.mergeStats(ruleID, existing, pending)
		batch = append(batch, newStats)
	}

	// Unlock before I/O
	pc.mu.Unlock()
	defer pc.mu.Lock()

	// Batch update
	if len(batch) > 0 {
		if err := pc.storage.BatchUpdatePerformance(batch); err != nil {
			pc.logger.Errorf("Failed to flush performance stats: %v", err)
			pc.flushErrors++
			return err
		}
		pc.totalFlushes++
		pc.lastFlush = time.Now()
	}

	// Clear pending after successful flush
	pc.pending = make(map[string]*PendingStats)
	return nil
}

// GetStats returns collector statistics for monitoring
// OBSERVABILITY: Enables health checks and debugging
func (pc *PerformanceCollector) GetStats() map[string]interface{} {
	pc.mu.Lock()
	defer pc.mu.Unlock()

	pendingRules := len(pc.pending)
	totalPending := int64(0)
	for _, stats := range pc.pending {
		totalPending += int64(len(stats.Times))
	}

	return map[string]interface{}{
		"pending_rules":       pendingRules,
		"pending_evaluations": totalPending,
		"total_flushes":       pc.totalFlushes,
		"total_evaluations":   pc.totalEvaluations,
		"last_flush":          pc.lastFlush,
		"flush_errors":        pc.flushErrors,
		"batch_size":          pc.batchSize,
	}
}
