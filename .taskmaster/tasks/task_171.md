# Task ID: 171

**Title:** Add Rule Performance Tracking and Monitoring

**Status:** done

**Dependencies:** 164 ✓

**Priority:** medium

**Description:** Implement performance metrics collection, storage, and API endpoints for rule evaluation statistics and slow rule detection

**Details:**

Implementation:

1. Create storage/sqlite_rule_performance.go:
CREATE TABLE rule_performance (
    rule_id TEXT PRIMARY KEY,
    avg_eval_time_ms REAL,
    max_eval_time_ms REAL,
    p99_eval_time_ms REAL,
    total_evaluations INTEGER,
    total_matches INTEGER,
    false_positive_count INTEGER,
    last_evaluated TIMESTAMP,
    updated_at TIMESTAMP
)

2. Modify detect/engine.go to record metrics:
   - After each rule evaluation, record duration
   - Update performance_stats in rules table (JSON)
   - Batch updates every 100 evaluations to reduce writes
   - Calculate rolling averages and percentiles

3. Create api/rule_performance.go:
   GET /api/v1/rules/{id}/performance
   GET /api/v1/rules/performance/slow?threshold_ms=100
   POST /api/v1/rules/{id}/performance/false-positive (user-reported)

4. Add Prometheus metrics:
   - cerberus_rule_evaluation_duration_seconds (histogram)
   - cerberus_rule_evaluations_total (counter)
   - cerberus_rule_matches_total (counter)

5. Create background job to aggregate stats hourly

**Test Strategy:**

Create storage/sqlite_rule_performance_test.go:
1. Test performance stats recording
2. Test percentile calculation accuracy
3. Test slow rule detection query
4. Test false positive reporting
5. Test performance stats API endpoints
6. Test Prometheus metrics export
7. Load test: 10k rule evaluations, verify stats accuracy

## Subtasks

### 171.1. Create storage/sqlite_rule_performance.go with schema and CRUD operations

**Status:** pending  
**Dependencies:** None  

Implement the SQLite storage layer for rule performance metrics including table schema, insert/update operations, and query methods for retrieving performance statistics

**Details:**

Create storage/sqlite_rule_performance.go with:
1. SQL schema: CREATE TABLE rule_performance with fields (rule_id TEXT PRIMARY KEY, avg_eval_time_ms REAL, max_eval_time_ms REAL, p99_eval_time_ms REAL, total_evaluations INTEGER, total_matches INTEGER, false_positive_count INTEGER, last_evaluated TIMESTAMP, updated_at TIMESTAMP)
2. Migration function to create table if not exists
3. UpsertRulePerformance(ruleID string, stats *RulePerformanceStats) - atomic upsert operation
4. GetRulePerformance(ruleID string) - retrieve stats for single rule
5. GetSlowRules(thresholdMs float64) - query rules exceeding threshold
6. RecordFalsePositive(ruleID string) - increment false positive counter
7. Proper error handling and transaction management
8. Index on avg_eval_time_ms for slow rule queries

### 171.2. Implement performance tracking in detect/engine.go with batching

**Status:** pending  
**Dependencies:** 171.1  

Modify the detection engine to record rule evaluation duration and batch update performance statistics every 100 evaluations to minimize write overhead

**Details:**

Modify detect/engine.go:
1. Add per-rule performance buffer: map[string]*PerformanceBuffer with mutex protection
2. In ProcessEvent, wrap each rule evaluation with time.Now() before/after to capture duration
3. Store durations in ring buffer (size 100) for each rule
4. After 100 evaluations OR every 10 seconds (whichever comes first), flush buffer:
   - Calculate avg_eval_time_ms from buffer
   - Track max_eval_time_ms (absolute max)
   - Increment total_evaluations and total_matches counters
   - Call storage.UpsertRulePerformance with aggregated stats
5. Use sync.Map or sharded locks to avoid contention on hot path
6. Ensure goroutine-safe buffer access
7. Add graceful shutdown to flush pending buffers
8. Keep performance overhead under 5% of total evaluation time

### 171.3. Implement percentile calculation (p99) with rolling averages

**Status:** pending  
**Dependencies:** 171.2  

Add statistical algorithms to calculate p99 percentile and rolling averages for rule evaluation performance metrics

**Details:**

Implement in detect/performance_stats.go (new file):
1. Create PerformanceBuffer struct with circular buffer (size 1000) to store recent eval times
2. Implement calculateP99() using quickselect or histogram approximation:
   - Sort buffer copy (don't modify original)
   - Return value at 99th percentile index
   - Handle edge cases (empty buffer, single value)
3. Implement calculateRollingAverage() with exponential moving average:
   - EMA = alpha * current + (1-alpha) * previous_EMA
   - Use alpha=0.1 for smoothing
4. Track separate buffers for short-term (100 samples) and long-term (1000 samples) windows
5. Update max_eval_time_ms as absolute maximum across all time
6. Optimize for performance: pre-allocate buffers, minimize allocations
7. Add PerformanceSnapshot struct for thread-safe metric snapshots

### 171.4. Create api/rule_performance.go with REST endpoints

**Status:** pending  
**Dependencies:** 171.3  

Implement HTTP API endpoints for retrieving rule performance metrics, detecting slow rules, and reporting false positives

**Details:**

Create api/rule_performance.go:
1. GET /api/v1/rules/{id}/performance handler:
   - Retrieve RulePerformanceStats from storage
   - Return JSON with all metrics (avg, max, p99, counts)
   - Include rate metrics (match_rate = matches/evaluations)
2. GET /api/v1/rules/performance/slow?threshold_ms=100:
   - Query storage.GetSlowRules(threshold)
   - Support pagination (limit, offset)
   - Return sorted by avg_eval_time_ms descending
   - Include rule name/description for UX
3. POST /api/v1/rules/{id}/performance/false-positive:
   - Increment false_positive_count
   - Optional: accept feedback JSON for future analysis
   - Return updated stats
4. Add RBAC checks (require analyst role minimum)
5. Add input validation and proper error responses
6. Register routes in api.go setupRoutes()

### 171.5. Add Prometheus metrics and comprehensive load testing

**Status:** pending  
**Dependencies:** 171.4  

Integrate Prometheus histogram and counter metrics for rule evaluation performance and create comprehensive load tests simulating 10k+ evaluations

**Details:**

1. Modify metrics/metrics.go to add:
   - cerberus_rule_evaluation_duration_seconds (HistogramVec with labels: rule_id, rule_name) - buckets: [0.001, 0.01, 0.1, 0.5, 1, 5]
   - cerberus_rule_evaluations_total (CounterVec with labels: rule_id, matched)
   - cerberus_rule_false_positives_total (CounterVec with label: rule_id)
2. In detect/engine.go ProcessEvent, after each evaluation:
   - Record histogram observation: metrics.RuleEvaluationDuration.WithLabelValues(ruleID, ruleName).Observe(duration.Seconds())
   - Increment counter: metrics.RuleEvaluations.WithLabelValues(ruleID, fmt.Sprint(matched)).Inc()
3. Create detect/engine_load_test.go:
   - Simulate 10,000 rule evaluations with varying complexity
   - Test concurrent evaluation (100 goroutines)
   - Verify performance overhead remains <5%
   - Verify all metrics correctly recorded
   - Test memory stability (no leaks)
4. Add /metrics endpoint exposition in api.go if not exists
5. Document Prometheus queries for common dashboards
