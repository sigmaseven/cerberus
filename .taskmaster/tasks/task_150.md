# Task ID: 150

**Title:** Add Missing Database Indexes for Query Performance

**Status:** done

**Dependencies:** None

**Priority:** high

**Description:** Create indexes for all WHERE/ORDER BY columns in hot query paths to reduce dashboard query time from 3.2s to <100ms.

**Details:**

Existing indexes in storage/sqlite.go:196-198:
```sql
CREATE INDEX IF NOT EXISTS idx_rules_enabled ON rules(enabled);
CREATE INDEX IF NOT EXISTS idx_rules_severity ON rules(severity);
CREATE INDEX IF NOT EXISTS idx_rules_type ON rules(type);
```

Missing critical indexes:
1. rules.created_at (used in sorting)
2. rules.updated_at (used in filtering)
3. (enabled, severity) composite index (common query)
4. alerts.status (hot path in dashboard)
5. alerts.created_at (pagination sorting)
6. alerts.rule_id (JOIN condition)
7. events.timestamp (time-range queries)
8. events.event_type (filtering)
9. correlation_rules.enabled (filtering)
10. playbooks.status (dashboard query)

Impact:
- Dashboard query: 3.2s (should be <100ms)
- Table scan on 100K rules
- P95 latency: 5 seconds

Implementation:
1. Identify all hot query paths via profiling:
   ```go
   // Enable query logging
   _, err := db.Exec("PRAGMA query_only=ON")
   ```
2. Add indexes in storage/sqlite.go createTables():
   ```sql
   -- Single column indexes
   CREATE INDEX IF NOT EXISTS idx_rules_created_at ON rules(created_at);
   CREATE INDEX IF NOT EXISTS idx_rules_updated_at ON rules(updated_at);
   CREATE INDEX IF NOT EXISTS idx_alerts_status ON alerts(status);
   CREATE INDEX IF NOT EXISTS idx_alerts_created_at ON alerts(created_at);
   CREATE INDEX IF NOT EXISTS idx_alerts_rule_id ON alerts(rule_id);
   CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp);
   CREATE INDEX IF NOT EXISTS idx_events_type ON events(event_type);
   
   -- Composite indexes (order matters: most selective first)
   CREATE INDEX IF NOT EXISTS idx_rules_enabled_severity ON rules(enabled, severity);
   CREATE INDEX IF NOT EXISTS idx_alerts_status_created ON alerts(status, created_at DESC);
   CREATE INDEX IF NOT EXISTS idx_events_type_timestamp ON events(event_type, timestamp DESC);
   ```
3. Use EXPLAIN QUERY PLAN to verify index usage:
   ```go
   rows, err := db.Query("EXPLAIN QUERY PLAN SELECT * FROM rules WHERE enabled = 1 ORDER BY created_at DESC")
   // Verify output contains "USING INDEX idx_rules_enabled_severity"
   ```
4. Monitor index effectiveness with metrics:
   - Query execution time histogram
   - Index hit ratio
   - Full table scan count
5. Document indexing strategy in storage/README.md:
   - Index selection criteria
   - Composite index ordering
   - Index maintenance (VACUUM, ANALYZE)

Benchmark targets:
- Dashboard query: <100ms (50x improvement)
- Alert listing: <50ms
- Rule search: <30ms

**Test Strategy:**

1. EXPLAIN QUERY PLAN test - verify index usage for all hot queries
2. Benchmark test - measure query time before/after (target: 50x speedup)
3. Load test - verify performance under 10K concurrent users
4. Index size test - ensure indexes don't bloat database (max 30% overhead)
5. Query planner metrics - track index scans vs table scans
6. Dashboard performance test - measure page load time (<1s total)
7. Integration test - verify correctness of indexed queries

## Subtasks

### 150.1. Profile hot query paths and identify missing indexes using EXPLAIN QUERY PLAN

**Status:** done  
**Dependencies:** None  

Analyze all hot query paths (dashboard queries, alert listing, rule search, event time-range queries) to identify WHERE/ORDER BY columns that lack proper indexes, validate existing indexes, and document actual performance bottlenecks.

**Details:**

1. Enable query logging in test environment with PRAGMA query_only=ON
2. Capture all dashboard queries (rules, alerts, events, correlation_rules, playbooks)
3. Run EXPLAIN QUERY PLAN on each query to identify table scans vs index usage
4. Audit existing indexes in storage/sqlite.go (lines 196-473 contain 40+ indexes already)
5. Reconcile task description (claims 3 indexes) with actual state (40+ found)
6. Identify truly missing indexes for:
   - rules.created_at, rules.updated_at (sorting/filtering)
   - alerts.status, alerts.created_at, alerts.rule_id (dashboard/JOINs)
   - events.timestamp, events.event_type (time-range queries)
   - correlation_rules.enabled, playbooks.status (filtering)
7. Document findings in storage/INDEX_ANALYSIS.md with query plans and performance impact
8. Verify 3.2s dashboard query claim with actual benchmarks

### 150.2. Design and implement single-column and composite indexes with optimal ordering

**Status:** pending  
**Dependencies:** 150.1  

Add missing indexes to storage/sqlite.go createTables() function, including single-column indexes for frequently filtered columns and composite indexes with proper column ordering (most selective first).

**Details:**

1. Add single-column indexes in storage/sqlite.go createTables():
   - CREATE INDEX IF NOT EXISTS idx_rules_created_at ON rules(created_at);
   - CREATE INDEX IF NOT EXISTS idx_rules_updated_at ON rules(updated_at);
   - CREATE INDEX IF NOT EXISTS idx_alerts_status ON alerts(status);
   - CREATE INDEX IF NOT EXISTS idx_alerts_created_at ON alerts(created_at);
   - CREATE INDEX IF NOT EXISTS idx_alerts_rule_id ON alerts(rule_id);
   - CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp);
   - CREATE INDEX IF NOT EXISTS idx_events_type ON events(event_type);
   - CREATE INDEX IF NOT EXISTS idx_correlation_rules_enabled ON correlation_rules(enabled);
   - CREATE INDEX IF NOT EXISTS idx_playbooks_status ON playbooks(status);

2. Add composite indexes with DESC ordering for pagination:
   - CREATE INDEX IF NOT EXISTS idx_rules_enabled_severity ON rules(enabled, severity);
   - CREATE INDEX IF NOT EXISTS idx_alerts_status_created ON alerts(status, created_at DESC);
   - CREATE INDEX IF NOT EXISTS idx_events_type_timestamp ON events(event_type, timestamp DESC);

3. Follow composite index ordering rules: equality filters first (=), then range filters (>, <), then ORDER BY columns
4. Add migration in storage/migrations_sqlite.go for version upgrade
5. Test index creation doesn't break existing queries

### 150.3. Add index effectiveness monitoring with query execution metrics

**Status:** pending  
**Dependencies:** 150.2  

Implement monitoring infrastructure to track query execution time histograms, index hit ratios, and full table scan counts to validate index effectiveness in production.

**Details:**

1. Add query performance metrics in metrics/metrics.go:
   - query_duration_seconds histogram (buckets: 0.01, 0.05, 0.1, 0.5, 1, 5)
   - index_hit_ratio gauge (successful index lookups / total queries)
   - full_table_scans_total counter
   - query_type label (dashboard, alerts, rules, events)

2. Add SQL query wrapper in storage/sqlite.go:
   - Intercept all Query/QueryRow/Exec calls
   - Record execution time
   - Parse EXPLAIN QUERY PLAN to detect table scans
   - Increment appropriate metrics

3. Add periodic ANALYZE commands to update query planner statistics:
   - Run ANALYZE after bulk inserts (>1000 rows)
   - Schedule ANALYZE on startup and every 24 hours

4. Document monitoring approach in storage/README.md:
   - How to interpret metrics
   - When to add new indexes
   - Index maintenance schedule (VACUUM, ANALYZE)
   - Composite index column ordering guidelines

### 150.4. Benchmark dashboard query performance and validate 50x improvement target

**Status:** pending  
**Dependencies:** 150.2, 150.3  

Create comprehensive benchmarks measuring dashboard query performance before/after index changes, validate 3.2s → <100ms improvement claim, and conduct load testing under 10K concurrent users.

**Details:**

1. Create benchmark test in storage/sqlite_benchmark_test.go:
   - BenchmarkDashboardQuery (main dashboard load)
   - BenchmarkAlertListing (alert pagination with status filter)
   - BenchmarkRuleSearch (rule search with enabled+severity filters)
   - BenchmarkEventTimeRange (event queries with timestamp range)

2. Populate test database with realistic data:
   - 100K rules (matching task description)
   - 500K alerts (various statuses)
   - 1M events (30-day time range)
   - 10K correlation rules
   - 1K playbooks

3. Measure baseline performance WITHOUT new indexes:
   - Record P50, P95, P99 latencies for each query type
   - Verify 3.2s dashboard query claim

4. Measure performance WITH new indexes:
   - Dashboard query target: <100ms (50x improvement from 3.2s)
   - Alert listing target: <50ms
   - Rule search target: <30ms
   - Event time-range target: <100ms

5. Conduct load testing with 10K concurrent users:
   - Use Go testing.B with -benchtime=10000x
   - Measure throughput (queries/second)
   - Monitor connection pool exhaustion
   - Verify no query timeouts

6. Document results in BENCHMARK_RESULTS.md with before/after comparison
