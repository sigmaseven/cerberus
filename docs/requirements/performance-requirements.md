# Performance Requirements & SLA Specifications

**Document Owner**: Performance Engineering Team
**Created**: 2025-11-16
**Status**: DRAFT - Pending Load Testing
**Classification**: TBD - Many requirements not yet determined
**Authoritative Sources**:
- "The Art of Capacity Planning" by John Allspaw & Jesse Robbins
- "Systems Performance" by Brendan Gregg (2nd Edition)
- Industry benchmarks for SIEM systems

**Purpose**: Define performance requirements and SLAs for Cerberus SIEM

---

## 1. EXECUTIVE SUMMARY

**Current Status**: Most performance requirements are **NOT YET DEFINED**.

**Why This Matters**: Without defined SLAs, performance tests are meaningless. A test that verifies "query completes in 5 seconds" is useless if the actual requirement is 100ms.

**This Document's Purpose**:
1. Identify performance-critical operations
2. Mark TBDs for requirements that need load testing to determine
3. Provide framework for performance testing once requirements are defined

---

## 2. PERFORMANCE TESTING PHILOSOPHY

### 2.1 Don't Test Without Requirements

**WRONG Approach**:
```go
func TestPerformance_QuerySpeed(t *testing.T) {
    start := time.Now()
    results := storage.Query(...)
    elapsed := time.Since(start)

    // What does 100ms mean? Is this good or bad?
    assert.Less(t, elapsed, 100*time.Millisecond)
}
```

**RIGHT Approach**:
```go
func TestPerformance_QuerySpeed_MeetsSLA(t *testing.T) {
    // Reference: performance-requirements.md Section 3.1
    // SLA: Event search MUST complete in <200ms (p99) for 10K events
    // Source: Load test report 2024-Q1

    start := time.Now()
    results := storage.SearchEvents(query, limit: 100)
    elapsed := time.Since(start)

    // Test against documented SLA
    assert.Less(t, elapsed, 200*time.Millisecond,
        "Query exceeded p99 SLA of 200ms (see performance-requirements.md#3.1)")
}
```

---

## 3. EVENT INGESTION PERFORMANCE

### 3.1 Event Ingestion Throughput

**TBD - CRITICAL REQUIREMENT NOT YET DEFINED**

```
Question: What event ingestion throughput must Cerberus support?

Owner: Product Management + Performance Team
Deadline: Week 2 (blocks ingestion testing)

Considerations:
1. Typical enterprise SIEM ingestion rates:
   - Small:  1,000-10,000 events/sec
   - Medium: 10,000-100,000 events/sec
   - Large:  100,000-1,000,000 events/sec

2. Cerberus target deployment size:
   - TBD: Small/Medium/Large/Enterprise?

3. Peak vs. sustained load:
   - Sustained: Average event rate over 24 hours
   - Peak: Maximum burst (e.g., during incident response)

REQUIRED ANALYSIS:
- Survey target customers for expected event volumes
- Perform load testing to determine current capacity
- Define minimum viable throughput
- Plan for scalability (horizontal scaling via ClickHouse replication)

RECOMMENDATION: Start with 10,000 events/sec sustained, 50,000 events/sec peak
```

**Test Requirements** (once SLA defined):
```go
func TestEventIngestion_ThroughputSLA(t *testing.T) {
    if testing.Short() {
        t.Skip("Throughput test requires -short flag disabled")
    }

    // Reference: performance-requirements.md Section 3.1
    // SLA: MUST ingest 10,000 events/sec sustained
    // Source: [TBD - Load test report]

    const slaEventsPerSec = 10_000
    const testDuration = 60 * time.Second

    storage := setupStorage(t)
    eventGenerator := newEventGenerator()

    start := time.Now()
    eventsIngested := 0

    ticker := time.NewTicker(10 * time.Millisecond)
    defer ticker.Stop()

    for time.Since(start) < testDuration {
        <-ticker.C

        // Ingest batch of events
        batch := eventGenerator.GenerateBatch(100)
        err := storage.InsertEvents(batch)
        require.NoError(t, err)
        eventsIngested += len(batch)
    }

    elapsed := time.Since(start)
    actualRate := float64(eventsIngested) / elapsed.Seconds()

    // Verify: Met throughput SLA
    t.Logf("Ingested %d events in %v (%.0f events/sec)", eventsIngested, elapsed, actualRate)
    assert.GreaterOrEqual(t, actualRate, float64(slaEventsPerSec),
        "Failed to meet ingestion SLA of %d events/sec", slaEventsPerSec)
}
```

---

### 3.2 Event Ingestion Latency

**TBD - REQUIREMENT NOT YET DEFINED**

```
Question: What is acceptable latency from event arrival to searchability?

Owner: Product Management
Deadline: Week 2

Considerations:
- Real-time SIEM: <1 second latency
- Near-real-time: 1-5 seconds
- Batch-oriented: 5-60 seconds

Factors:
- ClickHouse async inserts add latency
- MergeTree background merges affect query performance
- Buffering increases throughput but adds latency

REQUIRED: Define acceptable latency (p50, p95, p99)
```

**Test Template** (once SLA defined):
```go
func TestEventIngestion_LatencySLA(t *testing.T) {
    // SLA: [TBD] p99 latency < [TBD]ms from ingest to searchable
}
```

---

## 4. RULE EVALUATION PERFORMANCE

### 4.1 Rule Evaluation Throughput

**TBD - REQUIREMENT NOT YET DEFINED**

```
Question: How many rules can we evaluate per event?

Owner: Detection Engineering Team
Deadline: Week 2

Considerations:
1. Number of rules in typical deployment:
   - Small SIEM: 100-500 rules
   - Medium SIEM: 500-2,000 rules
   - Large SIEM: 2,000-10,000 rules

2. Rule complexity:
   - Simple: Single condition (event_type = "login")
   - Medium: 3-5 conditions with AND/OR logic
   - Complex: Regex patterns, nested fields

3. Acceptable evaluation time per event:
   - Fast path: <1ms for simple rules
   - Slow path: <10ms for complex rules

CURRENT BOTTLENECK HYPOTHESIS:
- Regex evaluation without timeout (ReDoS risk)
- No rule indexing (evaluates all rules for every event)
- No caching of field extractions

RECOMMENDATION:
- Benchmark current throughput
- Set initial SLA: 1,000 rules in <10ms per event (p99)
- Plan optimization (rule indexing, field caching)
```

**Test Template**:
```go
func BenchmarkRuleEngine_EvaluateThroughput(b *testing.B) {
    // SLA: [TBD] Evaluate 1,000 rules per event in <10ms (p99)

    // Setup: Load 1,000 production-like rules
    rules := loadProductionRules(1000)
    engine := detect.NewRuleEngine(rules, nil, 0)
    event := createRealisticEvent()

    b.ResetTimer()
    for i := 0; i < b.N; i++ {
        matches := engine.Evaluate(event)
        _ = matches
    }

    // Report: ns/op (time per evaluation)
}
```

---

### 4.2 Correlation Rule Performance

**TBD - REQUIREMENT NOT YET DEFINED**

```
Question: How many correlation rules with what memory limits?

Owner: Detection Engineering Team
Deadline: Week 2

Current Implementation:
- MaxCorrelationEventsPerRule = 1,000 (hardcoded, line 18 detect/engine.go)
- MaxCorrelationRulesTracked = 100 (hardcoded, line 20 detect/engine.go)

Questions:
1. Are these limits appropriate?
2. What is memory usage at these limits?
3. What is performance impact?

REQUIRED ANALYSIS:
- Memory profiling with max limits
- Performance testing with 100 active correlation rules
- Determine if limits should be configurable

RECOMMENDATION:
- Load test with realistic correlation rules
- Monitor memory usage and CPU impact
- Adjust limits based on empirical data
```

---

## 5. QUERY PERFORMANCE

### 5.1 Event Search Performance

**TBD - REQUIREMENT NOT YET DEFINED**

```
Question: What are acceptable query response times?

Owner: UX Team + Performance Team
Deadline: Week 2

Industry Standards (from UX research):
- <100ms: Perceived as instant
- 100-300ms: Slight delay, acceptable for search
- 300-1000ms: Noticeable delay, user waits
- >1000ms: User loses focus, poor experience

SIEM-Specific Considerations:
- Interactive search: p95 <300ms
- Saved search / dashboard: p95 <1s
- Report generation: p95 <10s
- Historical analysis (30 days): p95 <30s

Query Complexity:
- Simple filter (last 1 hour): <100ms
- Complex aggregation (group by user, last 24h): <1s
- Full-text search (regex, last 7 days): <5s

RECOMMENDATION: Define SLAs per query type and time range
```

**Test Template**:
```go
func TestEventSearch_InteractiveQuerySLA(t *testing.T) {
    // SLA: [TBD] Simple queries <300ms (p95)

    storage := setupStorageWithEvents(10_000)

    query := search.Query{
        Field:    "event_type",
        Operator: "equals",
        Value:    "user_login",
        TimeRange: search.Last1Hour,
    }

    start := time.Now()
    results, err := storage.SearchEvents(query)
    elapsed := time.Since(start)

    require.NoError(t, err)
    assert.Less(t, elapsed, 300*time.Millisecond,
        "Interactive query exceeded p95 SLA of 300ms")
}
```

---

### 5.2 Alert Query Performance

**TBD - REQUIREMENT NOT YET DEFINED**

```
Question: Alert dashboard refresh rate and query performance?

Owner: UX Team
Deadline: Week 2

Typical Usage:
- Security analyst dashboard: Refreshes every 10-30 seconds
- Alert list query: Last 24 hours of alerts
- Alert detail: Single alert lookup by ID

RECOMMENDATION:
- Alert list query: <500ms for last 24h (p95)
- Single alert lookup: <50ms (p95)
- Alert aggregations (count by severity): <200ms (p95)
```

---

## 6. API PERFORMANCE

### 6.1 REST API Response Times

**TBD - REQUIREMENT NOT YET DEFINED**

```
Question: What are acceptable API response times?

Owner: API Team + UX Team
Deadline: Week 2

Industry Standards:
- GET requests (cached): <50ms
- GET requests (uncached): <200ms
- POST/PUT requests: <500ms
- Bulk operations: <5s

Current Implementation:
- ReadTimeout: 15 seconds (api/api.go line 331)
- WriteTimeout: 15 seconds (api/api.go line 332)

Questions:
1. Are 15s timeouts appropriate?
2. What are actual p95/p99 response times?

RECOMMENDATION:
- Measure current API performance
- Set SLAs per endpoint based on actual usage
- Implement per-endpoint timeouts (not global)
```

**Test Template**:
```go
func TestAPI_ResponseTimeSLA(t *testing.T) {
    // SLA: [TBD] GET /api/v1/rules <200ms (p95)

    server := setupTestServer(t)

    start := time.Now()
    resp := makeRequest(t, "GET", "/api/v1/rules")
    elapsed := time.Since(start)

    assert.Equal(t, 200, resp.StatusCode)
    assert.Less(t, elapsed, 200*time.Millisecond,
        "API endpoint exceeded p95 SLA")
}
```

---

### 6.2 WebSocket Performance

**TBD - REQUIREMENT NOT YET DEFINED**

```
Question: WebSocket event streaming performance requirements?

Owner: Frontend Team + Performance Team
Deadline: Week 3

Considerations:
- How many concurrent WebSocket connections?
- What event update frequency (every 1s? 5s? 10s?)?
- What is acceptable latency for real-time updates?

Current Implementation:
- WebSocket server exists (frontend/src/services/websocket.ts)
- No documented performance requirements

REQUIRED ANALYSIS:
- Determine expected concurrent users
- Load test WebSocket connections
- Define SLA for update latency
```

---

## 7. RESOURCE UTILIZATION LIMITS

### 7.1 Memory Usage Limits

**TBD - REQUIREMENT NOT YET DEFINED**

```
Question: What are acceptable memory usage limits?

Owner: Operations Team
Deadline: Week 2

Current Observations:
- No explicit memory limits set
- Correlation state has hardcoded limits (detect/engine.go)
- No circuit breakers for memory exhaustion

Typical SIEM Memory Usage:
- Small deployment: 2-4 GB
- Medium deployment: 8-16 GB
- Large deployment: 32-64 GB

REQUIRED:
- Determine target deployment size (VM specs)
- Set memory limits for each component
- Implement circuit breakers when limits approached

RECOMMENDATION:
- Set RSS limit per deployment size
- Alert at 80% memory usage
- Reject requests at 95% memory usage
```

**Test Template**:
```go
func TestMemoryUsage_StaysBelowLimit(t *testing.T) {
    // SLA: [TBD] Memory usage <4GB for small deployment

    if testing.Short() {
        t.Skip("Memory test requires -short flag disabled")
    }

    // Run system under load
    // Measure peak memory usage
    // Verify below limit
}
```

---

### 7.2 CPU Usage Limits

**TBD - REQUIREMENT NOT YET DEFINED**

```
Question: What are acceptable CPU usage patterns?

Owner: Performance Team
Deadline: Week 2

Considerations:
- Average CPU usage under normal load
- Peak CPU during bursts
- Number of CPU cores available

RECOMMENDATION:
- Target <70% average CPU usage (leaves headroom)
- Peak <90% CPU during bursts
- Horizontal scaling if sustained >80%
```

---

### 7.3 Database Connection Pool Sizing

**Current Settings**:
- **ClickHouse**: `MaxOpenConns` from config (configurable)
- **SQLite**: `MaxOpenConns = 1` (hardcoded, line 41 sqlite.go)

**TBD - REQUIREMENT VALIDATION NEEDED**:
```
Question: Are current connection pool sizes appropriate?

Owner: Database Team
Deadline: Week 2

SQLite Analysis:
- Current: MaxOpenConns = 1 (single writer)
- Rationale: SQLite WAL mode performs best with single writer
- Source: https://www.sqlite.org/wal.html#concurrency
- Status: ✅ LIKELY CORRECT

ClickHouse Analysis:
- Current: MaxPoolSize from config (default TBD)
- Question: What is optimal pool size?
- Formula: pool_size = (core_count * 2) + effective_spindle_count
- REQUIRED: Load test to determine optimal value

RECOMMENDATION:
- Keep SQLite at 1 (correct for WAL mode)
- Load test ClickHouse with different pool sizes
- Document optimal value in config
```

---

## 8. SCALABILITY REQUIREMENTS

### 8.1 Horizontal Scaling

**TBD - REQUIREMENT NOT YET DEFINED**

```
Question: Must Cerberus support horizontal scaling?

Owner: Architecture Team
Deadline: Week 3

Current Architecture:
- Single-node deployment (no horizontal scaling)
- ClickHouse can be clustered (not documented)
- SQLite is single-node (cannot cluster)

Options:
1. Single-node only (vertical scaling)
   - Pro: Simpler architecture
   - Con: Limited by single machine capacity

2. Horizontal scaling (multi-node)
   - Pro: Linear scalability
   - Con: Complex deployment, state synchronization

DECISION NEEDED: Target deployment model
```

---

### 8.2 Data Volume Scalability

**TBD - REQUIREMENT NOT YET DEFINED**

```
Question: How much data must Cerberus handle?

Owner: Product Management
Deadline: Week 2

Considerations:
- Retention period: 30 days? 90 days? 1 year?
- Event volume: 10K/sec × 86400 sec/day × 30 days = 25.9 billion events
- Storage per event: ~1KB average = 25.9 TB for 30 days
- Index overhead: ~20% = 31 TB total

ClickHouse Capabilities:
- Single-node: 10s of TB (with compression)
- Clustered: 100s of TB to PB scale

REQUIRED:
- Define retention policy
- Estimate storage requirements
- Plan for archival (move to S3 after 90 days?)

RECOMMENDATION:
- Support 90-day retention as baseline
- Implement TTL-based archival
- Document storage sizing recommendations
```

---

## 9. BENCHMARKING FRAMEWORK

### 9.1 Required Benchmarks

Before defining SLAs, run these benchmarks:

1. **Event Ingestion Benchmark**
   - Single-event latency
   - Batch ingestion throughput
   - Vary batch sizes: 10, 100, 1000, 10000

2. **Rule Evaluation Benchmark**
   - Rule count: 10, 100, 1000, 10000
   - Rule complexity: simple, medium, complex
   - Measure: time per event, memory usage

3. **Query Performance Benchmark**
   - Query types: simple filter, aggregation, full-text search
   - Time ranges: 1h, 24h, 7d, 30d
   - Result set sizes: 10, 100, 1000, 10000

4. **Correlation Rule Benchmark**
   - Correlation window sizes: 5m, 1h, 24h
   - Event rates: 100/s, 1000/s, 10000/s
   - Memory usage over time

5. **API Endpoint Benchmark**
   - All GET/POST/PUT endpoints
   - Measure p50, p95, p99 latencies
   - Concurrent request handling

### 9.2 Load Testing Scenarios

**Realistic Load Profiles**:

1. **Normal Load**
   - 1,000 events/sec sustained
   - 50 rules
   - 5 concurrent users

2. **Peak Load**
   - 10,000 events/sec burst
   - 500 rules
   - 20 concurrent users

3. **Stress Test**
   - 50,000 events/sec
   - 2,000 rules
   - 100 concurrent users
   - Run until failure, measure breaking point

---

## 10. PERFORMANCE TEST REQUIREMENTS

Once SLAs are defined, create these tests:

### 10.1 Unit-Level Performance Tests
```go
func BenchmarkRuleEngine_SimpleRule(b *testing.B) { /* ... */ }
func BenchmarkRuleEngine_ComplexRule(b *testing.B) { /* ... */ }
func BenchmarkRuleEngine_RegexRule(b *testing.B) { /* ... */ }
```

### 10.2 Integration Performance Tests
```go
func TestEventIngestion_SustainedLoad(t *testing.T) { /* ... */ }
func TestEventQuery_LargeResultSet(t *testing.T) { /* ... */ }
```

### 10.3 Stress Tests
```go
func TestSystem_StressTest_BreakingPoint(t *testing.T) { /* ... */ }
```

---

## 11. COMPLIANCE VERIFICATION CHECKLIST

Before declaring performance testing complete:

### 11.1 Requirements Definition
- [ ] Event ingestion throughput SLA defined
- [ ] Event ingestion latency SLA defined
- [ ] Rule evaluation throughput SLA defined
- [ ] Query response time SLAs defined (per query type)
- [ ] API response time SLAs defined (per endpoint)
- [ ] Memory usage limits defined
- [ ] CPU usage limits defined

### 11.2 Benchmarking Complete
- [ ] Event ingestion benchmarks run
- [ ] Rule evaluation benchmarks run
- [ ] Query performance benchmarks run
- [ ] API endpoint benchmarks run
- [ ] Results documented and approved

### 11.3 Performance Tests Implemented
- [ ] All SLA-based tests implemented
- [ ] Benchmarks added to CI/CD
- [ ] Load testing automated
- [ ] Stress testing documented

### 11.4 Monitoring & Alerting
- [ ] Performance metrics exposed (Prometheus)
- [ ] Dashboards created (Grafana)
- [ ] Alerts configured for SLA violations
- [ ] Runbooks created for performance degradation

---

## 12. TBD TRACKER - PERFORMANCE DECISIONS NEEDED

| Item | Question | Owner | Deadline | Priority | Status |
|------|----------|-------|----------|----------|--------|
| TBD-PERF-001 | Event ingestion throughput SLA | Product + Perf Team | Week 2 | CRITICAL | OPEN |
| TBD-PERF-002 | Event ingestion latency SLA | Product Team | Week 2 | HIGH | OPEN |
| TBD-PERF-003 | Rule evaluation throughput SLA | Detection Team | Week 2 | HIGH | OPEN |
| TBD-PERF-004 | Query response time SLAs | UX + Perf Team | Week 2 | HIGH | OPEN |
| TBD-PERF-005 | API response time SLAs | API Team | Week 2 | MEDIUM | OPEN |
| TBD-PERF-006 | Memory usage limits | Operations Team | Week 2 | HIGH | OPEN |
| TBD-PERF-007 | CPU usage limits | Operations Team | Week 2 | MEDIUM | OPEN |
| TBD-PERF-008 | ClickHouse pool size | Database Team | Week 2 | MEDIUM | OPEN |
| TBD-PERF-009 | Horizontal scaling support | Architecture Team | Week 3 | LOW | OPEN |
| TBD-PERF-010 | Data retention period | Product Team | Week 2 | HIGH | OPEN |

---

## 13. REFERENCES

### 13.1 Books
1. **"Systems Performance"** by Brendan Gregg (2nd Edition, 2020)
   - Chapter 2: Methodology
   - Chapter 6: CPUs
   - Chapter 7: Memory

2. **"The Art of Capacity Planning"** by John Allspaw & Jesse Robbins
   - Chapter 3: Defining Performance Metrics

### 13.2 Industry Benchmarks
1. **Splunk Performance Benchmarks**: (TBD - find public benchmarks)
2. **Elastic SIEM Performance**: (TBD - find public benchmarks)
3. **ClickHouse Benchmarks**: https://clickhouse.com/benchmark

### 13.3 Internal Documents
1. **BACKEND_TEST_REMEDIATIONS.md**: Performance testing requirements
2. **detect/engine.go**: Correlation memory limits
3. **api/api.go**: Timeout configurations

---

**Document Status**: DRAFT - CRITICAL: Most requirements undefined
**Next Steps**:
1. Run benchmarking suite (Week 1-2)
2. Define SLAs based on benchmarks (Week 2)
3. Implement performance tests (Week 3-4)
**Approver**: Performance Lead + Product Management + Operations
**Version**: 1.0-DRAFT

---

## APPENDIX A: WHY WE CAN'T TEST PERFORMANCE YET

**The Problem**: 72% of existing tests rubber-stamp current behavior.

**For Performance Tests**: This is WORSE because:
1. Performance varies by hardware (developer laptop ≠ production server)
2. Performance varies by data volume (100 events ≠ 10 million events)
3. Performance varies by load (single user ≠ 100 concurrent users)

**Example of Meaningless Test**:
```go
// This test is USELESS
func TestQueryIsFast(t *testing.T) {
    elapsed := measureQueryTime()
    assert.Less(t, elapsed, 5*time.Second) // Why 5 seconds? No rationale.
}
```

**What We Need FIRST**:
1. Define target deployment size (small/medium/large)
2. Run load tests to measure current capacity
3. Define SLAs based on user requirements + capacity
4. THEN write tests to verify SLAs

**Timeline**: Weeks 1-2 for benchmarking, then Week 3-4 for test implementation
