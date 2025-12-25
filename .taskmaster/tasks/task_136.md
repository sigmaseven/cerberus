# Task ID: 136

**Title:** Audit and Fix Context Propagation in Critical Paths

**Status:** done

**Dependencies:** 134 ✓

**Priority:** high

**Description:** Replace context.Background() with proper request context propagation in high-priority API and storage operations

**Details:**

**HIGH PRIORITY - PRODUCTION STABILITY**

Problem: 437+ instances of context.Background() break timeout/cancellation chains.

Phased approach (focus on critical paths first):

**Phase 1: API Layer (20-30 instances)**
Files:
- `api/jwt.go:40` - JWT generation/validation
- `api/auth_handlers.go` - Login/logout handlers
- `api/handlers.go` - Main request handlers

Implementation:
```go
// BEFORE
ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)

// AFTER (in HTTP handlers)
ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)

// AFTER (in background tasks - keep Background)
ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
```

**Phase 2: Storage Layer (50-80 instances)**
Files:
- `storage/sqlite_*.go` - All CRUD operations
- `storage/clickhouse_*.go` - ClickHouse operations

Ensure all storage methods accept and use context parameter.

**Phase 3: Detection Engine (30-50 instances)**
Files:
- `detect/engine.go` - Rule evaluation
- `detect/actions.go` - Action execution
- `detect/detector.go` - Detection loops

**Phase 4: ML/SOAR (remaining instances)**
Files:
- `ml/*.go` - ML training/inference
- `soar/*.go` - Playbook execution

Keep context.Background() for:
- Init functions
- Background goroutines with independent lifecycle
- Test setup

Add documentation comments explaining when Background is appropriate.

**Test Strategy:**

1. Static analysis: Use grep to track remaining context.Background() count
2. Add request timeout tests: Verify timeouts propagate to DB queries
3. Load test: Ensure cancellation works under high load
4. Integration test: Cancel request mid-execution, verify cleanup
5. Use go race detector: `go test -race ./...`
6. Monitor for goroutine leaks in long-running tests
7. Performance baseline: Ensure no regression in latency

## Subtasks

### 136.1. Audit and categorize all context.Background() instances across codebase

**Status:** done  
**Dependencies:** None  

Perform comprehensive audit of all 488 context.Background() instances to categorize them into: request-scoped contexts (must fix), background goroutines (keep Background), initialization code (keep Background), and test code (review case-by-case)

**Details:**

Use grep to find all instances: `grep -rn 'context.Background()' --include='*.go' --exclude='*_test.go'`. Create categorized spreadsheet/document with: file path, line number, function name, context type (request/background/init), priority (critical/high/medium/low), and fix recommendation. Focus on identifying the 20-30 API layer instances, 50-80 storage layer instances, and 30-50 detection engine instances mentioned in phases 1-3. Document which instances should legitimately remain as Background (init functions, independent background workers, long-running goroutines with separate lifecycle). This audit provides the foundation for all subsequent fix phases.

### 136.2. Fix API layer context propagation (Phase 1: 20-30 instances)

**Status:** done  
**Dependencies:** 136.1, 136.134  

Replace context.Background() with r.Context() in HTTP handlers across api/jwt.go, api/auth_handlers.go, and api/handlers.go to enable proper request timeout and cancellation propagation

**Details:**

Focus on critical API endpoints:
1. api/jwt.go:40 - JWT generation/validation: Change `ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)` to `ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)`
2. api/auth_handlers.go - Login/logout handlers: Propagate request context to storage calls and JWT operations
3. api/handlers.go - Main request handlers: Ensure all downstream calls receive r.Context() or derived contexts

Pattern:
```go
// BEFORE
func (s *Server) HandleLogin(w http.ResponseWriter, r *http.Request) {
    ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
    defer cancel()
    user, err := s.storage.GetUser(ctx, username)
}

// AFTER
func (s *Server) HandleLogin(w http.ResponseWriter, r *http.Request) {
    ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
    defer cancel()
    user, err := s.storage.GetUser(ctx, username)
}
```

Ensure middleware-injected context values (from task 134) are preserved.

### 136.3. Fix storage layer context propagation (Phase 2: 50-80 instances)

**Status:** done  
**Dependencies:** 136.1, 136.2  

Update all storage layer CRUD operations in storage/sqlite_*.go and storage/clickhouse_*.go to properly use passed context parameters instead of creating new Background contexts

**Details:**

Audit and fix all storage methods to respect context timeouts and cancellations:

1. Review all storage interface methods to ensure context parameter exists
2. Fix implementations in:
   - storage/sqlite_*.go files (rules, alerts, actions, correlation rules, users, roles, etc.)
   - storage/clickhouse_*.go files (events, alerts, audit logs)

3. Common patterns to fix:
```go
// BEFORE
func (s *SQLiteStorage) GetRule(ctx context.Context, id string) (*Rule, error) {
    queryCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
    defer cancel()
    row := s.db.QueryRowContext(queryCtx, "SELECT ...")
}

// AFTER
func (s *SQLiteStorage) GetRule(ctx context.Context, id string) (*Rule, error) {
    queryCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
    defer cancel()
    row := s.db.QueryRowContext(queryCtx, "SELECT ...")
}
```

4. Ensure batch operations and transactions properly propagate context
5. Keep Background context for retention cleanup and migration background tasks

### 136.4. Fix detection engine context propagation (Phase 3: 30-50 instances)

**Status:** done  
**Dependencies:** 136.1, 136.3  

Update detection engine components in detect/engine.go, detect/actions.go, and detect/detector.go to propagate context from event ingestion through rule evaluation to action execution

**Details:**

Fix context propagation through detection pipeline:

1. detect/engine.go - Rule evaluation:
   - Ensure EvaluateRule receives and uses event context
   - Propagate to Sigma engine, correlation evaluators
   - Add timeout for rule evaluation

2. detect/actions.go - Action execution:
   - Fix SMTP, webhook, script execution contexts
   - Ensure SSRF protection from task 133 works with proper context
   - Add configurable timeouts per action type

3. detect/detector.go - Detection loops:
   - Event processing loop: Use event context or create derived context
   - Background correlation state maintenance: Keep Background context
   - Rule reload operations: Keep Background context

Pattern:
```go
// BEFORE
func (e *Engine) ProcessEvent(event *Event) error {
    ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
    defer cancel()
    return e.evaluateRules(ctx, event)
}

// AFTER
func (e *Engine) ProcessEvent(ctx context.Context, event *Event) error {
    evalCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
    defer cancel()
    return e.evaluateRules(evalCtx, event)
}
```

Keep Background for: correlation state cleanup, rule reload, metrics collection

### 136.5. Fix ML and SOAR layers context propagation (Phase 4)

**Status:** done  
**Dependencies:** 136.1, 136.4  

Update ML training/inference operations and SOAR playbook execution to use proper context propagation for request-scoped operations while maintaining Background contexts for long-running background tasks

**Details:**

Fix remaining context.Background() instances in ML and SOAR systems:

1. ml/*.go files:
   - ML model training: Keep Background (long-running)
   - Real-time inference API calls: Use request context
   - Model loading/initialization: Keep Background
   - Metrics collection: Keep Background

2. soar/*.go files:
   - Playbook execution triggered by API: Use request context with timeout
   - Playbook execution triggered by alert: Create derived context with playbook timeout
   - Background playbook scheduler: Keep Background
   - Playbook step execution: Propagate playbook context

Pattern for playbook execution:
```go
// API-triggered playbook
func (s *SOAREngine) ExecutePlaybook(ctx context.Context, playbookID string) error {
    pbCtx, cancel := context.WithTimeout(ctx, s.playbookTimeout)
    defer cancel()
    return s.runPlaybook(pbCtx, playbookID)
}

// Alert-triggered playbook (no parent request)
func (s *SOAREngine) ExecutePlaybookForAlert(alertID string) error {
    pbCtx, cancel := context.WithTimeout(context.Background(), s.playbookTimeout)
    defer cancel()
    return s.runPlaybook(pbCtx, alertID)
}
```

Document rationale for each Background context decision

### 136.6. Add comprehensive context timeout and cancellation tests

**Status:** done  
**Dependencies:** 136.2, 136.3, 136.4, 136.5  

Create integration and unit tests to verify context propagation, timeout behavior, and proper cancellation cleanup across all fixed layers (API, storage, detection, ML, SOAR)

**Details:**

Develop comprehensive test suite covering:

1. Unit tests for each layer:
   - Test context.Context parameter acceptance
   - Test timeout propagation (parent timeout < child timeout)
   - Test cancellation propagation
   - Test context value preservation (task 134 integration)

2. Integration tests:
   - End-to-end request timeout: HTTP → API → Storage → Detection
   - Alert-triggered workflow: Event → Detection → Action with timeout
   - Playbook execution: API → SOAR → ML with cancellation
   - Client disconnect simulation: Cancel HTTP request mid-processing

3. Edge cases:
   - Nested context timeouts (verify shortest wins)
   - Context cancellation during transaction
   - Context cancellation during action execution
   - Parallel goroutines with shared parent context

4. Test helper utilities:
```go
func TestContextPropagation(t *testing.T) {
    ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
    defer cancel()
    
    err := apiHandler(ctx)
    if !errors.Is(err, context.DeadlineExceeded) {
        t.Fatal("expected timeout error")
    }
}
```

5. Document expected behavior for Background context usage

### 136.7. Performance testing and goroutine leak detection

**Status:** done  
**Dependencies:** 136.2, 136.3, 136.4, 136.5, 136.6  

Conduct load testing, performance benchmarking, and goroutine leak detection to ensure context propagation changes don't introduce performance regressions or resource leaks

**Details:**

Comprehensive validation of context propagation implementation:

1. Baseline metrics (before fixes):
   - Request latency (p50, p95, p99)
   - Throughput (requests/sec)
   - Goroutine count under load
   - Memory usage

2. Performance testing:
   - Load test: 1000 concurrent requests, measure latency impact
   - Stress test: Gradual load increase to breaking point
   - Endurance test: Sustained load for 1+ hour
   - Benchmark critical paths: API handlers, storage queries, rule evaluation

3. Goroutine leak detection:
   - Use pprof to capture goroutine profiles before/after load tests
   - Test scenarios:
     * 10000 requests with random cancellations
     * Long-running playbooks with early termination
     * ML inference with timeout failures
   - Verify goroutine count returns to baseline

4. Resource monitoring:
   - CPU usage during high load
   - Memory allocation patterns
   - Context allocation overhead
   - Database connection pool behavior

5. Comparison testing:
```bash
# Before context fixes
go test -bench=. -benchmem -count=5 > before.txt

# After context fixes  
go test -bench=. -benchmem -count=5 > after.txt

# Compare
benchstat before.txt after.txt
```

6. Static analysis:
   - Run `grep -r 'context.Background()' --include='*.go' --exclude='*_test.go'`
   - Verify count reduced from 488 to expected legitimate usage (~50-100)
   - Document all remaining Background usage with inline comments
