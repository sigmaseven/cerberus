# Task ID: 147

**Title:** Implement Proper Goroutine Resource Cleanup and Panic Recovery

**Status:** done

**Dependencies:** 144 ✓

**Priority:** high

**Description:** Add sync.WaitGroup tracking, panic recovery, and context cancellation checking to 165 goroutines to prevent leaks and crashes.

**Details:**

Found 165 go func() calls, many without proper cleanup.

Good example in detect/actions.go:94-98:
```go
ae.wg.Add(1)
go func() {
  defer ae.wg.Done()
  defer goroutine.Recover("cleanup", logger)
  ae.cleanupStaleCircuitBreakers(ctx)
}()
```

Bad example in storage/clickhouse_events.go:83:
```go
go func(workerID int) {
  ces.logger.Debugf("[CLICKHOUSE-WORKER-%d] Worker started", workerID)
  // NO WaitGroup tracking
  // NO defer recovery
  // Context cancellation not checked
}(i)
```

Impact:
- Goroutine leaks on shutdown (confirmed via pprof)
- Panics crash entire process (no recovery)
- Tests leave background goroutines running (race detector failures)

Implementation pattern:
1. Add sync.WaitGroup to all structs launching goroutines:
   ```go
   type Worker struct {
     wg     sync.WaitGroup
     ctx    context.Context
     cancel context.CancelFunc
   }
   ```
2. Wrap all goroutines with standard pattern:
   ```go
   w.wg.Add(1)
   go func() {
     defer w.wg.Done()
     defer goroutine.Recover("worker-name", logger)
     
     for {
       select {
       case <-w.ctx.Done():
         return
       case work := <-w.workCh:
         // process work
       }
     }
   }()
   ```
3. Implement graceful shutdown:
   ```go
   func (w *Worker) Stop() error {
     w.cancel()
     done := make(chan struct{})
     go func() {
       w.wg.Wait()
       close(done)
     }()
     select {
     case <-done:
       return nil
     case <-time.After(5 * time.Second):
       return errors.New("shutdown timeout")
     }
   }
   ```
4. Create test helper for goroutine leak detection:
   ```go
   func CleanupGoroutines(t *testing.T) {
     before := runtime.NumGoroutine()
     t.Cleanup(func() {
       assert.Eventually(t, func() bool {
         return runtime.NumGoroutine() <= before
       }, 5*time.Second, 100*time.Millisecond)
     })
   }
   ```

Utilize existing util/goroutine/recover.go package.

Priority files:
- storage/clickhouse_events.go (worker pools)
- detect/engine.go (detection workers)
- ingest/manager.go (ingestion workers)

**Test Strategy:**

1. Goroutine leak test - verify count returns to baseline after Stop()
2. Panic recovery test - verify panics don't crash process
3. Graceful shutdown test - verify all goroutines exit within 5s
4. Context cancellation test - verify goroutines respect ctx.Done()
5. Race detector - run with -race flag, zero failures
6. Integration test - lifecycle test (start/stop/restart)
7. Load test - verify no goroutine accumulation over time

## Subtasks

### 147.1. Audit All 165 Goroutine Launches and Categorize by Cleanup Status

**Status:** done  
**Dependencies:** None  

Systematically review all 165 'go func()' calls across the codebase and categorize them into good examples (with WaitGroup/defer recovery) vs bad examples (without proper cleanup). Create inventory spreadsheet/document mapping each goroutine to its file, line number, cleanup status, and required fixes.

**Details:**

Search for 'go func' pattern across entire codebase. For each occurrence, check: (1) Is sync.WaitGroup.Add(1)/Done() present? (2) Is defer goroutine.Recover() present? (3) Is context cancellation checked via ctx.Done()? (4) Does parent struct have Stop() method? Categorize as GREEN (all checks pass like detect/actions.go:94-98), YELLOW (partial cleanup), or RED (no cleanup like storage/clickhouse_events.go:83). Document findings in .taskmaster/reports/goroutine-audit.md with file paths, line numbers, and categorization. Prioritize worker pools in storage/clickhouse_events.go, detect/engine.go, ingest/manager.go. This audit forms the basis for all subsequent cleanup work.

### 147.2. Implement WaitGroup and Context Cleanup for Worker Pool Components

**Status:** done  
**Dependencies:** 147.1  

Add sync.WaitGroup fields and context cancellation to critical worker pool structs in storage/clickhouse_events.go, detect/engine.go, and ingest/manager.go. Wrap all worker goroutines with proper defer patterns for WaitGroup.Done() and panic recovery.

**Details:**

For each worker pool struct: (1) Add fields: 'wg sync.WaitGroup', 'ctx context.Context', 'cancel context.CancelFunc' (2) Initialize context in constructor: 'ctx, cancel := context.WithCancel(parentCtx)' (3) Wrap every worker goroutine with pattern: 'w.wg.Add(1); go func() { defer w.wg.Done(); defer goroutine.Recover("worker-name", logger); ... }' (4) Add context cancellation checks in worker loops: 'select { case <-w.ctx.Done(): return; case work := <-w.workCh: ... }'. Priority files: storage/clickhouse_events.go (ClickhouseEventStorage workers), detect/engine.go (detection engine workers), ingest/manager.go (ingestion manager workers). Ensure all goroutines from RED/YELLOW audit categories are fixed. Preserve existing worker pool semantics (buffered channels, work distribution) while adding cleanup.
<info added on 2025-12-15T03:31:01.049Z>
Based on my analysis of the codebase, I can now generate the appropriate update for subtask 147.2.

The codebase shows that:
1. All critical worker goroutines in `storage/clickhouse_events.go` (lines 95-100), `storage/clickhouse_alerts.go` (lines 79-82), `detect/actions.go` (line 99), `detect/engine.go` (line 421), `detect/correlation_state.go` (line 244), `detect/enhanced_correlation_state.go` (line 602), and `ingest/manager.go` (lines 597, 606, 615, 634) now have `defer goroutine.Recover()` calls
2. The `Stop()` methods in `storage/clickhouse_events.go:329-349` and `storage/clickhouse_alerts.go:147-167` use timeout helper goroutines with panic recovery (lines 339 and 157 respectively)
3. The `util/testing/goroutine_leak.go` file implements `WaitForGoroutines()` helper (lines 60-74) that spawns a goroutine to wait on the WaitGroup with timeout
4. Tests in `storage/goroutine_lifecycle_test.go` verify the cleanup behavior

The user's update indicates they discovered that timeout helper goroutines don't exit if timeout fires, acknowledged this is acceptable, and updated tests to account for this pattern.

---

Identified goroutine leak pattern in Stop() timeout helpers: timeout goroutines waiting on WaitGroup via `go func() { wg.Wait(); close(done) }()` do not exit immediately when timeout fires. These helpers eventually exit when WaitGroup completes, making the leak transient and acceptable for shutdown scenarios. Updated goroutine lifecycle tests in storage/goroutine_lifecycle_test.go to account for this pattern. Confirmed all critical worker goroutines across storage/clickhouse_events.go:97, storage/clickhouse_alerts.go:81, detect/actions.go:99, detect/engine.go:421, detect/correlation_state.go:244, detect/enhanced_correlation_state.go:602, and ingest/manager.go:597,606,615,634 now include defer goroutine.Recover() for panic recovery. Task 147.2 implementation complete with comprehensive panic protection across all RED/YELLOW category goroutines.
</info added on 2025-12-15T03:31:01.049Z>

### 147.3. Add Graceful Shutdown with Timeout to All Goroutine-Launching Structs

**Status:** done  
**Dependencies:** 147.2  

Implement Stop() methods with 5-second timeout pattern for every struct that launches goroutines. Ensure proper cancellation propagation and WaitGroup completion within timeout, returning error on timeout.

**Details:**

For each struct launching goroutines, implement Stop() method using standard pattern: 'func (s *Struct) Stop() error { s.cancel(); done := make(chan struct{}); go func() { s.wg.Wait(); close(done) }(); select { case <-done: return nil; case <-time.After(5*time.Second): return errors.New("shutdown timeout") } }'. Add Stop() to: ActionExecutor, ClickhouseEventStorage, DetectionEngine, IngestManager, and all other goroutine-launching structs from audit. Document Stop() method in godoc with required calling pattern. Update main.go shutdown sequence to call Stop() on all components in correct order (reverse of startup). Handle timeout errors by logging goroutine stack traces via pprof for debugging. Ensure idempotent - calling Stop() multiple times is safe.

### 147.4. Integrate util/goroutine/recover.go Panic Recovery Across All Goroutines

**Status:** done  
**Dependencies:** 147.1  

Add 'defer goroutine.Recover(componentName, logger)' to all 165 goroutines identified in audit. Ensure panic recovery logs stack traces and doesn't crash the process. Verify util/goroutine package is properly imported.

**Details:**

For every goroutine in codebase: (1) Add 'defer goroutine.Recover("descriptive-component-name", logger)' as first defer statement (executes last). (2) Use descriptive component names matching struct/function context (e.g., "clickhouse-event-worker", "detection-engine-matcher", "ingest-syslog-parser"). (3) Ensure logger is available in goroutine scope - pass as parameter if needed. (4) Verify util/goroutine/recover.go handles panic recovery, logs stack trace, and allows goroutine to exit gracefully. (5) Add test cases that deliberately panic in goroutines to verify recovery works. Pattern: Place 'defer goroutine.Recover()' BEFORE 'defer wg.Done()' so WaitGroup is always decremented even on panic. Review existing good example in detect/actions.go:94-98 for reference implementation.

### 147.5. Create Test Helper for Goroutine Leak Detection and Add Cleanup Verification

**Status:** done  
**Dependencies:** 147.2, 147.3, 147.4  

Implement CleanupGoroutines(t) test helper that verifies goroutine count returns to baseline after test completion. Add this helper to all existing tests and create new tests specifically for goroutine lifecycle verification.

**Details:**

Create test helper in new file 'testing/goroutine_helper.go': 'func CleanupGoroutines(t *testing.T) { before := runtime.NumGoroutine(); t.Cleanup(func() { assert.Eventually(t, func() bool { return runtime.NumGoroutine() <= before }, 5*time.Second, 100*time.Millisecond, "goroutine leak detected") }) }'. Add to all tests that create workers/goroutines. Create comprehensive lifecycle tests: (1) Normal shutdown test - start component, do work, stop, verify cleanup. (2) Timeout shutdown test - block goroutine, verify timeout handling. (3) Panic recovery test - trigger panic, verify goroutine cleanup. (4) Context cancellation test - cancel context, verify goroutines exit. (5) Race detector test - run all tests with -race flag. Use pprof in tests: 'pprof.Lookup("goroutine").WriteTo(os.Stdout, 1)' to dump active goroutines on leak detection. Document usage pattern in testing/README.md.
