# Task ID: 139

**Title:** Implement Graceful ActionExecutor Lifecycle Management

**Status:** done

**Dependencies:** None

**Priority:** medium

**Description:** Fix goroutine leak in ActionExecutor cleanup by ensuring Stop() is called and documented

**Details:**

**RESOURCE LEAK PREVENTION**

Location: `detect/actions.go`

Problem: Circuit breaker cleanup goroutine started in constructor without clear shutdown guarantee.

Current code pattern:
```go
func NewActionExecutorWithCircuitBreaker(...) *ActionExecutor {
    ctx, cancel := context.WithCancel(context.Background())
    ae := &ActionExecutor{
        cleanupCancel: cancel,
    }
    go ae.cleanupStaleCircuitBreakers(ctx) // Potential leak
    return ae
}
```

Implementation:

1. **Verify Stop() method exists and calls cleanup:**
   ```go
   func (ae *ActionExecutor) Stop() error {
       if ae.cleanupCancel != nil {
           ae.cleanupCancel()
       }
       // Wait for cleanup goroutine to exit
       ae.wg.Wait()
       return nil
   }
   ```

2. **Add WaitGroup for tracking:**
   ```go
   type ActionExecutor struct {
       // ...
       cleanupCancel context.CancelFunc
       wg            sync.WaitGroup
   }
   
   func NewActionExecutorWithCircuitBreaker(...) *ActionExecutor {
       ctx, cancel := context.WithCancel(context.Background())
       ae := &ActionExecutor{
           cleanupCancel: cancel,
       }
       ae.wg.Add(1)
       go func() {
           defer ae.wg.Done()
           ae.cleanupStaleCircuitBreakers(ctx)
       }()
       return ae
   }
   ```

3. **Document lifecycle requirements:**
   - Add godoc comment requiring Stop() call
   - Update caller code to ensure Stop() is called
   - Consider adding finalizer or defer in main.go

4. **Ensure main.go calls Stop():**
   ```go
   defer actionExecutor.Stop()
   ```

5. **Add io.Closer interface:**
   ```go
   func (ae *ActionExecutor) Close() error {
       return ae.Stop()
   }
   ```

**Test Strategy:**

1. Unit test: Create ActionExecutor, verify Stop() stops goroutine
2. Leak test: Use goleak to detect goroutine leaks
   ```go
   defer goleak.VerifyNone(t)
   ae := NewActionExecutorWithCircuitBreaker(...)
   defer ae.Stop()
   ```
3. Integration test: Full lifecycle test with startup/shutdown
4. Load test: Create/destroy many executors, monitor goroutine count
5. Manual verification: Add logging to cleanup goroutine exit
6. Benchmark: Measure resource usage before/after fix
7. Review all other goroutines started in constructors

## Subtasks

### 139.1. Add WaitGroup tracking to ActionExecutor constructor and cleanup goroutine

**Status:** done  
**Dependencies:** None  

Modify ActionExecutor struct to include sync.WaitGroup field and update NewActionExecutorWithCircuitBreaker to properly track the cleanup goroutine lifecycle using WaitGroup.Add(1) before starting goroutine and defer wg.Done() inside goroutine.

**Details:**

1. Add `wg sync.WaitGroup` field to ActionExecutor struct in detect/actions.go
2. In NewActionExecutorWithCircuitBreaker constructor, call ae.wg.Add(1) before launching goroutine
3. Wrap cleanupStaleCircuitBreakers call in anonymous function with defer ae.wg.Done()
4. Ensure cleanupCancel field is properly initialized
5. Verify the goroutine respects context cancellation in cleanupStaleCircuitBreakers method

### 139.2. Enhance Stop() method and implement io.Closer interface

**Status:** done  
**Dependencies:** 139.1  

Verify existing Stop() method at detect/actions.go:266-270, enhance it to call cleanupCancel and wait for WaitGroup, then add Close() method implementing io.Closer interface for standard cleanup pattern.

**Details:**

1. Review current Stop() implementation in detect/actions.go:266-270
2. Add nil-check for cleanupCancel before calling it
3. Add ae.wg.Wait() call to block until cleanup goroutine completes
4. Implement Close() method that delegates to Stop() for io.Closer interface compliance
5. Add comprehensive godoc comments documenting lifecycle requirements and necessity of calling Stop()/Close()
6. Add mutex protection if Stop() can be called concurrently

### 139.3. Update all instantiation sites and add comprehensive lifecycle tests

**Status:** done  
**Dependencies:** 139.2  

Find all ActionExecutor instantiation sites (especially main.go), ensure Stop()/Close() is called with defer, and create comprehensive tests including goleak detection for goroutine leak prevention.

**Details:**

1. Search codebase for NewActionExecutorWithCircuitBreaker calls (main.go, tests, etc.)
2. Add `defer actionExecutor.Stop()` or `defer actionExecutor.Close()` at each instantiation site
3. Create goleak-based test: `defer goleak.VerifyNone(t)` before creating ActionExecutor
4. Create integration test covering full lifecycle: construct -> use -> stop -> verify cleanup
5. Add test measuring goroutine count before/after ActionExecutor lifecycle
6. Document lifecycle requirements in package documentation
7. Consider adding runtime.SetFinalizer as safety net (document as not primary cleanup mechanism)
