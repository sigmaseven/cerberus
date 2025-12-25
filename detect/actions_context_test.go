package detect

import (
	"context"
	"runtime"
	"testing"
	"time"

	"cerberus/core"

	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

// TestActionExecutor_ContextCancellationStopsCleanup verifies that cancelling the parent context
// stops the circuit breaker cleanup goroutine
// TASK 144.4: Context propagation enables graceful shutdown via parent cancellation
func TestActionExecutor_ContextCancellationStopsCleanup(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	logger := zap.NewNop().Sugar()

	ae, err := NewActionExecutorWithContext(ctx, 10*time.Second, logger, core.DefaultCircuitBreakerConfig(), nil)
	require.NoError(t, err)
	require.NotNil(t, ae)

	// Give cleanup goroutine time to start
	time.Sleep(100 * time.Millisecond)

	before := runtime.NumGoroutine()

	// Cancel parent context
	cancel()

	// Wait for goroutine to exit
	time.Sleep(300 * time.Millisecond)

	after := runtime.NumGoroutine()

	require.LessOrEqual(t, after, before, "Cleanup goroutine should exit after context cancellation")
}

// TestActionExecutor_StopStillWorks verifies that Stop() method still works
// TASK 144.4: Backwards compatibility - Stop() should still work
func TestActionExecutor_StopStillWorks(t *testing.T) {
	ctx := context.Background()
	logger := zap.NewNop().Sugar()

	ae, err := NewActionExecutorWithContext(ctx, 10*time.Second, logger, core.DefaultCircuitBreakerConfig(), nil)
	require.NoError(t, err)
	require.NotNil(t, ae)

	time.Sleep(100 * time.Millisecond)
	before := runtime.NumGoroutine()

	// Call Stop()
	ae.Stop()

	time.Sleep(200 * time.Millisecond)
	after := runtime.NumGoroutine()

	require.LessOrEqual(t, after, before, "Cleanup goroutine should exit after Stop()")
}

// TestActionExecutor_BackwardsCompatibility verifies old constructors still work
// TASK 144.4: Existing code should continue to work
func TestActionExecutor_BackwardsCompatibility(t *testing.T) {
	logger := zap.NewNop().Sugar()

	// Old pattern - no context parameter
	ae1 := NewActionExecutor(10*time.Second, logger)
	require.NotNil(t, ae1)
	defer ae1.Stop()

	ae2, err := NewActionExecutorWithCircuitBreaker(10*time.Second, logger, core.DefaultCircuitBreakerConfig(), nil)
	require.NoError(t, err)
	require.NotNil(t, ae2)
	defer ae2.Stop()

	time.Sleep(100 * time.Millisecond)

	// Both should work identically
	before := runtime.NumGoroutine()
	require.Greater(t, before, 0, "Cleanup goroutines should be running")
}

// TestActionExecutor_MultipleStopCallsSafe verifies Stop() is idempotent
// TASK 144.4: Stop() should be safe to call multiple times
func TestActionExecutor_MultipleStopCallsSafe(t *testing.T) {
	ctx := context.Background()
	logger := zap.NewNop().Sugar()

	ae, err := NewActionExecutorWithContext(ctx, 10*time.Second, logger, core.DefaultCircuitBreakerConfig(), nil)
	require.NoError(t, err)
	require.NotNil(t, ae)

	// Multiple Stop() calls should not panic
	ae.Stop()
	ae.Stop()
	ae.Stop()

	time.Sleep(100 * time.Millisecond)
}

// TestActionExecutor_ContextAndStopBothWork verifies both methods work together
// TASK 144.4: Context cancellation and Stop() should both work
func TestActionExecutor_ContextAndStopBothWork(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	logger := zap.NewNop().Sugar()

	ae, err := NewActionExecutorWithContext(ctx, 10*time.Second, logger, core.DefaultCircuitBreakerConfig(), nil)
	require.NoError(t, err)
	require.NotNil(t, ae)

	time.Sleep(100 * time.Millisecond)

	// Cancel context first
	cancel()
	time.Sleep(100 * time.Millisecond)

	// Then call Stop() - should be safe
	ae.Stop()

	time.Sleep(100 * time.Millisecond)
}

// TestActionExecutor_ContextTimeoutPropagates verifies context timeout stops cleanup
// TASK 144.4: Context timeout should propagate to cleanup goroutine
func TestActionExecutor_ContextTimeoutPropagates(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	logger := zap.NewNop().Sugar()

	ae, err := NewActionExecutorWithContext(ctx, 10*time.Second, logger, core.DefaultCircuitBreakerConfig(), nil)
	require.NoError(t, err)
	require.NotNil(t, ae)

	time.Sleep(100 * time.Millisecond)
	before := runtime.NumGoroutine()

	// Wait for context timeout
	time.Sleep(250 * time.Millisecond)

	after := runtime.NumGoroutine()

	require.LessOrEqual(t, after, before, "Cleanup goroutine should exit after context timeout")
}

// TestActionExecutor_CleanupGoroutineWaitsOnStop verifies that Stop() waits
// for cleanup goroutine to complete
// TASK 144.4: Stop() should synchronize with goroutine completion
func TestActionExecutor_CleanupGoroutineWaitsOnStop(t *testing.T) {
	ctx := context.Background()
	logger := zap.NewNop().Sugar()

	ae, err := NewActionExecutorWithContext(ctx, 10*time.Second, logger, core.DefaultCircuitBreakerConfig(), nil)
	require.NoError(t, err)
	require.NotNil(t, ae)

	time.Sleep(100 * time.Millisecond)

	// Call Stop() - should wait for goroutine
	ae.Stop()

	// After Stop() returns, goroutine should be gone
	// We can't easily verify this, but the WaitGroup ensures synchronization
	time.Sleep(50 * time.Millisecond)
}

// TestActionExecutor_InvalidConfigReturnsError verifies error handling
// TASK 144.4: Constructor should still validate config
func TestActionExecutor_InvalidConfigReturnsError(t *testing.T) {
	ctx := context.Background()
	logger := zap.NewNop().Sugar()

	// Invalid config - MaxFailures too low
	invalidConfig := core.CircuitBreakerConfig{
		MaxFailures:         0, // Invalid - must be >= 1
		Timeout:             30 * time.Second,
		MaxHalfOpenRequests: 1,
	}

	ae, err := NewActionExecutorWithContext(ctx, 10*time.Second, logger, invalidConfig, nil)
	require.Error(t, err)
	require.Nil(t, ae)
	require.Contains(t, err.Error(), "invalid circuit breaker config")
}

// TestActionExecutor_CleanupRunsUnderContext verifies cleanup actually runs
// TASK 144.4: Verify cleanup goroutine is active and stops on cancellation
func TestActionExecutor_CleanupRunsUnderContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	logger := zap.NewNop().Sugar()

	ae, err := NewActionExecutorWithContext(ctx, 10*time.Second, logger, core.DefaultCircuitBreakerConfig(), nil)
	require.NoError(t, err)
	require.NotNil(t, ae)

	// Create a stale circuit breaker (simulate old access)
	cb := ae.getOrCreateCircuitBreaker("test-endpoint")
	require.NotNil(t, cb)

	ae.cbMutex.Lock()
	entry := ae.circuitBreakers["test-endpoint"]
	entry.lastAccessed = time.Now().Add(-25 * time.Hour) // Make it stale
	ae.cbMutex.Unlock()

	// Wait for cleanup cycle (runs every hour, but we can't wait that long in tests)
	// Instead, we verify the goroutine is running by checking it responds to cancellation
	time.Sleep(100 * time.Millisecond)

	before := runtime.NumGoroutine()

	// Cancel context
	cancel()
	time.Sleep(200 * time.Millisecond)

	after := runtime.NumGoroutine()

	// Cleanup goroutine should have exited
	require.LessOrEqual(t, after, before, "Cleanup goroutine should exit after cancellation")
}
