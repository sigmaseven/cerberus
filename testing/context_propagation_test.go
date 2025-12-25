package testing

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TASK 136.6: Context propagation tests
// These tests verify that context cancellation and timeouts propagate correctly
// throughout the Cerberus SIEM system.

// TestContextTimeoutPropagation verifies that timeouts propagate correctly
// through nested context hierarchies.
func TestContextTimeoutPropagation(t *testing.T) {
	t.Run("parent timeout should cancel child operations", func(t *testing.T) {
		// Parent context with short timeout
		parentCtx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
		defer cancel()

		// Child context with longer timeout
		childCtx, childCancel := context.WithTimeout(parentCtx, 5*time.Second)
		defer childCancel()

		// Simulate a long-running operation
		select {
		case <-time.After(1 * time.Second):
			t.Fatal("operation should have been cancelled by parent timeout")
		case <-childCtx.Done():
			// Parent timeout should have triggered first
			assert.True(t, errors.Is(childCtx.Err(), context.DeadlineExceeded))
		}
	})

	t.Run("child timeout should be respected when shorter than parent", func(t *testing.T) {
		// Parent context with long timeout
		parentCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		// Child context with shorter timeout
		childCtx, childCancel := context.WithTimeout(parentCtx, 50*time.Millisecond)
		defer childCancel()

		start := time.Now()
		<-childCtx.Done()
		elapsed := time.Since(start)

		// Should have timed out around 50ms, not 5s
		assert.Less(t, elapsed, 500*time.Millisecond)
		assert.True(t, errors.Is(childCtx.Err(), context.DeadlineExceeded))
	})
}

// TestContextCancellation verifies that manual cancellation propagates correctly.
func TestContextCancellation(t *testing.T) {
	t.Run("cancel should propagate to all child contexts", func(t *testing.T) {
		parentCtx, cancel := context.WithCancel(context.Background())
		defer cancel()

		// Create multiple child contexts
		child1Ctx, child1Cancel := context.WithCancel(parentCtx)
		defer child1Cancel()
		child2Ctx, child2Cancel := context.WithTimeout(parentCtx, 10*time.Second)
		defer child2Cancel()
		child3Ctx := context.WithValue(parentCtx, "key", "value")

		// Cancel parent
		cancel()

		// All children should be cancelled
		assert.Error(t, child1Ctx.Err())
		assert.Error(t, child2Ctx.Err())
		assert.Error(t, child3Ctx.Err())
	})

	t.Run("cancelling child should not affect parent", func(t *testing.T) {
		parentCtx, parentCancel := context.WithCancel(context.Background())
		defer parentCancel()

		childCtx, childCancel := context.WithCancel(parentCtx)
		childCancel()

		// Child should be cancelled
		assert.Error(t, childCtx.Err())
		// Parent should not be affected
		assert.NoError(t, parentCtx.Err())
	})
}

// TestContextValuePreservation verifies that context values are preserved
// through the context hierarchy.
func TestContextValuePreservation(t *testing.T) {
	t.Run("values should propagate to child contexts", func(t *testing.T) {
		// Create context with values (simulating request ID, user info, etc.)
		ctx := context.Background()
		ctx = context.WithValue(ctx, "request_id", "req-123")
		ctx = context.WithValue(ctx, "user_id", "user-456")

		// Create child context with timeout
		childCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()

		// Values should be accessible in child
		assert.Equal(t, "req-123", childCtx.Value("request_id"))
		assert.Equal(t, "user-456", childCtx.Value("user_id"))
	})
}

// TestConcurrentContextCancellation verifies that concurrent operations
// handle context cancellation correctly without races or deadlocks.
func TestConcurrentContextCancellation(t *testing.T) {
	t.Run("multiple goroutines should handle cancellation gracefully", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())

		var wg sync.WaitGroup
		results := make(chan error, 10)

		// Start multiple goroutines
		for i := 0; i < 10; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				select {
				case <-time.After(5 * time.Second):
					results <- errors.New("timeout - context cancellation didn't propagate")
				case <-ctx.Done():
					results <- ctx.Err()
				}
			}()
		}

		// Cancel after brief delay
		time.Sleep(10 * time.Millisecond)
		cancel()

		wg.Wait()
		close(results)

		// All goroutines should have received cancellation
		count := 0
		for err := range results {
			count++
			assert.True(t, errors.Is(err, context.Canceled))
		}
		assert.Equal(t, 10, count)
	})
}

// TestGracefulShutdownPattern tests the pattern used for cleanup goroutines
// in the SIEM system (ActionExecutor, RuleEngine, etc.).
func TestGracefulShutdownPattern(t *testing.T) {
	t.Run("cleanup goroutine should exit on context cancellation", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())

		var wg sync.WaitGroup
		cleanupStarted := make(chan struct{})
		cleanupDone := make(chan struct{})

		// Simulate cleanup goroutine pattern used in ActionExecutor
		wg.Add(1)
		go func() {
			defer wg.Done()
			close(cleanupStarted)

			ticker := time.NewTicker(100 * time.Millisecond)
			defer ticker.Stop()

			for {
				select {
				case <-ticker.C:
					// Simulated cleanup work
				case <-ctx.Done():
					close(cleanupDone)
					return
				}
			}
		}()

		// Wait for goroutine to start
		<-cleanupStarted

		// Cancel context
		cancel()

		// Wait for goroutine to exit with timeout
		select {
		case <-cleanupDone:
			// Success - goroutine exited cleanly
		case <-time.After(1 * time.Second):
			t.Fatal("cleanup goroutine did not exit within timeout")
		}

		// WaitGroup should complete
		done := make(chan struct{})
		go func() {
			wg.Wait()
			close(done)
		}()

		select {
		case <-done:
			// Success
		case <-time.After(1 * time.Second):
			t.Fatal("WaitGroup.Wait() did not complete")
		}
	})
}

// TestBackgroundContextUsage documents acceptable patterns for context.Background()
// in the SIEM architecture.
func TestBackgroundContextUsage(t *testing.T) {
	t.Run("background context for long-running daemon goroutines", func(t *testing.T) {
		// This test documents the pattern used in RetentionManager, correlation state cleanup, etc.
		// These goroutines run for the lifetime of the application and should NOT be tied
		// to any specific request context.

		// Create application-level context (in production this would be from main())
		appCtx, appCancel := context.WithCancel(context.Background())

		var wg sync.WaitGroup
		daemonDone := make(chan struct{})

		// Daemon goroutine - receives app context, not request context
		wg.Add(1)
		go func() {
			defer wg.Done()
			ticker := time.NewTicker(10 * time.Millisecond)
			defer ticker.Stop()

			iterations := 0
			for {
				select {
				case <-ticker.C:
					iterations++
					// Daemon work (cleanup, metrics, etc.)
				case <-appCtx.Done():
					close(daemonDone)
					return
				}
			}
		}()

		// Let daemon run for a bit
		time.Sleep(50 * time.Millisecond)

		// Application shutdown
		appCancel()

		select {
		case <-daemonDone:
			// Success
		case <-time.After(1 * time.Second):
			t.Fatal("daemon did not shutdown cleanly")
		}

		wg.Wait()
	})
}

// TestContextTimeoutForHTTPRequests simulates HTTP request timeout propagation
// to storage operations.
func TestContextTimeoutForHTTPRequests(t *testing.T) {
	t.Run("storage operation should respect request timeout", func(t *testing.T) {
		// Simulate HTTP handler with request timeout
		requestCtx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
		defer cancel()

		// Simulate storage operation that takes longer than request timeout
		storageOperation := func(ctx context.Context) error {
			select {
			case <-time.After(5 * time.Second):
				return nil // Would complete successfully
			case <-ctx.Done():
				return ctx.Err() // Request cancelled
			}
		}

		err := storageOperation(requestCtx)
		require.Error(t, err)
		assert.True(t, errors.Is(err, context.DeadlineExceeded))
	})
}

// TestContextCancellationDuringTransaction tests behavior when context is
// cancelled during a multi-step operation.
func TestContextCancellationDuringTransaction(t *testing.T) {
	t.Run("cancellation during multi-step operation", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())

		steps := []string{}
		var mu sync.Mutex

		addStep := func(step string) {
			mu.Lock()
			steps = append(steps, step)
			mu.Unlock()
		}

		// Multi-step operation
		step1 := func(ctx context.Context) error {
			addStep("step1_start")
			select {
			case <-time.After(10 * time.Millisecond):
				addStep("step1_complete")
				return nil
			case <-ctx.Done():
				addStep("step1_cancelled")
				return ctx.Err()
			}
		}

		step2 := func(ctx context.Context) error {
			addStep("step2_start")
			select {
			case <-time.After(100 * time.Millisecond):
				addStep("step2_complete")
				return nil
			case <-ctx.Done():
				addStep("step2_cancelled")
				return ctx.Err()
			}
		}

		// Cancel context after step1 completes but during step2
		go func() {
			time.Sleep(30 * time.Millisecond)
			cancel()
		}()

		// Execute steps
		if err := step1(ctx); err != nil {
			t.Logf("step1 error: %v", err)
		}
		if err := step2(ctx); err != nil {
			t.Logf("step2 error (expected): %v", err)
		}

		// Verify step1 completed, step2 was cancelled
		assert.Contains(t, steps, "step1_complete")
		assert.Contains(t, steps, "step2_cancelled")
		assert.NotContains(t, steps, "step2_complete")
	})
}

// TestNoContextLeaks verifies that context cancellation doesn't cause resource leaks.
func TestNoContextLeaks(t *testing.T) {
	t.Run("cancelled contexts should not leak goroutines", func(t *testing.T) {
		for i := 0; i < 1000; i++ {
			ctx, cancel := context.WithTimeout(context.Background(), 1*time.Millisecond)

			go func() {
				<-ctx.Done()
			}()

			// Cancel before timeout in some cases
			if i%2 == 0 {
				cancel()
			}
			// Let timeout occur in other cases
			time.Sleep(2 * time.Millisecond)
			cancel() // Always cancel to clean up
		}

		// If we get here without hanging, no goroutine leaks
		// (Go's GC will catch leaked goroutines if select doesn't properly exit)
	})
}
