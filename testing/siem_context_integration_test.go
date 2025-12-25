package testing

import (
	"context"
	"errors"
	"testing"
	"time"

	"cerberus/core"
	"cerberus/detect"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

// TASK 136.6: SIEM-specific context propagation integration tests
// These tests verify context handling in actual Cerberus components.

// TestRuleEngineContextHandling tests that the RuleEngine handles context correctly.
func TestRuleEngineContextHandling(t *testing.T) {
	t.Run("engine shutdown should complete within timeout", func(t *testing.T) {
		// Create a simple rule engine
		rules := []core.Rule{}
		correlationRules := []core.CorrelationRule{}
		engine := detect.NewRuleEngine(rules, correlationRules, 3600)
		require.NotNil(t, engine)

		// Engine should be stoppable
		done := make(chan struct{})
		go func() {
			engine.Stop()
			close(done)
		}()

		select {
		case <-done:
			// Success - engine stopped cleanly
		case <-time.After(5 * time.Second):
			t.Fatal("engine.Stop() did not complete within timeout")
		}
	})

	t.Run("rule evaluation should complete quickly without hanging", func(t *testing.T) {
		// Create engine with no rules - focus on testing that evaluation doesn't hang
		rules := []core.Rule{}
		engine := detect.NewRuleEngine(rules, nil, 3600)
		defer engine.Stop()

		// Create test event
		event := &core.Event{
			EventID:   "evt-123",
			EventType: "test",
			Timestamp: time.Now(),
			Fields:    make(map[string]interface{}),
		}

		// Evaluate should complete quickly and not hang
		done := make(chan struct{})
		go func() {
			_ = engine.Evaluate(event)
			close(done)
		}()

		select {
		case <-done:
			// Success - evaluation completed without hanging
		case <-time.After(5 * time.Second):
			t.Fatal("rule evaluation hung - context propagation issue")
		}
	})
}

// TestActionExecutorContextHandling tests the ActionExecutor context lifecycle.
func TestActionExecutorContextHandling(t *testing.T) {
	t.Run("action executor should shutdown gracefully", func(t *testing.T) {
		logger := zap.NewNop().Sugar()
		executor := detect.NewActionExecutor(30*time.Second, logger)
		require.NotNil(t, executor)

		// Stop should complete quickly and not hang
		done := make(chan struct{})
		go func() {
			executor.Stop()
			close(done)
		}()

		select {
		case <-done:
			// Success
		case <-time.After(5 * time.Second):
			t.Fatal("action executor Stop() did not complete within timeout")
		}
	})

	t.Run("multiple stop calls should be safe", func(t *testing.T) {
		logger := zap.NewNop().Sugar()
		executor := detect.NewActionExecutor(30*time.Second, logger)

		// Multiple Stop() calls should be safe (idempotent)
		executor.Stop()
		executor.Stop()
		executor.Stop()

		// Should not panic or hang
	})
}

// TestCorrelationStateContextHandling tests correlation state cleanup context handling.
func TestCorrelationStateContextHandling(t *testing.T) {
	t.Run("correlation state store should cleanup on shutdown", func(t *testing.T) {
		logger := zap.NewNop().Sugar()
		store := detect.NewCorrelationStateStore(logger)
		require.NotNil(t, store)

		// Add some state
		event := &core.Event{
			EventID:   "evt-456",
			EventType: "test",
			Timestamp: time.Now(),
			Fields:    map[string]interface{}{"src_ip": "192.168.1.1"},
		}
		store.AddEvent("test-rule", "src_ip", event)

		// Stop should complete gracefully
		done := make(chan struct{})
		go func() {
			store.Stop()
			close(done)
		}()

		select {
		case <-done:
			// Success
		case <-time.After(5 * time.Second):
			t.Fatal("correlation store Stop() did not complete within timeout")
		}
	})
}

// TestEventProcessingContextSimulation simulates the detection pipeline context flow.
func TestEventProcessingContextSimulation(t *testing.T) {
	t.Run("simulate event processing with timeout", func(t *testing.T) {
		// This simulates the pattern used in Detector.run()
		// Events are processed from a channel without request context

		eventCh := make(chan *core.Event, 10)
		resultCh := make(chan bool, 10)
		ctx, cancel := context.WithCancel(context.Background())

		// Simulate detection worker
		go func() {
			for {
				select {
				case <-ctx.Done():
					return
				case event, ok := <-eventCh:
					if !ok {
						return
					}
					// Simulate rule evaluation (would be engine.Evaluate(event))
					_ = event.EventType
					resultCh <- true
				}
			}
		}()

		// Send test events
		for i := 0; i < 5; i++ {
			eventCh <- &core.Event{
				EventID:   "evt-" + string(rune('0'+i)),
				EventType: "test",
				Timestamp: time.Now(),
			}
		}

		// Verify events are processed
		processed := 0
		timeout := time.After(1 * time.Second)
	loop:
		for {
			select {
			case <-resultCh:
				processed++
				if processed >= 5 {
					break loop
				}
			case <-timeout:
				break loop
			}
		}

		assert.Equal(t, 5, processed, "all events should be processed")

		// Shutdown
		cancel()
		close(eventCh)
	})
}

// TestTimeoutInNestedOperations verifies timeout propagation in nested operations.
func TestTimeoutInNestedOperations(t *testing.T) {
	t.Run("nested operation should respect outer timeout", func(t *testing.T) {
		// Outer context with short timeout (simulating HTTP request timeout)
		outerCtx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
		defer cancel()

		// Simulated storage operation that creates its own timeout
		storageOp := func(ctx context.Context) error {
			// Storage creates a derived context with longer timeout
			// but should still respect parent's shorter timeout
			opCtx, opCancel := context.WithTimeout(ctx, 5*time.Second)
			defer opCancel()

			select {
			case <-time.After(1 * time.Second):
				return nil
			case <-opCtx.Done():
				return opCtx.Err()
			}
		}

		// Should fail with outer timeout
		err := storageOp(outerCtx)
		require.Error(t, err)
		assert.True(t, errors.Is(err, context.DeadlineExceeded))
	})
}

// TestBackgroundWorkerContextPattern verifies the pattern used by background workers.
func TestBackgroundWorkerContextPattern(t *testing.T) {
	t.Run("background worker should use application context", func(t *testing.T) {
		// This pattern is used by RetentionManager, ML training pipeline, etc.
		// Background workers receive context.WithCancel(context.Background()) at creation

		appCtx, appCancel := context.WithCancel(context.Background())
		iterations := 0
		workerDone := make(chan struct{})

		// Simulate background worker
		go func() {
			ticker := time.NewTicker(10 * time.Millisecond)
			defer ticker.Stop()

			for {
				select {
				case <-ticker.C:
					iterations++
				case <-appCtx.Done():
					close(workerDone)
					return
				}
			}
		}()

		// Let worker run
		time.Sleep(50 * time.Millisecond)

		// Shutdown via application context
		appCancel()

		select {
		case <-workerDone:
			// Success
			assert.Greater(t, iterations, 0, "worker should have run at least once")
		case <-time.After(1 * time.Second):
			t.Fatal("worker did not shutdown cleanly")
		}
	})
}
