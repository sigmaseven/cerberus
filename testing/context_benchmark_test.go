package testing

import (
	"context"
	"runtime"
	"testing"
	"time"

	"cerberus/core"
	"cerberus/detect"

	"github.com/stretchr/testify/assert"
	"go.uber.org/zap"
)

// TASK 136.7: Performance benchmarks for context propagation
// These benchmarks verify that context propagation doesn't introduce
// significant performance overhead.

// BenchmarkContextCreation measures the overhead of creating contexts.
func BenchmarkContextCreation(b *testing.B) {
	b.Run("WithCancel", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			_ = ctx
		}
	})

	b.Run("WithTimeout", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			cancel()
			_ = ctx
		}
	})

	b.Run("WithValue", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			ctx := context.WithValue(context.Background(), "key", "value")
			_ = ctx
		}
	})

	b.Run("NestedContexts", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			ctx1 := context.WithValue(context.Background(), "request_id", "req-123")
			ctx2, cancel := context.WithTimeout(ctx1, 30*time.Second)
			ctx3, cancel2 := context.WithCancel(ctx2)
			cancel2()
			cancel()
			_ = ctx3
		}
	})
}

// BenchmarkRuleEngineEvaluation measures rule evaluation performance.
func BenchmarkRuleEngineEvaluation(b *testing.B) {
	rules := []core.Rule{}
	engine := detect.NewRuleEngine(rules, nil, 3600)
	defer engine.Stop()

	event := &core.Event{
		EventID:   "evt-bench",
		EventType: "login_attempt",
		Timestamp: time.Now(),
		Fields:    map[string]interface{}{"username": "testuser", "src_ip": "192.168.1.1"},
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_ = engine.Evaluate(event)
	}
}

// BenchmarkActionExecutorCreation measures ActionExecutor creation/cleanup overhead.
func BenchmarkActionExecutorCreation(b *testing.B) {
	logger := zap.NewNop().Sugar()

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		executor := detect.NewActionExecutor(30*time.Second, logger)
		executor.Stop()
	}
}

// BenchmarkCorrelationStateOperations measures correlation state performance.
func BenchmarkCorrelationStateOperations(b *testing.B) {
	logger := zap.NewNop().Sugar()
	store := detect.NewCorrelationStateStore(logger)
	defer store.Stop()

	event := &core.Event{
		EventID:   "evt-bench",
		EventType: "login_attempt",
		Timestamp: time.Now(),
		Fields:    map[string]interface{}{"src_ip": "192.168.1.1"},
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		store.AddEvent("test-rule", "src_ip", event)
		_ = store.GetEvents("test-rule", "192.168.1.1")
	}
}

// BenchmarkContextCancellationPropagation measures cancellation propagation speed.
func BenchmarkContextCancellationPropagation(b *testing.B) {
	b.Run("SingleLevel", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			ctx, cancel := context.WithCancel(context.Background())
			done := make(chan struct{})
			go func() {
				<-ctx.Done()
				close(done)
			}()
			cancel()
			<-done
		}
	})

	b.Run("ThreeLevels", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			ctx1, cancel1 := context.WithCancel(context.Background())
			ctx2, cancel2 := context.WithCancel(ctx1)
			ctx3, cancel3 := context.WithCancel(ctx2)
			done := make(chan struct{})
			go func() {
				<-ctx3.Done()
				close(done)
			}()
			cancel1()
			<-done
			// Ensure all cancel functions are called to prevent vet warnings
			// (cancel1 already called, these are no-ops but satisfy vet)
			cancel2()
			cancel3()
		}
	})
}

// TestGoroutineLeakDetection verifies that operations don't leak goroutines.
func TestGoroutineLeakDetection(t *testing.T) {
	// Get baseline goroutine count
	runtime.GC()
	time.Sleep(100 * time.Millisecond) // Let any cleanup finish
	baseline := runtime.NumGoroutine()

	t.Run("RuleEngine_NoLeak", func(t *testing.T) {
		for i := 0; i < 100; i++ {
			engine := detect.NewRuleEngine([]core.Rule{}, nil, 3600)
			_ = engine.Evaluate(&core.Event{
				EventID:   "evt-leak",
				EventType: "test",
				Timestamp: time.Now(),
			})
			engine.Stop()
		}

		runtime.GC()
		time.Sleep(100 * time.Millisecond)
		current := runtime.NumGoroutine()

		// Allow for some variance but should be close to baseline
		assert.LessOrEqual(t, current, baseline+10,
			"goroutine count should return close to baseline (baseline=%d, current=%d)", baseline, current)
	})

	t.Run("ActionExecutor_NoLeak", func(t *testing.T) {
		logger := zap.NewNop().Sugar()
		for i := 0; i < 100; i++ {
			executor := detect.NewActionExecutor(30*time.Second, logger)
			executor.Stop()
		}

		runtime.GC()
		time.Sleep(100 * time.Millisecond)
		current := runtime.NumGoroutine()

		assert.LessOrEqual(t, current, baseline+10,
			"goroutine count should return close to baseline (baseline=%d, current=%d)", baseline, current)
	})

	t.Run("CorrelationStateStore_NoLeak", func(t *testing.T) {
		logger := zap.NewNop().Sugar()
		for i := 0; i < 100; i++ {
			store := detect.NewCorrelationStateStore(logger)
			store.AddEvent("test-rule", "key", &core.Event{
				EventID:   "evt-leak",
				EventType: "test",
				Timestamp: time.Now(),
			})
			store.Stop()
		}

		runtime.GC()
		time.Sleep(100 * time.Millisecond)
		current := runtime.NumGoroutine()

		assert.LessOrEqual(t, current, baseline+10,
			"goroutine count should return close to baseline (baseline=%d, current=%d)", baseline, current)
	})
}

// TestContextCancellationUnderLoad tests context handling under load.
func TestContextCancellationUnderLoad(t *testing.T) {
	const numOperations = 1000

	t.Run("rapid_cancellation_no_panic", func(t *testing.T) {
		for i := 0; i < numOperations; i++ {
			ctx, cancel := context.WithTimeout(context.Background(), 1*time.Millisecond)

			// Start operation that will be cancelled
			done := make(chan struct{})
			go func() {
				select {
				case <-time.After(1 * time.Second):
				case <-ctx.Done():
				}
				close(done)
			}()

			// Random cancellation timing
			if i%3 == 0 {
				cancel() // Immediate cancel
			}
			<-done
			cancel() // Always clean up
		}
		// Success if no panic occurred
	})
}

// BenchmarkContextPassthrough measures overhead of passing context through layers.
func BenchmarkContextPassthrough(b *testing.B) {
	// Simulate the pattern: API -> Storage -> Database
	var layer1, layer2, layer3 func(ctx context.Context, data string) string

	layer3 = func(ctx context.Context, data string) string {
		// Check context is still valid
		if ctx.Err() != nil {
			return ""
		}
		return data + "_processed"
	}
	layer2 = func(ctx context.Context, data string) string {
		return layer3(ctx, data)
	}
	layer1 = func(ctx context.Context, data string) string {
		return layer2(ctx, data)
	}

	ctx := context.Background()
	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_ = layer1(ctx, "test")
	}
}

// BenchmarkContextValueLookup measures the cost of context value lookups.
func BenchmarkContextValueLookup(b *testing.B) {
	ctx := context.Background()
	ctx = context.WithValue(ctx, "key1", "value1")
	ctx = context.WithValue(ctx, "key2", "value2")
	ctx = context.WithValue(ctx, "key3", "value3")

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_ = ctx.Value("key1")
		_ = ctx.Value("key2")
		_ = ctx.Value("key3")
	}
}
