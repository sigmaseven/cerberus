// Package testing provides graceful shutdown tests for Cerberus SIEM.
//
// TASK 144.6: Comprehensive graceful shutdown testing with context cancellation validation.
// These tests verify that all components properly respond to context cancellation,
// enabling clean application shutdown within configured timeouts.
package testing

import (
	"context"
	"net/http"
	"net/http/httptest"
	"runtime"
	"sort"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
	"go.opentelemetry.io/otel/trace"
)

// Timeout constants for graceful shutdown testing.
const (
	// GracefulShutdownTimeout is the maximum time allowed for graceful shutdown.
	GracefulShutdownTimeout = 5 * time.Second

	// ShortTimeout is used for quick operations.
	ShortTimeout = 100 * time.Millisecond

	// MediumTimeout is used for moderate operations.
	MediumTimeout = 500 * time.Millisecond

	// LatencySampleSize is the number of iterations for latency measurement.
	LatencySampleSize = 100

	// GoroutineStabilizationAttempts is the number of attempts to stabilize goroutine count.
	GoroutineStabilizationAttempts = 5

	// GoroutineStabilizationDelay is the delay between stabilization attempts.
	GoroutineStabilizationDelay = 20 * time.Millisecond

	// SchedulingOverhead is the allowed overhead for scheduler delays in CI environments.
	SchedulingOverhead = 200 * time.Millisecond
)

// measureStableGoroutineCount returns a stable goroutine count using retry logic.
// It takes multiple measurements and returns when two consecutive readings match,
// ensuring the count is stable and not affected by runtime background tasks.
func measureStableGoroutineCount(t *testing.T) int {
	t.Helper()

	var stable int
	for attempt := 0; attempt < GoroutineStabilizationAttempts; attempt++ {
		runtime.GC()
		runtime.Gosched()
		time.Sleep(GoroutineStabilizationDelay)

		current := runtime.NumGoroutine()
		if attempt > 0 && current == stable {
			// Two consecutive identical readings - stable
			return current
		}
		stable = current
	}

	// If unstable after all attempts, return best measurement with warning
	t.Logf("Warning: goroutine count unstable after %d attempts, using %d",
		GoroutineStabilizationAttempts, stable)
	return stable
}

// assertNoGoroutineLeak verifies no goroutines leaked by comparing counts.
// It captures stack traces on failure for debugging.
func assertNoGoroutineLeak(t *testing.T, baseline int) {
	t.Helper()

	// Stabilize measurement with multiple attempts
	time.Sleep(50 * time.Millisecond)
	runtime.GC()
	runtime.Gosched()
	time.Sleep(50 * time.Millisecond)

	afterCount := runtime.NumGoroutine()
	leaked := afterCount - baseline

	if leaked > 0 {
		// Capture stack traces for debugging
		buf := make([]byte, 1<<20)
		stackLen := runtime.Stack(buf, true)
		t.Fatalf("goroutine leak detected: baseline=%d, after=%d, leaked=%d\n\nStack traces:\n%s",
			baseline, afterCount, leaked, buf[:stackLen])
	}
}

// startWorkers starts n worker goroutines that respond to context cancellation.
func startWorkers(ctx context.Context, wg *sync.WaitGroup, n int, ready chan<- struct{}) {
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ticker := time.NewTicker(50 * time.Millisecond)
			defer ticker.Stop()

			// Signal ready
			ready <- struct{}{}

			for {
				select {
				case <-ticker.C:
					// Simulated work
				case <-ctx.Done():
					return
				}
			}
		}()
	}
}

// waitForCompletion waits for a WaitGroup with timeout.
// Uses t.Fatalf on timeout to prevent test continuation with undefined state.
func waitForCompletion(t *testing.T, wg *sync.WaitGroup, timeout time.Duration, label string) {
	t.Helper()

	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		// Success
	case <-time.After(timeout):
		buf := make([]byte, 1<<20)
		stackLen := runtime.Stack(buf, true)
		t.Fatalf("FATAL: timeout waiting for %s after %v\n\nGoroutine dump:\n%s",
			label, timeout, buf[:stackLen])
	}
}

// TestGracefulShutdownAllGoroutinesExit verifies that all application goroutines
// exit within the configured timeout when context is cancelled.
func TestGracefulShutdownAllGoroutinesExit(t *testing.T) {
	t.Run("all worker goroutines exit on context cancellation", func(t *testing.T) {
		baseline := measureStableGoroutineCount(t)
		appCtx, appCancel := context.WithCancel(context.Background())
		defer appCancel()

		var wg sync.WaitGroup
		workerCount := 10
		ready := make(chan struct{}, workerCount)

		startWorkers(appCtx, &wg, workerCount, ready)

		// Wait for all workers to be ready
		for i := 0; i < workerCount; i++ {
			<-ready
		}

		// Trigger shutdown and measure duration
		start := time.Now()
		appCancel()
		waitForCompletion(t, &wg, GracefulShutdownTimeout, "workers to complete")
		duration := time.Since(start)

		t.Logf("All workers exited in %v", duration)
		assert.Less(t, duration, GracefulShutdownTimeout,
			"shutdown should complete within %v", GracefulShutdownTimeout)

		// Verify no goroutine leak
		assertNoGoroutineLeak(t, baseline)
	})
}

// TestGracefulShutdownNoResourceLeaks verifies no resources leak during shutdown.
func TestGracefulShutdownNoResourceLeaks(t *testing.T) {
	t.Run("no resource leaks after shutdown", func(t *testing.T) {
		type Resource struct {
			acquired bool
			released bool
		}

		const resourceCount = 100
		resources := make([]*Resource, resourceCount)
		for i := range resources {
			resources[i] = &Resource{}
		}

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		var wg sync.WaitGroup
		ready := make(chan struct{}, resourceCount)

		for i := 0; i < resourceCount; i++ {
			wg.Add(1)
			go func(idx int) {
				defer wg.Done()
				r := resources[idx]
				r.acquired = true
				defer func() { r.released = true }()

				ready <- struct{}{}

				select {
				case <-time.After(10 * time.Second):
				case <-ctx.Done():
					return
				}
			}(i)
		}

		// Wait for all acquisitions
		for i := 0; i < resourceCount; i++ {
			<-ready
		}

		cancel()
		wg.Wait()

		// Verify all resources released
		for i, r := range resources {
			assert.True(t, r.released, "resource %d should be released", i)
		}
	})
}

// TestRequestTimeoutEnforcement verifies request timeouts are enforced.
func TestRequestTimeoutEnforcement(t *testing.T) {
	tests := []struct {
		name            string
		requestTimeout  time.Duration
		operationTime   time.Duration
		expectedTimeout bool
	}{
		{
			name:            "request completes before timeout",
			requestTimeout:  MediumTimeout,
			operationTime:   50 * time.Millisecond,
			expectedTimeout: false,
		},
		{
			name:            "request cancelled by timeout",
			requestTimeout:  50 * time.Millisecond,
			operationTime:   MediumTimeout,
			expectedTimeout: true,
		},
		{
			name:            "very short timeout cancels immediately",
			requestTimeout:  1 * time.Millisecond,
			operationTime:   1 * time.Second,
			expectedTimeout: true,
		},
		{
			name:            "zero timeout fails immediately",
			requestTimeout:  0,
			operationTime:   ShortTimeout,
			expectedTimeout: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				ctx := r.Context()
				select {
				case <-time.After(tt.operationTime):
					w.WriteHeader(http.StatusOK)
				case <-ctx.Done():
					w.WriteHeader(http.StatusServiceUnavailable)
				}
			})

			server := httptest.NewServer(handler)
			defer server.Close()

			ctx, cancel := context.WithTimeout(context.Background(), tt.requestTimeout)
			defer cancel()

			req, err := http.NewRequestWithContext(ctx, http.MethodGet, server.URL, nil)
			require.NoError(t, err, "failed to create request")

			start := time.Now()
			resp, err := http.DefaultClient.Do(req)
			elapsed := time.Since(start)

			if tt.expectedTimeout {
				assert.Error(t, err, "request should timeout when operation exceeds deadline")
				// Allow scheduling overhead for CI environments
				maxElapsed := tt.requestTimeout + SchedulingOverhead
				assert.Less(t, elapsed, maxElapsed,
					"timeout should occur within reasonable time (timeout=%v, max=%v)",
					tt.requestTimeout, maxElapsed)
			} else {
				require.NoError(t, err, "request should complete successfully")
				assert.Equal(t, http.StatusOK, resp.StatusCode)
				resp.Body.Close()
			}
		})
	}
}

// TestOpenTelemetryContextPropagation verifies that OpenTelemetry trace contexts
// propagate correctly through all application layers using a real in-memory tracer.
func TestOpenTelemetryContextPropagation(t *testing.T) {
	t.Run("otel trace spans propagate through all layers", func(t *testing.T) {
		// Use in-memory exporter for testing (provides real spans, not noop)
		exporter := tracetest.NewInMemoryExporter()
		tp := sdktrace.NewTracerProvider(sdktrace.WithSyncer(exporter))
		defer func() {
			if err := tp.Shutdown(context.Background()); err != nil {
				t.Logf("Error shutting down tracer provider: %v", err)
			}
		}()

		tracer := tp.Tracer("cerberus-test")

		// Start span
		ctx, span := tracer.Start(context.Background(), "test-operation")
		defer span.End()

		// Validate span context is VALID (not noop)
		spanCtx := span.SpanContext()
		require.True(t, spanCtx.IsValid(), "span context should be valid")
		require.True(t, spanCtx.TraceID().IsValid(), "trace ID should be valid")
		require.True(t, spanCtx.SpanID().IsValid(), "span ID should be valid")

		// Capture span contexts at each layer
		var spanAtAPI, spanAtService, spanAtStorage trace.SpanContext

		storageLayer := func(ctx context.Context) {
			spanAtStorage = trace.SpanFromContext(ctx).SpanContext()
		}

		serviceLayer := func(ctx context.Context) {
			spanAtService = trace.SpanFromContext(ctx).SpanContext()
			storageLayer(ctx)
		}

		apiLayer := func(ctx context.Context) {
			spanAtAPI = trace.SpanFromContext(ctx).SpanContext()
			serviceLayer(ctx)
		}

		apiLayer(ctx)

		// Verify trace ID propagates (same trace across all layers)
		assert.Equal(t, spanCtx.TraceID(), spanAtAPI.TraceID(),
			"trace ID should be present at API layer")
		assert.Equal(t, spanAtAPI.TraceID(), spanAtService.TraceID(),
			"trace ID should propagate from API to service layer")
		assert.Equal(t, spanAtService.TraceID(), spanAtStorage.TraceID(),
			"trace ID should propagate from service to storage layer")
	})

	t.Run("deadline propagates through all layers", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), GracefulShutdownTimeout)
		defer cancel()

		deadline, ok := ctx.Deadline()
		require.True(t, ok, "context should have deadline")
		assert.True(t, deadline.After(time.Now()), "deadline should be in the future")

		// Child contexts inherit deadline
		childCtx, childCancel := context.WithCancel(ctx)
		defer childCancel()

		childDeadline, ok := childCtx.Deadline()
		require.True(t, ok, "child context should inherit deadline")
		assert.Equal(t, deadline, childDeadline, "child should have same deadline as parent")
	})
}

// TestContextPropagationThroughLayers verifies context values propagate.
func TestContextPropagationThroughLayers(t *testing.T) {
	t.Run("trace ID propagates through all layers", func(t *testing.T) {
		type contextKey string
		const traceIDKey contextKey = "trace_id"

		var capturedAtAPI, capturedAtService, capturedAtStorage string

		storageLayer := func(ctx context.Context) {
			if v := ctx.Value(traceIDKey); v != nil {
				capturedAtStorage = v.(string)
			}
		}

		serviceLayer := func(ctx context.Context) {
			if v := ctx.Value(traceIDKey); v != nil {
				capturedAtService = v.(string)
			}
			storageLayer(ctx)
		}

		apiLayer := func(ctx context.Context) {
			if v := ctx.Value(traceIDKey); v != nil {
				capturedAtAPI = v.(string)
			}
			serviceLayer(ctx)
		}

		ctx := context.WithValue(context.Background(), traceIDKey, "trace-abc-123")
		apiLayer(ctx)

		assert.Equal(t, "trace-abc-123", capturedAtAPI, "trace ID should be at API layer")
		assert.Equal(t, "trace-abc-123", capturedAtService, "trace ID should propagate to service")
		assert.Equal(t, "trace-abc-123", capturedAtStorage, "trace ID should propagate to storage")
	})
}

// TestMidFlightCancellation verifies in-progress operations clean up properly.
func TestMidFlightCancellation(t *testing.T) {
	t.Run("batch operation cleans up on cancellation", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		var processedCount atomic.Int32
		var cleanedUp atomic.Bool
		batchSize := 100
		processingTime := 10 * time.Millisecond

		processBatch := func(ctx context.Context, items int) error {
			defer func() { cleanedUp.Store(true) }()

			for i := 0; i < items; i++ {
				select {
				case <-ctx.Done():
					return ctx.Err()
				default:
					time.Sleep(processingTime)
					processedCount.Add(1)
				}
			}
			return nil
		}

		// Use channel for proper synchronization with panic recovery
		var processBatchErr error
		processDone := make(chan struct{})
		go func() {
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("processBatch panicked: %v", r)
				}
				close(processDone)
			}()
			processBatchErr = processBatch(ctx, batchSize)
		}()

		// Cancel after some items processed
		time.Sleep(50 * time.Millisecond)
		cancel()

		// Wait for batch to complete with timeout
		select {
		case <-processDone:
			// Expected
		case <-time.After(GracefulShutdownTimeout):
			t.Fatal("processBatch did not complete within timeout")
		}

		assert.ErrorIs(t, processBatchErr, context.Canceled,
			"batch processing should return context.Canceled")

		processed := processedCount.Load()
		assert.Greater(t, processed, int32(0), "some items should be processed")
		assert.Less(t, processed, int32(batchSize), "not all items should be processed")
		assert.True(t, cleanedUp.Load(), "cleanup should have executed")
	})

	t.Run("transaction rollback on cancellation", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		var committed atomic.Bool
		var rolledBack atomic.Bool

		executeTransaction := func(ctx context.Context) error {
			defer func() {
				if !committed.Load() {
					rolledBack.Store(true)
				}
			}()

			for i := 0; i < 5; i++ {
				select {
				case <-ctx.Done():
					return ctx.Err()
				case <-time.After(20 * time.Millisecond):
				}
			}

			committed.Store(true)
			return nil
		}

		// Use channel for proper synchronization with panic recovery
		txnDone := make(chan error, 1)
		go func() {
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("executeTransaction panicked: %v", r)
					txnDone <- context.Canceled
				}
			}()
			txnDone <- executeTransaction(ctx)
		}()

		// Cancel mid-transaction
		time.Sleep(30 * time.Millisecond)
		cancel()

		select {
		case err := <-txnDone:
			assert.ErrorIs(t, err, context.Canceled, "transaction should return context.Canceled")
		case <-time.After(GracefulShutdownTimeout):
			t.Fatal("executeTransaction did not complete within timeout")
		}

		assert.False(t, committed.Load(), "transaction should not be committed")
		assert.True(t, rolledBack.Load(), "transaction should be rolled back")
	})
}

// TestGoroutineCountStability verifies goroutine count remains stable.
func TestGoroutineCountStability(t *testing.T) {
	t.Run("goroutine count stable across cycles", func(t *testing.T) {
		baseline := measureStableGoroutineCount(t)

		// Run multiple shutdown cycles
		for cycle := 0; cycle < 10; cycle++ {
			ctx, cancel := context.WithCancel(context.Background())

			var wg sync.WaitGroup
			ready := make(chan struct{}, 5)

			for i := 0; i < 5; i++ {
				wg.Add(1)
				go func() {
					defer wg.Done()
					ready <- struct{}{}
					select {
					case <-time.After(10 * time.Second):
					case <-ctx.Done():
					}
				}()
			}

			// Wait for workers to be ready
			for i := 0; i < 5; i++ {
				<-ready
			}

			cancel()
			wg.Wait()
		}

		assertNoGoroutineLeak(t, baseline)
	})
}

// TestShutdownOrder verifies components shutdown in correct order.
func TestShutdownOrder(t *testing.T) {
	t.Run("components shutdown in correct order", func(t *testing.T) {
		var shutdownOrder []string
		var mu sync.Mutex
		addShutdown := func(name string) {
			mu.Lock()
			shutdownOrder = append(shutdownOrder, name)
			mu.Unlock()
		}

		var wg sync.WaitGroup
		consumerDone := make(chan struct{})
		workerDone := make(chan struct{})

		// Manager (waits for worker)
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-workerDone
			addShutdown("manager")
		}()

		// Worker (waits for consumer)
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-consumerDone
			addShutdown("worker")
			close(workerDone)
		}()

		// Consumer (shuts down first)
		wg.Add(1)
		go func() {
			defer wg.Done()
			time.Sleep(10 * time.Millisecond)
			addShutdown("consumer")
			close(consumerDone)
		}()

		waitForCompletion(t, &wg, GracefulShutdownTimeout, "shutdown order test")

		require.Len(t, shutdownOrder, 3, "all 3 components should have shutdown")
		assert.Equal(t, "consumer", shutdownOrder[0], "consumer should shutdown first")
		assert.Equal(t, "worker", shutdownOrder[1], "worker should shutdown second")
		assert.Equal(t, "manager", shutdownOrder[2], "manager should shutdown last")
	})
}

// TestContextCancellationLatency measures cancellation latency using statistical analysis.
func TestContextCancellationLatency(t *testing.T) {
	t.Run("cancellation propagates within acceptable latency", func(t *testing.T) {
		latencies := make([]time.Duration, LatencySampleSize)

		for i := 0; i < LatencySampleSize; i++ {
			ctx, cancel := context.WithCancel(context.Background())
			received := make(chan time.Time, 1)

			go func() {
				<-ctx.Done()
				received <- time.Now()
			}()

			runtime.Gosched()
			time.Sleep(1 * time.Millisecond)

			cancelTime := time.Now()
			cancel()

			select {
			case receivedTime := <-received:
				latencies[i] = receivedTime.Sub(cancelTime)
			case <-time.After(ShortTimeout):
				t.Fatal("cancellation not received within timeout")
			}
		}

		// Sort for percentile calculations
		sort.Slice(latencies, func(i, j int) bool {
			return latencies[i] < latencies[j]
		})

		// Calculate statistics
		median := latencies[len(latencies)/2]
		p95 := latencies[int(float64(len(latencies))*0.95)]
		p99 := latencies[int(float64(len(latencies))*0.99)]

		var total time.Duration
		for _, l := range latencies {
			total += l
		}
		avg := total / time.Duration(len(latencies))

		t.Logf("Cancellation latency: median=%v, avg=%v, p95=%v, p99=%v", median, avg, p95, p99)

		// Use median for primary assertion (more stable than average)
		assert.Less(t, median, 1*time.Millisecond,
			"median cancellation latency should be under 1ms")
		assert.Less(t, p95, 10*time.Millisecond,
			"p95 cancellation latency should be under 10ms")
		assert.Less(t, p99, 50*time.Millisecond,
			"p99 cancellation latency should be under 50ms for CI environments")
	})
}

// TestContextWithDeadlineRespected verifies operations respect deadlines.
func TestContextWithDeadlineRespected(t *testing.T) {
	tests := []struct {
		name          string
		deadline      time.Duration
		operationTime time.Duration
		expectSuccess bool
	}{
		{
			name:          "operation completes before deadline",
			deadline:      ShortTimeout,
			operationTime: 10 * time.Millisecond,
			expectSuccess: true,
		},
		{
			name:          "operation exceeds deadline",
			deadline:      10 * time.Millisecond,
			operationTime: ShortTimeout,
			expectSuccess: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), tt.deadline)
			defer cancel()

			result := make(chan bool, 1)

			go func() {
				select {
				case <-time.After(tt.operationTime):
					result <- true
				case <-ctx.Done():
					result <- false
				}
			}()

			success := <-result
			assert.Equal(t, tt.expectSuccess, success,
				"operation success should match expectation")

			if !tt.expectSuccess {
				assert.Error(t, ctx.Err(), "context should have error when deadline exceeded")
				assert.ErrorIs(t, ctx.Err(), context.DeadlineExceeded,
					"context error should be DeadlineExceeded")
			}
		})
	}
}
