package core

import (
	"context"
	"runtime"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

// TestWorkerPool_ContextCancellationStopsWorkers verifies that cancelling parent context
// stops all worker goroutines
// TASK 144.4: Context propagation enables graceful shutdown via parent cancellation
func TestWorkerPool_ContextCancellationStopsWorkers(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	logger := zap.NewNop().Sugar()

	wp := NewWorkerPoolWithContext(ctx, 4, 100, "test-pool", logger)
	require.NotNil(t, wp)

	// Start workers
	err := wp.Start()
	require.NoError(t, err)

	// Give workers time to start
	time.Sleep(100 * time.Millisecond)

	before := runtime.NumGoroutine()

	// Cancel parent context
	cancel()

	// Wait for workers to exit
	time.Sleep(300 * time.Millisecond)

	after := runtime.NumGoroutine()

	// All worker goroutines should exit
	require.LessOrEqual(t, after, before-3, "At least 3 worker goroutines should exit (4 workers started)")
}

// TestWorkerPool_StopStillWorks verifies Stop() method still works correctly
// TASK 144.4: Backwards compatibility - Stop() should still work
func TestWorkerPool_StopStillWorks(t *testing.T) {
	ctx := context.Background()
	logger := zap.NewNop().Sugar()

	wp := NewWorkerPoolWithContext(ctx, 4, 100, "test-pool", logger)
	require.NotNil(t, wp)

	err := wp.Start()
	require.NoError(t, err)

	time.Sleep(100 * time.Millisecond)
	before := runtime.NumGoroutine()

	// Call Stop()
	wp.Stop()

	time.Sleep(200 * time.Millisecond)
	after := runtime.NumGoroutine()

	require.LessOrEqual(t, after, before-3, "Worker goroutines should exit after Stop()")
}

// TestWorkerPool_BackwardsCompatibility verifies old constructors still work
// TASK 144.4: Existing code should continue to work
func TestWorkerPool_BackwardsCompatibility(t *testing.T) {
	logger := zap.NewNop().Sugar()

	// Old patterns - no context parameter
	wp1 := NewWorkerPool(4, 100, logger)
	require.NotNil(t, wp1)

	wp2 := NewWorkerPoolWithType(4, 100, "custom-pool", logger)
	require.NotNil(t, wp2)

	// Start both
	require.NoError(t, wp1.Start())
	require.NoError(t, wp2.Start())

	defer wp1.Stop()
	defer wp2.Stop()

	time.Sleep(100 * time.Millisecond)

	// Both should work
	stats1 := wp1.GetStats()
	require.True(t, stats1.Running)
	require.Equal(t, 4, stats1.Workers)

	stats2 := wp2.GetStats()
	require.True(t, stats2.Running)
	require.Equal(t, 4, stats2.Workers)
}

// TestWorkerPool_MultipleStopCallsSafe verifies Stop() is idempotent
// TASK 144.4: Stop() should be safe to call multiple times
func TestWorkerPool_MultipleStopCallsSafe(t *testing.T) {
	ctx := context.Background()
	logger := zap.NewNop().Sugar()

	wp := NewWorkerPoolWithContext(ctx, 4, 100, "test-pool", logger)
	require.NotNil(t, wp)

	err := wp.Start()
	require.NoError(t, err)

	time.Sleep(100 * time.Millisecond)

	// Multiple Stop() calls should not panic
	wp.Stop()
	wp.Stop()
	wp.Stop()

	time.Sleep(100 * time.Millisecond)
}

// TestWorkerPool_ContextAndStopBothWork verifies both methods work together
// TASK 144.4: Context cancellation and Stop() should both work
func TestWorkerPool_ContextAndStopBothWork(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	logger := zap.NewNop().Sugar()

	wp := NewWorkerPoolWithContext(ctx, 4, 100, "test-pool", logger)
	require.NotNil(t, wp)

	err := wp.Start()
	require.NoError(t, err)

	time.Sleep(100 * time.Millisecond)

	// Cancel context first
	cancel()
	time.Sleep(100 * time.Millisecond)

	// Then call Stop() - should be safe
	wp.Stop()

	time.Sleep(100 * time.Millisecond)
}

// TestWorkerPool_ContextTimeoutPropagates verifies context timeout stops workers
// TASK 144.4: Context timeout should propagate to workers
func TestWorkerPool_ContextTimeoutPropagates(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	logger := zap.NewNop().Sugar()

	wp := NewWorkerPoolWithContext(ctx, 4, 100, "test-pool", logger)
	require.NotNil(t, wp)

	err := wp.Start()
	require.NoError(t, err)

	time.Sleep(100 * time.Millisecond)
	before := runtime.NumGoroutine()

	// Wait for context timeout
	time.Sleep(250 * time.Millisecond)

	after := runtime.NumGoroutine()

	require.LessOrEqual(t, after, before-3, "Workers should exit after context timeout")
}

// TestWorkerPool_TasksProcessedBeforeShutdown verifies that in-flight tasks
// complete before workers exit
// TASK 144.4: Graceful shutdown should complete in-flight tasks
func TestWorkerPool_TasksProcessedBeforeShutdown(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	logger := zap.NewNop().Sugar()

	wp := NewWorkerPoolWithContext(ctx, 2, 10, "test-pool", logger)
	require.NotNil(t, wp)

	err := wp.Start()
	require.NoError(t, err)
	defer wp.Stop()

	var completed atomic.Int32

	// Submit tasks
	for i := 0; i < 5; i++ {
		err := wp.Submit(func() {
			time.Sleep(50 * time.Millisecond)
			completed.Add(1)
		})
		require.NoError(t, err)
	}

	// Give tasks time to be picked up
	time.Sleep(100 * time.Millisecond)

	// Cancel context
	cancel()

	// Stop and wait for workers
	wp.Stop()

	// At least some tasks should have completed
	// (Workers process tasks already picked up before exiting)
	count := completed.Load()
	require.Greater(t, count, int32(0), "Some tasks should complete before shutdown")
}

// TestWorkerPool_WorkersExitOnChannelClose verifies workers exit when channel closes
// TASK 144.4: Workers should respect both context and channel closure
func TestWorkerPool_WorkersExitOnChannelClose(t *testing.T) {
	ctx := context.Background()
	logger := zap.NewNop().Sugar()

	wp := NewWorkerPoolWithContext(ctx, 4, 100, "test-pool", logger)
	require.NotNil(t, wp)

	err := wp.Start()
	require.NoError(t, err)

	time.Sleep(100 * time.Millisecond)
	before := runtime.NumGoroutine()

	// Stop closes the channel
	wp.Stop()

	time.Sleep(200 * time.Millisecond)
	after := runtime.NumGoroutine()

	// Workers should exit
	require.LessOrEqual(t, after, before-3, "Workers should exit after channel close")
}

// TestWorkerPool_SubmitAfterContextCancelled verifies Submit fails after cancellation
// TASK 144.4: Submit should fail gracefully after shutdown
func TestWorkerPool_SubmitAfterContextCancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	logger := zap.NewNop().Sugar()

	wp := NewWorkerPoolWithContext(ctx, 2, 10, "test-pool", logger)
	require.NotNil(t, wp)

	err := wp.Start()
	require.NoError(t, err)

	time.Sleep(100 * time.Millisecond)

	// Cancel and stop
	cancel()
	wp.Stop()

	time.Sleep(100 * time.Millisecond)

	// Submit should fail
	err = wp.Submit(func() {
		t.Error("Task should not execute after shutdown")
	})
	require.Error(t, err)
	require.Equal(t, ErrWorkerPoolNotRunning, err)
}

// TestWorkerPool_PanicRecoveryWithContext verifies panic recovery works with context
// TASK 144.4: Worker panic should not crash pool and should respect context
func TestWorkerPool_PanicRecoveryWithContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	logger := zap.NewNop().Sugar()

	wp := NewWorkerPoolWithContext(ctx, 2, 10, "test-pool", logger)
	require.NotNil(t, wp)

	err := wp.Start()
	require.NoError(t, err)
	defer wp.Stop()

	var completed atomic.Int32

	// Submit task that panics
	err = wp.Submit(func() {
		panic("test panic")
	})
	require.NoError(t, err)

	// Submit normal task
	err = wp.Submit(func() {
		completed.Add(1)
	})
	require.NoError(t, err)

	// Wait for tasks
	time.Sleep(200 * time.Millisecond)

	// Normal task should complete despite panic in other task
	require.Equal(t, int32(1), completed.Load(), "Normal task should complete")

	// Cancel context - workers should still exit gracefully
	cancel()
	time.Sleep(200 * time.Millisecond)
}

// TestWorkerPool_MetricsWithContext verifies metrics work with context lifecycle
// TASK 144.4: Metrics should reflect context-aware lifecycle
func TestWorkerPool_MetricsWithContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	logger := zap.NewNop().Sugar()

	wp := NewWorkerPoolWithContext(ctx, 4, 100, "metrics-test", logger)
	require.NotNil(t, wp)

	err := wp.Start()
	require.NoError(t, err)

	stats := wp.GetStats()
	require.True(t, stats.Running)
	require.Equal(t, 4, stats.Workers)
	require.Equal(t, 100, stats.Capacity)

	// Submit some tasks
	for i := 0; i < 5; i++ {
		err := wp.Submit(func() {
			time.Sleep(10 * time.Millisecond)
		})
		require.NoError(t, err)
	}

	time.Sleep(50 * time.Millisecond)

	// Stop
	wp.Stop()

	// After stop, running should be false
	stats = wp.GetStats()
	require.False(t, stats.Running)
}
