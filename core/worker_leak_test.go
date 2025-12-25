package core

import (
	"runtime"
	"testing"
	"time"

	"go.uber.org/zap"
)

// TestWorkerPoolGoroutineLeak verifies that WorkerPool.Stop() doesn't leak goroutines
// BLOCKING-6: Goroutine leak detection test for WorkerPool
func TestWorkerPoolGoroutineLeak(t *testing.T) {
	runtime.GC()
	time.Sleep(100 * time.Millisecond)
	initialGoroutines := runtime.NumGoroutine()

	logger, _ := zap.NewDevelopment()
	sugar := logger.Sugar()
	defer logger.Sync()

	// Create worker pool
	pool := NewWorkerPoolWithType(4, 10, "test-pool", sugar)

	// Start pool (launches worker goroutines)
	if err := pool.Start(); err != nil {
		t.Fatalf("Failed to start worker pool: %v", err)
	}

	// Allow workers to start
	time.Sleep(200 * time.Millisecond)

	// Stop pool
	pool.Stop()

	// Force GC and wait for goroutines to terminate
	runtime.GC()
	time.Sleep(500 * time.Millisecond)

	finalGoroutines := runtime.NumGoroutine()

	// BLOCKING-2 FIX: WorkerPool.Stop() now has timeout, so goroutines should not leak
	if finalGoroutines > initialGoroutines+5 {
		t.Errorf("Goroutine leak detected: initial=%d, final=%d, leaked=%d",
			initialGoroutines, finalGoroutines, finalGoroutines-initialGoroutines)
	} else {
		t.Logf("No goroutine leak detected: initial=%d, final=%d", initialGoroutines, finalGoroutines)
	}
}

// TestWorkerPoolGoroutineLeakWithTasks verifies no leaks when tasks are submitted
// BLOCKING-6: Load test for WorkerPool goroutine leak detection
func TestWorkerPoolGoroutineLeakWithTasks(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping load test in short mode")
	}

	runtime.GC()
	time.Sleep(100 * time.Millisecond)
	initialGoroutines := runtime.NumGoroutine()

	logger, _ := zap.NewDevelopment()
	sugar := logger.Sugar()
	defer logger.Sync()

	pool := NewWorkerPoolWithType(8, 100, "test-pool-load", sugar)

	if err := pool.Start(); err != nil {
		t.Fatalf("Failed to start worker pool: %v", err)
	}

	// Submit many tasks
	taskCount := 1000
	completed := make(chan struct{}, taskCount)
	for i := 0; i < taskCount; i++ {
		err := pool.Submit(func() {
			time.Sleep(1 * time.Millisecond) // Simulate work
			completed <- struct{}{}
		})
		if err != nil {
			t.Logf("Warning: task submission failed: %v", err)
		}
	}

	// Wait for tasks to complete (with timeout)
	timeout := time.After(10 * time.Second)
	completedCount := 0
	for completedCount < taskCount {
		select {
		case <-completed:
			completedCount++
		case <-timeout:
			t.Logf("Timeout waiting for tasks: completed=%d/%d", completedCount, taskCount)
			goto stopPool
		}
	}

stopPool:
	pool.Stop()

	runtime.GC()
	time.Sleep(500 * time.Millisecond)

	finalGoroutines := runtime.NumGoroutine()
	if finalGoroutines > initialGoroutines+5 {
		t.Errorf("Goroutine leak with tasks: initial=%d, final=%d, leaked=%d",
			initialGoroutines, finalGoroutines, finalGoroutines-initialGoroutines)
	} else {
		t.Logf("No goroutine leak with tasks: initial=%d, final=%d, completed=%d/%d",
			initialGoroutines, finalGoroutines, completedCount, taskCount)
	}
}

// TestWorkerPoolMultipleStartStop tests multiple start/stop cycles
// BLOCKING-6: Ensure Start/Stop can be called multiple times without leaks
func TestWorkerPoolMultipleStartStop(t *testing.T) {
	runtime.GC()
	time.Sleep(100 * time.Millisecond)
	initialGoroutines := runtime.NumGoroutine()

	logger, _ := zap.NewDevelopment()
	sugar := logger.Sugar()
	defer logger.Sync()

	for cycle := 0; cycle < 5; cycle++ {
		pool := NewWorkerPoolWithType(2, 5, "test-pool-cycle", sugar)

		if err := pool.Start(); err != nil {
			t.Fatalf("Cycle %d: Failed to start worker pool: %v", cycle, err)
		}

		// Submit some tasks
		for i := 0; i < 10; i++ {
			pool.Submit(func() {
				time.Sleep(10 * time.Millisecond)
			})
		}

		time.Sleep(100 * time.Millisecond)
		pool.Stop()
		time.Sleep(100 * time.Millisecond)
	}

	runtime.GC()
	time.Sleep(500 * time.Millisecond)

	finalGoroutines := runtime.NumGoroutine()
	if finalGoroutines > initialGoroutines+5 {
		t.Errorf("Goroutine leak after multiple cycles: initial=%d, final=%d, leaked=%d",
			initialGoroutines, finalGoroutines, finalGoroutines-initialGoroutines)
	} else {
		t.Logf("No goroutine leak after 5 start/stop cycles: initial=%d, final=%d", initialGoroutines, finalGoroutines)
	}
}
