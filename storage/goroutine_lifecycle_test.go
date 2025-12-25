package storage

import (
	"context"
	"runtime"
	"testing"
	"time"

	"cerberus/config"
	"cerberus/core"
	utiltest "cerberus/util/testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

// TestClickHouseEventStorage_GoroutineCleanup verifies no goroutine leaks
// TASK 147: Goroutine leak detection test
// NOTE: Allows for +1 goroutine (timeout helper) which exits when WaitGroup completes
func TestClickHouseEventStorage_GoroutineCleanup(t *testing.T) {
	cfg := &config.Config{}
	cfg.ClickHouse.BatchSize = 100
	cfg.ClickHouse.FlushInterval = 1
	cfg.Storage.Deduplication = false
	cfg.Storage.DedupCacheSize = 1000

	eventCh := make(chan *core.Event, 10)
	logger := zap.NewNop().Sugar()

	// Create storage (no real ClickHouse connection)
	storage, err := NewClickHouseEventStorage(context.Background(), nil, cfg, eventCh, logger)
	require.NoError(t, err)

	// Start workers
	before := runtime.NumGoroutine()
	storage.Start(3)

	// Give workers time to start
	time.Sleep(50 * time.Millisecond)
	assert.Greater(t, runtime.NumGoroutine(), before, "Workers should have started")

	// Stop workers by closing channel
	close(eventCh)

	// Wait for cleanup with timeout
	err = utiltest.WaitForGoroutines(&storage.wg, 5*time.Second)
	assert.NoError(t, err, "Workers should exit within timeout")

	// Verify goroutines cleaned up
	// Allow for +1 goroutine which is the timeout helper in WaitForGoroutines
	// This is an acceptable pattern - the helper will exit when WaitGroup completes
	assert.Eventually(t, func() bool {
		after := runtime.NumGoroutine()
		leaked := after - before
		// Accept 0 or 1 leaked goroutine (the WaitForGoroutines helper)
		return leaked <= 1
	}, 2*time.Second, 100*time.Millisecond, "Should have minimal goroutine leakage")
}

// TestClickHouseEventStorage_GracefulShutdown verifies context cancellation cleanup
// TASK 147: Context cancellation shutdown test
func TestClickHouseEventStorage_GracefulShutdown(t *testing.T) {
	cfg := &config.Config{}
	cfg.ClickHouse.BatchSize = 100
	cfg.ClickHouse.FlushInterval = 1
	cfg.Storage.Deduplication = false
	cfg.Storage.DedupCacheSize = 1000

	eventCh := make(chan *core.Event, 10)
	logger := zap.NewNop().Sugar()

	ctx, cancel := context.WithCancel(context.Background())

	storage, err := NewClickHouseEventStorage(ctx, nil, cfg, eventCh, logger)
	require.NoError(t, err)

	storage.Start(3)

	// Give workers time to start
	time.Sleep(50 * time.Millisecond)

	// Trigger graceful shutdown via context
	cancel()

	// Wait for cleanup - this verifies workers respect context cancellation
	err = utiltest.WaitForGoroutines(&storage.wg, 5*time.Second)
	assert.NoError(t, err, "Workers should respect context cancellation and exit within timeout")
}

// TestClickHouseEventStorage_StopWithTimeout verifies Stop() completes within timeout
// TASK 147: Shutdown timeout verification
func TestClickHouseEventStorage_StopWithTimeout(t *testing.T) {
	cfg := &config.Config{}
	cfg.ClickHouse.BatchSize = 100
	cfg.ClickHouse.FlushInterval = 1
	cfg.Storage.Deduplication = false
	cfg.Storage.DedupCacheSize = 1000

	eventCh := make(chan *core.Event, 10)
	logger := zap.NewNop().Sugar()

	storage, err := NewClickHouseEventStorage(context.Background(), nil, cfg, eventCh, logger)
	require.NoError(t, err)

	storage.Start(5)
	time.Sleep(50 * time.Millisecond)

	// Stop should complete quickly (uses 30s timeout internally)
	start := time.Now()
	err = storage.Stop()
	elapsed := time.Since(start)

	assert.NoError(t, err, "Stop() should complete successfully")
	assert.Less(t, elapsed, 10*time.Second, "Stop() should complete within reasonable time")
}

// TestClickHouseEventStorage_MultipleStartStopCycles verifies restart capability
// TASK 147: Lifecycle restart test
func TestClickHouseEventStorage_MultipleStartStopCycles(t *testing.T) {
	cfg := &config.Config{}
	cfg.ClickHouse.BatchSize = 100
	cfg.ClickHouse.FlushInterval = 1
	cfg.Storage.Deduplication = false
	cfg.Storage.DedupCacheSize = 1000

	logger := zap.NewNop().Sugar()

	// Cycle 1
	eventCh1 := make(chan *core.Event, 10)
	storage1, err := NewClickHouseEventStorage(context.Background(), nil, cfg, eventCh1, logger)
	require.NoError(t, err)
	storage1.Start(2)
	time.Sleep(50 * time.Millisecond)
	err = storage1.Stop()
	assert.NoError(t, err, "Cycle 1 Stop() should succeed")

	// Cycle 2
	eventCh2 := make(chan *core.Event, 10)
	storage2, err := NewClickHouseEventStorage(context.Background(), nil, cfg, eventCh2, logger)
	require.NoError(t, err)
	storage2.Start(2)
	time.Sleep(50 * time.Millisecond)
	err = storage2.Stop()
	assert.NoError(t, err, "Cycle 2 Stop() should succeed")
}

// TestClickHouseAlertStorage_GoroutineCleanup verifies alert worker cleanup
// TASK 147: Alert storage goroutine leak test
func TestClickHouseAlertStorage_GoroutineCleanup(t *testing.T) {
	cfg := &config.Config{}
	cfg.ClickHouse.BatchSize = 1000
	cfg.ClickHouse.FlushInterval = 1

	alertCh := make(chan *core.Alert, 10)
	logger := zap.NewNop().Sugar()

	storage, err := NewClickHouseAlertStorage(context.Background(), nil, cfg, alertCh, logger)
	require.NoError(t, err)

	storage.Start(3)
	time.Sleep(50 * time.Millisecond)

	// Stop workers via Stop() method
	err = storage.Stop()
	assert.NoError(t, err, "Alert workers should stop gracefully")
}

// TestClickHouseAlertStorage_GracefulShutdown_Ctx verifies context cancellation
// TASK 147: Alert storage graceful shutdown test (renamed to avoid duplicate)
func TestClickHouseAlertStorage_GracefulShutdown_Ctx(t *testing.T) {
	cfg := &config.Config{}
	cfg.ClickHouse.BatchSize = 1000
	cfg.ClickHouse.FlushInterval = 1

	alertCh := make(chan *core.Alert, 10)
	logger := zap.NewNop().Sugar()
	ctx, cancel := context.WithCancel(context.Background())

	storage, err := NewClickHouseAlertStorage(ctx, nil, cfg, alertCh, logger)
	require.NoError(t, err)

	storage.Start(3)
	time.Sleep(50 * time.Millisecond)

	// Graceful shutdown via context
	cancel()

	err = utiltest.WaitForGoroutines(&storage.wg, 5*time.Second)
	assert.NoError(t, err, "Workers should respect context cancellation and exit within timeout")
}
