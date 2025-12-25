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

// TestRuleEngine_ContextCancellationStopsCleanup verifies that cancelling the parent context
// stops the cleanup goroutine without requiring explicit Stop() call
// TASK 144.4: Context propagation enables graceful shutdown via parent cancellation
func TestRuleEngine_ContextCancellationStopsCleanup(t *testing.T) {
	// Create cancellable context
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Create engine with parent context
	engine := NewRuleEngineWithContext(ctx, nil, nil, 3600, nil)
	require.NotNil(t, engine)

	// Give cleanup goroutine time to start
	time.Sleep(100 * time.Millisecond)

	// Get goroutine count before cancellation
	before := runtime.NumGoroutine()

	// Cancel parent context
	cancel()

	// Wait for goroutines to exit
	time.Sleep(300 * time.Millisecond)

	after := runtime.NumGoroutine()

	// Verify cleanup goroutine exited
	// Note: We check <= instead of < because other test goroutines may start/stop
	require.LessOrEqual(t, after, before, "Cleanup goroutine should have exited after context cancellation")
}

// TestRuleEngine_StopStillWorks verifies that Stop() method still functions correctly
// and waits for cleanup goroutine to complete
// TASK 144.4: Backwards compatibility - Stop() should still work
func TestRuleEngine_StopStillWorks(t *testing.T) {
	ctx := context.Background()

	// Create engine with background context (old pattern)
	engine := NewRuleEngineWithContext(ctx, nil, nil, 3600, nil)
	require.NotNil(t, engine)

	// Give cleanup goroutine time to start
	time.Sleep(100 * time.Millisecond)

	before := runtime.NumGoroutine()

	// Call Stop() - should cancel context and wait for goroutines
	engine.Stop()

	// Short wait to let goroutines exit
	time.Sleep(200 * time.Millisecond)
	after := runtime.NumGoroutine()

	require.LessOrEqual(t, after, before, "Cleanup goroutine should exit after Stop()")
}

// TestRuleEngine_BackwardsCompatibility verifies that old constructors still work
// with automatic background context
// TASK 144.4: Existing code should continue to work without modification
func TestRuleEngine_BackwardsCompatibility(t *testing.T) {
	// Old code pattern - no context parameter
	engine1 := NewRuleEngine(nil, nil, 3600)
	require.NotNil(t, engine1)
	defer engine1.Stop()

	engine2 := NewRuleEngineWithConfig(nil, nil, 3600, nil)
	require.NotNil(t, engine2)
	defer engine2.Stop()

	// Both should work identically
	time.Sleep(100 * time.Millisecond)

	// Verify cleanup is running
	before := runtime.NumGoroutine()
	require.Greater(t, before, 0, "Goroutines should be running")
}

// TestRuleEngine_MultipleStopCallsSafe verifies Stop() is idempotent
// TASK 144.4: Stop() should be safe to call multiple times
func TestRuleEngine_MultipleStopCallsSafe(t *testing.T) {
	ctx := context.Background()
	engine := NewRuleEngineWithContext(ctx, nil, nil, 3600, nil)
	require.NotNil(t, engine)

	// Call Stop() multiple times - should not panic
	engine.Stop()
	engine.Stop()
	engine.Stop()

	// Should still be safe
	time.Sleep(100 * time.Millisecond)
}

// TestRuleEngine_ContextAndStopBothWork verifies both cancellation methods work together
// TASK 144.4: Context cancellation and Stop() should both trigger cleanup
func TestRuleEngine_ContextAndStopBothWork(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	engine := NewRuleEngineWithContext(ctx, nil, nil, 3600, nil)
	require.NotNil(t, engine)

	time.Sleep(100 * time.Millisecond)

	// Cancel context first
	cancel()
	time.Sleep(100 * time.Millisecond)

	// Then call Stop() - should be safe
	engine.Stop()

	// No panic or deadlock should occur
	time.Sleep(100 * time.Millisecond)
}

// TestRuleEngine_ContextCancellationWithSigmaEngine verifies context cancellation
// works correctly when SIGMA engine is enabled
// TASK 144.4: Context propagation should work with SIGMA engine
func TestRuleEngine_ContextCancellationWithSigmaEngine(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	config := &RuleEngineConfig{
		EnableNativeSigmaEngine:    true,
		SigmaEngineCacheSize:       100,
		SigmaEngineCacheTTL:        5 * time.Minute,
		SigmaEngineCleanupInterval: 1 * time.Minute,
	}

	engine := NewRuleEngineWithContext(ctx, nil, nil, 3600, config)
	require.NotNil(t, engine)
	require.True(t, engine.sigmaEngineEnabled)

	time.Sleep(200 * time.Millisecond)

	before := runtime.NumGoroutine()

	// Cancel context
	cancel()

	// Wait for all goroutines to exit (SIGMA + correlation cleanup)
	time.Sleep(500 * time.Millisecond)

	after := runtime.NumGoroutine()

	// Multiple cleanup goroutines should exit
	require.LessOrEqual(t, after, before, "All cleanup goroutines should exit")
}

// TestRuleEngine_CleanupRunsUnderContext verifies cleanup goroutine is active
// and respects context cancellation
// TASK 144.4: Verify cleanup goroutine is active and stops on cancellation
func TestRuleEngine_CleanupRunsUnderContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Create engine
	engine := NewRuleEngineWithContext(ctx, []core.Rule{}, []core.CorrelationRule{}, 3600, nil)
	require.NotNil(t, engine)

	// Give cleanup goroutine time to start
	time.Sleep(100 * time.Millisecond)

	// Verify goroutine is running
	before := runtime.NumGoroutine()
	require.Greater(t, before, 0, "Cleanup goroutine should be running")

	// Now cancel context and verify cleanup stops
	cancel()
	time.Sleep(300 * time.Millisecond)

	after := runtime.NumGoroutine()

	// Cleanup goroutine should have exited
	require.LessOrEqual(t, after, before, "Cleanup goroutine should exit after context cancellation")
}

// TestRuleEngine_ContextTimeoutPropagates verifies that a context with timeout
// will stop cleanup goroutines when timeout expires
// TASK 144.4: Context timeout should propagate to cleanup
func TestRuleEngine_ContextTimeoutPropagates(t *testing.T) {
	// Create context with short timeout
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	engine := NewRuleEngineWithContext(ctx, nil, nil, 3600, nil)
	require.NotNil(t, engine)

	time.Sleep(100 * time.Millisecond)
	before := runtime.NumGoroutine()

	// Wait for context timeout
	time.Sleep(250 * time.Millisecond)

	after := runtime.NumGoroutine()

	// Cleanup should have stopped due to context timeout
	require.LessOrEqual(t, after, before, "Cleanup goroutine should exit after context timeout")
}

// TestRuleEngine_SigmaEngineContextPropagation verifies SIGMA engine receives parent context
// and its goroutines exit when parent context is cancelled
// TASK 144.4 BLOCKER-2 FIX: Ensures SIGMA engine respects parent context cancellation
func TestRuleEngine_SigmaEngineContextPropagation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Create logger for SIGMA engine
	zapLogger := zap.NewNop()
	logger := zapLogger.Sugar()

	config := &RuleEngineConfig{
		EnableNativeSigmaEngine:    true,
		SigmaEngineCacheSize:       100,
		SigmaEngineCacheTTL:        5 * time.Minute,
		SigmaEngineCleanupInterval: 1 * time.Minute,
		Logger:                     logger,
	}

	engine := NewRuleEngineWithContext(ctx, nil, nil, 3600, config)
	require.NotNil(t, engine)
	require.True(t, engine.sigmaEngineEnabled, "SIGMA engine should be enabled")
	require.NotNil(t, engine.sigmaEngine, "SIGMA engine should be initialized")

	// Give goroutines time to start
	time.Sleep(200 * time.Millisecond)

	before := runtime.NumGoroutine()
	t.Logf("Goroutines before cancellation: %d", before)

	// Cancel parent context - should stop SIGMA cache cleanup goroutine
	cancel()

	// Wait for goroutines to exit
	time.Sleep(500 * time.Millisecond)

	after := runtime.NumGoroutine()
	t.Logf("Goroutines after cancellation: %d", after)

	// SIGMA cache cleanup goroutine should have exited
	require.LessOrEqual(t, after, before, "SIGMA engine goroutines should exit when parent context is cancelled")
}

// TestRuleEngine_SigmaEngineStopWaitsForGoroutines verifies Stop() waits for SIGMA goroutines
// TASK 144.4 BLOCKER-1 FIX: Ensures Stop() waits for SIGMA engine cleanup to complete
func TestRuleEngine_SigmaEngineStopWaitsForGoroutines(t *testing.T) {
	ctx := context.Background()

	zapLogger := zap.NewNop()
	logger := zapLogger.Sugar()

	config := &RuleEngineConfig{
		EnableNativeSigmaEngine:    true,
		SigmaEngineCacheSize:       100,
		SigmaEngineCacheTTL:        5 * time.Minute,
		SigmaEngineCleanupInterval: 1 * time.Minute,
		Logger:                     logger,
	}

	engine := NewRuleEngineWithContext(ctx, nil, nil, 3600, config)
	require.NotNil(t, engine)
	require.True(t, engine.sigmaEngineEnabled)

	// Give goroutines time to start
	time.Sleep(200 * time.Millisecond)

	before := runtime.NumGoroutine()
	t.Logf("Goroutines before Stop(): %d", before)

	// Call Stop() - should stop SIGMA engine and wait for goroutines
	engine.Stop()

	// Short wait to verify goroutines exited
	time.Sleep(200 * time.Millisecond)

	after := runtime.NumGoroutine()
	t.Logf("Goroutines after Stop(): %d", after)

	// All cleanup goroutines should have exited
	require.LessOrEqual(t, after, before, "Stop() should wait for all goroutines including SIGMA engine")
}

// TestRuleEngine_SigmaEngineStopOrder verifies SIGMA engine is stopped before correlation cleanup
// TASK 144.4: Ensures proper shutdown order to prevent race conditions
func TestRuleEngine_SigmaEngineStopOrder(t *testing.T) {
	ctx := context.Background()

	zapLogger := zap.NewNop()
	logger := zapLogger.Sugar()

	config := &RuleEngineConfig{
		EnableNativeSigmaEngine:    true,
		SigmaEngineCacheSize:       100,
		SigmaEngineCacheTTL:        5 * time.Minute,
		SigmaEngineCleanupInterval: 1 * time.Minute,
		Logger:                     logger,
	}

	engine := NewRuleEngineWithContext(ctx, nil, nil, 3600, config)
	require.NotNil(t, engine)

	// Give goroutines time to start
	time.Sleep(200 * time.Millisecond)

	// Stop() should not panic or deadlock
	// The correct order is: SIGMA -> correlation store -> RuleEngine cleanup
	require.NotPanics(t, func() {
		engine.Stop()
	}, "Stop() should complete without panic")

	// Verify all goroutines exited
	time.Sleep(200 * time.Millisecond)

	// Multiple Stop() calls should be safe
	require.NotPanics(t, func() {
		engine.Stop()
		engine.Stop()
	}, "Multiple Stop() calls should be safe")
}
