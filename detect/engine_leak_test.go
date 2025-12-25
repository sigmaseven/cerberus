package detect

import (
	"runtime"
	"testing"
	"time"

	"cerberus/core"
)

// TestRuleEngineGoroutineLeak verifies that RuleEngine.Stop() doesn't leak goroutines
// BLOCKING-6: Goroutine leak detection test for RuleEngine cleanup goroutine
func TestRuleEngineGoroutineLeak(t *testing.T) {
	runtime.GC()
	time.Sleep(100 * time.Millisecond)
	initialGoroutines := runtime.NumGoroutine()

	// Create rule engine (starts cleanup goroutine)
	engine := NewRuleEngine([]core.Rule{}, []core.CorrelationRule{}, 60)

	// Allow cleanup goroutine to start
	time.Sleep(200 * time.Millisecond)

	// Stop engine
	engine.Stop()

	// Force GC and wait for goroutines to terminate
	runtime.GC()
	time.Sleep(500 * time.Millisecond)

	finalGoroutines := runtime.NumGoroutine()

	// BLOCKING-4 FIX: RuleEngine cleanup goroutine now has proper panic recovery and timeout
	if finalGoroutines > initialGoroutines+5 {
		t.Errorf("Goroutine leak detected: initial=%d, final=%d, leaked=%d",
			initialGoroutines, finalGoroutines, finalGoroutines-initialGoroutines)
	} else {
		t.Logf("No goroutine leak detected: initial=%d, final=%d", initialGoroutines, finalGoroutines)
	}
}

// TestRuleEngineGoroutineLeakWithActivity verifies no leaks with active correlation state
// BLOCKING-6: Test cleanup goroutine under load
func TestRuleEngineGoroutineLeakWithActivity(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping load test in short mode")
	}

	runtime.GC()
	time.Sleep(100 * time.Millisecond)
	initialGoroutines := runtime.NumGoroutine()

	// Create correlation rule
	rule := core.CorrelationRule{
		ID:       "test-correlation",
		Name:     "Test Correlation",
		Sequence: []string{"event1", "event2"},
		Window:   10 * time.Second,
	}

	engine := NewRuleEngine([]core.Rule{}, []core.CorrelationRule{rule}, 5)

	// Create events to populate correlation state
	for i := 0; i < 100; i++ {
		event := &core.Event{
			EventID:   "test-event",
			Timestamp: time.Now(),
			EventType: "event1",
			Fields:    map[string]interface{}{},
		}
		engine.EvaluateCorrelation(event)
		time.Sleep(10 * time.Millisecond)
	}

	// Let cleanup goroutine run a few times
	time.Sleep(2 * time.Second)

	// Stop engine
	engine.Stop()

	runtime.GC()
	time.Sleep(500 * time.Millisecond)

	finalGoroutines := runtime.NumGoroutine()
	if finalGoroutines > initialGoroutines+5 {
		t.Errorf("Goroutine leak with activity: initial=%d, final=%d, leaked=%d",
			initialGoroutines, finalGoroutines, finalGoroutines-initialGoroutines)
	} else {
		t.Logf("No goroutine leak with activity: initial=%d, final=%d", initialGoroutines, finalGoroutines)
	}
}

// TestRuleEngineMultipleStop tests multiple Stop() calls
// BLOCKING-6: Ensure Stop() is idempotent
func TestRuleEngineMultipleStop(t *testing.T) {
	runtime.GC()
	time.Sleep(100 * time.Millisecond)
	initialGoroutines := runtime.NumGoroutine()

	engine := NewRuleEngine([]core.Rule{}, []core.CorrelationRule{}, 60)
	time.Sleep(200 * time.Millisecond)

	// Call Stop() multiple times
	engine.Stop()
	engine.Stop() // Should be safe to call multiple times
	engine.Stop()

	runtime.GC()
	time.Sleep(500 * time.Millisecond)

	finalGoroutines := runtime.NumGoroutine()
	if finalGoroutines > initialGoroutines+5 {
		t.Errorf("Goroutine leak after multiple stops: initial=%d, final=%d, leaked=%d",
			initialGoroutines, finalGoroutines, finalGoroutines-initialGoroutines)
	} else {
		t.Logf("No goroutine leak after multiple stops: initial=%d, final=%d", initialGoroutines, finalGoroutines)
	}
}
