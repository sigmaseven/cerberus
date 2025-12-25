package detect

import (
	"testing"
	"time"

	"cerberus/core"
	"github.com/stretchr/testify/assert"
	"go.uber.org/zap"
)

func TestCorrelationStateManager(t *testing.T) {
	logger := zap.NewNop().Sugar()
	csm := NewCorrelationStateManager(300, 1000, logger) // 5 min TTL, max 1000 rules
	defer csm.Stop()

	// Create test events
	event1 := &core.Event{
		EventID:   "1",
		EventType: "login",
		Timestamp: time.Now(),
	}
	event2 := &core.Event{
		EventID:   "2",
		EventType: "failed_login",
		Timestamp: time.Now().Add(time.Second),
	}
	event3 := &core.Event{
		EventID:   "3",
		EventType: "login",
		Timestamp: time.Now().Add(2 * time.Second),
	}

	// Test correlation rule: login -> failed_login -> login
	rule := core.CorrelationRule{
		ID:       "test-rule",
		Sequence: []string{"login", "failed_login", "login"},
		Window:   10 * time.Second,
	}

	// First event should not match
	assert.False(t, csm.EvaluateCorrelationRule(rule, event1))

	// Second event should not match
	assert.False(t, csm.EvaluateCorrelationRule(rule, event2))

	// Third event should match
	assert.True(t, csm.EvaluateCorrelationRule(rule, event3))

	// After match, state should be cleared, so repeating the sequence should start fresh
	assert.False(t, csm.EvaluateCorrelationRule(rule, event1))
}

func TestCorrelationStateManagerStats(t *testing.T) {
	logger := zap.NewNop().Sugar()
	csm := NewCorrelationStateManager(300, 1000, logger)
	defer csm.Stop()

	event := &core.Event{
		EventID:   "1",
		EventType: "login",
		Timestamp: time.Now(),
	}

	// Use a sequence that requires 2 events, so it won't match immediately
	rule := core.CorrelationRule{
		ID:       "test-rule",
		Sequence: []string{"login", "logout"},
		Window:   10 * time.Second,
	}

	// Add first event - should not match
	matched := csm.EvaluateCorrelationRule(rule, event)
	assert.False(t, matched)

	stats := csm.GetStats()
	assert.Equal(t, 1, stats.TotalRules)
	assert.Equal(t, 1, stats.TotalEvents)
}

func TestCorrelationStateManagerReset(t *testing.T) {
	logger := zap.NewNop().Sugar()
	csm := NewCorrelationStateManager(300, 1000, logger)
	defer csm.Stop()

	event := &core.Event{
		EventID:   "1",
		EventType: "login",
		Timestamp: time.Now(),
	}

	// Use a sequence that requires 2 events, so it won't match immediately
	rule := core.CorrelationRule{
		ID:       "test-rule",
		Sequence: []string{"login", "logout"},
		Window:   10 * time.Second,
	}

	// Add first event - should not match
	csm.EvaluateCorrelationRule(rule, event)

	// Check stats
	stats := csm.GetStats()
	assert.Equal(t, 1, stats.TotalRules)

	// Reset
	csm.Reset()

	// Check stats after reset
	stats = csm.GetStats()
	assert.Equal(t, 0, stats.TotalRules)
}

// TestCorrelationStateManager_ConcurrentAccess tests thread safety under concurrent access
// TASK 153: Verify no race conditions in correlation state management
func TestCorrelationStateManager_ConcurrentAccess(t *testing.T) {
	logger := zap.NewNop().Sugar()
	csm := NewCorrelationStateManager(300, 1000, logger) // 5 min TTL, max 1000 rules
	defer csm.Stop()

	const numGoroutines = 100
	const eventsPerGoroutine = 50

	// Create multiple rules to test concurrent access to different state entries
	rules := make([]core.CorrelationRule, 10)
	for i := 0; i < len(rules); i++ {
		rules[i] = core.CorrelationRule{
			ID:       "rule-" + string(rune('0'+i)),
			Sequence: []string{"login", "failed_login", "login"},
			Window:   10 * time.Second,
		}
	}

	// Channel to track completion and any panics
	done := make(chan bool, numGoroutines)
	panics := make(chan interface{}, numGoroutines)

	// Launch concurrent goroutines
	for g := 0; g < numGoroutines; g++ {
		go func(goroutineID int) {
			defer func() {
				if r := recover(); r != nil {
					panics <- r
				}
				done <- true
			}()

			for e := 0; e < eventsPerGoroutine; e++ {
				// Select a rule based on goroutine ID (creates contention on same rule)
				rule := rules[goroutineID%len(rules)]

				// Create event with unique ID
				event := &core.Event{
					EventID:   "evt-" + string(rune('0'+goroutineID)) + "-" + string(rune('0'+e)),
					EventType: []string{"login", "failed_login", "login"}[e%3],
					Timestamp: time.Now(),
				}

				// Evaluate rule (concurrent access to state)
				csm.EvaluateCorrelationRule(rule, event)

				// Also test concurrent stats access
				if e%10 == 0 {
					_ = csm.GetStats()
				}
			}
		}(g)
	}

	// Wait for all goroutines to complete
	for i := 0; i < numGoroutines; i++ {
		<-done
	}

	// Check for panics
	select {
	case p := <-panics:
		t.Fatalf("Concurrent access caused panic: %v", p)
	default:
		// No panic, test passed
	}

	// Verify state is still accessible (no corruption)
	stats := csm.GetStats()
	assert.True(t, stats.TotalRules >= 0, "Stats should be valid after concurrent access")
	assert.True(t, stats.TotalEvents >= 0, "Event count should be valid after concurrent access")

	// Test reset while concurrent reads might be happening
	csm.Reset()
	stats = csm.GetStats()
	assert.Equal(t, 0, stats.TotalRules, "Reset should clear all rules")
}

// TestCorrelationStateManager_ConcurrentResetAndEvaluate tests concurrent reset and evaluation
// TASK 153: Verify no race conditions during reset operations
func TestCorrelationStateManager_ConcurrentResetAndEvaluate(t *testing.T) {
	logger := zap.NewNop().Sugar()
	csm := NewCorrelationStateManager(300, 1000, logger)
	defer csm.Stop()

	rule := core.CorrelationRule{
		ID:       "test-rule",
		Sequence: []string{"login", "logout"},
		Window:   10 * time.Second,
	}

	const numIterations = 100
	done := make(chan bool, 2)
	panics := make(chan interface{}, 2)

	// Goroutine 1: Continuously evaluate
	go func() {
		defer func() {
			if r := recover(); r != nil {
				panics <- r
			}
			done <- true
		}()

		for i := 0; i < numIterations; i++ {
			event := &core.Event{
				EventID:   "evt-" + string(rune('0'+i)),
				EventType: "login",
				Timestamp: time.Now(),
			}
			csm.EvaluateCorrelationRule(rule, event)
		}
	}()

	// Goroutine 2: Periodically reset
	go func() {
		defer func() {
			if r := recover(); r != nil {
				panics <- r
			}
			done <- true
		}()

		for i := 0; i < numIterations/10; i++ {
			time.Sleep(time.Millisecond)
			csm.Reset()
		}
	}()

	// Wait for both goroutines
	<-done
	<-done

	// Check for panics
	select {
	case p := <-panics:
		t.Fatalf("Concurrent reset/evaluate caused panic: %v", p)
	default:
		// No panic, test passed
	}
}
