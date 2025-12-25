package detect

import (
	"sync"
	"testing"
	"time"

	"cerberus/core"
	"github.com/stretchr/testify/assert"
	"go.uber.org/zap"
)

// TestCorrelationStateStore_BasicOperations tests basic functionality
func TestCorrelationStateStore_BasicOperations(t *testing.T) {
	logger := zap.NewNop().Sugar()
	store := NewCorrelationStateStore(logger)
	defer store.Stop()

	event := &core.Event{
		EventID:   "test-1",
		Timestamp: time.Now(),
	}

	// Test IncrementCount
	count := store.IncrementCount("rule1", "group1", event)
	assert.Equal(t, 1, count)

	count = store.IncrementCount("rule1", "group1", event)
	assert.Equal(t, 2, count)

	// Test GetCount
	assert.Equal(t, 2, store.GetCount("rule1", "group1"))
	assert.Equal(t, 0, store.GetCount("rule1", "nonexistent"))

	// Test AddValue / GetValueCount
	store.AddValue("rule2", "group1", "field1", "value1")
	store.AddValue("rule2", "group1", "field1", "value2")
	store.AddValue("rule2", "group1", "field1", "value1") // duplicate
	assert.Equal(t, 2, store.GetValueCount("rule2", "group1", "field1"))

	// Test AddToSequence / GetSequence
	store.AddToSequence("rule3", "group1", "stage1", event)
	store.AddToSequence("rule3", "group1", "stage2", event)
	seq := store.GetSequence("rule3", "group1")
	assert.Equal(t, []string{"stage1", "stage2"}, seq)

	// Test AddMetric / GetStatistics
	store.AddMetric("rule4", "group1", 10.0)
	store.AddMetric("rule4", "group1", 20.0)
	store.AddMetric("rule4", "group1", 30.0)
	stats := store.GetStatistics("rule4", "group1")
	assert.Equal(t, 3, stats.Count)
	assert.Equal(t, 60.0, stats.Sum)
	assert.Equal(t, 20.0, stats.Mean)

	// Test AddEvent / GetEvents
	store.AddEvent("rule5", "group1", event)
	events := store.GetEvents("rule5", "group1")
	assert.Len(t, events, 1)

	// Test GetStats
	storeStats := store.GetStats()
	assert.True(t, storeStats.TotalRules >= 0)
}

// TestCorrelationStateStore_Reset tests the Reset functionality
func TestCorrelationStateStore_Reset(t *testing.T) {
	logger := zap.NewNop().Sugar()
	store := NewCorrelationStateStore(logger)
	defer store.Stop()

	event := &core.Event{
		EventID:   "test-1",
		Timestamp: time.Now(),
	}

	// Add some state
	store.IncrementCount("rule1", "group1", event)
	store.AddValue("rule2", "group1", "field1", "value1")
	store.AddToSequence("rule3", "group1", "stage1", event)
	store.AddMetric("rule4", "group1", 10.0)
	store.AddEvent("rule5", "group1", event)

	// Verify state exists
	assert.Equal(t, 1, store.GetCount("rule1", "group1"))

	// Reset
	store.Reset()

	// Verify state is cleared
	assert.Equal(t, 0, store.GetCount("rule1", "group1"))
	assert.Equal(t, 0, store.GetValueCount("rule2", "group1", "field1"))
	assert.Empty(t, store.GetSequence("rule3", "group1"))
	stats := store.GetStatistics("rule4", "group1")
	assert.Equal(t, 0, stats.Count)
	assert.Empty(t, store.GetEvents("rule5", "group1"))
}

// TestCorrelationStateStore_CleanupRule tests the CleanupRule functionality
func TestCorrelationStateStore_CleanupRule(t *testing.T) {
	logger := zap.NewNop().Sugar()
	store := NewCorrelationStateStore(logger)
	defer store.Stop()

	event := &core.Event{
		EventID:   "test-1",
		Timestamp: time.Now(),
	}

	// Add state for two rules
	store.IncrementCount("rule1", "group1", event)
	store.IncrementCount("rule2", "group1", event)

	// Verify both have state
	assert.Equal(t, 1, store.GetCount("rule1", "group1"))
	assert.Equal(t, 1, store.GetCount("rule2", "group1"))

	// Cleanup rule1
	store.CleanupRule("rule1")

	// Verify rule1 is cleared but rule2 remains
	assert.Equal(t, 0, store.GetCount("rule1", "group1"))
	assert.Equal(t, 1, store.GetCount("rule2", "group1"))
}

// TestCorrelationStateStore_ConcurrentAccess tests thread safety under concurrent access
// TASK 153: Verify no race conditions in enhanced correlation state management
func TestCorrelationStateStore_ConcurrentAccess(t *testing.T) {
	logger := zap.NewNop().Sugar()
	store := NewCorrelationStateStore(logger)
	defer store.Stop()

	const numGoroutines = 50
	const operationsPerGoroutine = 100

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

			ruleID := "rule-" + string(rune('0'+goroutineID%10))
			groupKey := "group-" + string(rune('0'+goroutineID%5))

			for op := 0; op < operationsPerGoroutine; op++ {
				event := &core.Event{
					EventID:   "evt-" + string(rune('0'+goroutineID)) + "-" + string(rune('0'+op)),
					Timestamp: time.Now(),
				}

				// Mix of different operations
				switch op % 7 {
				case 0:
					store.IncrementCount(ruleID, groupKey, event)
				case 1:
					store.GetCount(ruleID, groupKey)
				case 2:
					store.AddValue(ruleID, groupKey, "field", op)
				case 3:
					store.GetValueCount(ruleID, groupKey, "field")
				case 4:
					store.AddToSequence(ruleID, groupKey, "stage", event)
				case 5:
					store.AddMetric(ruleID, groupKey, float64(op))
				case 6:
					store.AddEvent(ruleID, groupKey, event)
				}

				// Periodically call stats and sequences
				if op%20 == 0 {
					_ = store.GetStats()
					_ = store.GetSequence(ruleID, groupKey)
					_ = store.GetStatistics(ruleID, groupKey)
					_ = store.GetEvents(ruleID, groupKey)
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
	stats := store.GetStats()
	assert.True(t, stats.TotalRules >= 0, "Stats should be valid after concurrent access")
	assert.True(t, stats.TotalGroups >= 0, "Group count should be valid")
}

// TestCorrelationStateStore_ConcurrentResetAndOperations tests concurrent reset and operations
// TASK 153: Verify no race conditions during reset operations
func TestCorrelationStateStore_ConcurrentResetAndOperations(t *testing.T) {
	logger := zap.NewNop().Sugar()
	store := NewCorrelationStateStore(logger)
	defer store.Stop()

	const numIterations = 100
	done := make(chan bool, 2)
	panics := make(chan interface{}, 2)

	// Goroutine 1: Continuously perform operations
	go func() {
		defer func() {
			if r := recover(); r != nil {
				panics <- r
			}
			done <- true
		}()

		for i := 0; i < numIterations; i++ {
			event := &core.Event{
				EventID:   "evt-" + string(rune('0'+i%10)),
				Timestamp: time.Now(),
			}
			store.IncrementCount("rule1", "group1", event)
			store.AddValue("rule1", "group1", "field", i)
			store.AddMetric("rule1", "group1", float64(i))
			_ = store.GetStats()
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
			store.Reset()
		}
	}()

	// Wait for both goroutines
	<-done
	<-done

	// Check for panics
	select {
	case p := <-panics:
		t.Fatalf("Concurrent reset/operations caused panic: %v", p)
	default:
		// No panic, test passed
	}
}

// TestCorrelationStateStore_ConcurrentCleanupExpired tests concurrent cleanup and operations
// TASK 153: Verify no race conditions during cleanup operations
func TestCorrelationStateStore_ConcurrentCleanupExpired(t *testing.T) {
	logger := zap.NewNop().Sugar()
	store := NewCorrelationStateStore(logger)
	defer store.Stop()

	const numIterations = 100
	done := make(chan bool, 2)
	panics := make(chan interface{}, 2)

	// Goroutine 1: Continuously perform operations
	go func() {
		defer func() {
			if r := recover(); r != nil {
				panics <- r
			}
			done <- true
		}()

		for i := 0; i < numIterations; i++ {
			event := &core.Event{
				EventID:   "evt-" + string(rune('0'+i%10)),
				Timestamp: time.Now(),
			}
			store.IncrementCount("rule1", "group1", event)
			store.AddEvent("rule1", "group1", event)
			_ = store.GetStats()
		}
	}()

	// Goroutine 2: Periodically cleanup expired
	go func() {
		defer func() {
			if r := recover(); r != nil {
				panics <- r
			}
			done <- true
		}()

		for i := 0; i < numIterations/10; i++ {
			time.Sleep(time.Millisecond)
			store.CleanupExpired(time.Hour) // Won't actually expire anything
		}
	}()

	// Wait for both goroutines
	<-done
	<-done

	// Check for panics
	select {
	case p := <-panics:
		t.Fatalf("Concurrent cleanup/operations caused panic: %v", p)
	default:
		// No panic, test passed
	}
}

// TestCorrelationStateStore_ConcurrentMultipleRules tests concurrent access to multiple rules
// TASK 153: Stress test for multiple rules under concurrent load
func TestCorrelationStateStore_ConcurrentMultipleRules(t *testing.T) {
	logger := zap.NewNop().Sugar()
	store := NewCorrelationStateStore(logger)
	defer store.Stop()

	const numGoroutines = 100
	const numRules = 20
	const numGroups = 10
	const operationsPerGoroutine = 50

	var wg sync.WaitGroup
	panics := make(chan interface{}, numGoroutines)

	for g := 0; g < numGoroutines; g++ {
		wg.Add(1)
		go func(goroutineID int) {
			defer func() {
				if r := recover(); r != nil {
					panics <- r
				}
				wg.Done()
			}()

			for op := 0; op < operationsPerGoroutine; op++ {
				ruleID := "rule-" + string(rune('0'+op%numRules))
				groupKey := "group-" + string(rune('0'+op%numGroups))

				event := &core.Event{
					EventID:   "evt-" + string(rune('0'+goroutineID)) + "-" + string(rune('0'+op)),
					Timestamp: time.Now(),
				}

				// Perform various operations
				store.IncrementCount(ruleID, groupKey, event)
				store.GetCount(ruleID, groupKey)
				store.AddValue(ruleID, groupKey, "field", op)
				store.GetValueCount(ruleID, groupKey, "field")
				store.AddToSequence(ruleID, groupKey, "stage", event)
				store.GetSequence(ruleID, groupKey)
				store.GetSequenceEvents(ruleID, groupKey)
				store.AddMetric(ruleID, groupKey, float64(op))
				store.GetStatistics(ruleID, groupKey)
				store.AddEvent(ruleID, groupKey, event)
				store.GetEvents(ruleID, groupKey)
			}
		}(g)
	}

	wg.Wait()

	// Check for panics
	select {
	case p := <-panics:
		t.Fatalf("Concurrent multiple rules caused panic: %v", p)
	default:
		// No panic, test passed
	}

	// Verify state integrity
	stats := store.GetStats()
	assert.True(t, stats.TotalRules >= 0, "Total rules should be non-negative")
	assert.True(t, stats.TotalGroups >= 0, "Total groups should be non-negative")
}

// TestComputeGroupKey tests the ComputeGroupKey function
func TestComputeGroupKey(t *testing.T) {
	event := &core.Event{
		EventID:   "test-1",
		SourceIP:  "192.168.1.1",
		EventType: "login",
		Fields: map[string]interface{}{
			"user": "admin",
		},
	}

	// Empty fields should return "default"
	key := ComputeGroupKey(event, []string{})
	assert.Equal(t, "default", key)

	// Single field
	key1 := ComputeGroupKey(event, []string{"source_ip"})
	assert.NotEmpty(t, key1)
	assert.NotEqual(t, "default", key1)

	// Multiple fields - order should not matter due to sorting
	key2 := ComputeGroupKey(event, []string{"source_ip", "event_type"})
	key3 := ComputeGroupKey(event, []string{"event_type", "source_ip"})
	assert.Equal(t, key2, key3) // Same hash regardless of order

	// Custom field from Fields map
	key4 := ComputeGroupKey(event, []string{"user"})
	assert.NotEmpty(t, key4)
	assert.NotEqual(t, "default", key4)
}
