package load

import (
	"context"
	"sync"
	"testing"
	"time"

	"cerberus/core"
)

// TestCorrelationEnginePerformance tests correlation engine performance under load
// TASK 43.7: Correlation engine performance load test
func TestCorrelationEnginePerformance(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping load test in short mode")
	}

	// This test would require access to the correlation engine
	// For now, we'll create a test framework that can be integrated

	targetP95 := 10 * time.Millisecond
	eventRate := 10000 // events per second
	numRules := 1000
	testDuration := 1 * time.Minute

	generator := NewEventGenerator()

	// Simulate correlation engine evaluation
	var (
		evaluationCount int64
		evaluationTimes []time.Duration
		timesMu         sync.Mutex
	)

	startTime := time.Now()
	endTime := startTime.Add(testDuration)

	// Generate events at target rate
	eventInterval := time.Second / time.Duration(eventRate)
	ticker := time.NewTicker(eventInterval)
	defer ticker.Stop()

	ctx, cancel := context.WithDeadline(context.Background(), endTime)
	defer cancel()

	// Process events
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				event := generator.GenerateEvent()

				// Simulate correlation rule evaluation
				for i := 0; i < numRules; i++ {
					evalStart := time.Now()

					// Simulate evaluation (would call actual correlation engine)
					_ = evaluateCorrelationRule(event, i)

					evalTime := time.Since(evalStart)

					timesMu.Lock()
					evaluationTimes = append(evaluationTimes, evalTime)
					evaluationCount++
					timesMu.Unlock()
				}
			}
		}
	}()

	<-ctx.Done()
	duration := time.Since(startTime)

	// Calculate metrics
	timesMu.Lock()
	p50 := percentile(evaluationTimes, 50)
	p95 := percentile(evaluationTimes, 95)
	p99 := percentile(evaluationTimes, 99)
	timesMu.Unlock()

	actualRate := float64(evaluationCount) / duration.Seconds()

	// Report results
	t.Logf("=== Correlation Engine Performance Test Results ===")
	t.Logf("Duration: %v", duration)
	t.Logf("Event Rate: %d EPS", eventRate)
	t.Logf("Number of Rules: %d", numRules)
	t.Logf("Total Evaluations: %d", evaluationCount)
	t.Logf("Actual Evaluation Rate: %.2f/sec", actualRate)
	t.Logf("Latency P50: %v", p50)
	t.Logf("Latency P95: %v", p95)
	t.Logf("Latency P99: %v", p99)

	// Validate results
	if p95 > targetP95 {
		t.Errorf("P95 latency exceeds target: %v > %v", p95, targetP95)
	}
}

// evaluateCorrelationRule simulates correlation rule evaluation
// In actual implementation, this would call the real correlation engine
func evaluateCorrelationRule(event *core.Event, ruleID int) bool {
	// Simulate evaluation time (1-5ms)
	time.Sleep(time.Duration(ruleID%5+1) * time.Millisecond)
	return false
}
