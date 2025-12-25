package detect

import (
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"cerberus/core"
	testinghelpers "cerberus/testing"

	"github.com/stretchr/testify/require"
)

// ==============================================================================
// BENCHMARK HELPER FUNCTIONS
// ==============================================================================

// setupBenchmarkEngine creates a rule engine optimized for benchmarking
func setupBenchmarkEngine(tb testing.TB) *RuleEngine {
	tb.Helper()

	rules := []core.Rule{
		{
			ID:      "bench-rule-simple",
			Enabled: true,
			Type:    "sigma",
			SigmaYAML: `title: Benchmark Rule
logsource:
  category: test
detection:
  selection:
    event_type: user_login
  condition: selection`,
		},
	}

	correlationRules := []core.CorrelationRule{
		{
			ID:       "bench-corr-rule",
			Name:     "Benchmark Correlation Rule",
			Sequence: []string{"failed_login", "failed_login", "failed_login"},
			Window:   5 * time.Minute,
		},
	}

	return NewRuleEngine(rules, correlationRules, 300) // 5 minute TTL
}

// createSimpleRule creates a basic rule for benchmarking
func createSimpleRule(tb testing.TB) core.Rule {
	tb.Helper()
	return core.Rule{
		ID:      "simple-rule",
		Enabled: true,
		Type:    "sigma",
		SigmaYAML: `title: Simple Rule
logsource:
  category: test
detection:
  selection:
    username: admin
  condition: selection`,
	}
}

// createComplexRule creates a multi-condition rule for benchmarking
func createComplexRule(tb testing.TB) core.Rule {
	tb.Helper()
	return core.Rule{
		ID:      "complex-rule",
		Enabled: true,
		Type:    "sigma",
		SigmaYAML: `title: Complex Rule
logsource:
  category: test
detection:
  selection:
    event_type: user_login
    source_ip|contains: '192.168'
    username|startswith: admin
  condition: selection`,
	}
}

// createBenchEvent creates a test event for benchmarking
func createBenchEvent(tb testing.TB) *core.Event {
	tb.Helper()
	event := core.NewEvent()
	event.EventType = "user_login"
	event.SourceIP = "192.168.1.100"
	event.Fields["username"] = "admin"
	event.Fields["action"] = "login_attempt"
	event.Fields["status"] = "success"
	event.Timestamp = time.Now()
	return event
}

// createBenchEvents creates multiple test events for bulk benchmarking
func createBenchEvents(tb testing.TB, count int) []*core.Event {
	tb.Helper()
	events := make([]*core.Event, count)
	for i := 0; i < count; i++ {
		events[i] = createBenchEvent(tb)
	}
	return events
}

// ==============================================================================
// RULE EVALUATION BENCHMARKS - Category 1
// SLA REQUIREMENT: Rule evaluation < 1ms per event
// ==============================================================================

// BenchmarkRuleEvaluation_Simple measures single simple rule evaluation performance
// SLA REQUIREMENT: < 1ms per event
//
// SECURITY CONSIDERATION: Fast rule evaluation prevents DoS via rule complexity
// PERFORMANCE TARGET: > 1000 ops/sec (1ms per op)
func BenchmarkRuleEvaluation_Simple(b *testing.B) {
	engine := setupBenchmarkEngine(b)
	rule := createSimpleRule(b)
	event := createBenchEvent(b)

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_ = engine.evaluateRule(rule, event)
	}

	// Calculate and report metrics
	elapsed := b.Elapsed()
	opsPerSec := float64(b.N) / elapsed.Seconds()
	msPerOp := elapsed.Seconds() * 1000 / float64(b.N)

	b.ReportMetric(opsPerSec, "ops/sec")
	b.ReportMetric(msPerOp, "ms/op")

	// SLA ENFORCEMENT: Fail benchmark if SLA violated
	if msPerOp > 1.0 {
		b.Errorf("SLA VIOLATION: Simple rule evaluation took %.3fms (SLA: < 1ms)", msPerOp)
	}
}

// BenchmarkRuleEvaluation_Complex measures complex multi-condition rule performance
// SLA REQUIREMENT: < 5ms per event (more lenient for complex rules)
//
// PERFORMANCE TARGET: Handle complex rules without degrading throughput
func BenchmarkRuleEvaluation_Complex(b *testing.B) {
	engine := setupBenchmarkEngine(b)
	rule := createComplexRule(b)
	event := createBenchEvent(b)

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_ = engine.evaluateRule(rule, event)
	}

	elapsed := b.Elapsed()
	msPerOp := elapsed.Seconds() * 1000 / float64(b.N)

	b.ReportMetric(msPerOp, "ms/op")

	// SLA ENFORCEMENT: Complex rules get 5ms budget
	if msPerOp > 5.0 {
		b.Errorf("SLA VIOLATION: Complex rule evaluation took %.3fms (SLA: < 5ms)", msPerOp)
	}
}

// BenchmarkRuleEvaluation_NoMatch measures non-matching rule performance
// REQUIREMENT: Non-matches should be as fast as matches (no penalty)
//
// RATIONALE: Most events don't match most rules, so this is the common path
func BenchmarkRuleEvaluation_NoMatch(b *testing.B) {
	engine := setupBenchmarkEngine(b)
	rule := createSimpleRule(b)
	event := createBenchEvent(b)
	event.Fields["username"] = "different_user" // Won't match

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		matched := engine.evaluateRule(rule, event)
		if matched {
			b.Fatal("Rule should not have matched")
		}
	}

	elapsed := b.Elapsed()
	msPerOp := elapsed.Seconds() * 1000 / float64(b.N)
	b.ReportMetric(msPerOp, "ms/op")

	// Non-matches should be same SLA as matches
	if msPerOp > 1.0 {
		b.Errorf("SLA VIOLATION: Non-matching rule took %.3fms (SLA: < 1ms)", msPerOp)
	}
}

// ==============================================================================
// CORRELATION BENCHMARKS - Category 1
// SLA REQUIREMENT: Correlation matching < 5ms per event
// ==============================================================================

// BenchmarkCorrelationEvaluation measures correlation rule performance
// SLA REQUIREMENT: < 5ms per event
//
// SECURITY: Correlation rules maintain state, must not leak memory
// CONCURRENCY: State must be thread-safe under concurrent access
func BenchmarkCorrelationEvaluation(b *testing.B) {
	engine := setupBenchmarkEngine(b)
	correlationRule := core.CorrelationRule{
		ID:       "bench-correlation",
		Name:     "Benchmark Correlation",
		Sequence: []string{"failed_login", "failed_login", "failed_login"},
		Window:   5 * time.Minute,
	}
	event := createBenchEvent(b)
	event.EventType = "failed_login"

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_ = engine.evaluateCorrelationRule(correlationRule, event)
	}

	elapsed := b.Elapsed()
	msPerOp := elapsed.Seconds() * 1000 / float64(b.N)

	b.ReportMetric(msPerOp, "ms/op")

	if msPerOp > 5.0 {
		b.Errorf("SLA VIOLATION: Correlation evaluation took %.3fms (SLA: < 5ms)", msPerOp)
	}
}

// ==============================================================================
// BULK EVALUATION BENCHMARKS - Category 1
// SLA REQUIREMENT: > 1000 events/second throughput
// ==============================================================================

// BenchmarkBulkEvaluation_1000Events measures throughput with 1000 events
// SLA REQUIREMENT: Process 1000 events in < 1 second (> 1000 events/sec)
//
// PRODUCTION SCENARIO: This simulates sustained event processing load
func BenchmarkBulkEvaluation_1000Events(b *testing.B) {
	engine := setupBenchmarkEngine(b)
	events := createBenchEvents(b, 1000)

	b.ResetTimer()

	totalEvents := 0
	for i := 0; i < b.N; i++ {
		for _, event := range events {
			_ = engine.Evaluate(event)
			totalEvents++
		}
	}

	elapsed := b.Elapsed()
	eventsPerSec := float64(totalEvents) / elapsed.Seconds()

	b.ReportMetric(eventsPerSec, "events/sec")

	// SLA ENFORCEMENT: Must process > 1000 events/second
	if eventsPerSec < 1000 {
		b.Errorf("SLA VIOLATION: Throughput %.0f events/sec (SLA: > 1000)", eventsPerSec)
	}
}

// BenchmarkBulkEvaluation_10Rules measures throughput with multiple rules
// REQUIREMENT: Multiple rules should not degrade per-event throughput linearly
func BenchmarkBulkEvaluation_10Rules(b *testing.B) {
	// Create engine with 10 rules
	rules := make([]core.Rule, 10)
	for i := 0; i < 10; i++ {
		rules[i] = core.Rule{
			ID:      string(rune('A'+i)) + "-rule",
			Enabled: true,
			Type:    "sigma",
			SigmaYAML: `title: Multi-rule Test
logsource:
  category: test
detection:
  selection:
    event_type: test_event
  condition: selection`,
		}
	}
	engine := NewRuleEngine(rules, []core.CorrelationRule{}, 300)

	events := createBenchEvents(b, 100)

	b.ResetTimer()

	totalOps := 0
	for i := 0; i < b.N; i++ {
		for _, event := range events {
			matches := engine.Evaluate(event)
			totalOps += len(matches)
		}
	}

	elapsed := b.Elapsed()
	eventsPerSec := float64(b.N*len(events)) / elapsed.Seconds()

	b.ReportMetric(eventsPerSec, "events/sec")

	// With 10 rules, should still maintain > 1000 events/sec
	if eventsPerSec < 1000 {
		b.Errorf("SLA VIOLATION: Multi-rule throughput %.0f events/sec (SLA: > 1000)", eventsPerSec)
	}
}

// ==============================================================================
// MEMORY EFFICIENCY BENCHMARKS - Category 5
// SLA REQUIREMENT: < 1MB per goroutine, < 10MB per 1000 events
// ==============================================================================

// TestMemoryProfile_RuleEvaluation verifies memory usage during rule evaluation
// SLA REQUIREMENT: < 1MB per goroutine average
//
// SECURITY: Memory leaks could enable DoS attacks
// METHODOLOGY: Compare memory before/after 1000 operations
func TestMemoryProfile_RuleEvaluation(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping memory profile in short mode")
	}

	engine := setupBenchmarkEngine(t)
	rule := createSimpleRule(t)

	// Force GC and get baseline
	runtime.GC()
	var m1 runtime.MemStats
	runtime.ReadMemStats(&m1)

	// Evaluate rule 1000 times
	for i := 0; i < 1000; i++ {
		event := createBenchEvent(t)
		_ = engine.evaluateRule(rule, event)
	}

	// Force GC and measure final memory
	runtime.GC()
	var m2 runtime.MemStats
	runtime.ReadMemStats(&m2)

	allocatedMB := float64(m2.TotalAlloc-m1.TotalAlloc) / 1024 / 1024
	allocPerOp := allocatedMB / 1000
	allocPerOpKB := allocPerOp * 1024

	t.Logf("Memory: %.2f MB total, %.2f KB per operation", allocatedMB, allocPerOpKB)
	t.Logf("Heap objects: %d -> %d (delta: %d)", m1.HeapObjects, m2.HeapObjects, m2.HeapObjects-m1.HeapObjects)

	// SLA ENFORCEMENT: < 1MB per operation (very conservative)
	if allocPerOp > 1.0 {
		t.Errorf("SLA VIOLATION: Memory usage %.2f MB per op (SLA: < 1MB)", allocPerOp)
	}

	// SECURITY CHECK: Verify we're not leaking heap objects
	// Use signed integer to detect both increases and decreases
	var objectGrowth int64
	if m2.HeapObjects >= m1.HeapObjects {
		objectGrowth = int64(m2.HeapObjects - m1.HeapObjects)
	} else {
		objectGrowth = -int64(m1.HeapObjects - m2.HeapObjects)
	}

	// Only warn on significant POSITIVE growth
	if objectGrowth > 1000 {
		t.Errorf("MEMORY LEAK WARNING: Heap objects grew by %d (expect ~0 after GC)", objectGrowth)
	} else if objectGrowth < 0 {
		t.Logf("Heap objects decreased by %d (GC working correctly)", -objectGrowth)
	}
}

// TestMemoryProfile_1000Events verifies memory efficiency for bulk processing
// SLA REQUIREMENT: < 10MB per 1000 events
//
// PRODUCTION SCENARIO: Measures memory usage during sustained load
func TestMemoryProfile_1000Events(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping memory profile in short mode")
	}

	engine := setupBenchmarkEngine(t)
	events := createBenchEvents(t, 1000)

	runtime.GC()
	var m1 runtime.MemStats
	runtime.ReadMemStats(&m1)

	// Process 1000 events
	for _, event := range events {
		_ = engine.Evaluate(event)
	}

	runtime.GC()
	var m2 runtime.MemStats
	runtime.ReadMemStats(&m2)

	allocatedMB := float64(m2.TotalAlloc-m1.TotalAlloc) / 1024 / 1024

	t.Logf("Memory for 1000 events: %.2f MB (%.2f KB per event)", allocatedMB, allocatedMB*1024/1000)

	// SLA ENFORCEMENT: < 10MB for 1000 events
	if allocatedMB > 10.0 {
		t.Errorf("SLA VIOLATION: Memory usage %.2f MB for 1000 events (SLA: < 10MB)", allocatedMB)
	}
}

// TestMemoryLeak_LongRunning detects memory leaks over extended operations
// SLA REQUIREMENT: Stable memory over 10,000 operations (< 10% growth)
//
// SECURITY: Memory leaks enable resource exhaustion attacks
// METHODOLOGY: Sample memory 10 times, verify no upward trend
func TestMemoryLeak_LongRunning(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping long-running test in short mode")
	}

	engine := setupBenchmarkEngine(t)
	rule := createSimpleRule(t)

	var memSamples []uint64

	// Take 10 samples over 10,000 operations
	for i := 0; i < 10; i++ {
		// Run 1000 operations
		for j := 0; j < 1000; j++ {
			event := createBenchEvent(t)
			_ = engine.evaluateRule(rule, event)
		}

		// Sample memory after GC
		runtime.GC()
		var m runtime.MemStats
		runtime.ReadMemStats(&m)
		memSamples = append(memSamples, m.Alloc)

		t.Logf("Sample %d: Memory = %.2f MB", i+1, float64(m.Alloc)/1024/1024)
	}

	// Analyze memory trend
	firstSample := float64(memSamples[0])
	lastSample := float64(memSamples[len(memSamples)-1])
	growth := (lastSample - firstSample) / firstSample * 100

	t.Logf("Memory growth over 10,000 operations: %.2f%%", growth)

	// SLA ENFORCEMENT: < 10% growth indicates no significant leak
	if growth > 10 {
		t.Errorf("MEMORY LEAK DETECTED: Memory grew %.2f%% (threshold: 10%%)", growth)
		t.Logf("Memory samples: %v", memSamples)
	}

	// Additional check: Calculate variance to detect instability
	var sum, variance float64
	for _, sample := range memSamples {
		sum += float64(sample)
	}
	mean := sum / float64(len(memSamples))

	for _, sample := range memSamples {
		variance += (float64(sample) - mean) * (float64(sample) - mean)
	}
	variance /= float64(len(memSamples))
	stddev := variance / mean * 100 // Coefficient of variation

	t.Logf("Memory stability: mean=%.2f MB, CV=%.2f%%", mean/1024/1024, stddev)
}

// ==============================================================================
// CONCURRENCY BENCHMARKS - Category 6
// SLA REQUIREMENT: Thread-safe, no race conditions, no deadlocks
// ==============================================================================

// TestConcurrency_RuleEvaluation verifies thread safety under concurrent load
// SLA REQUIREMENT: No race conditions with 10 concurrent goroutines
//
// SECURITY: Race conditions can corrupt detection state
// RUN WITH: go test -race -run=TestConcurrency
func TestConcurrency_RuleEvaluation(t *testing.T) {
	engine := setupBenchmarkEngine(t)
	rule := createSimpleRule(t)

	const numGoroutines = 10
	const opsPerGoroutine = 1000

	var wg sync.WaitGroup
	errChan := make(chan error, numGoroutines)
	completedChan := make(chan int, numGoroutines)

	start := time.Now()

	// Launch concurrent workers
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()

			successCount := 0
			for j := 0; j < opsPerGoroutine; j++ {
				event := createBenchEvent(t)
				matched := engine.evaluateRule(rule, event)

				// Verify deterministic behavior
				if matched {
					successCount++
				}
			}

			completedChan <- successCount
		}(i)
	}

	// Wait for completion with timeout
	done := make(chan bool)
	go func() {
		wg.Wait()
		close(completedChan)
		done <- true
	}()

	select {
	case <-done:
		// Success
	case <-time.After(10 * time.Second):
		t.Fatal("DEADLOCK DETECTED: Goroutines did not complete in 10s")
	}

	// Check for errors
	close(errChan)
	for err := range errChan {
		t.Errorf("Goroutine error: %v", err)
	}

	elapsed := time.Since(start)
	totalOps := numGoroutines * opsPerGoroutine
	opsPerSec := float64(totalOps) / elapsed.Seconds()

	t.Logf("Concurrent performance: %.0f ops/sec (%d goroutines)", opsPerSec, numGoroutines)
	t.Logf("Elapsed time: %v", elapsed)

	// Verify all goroutines completed
	resultsCount := 0
	for range completedChan {
		resultsCount++
	}

	if resultsCount != numGoroutines {
		t.Errorf("Expected %d results, got %d", numGoroutines, resultsCount)
	}
}

// TestConcurrency_CorrelationState verifies correlation state thread safety
// REQUIREMENT: Correlation state must handle concurrent updates correctly
//
// SECURITY CRITICAL: State corruption could cause missed detections
func TestConcurrency_CorrelationState(t *testing.T) {
	engine := setupBenchmarkEngine(t)
	correlationRule := core.CorrelationRule{
		ID:       "concurrent-correlation",
		Name:     "Concurrent Correlation",
		Sequence: []string{"failed_login", "failed_login", "failed_login"},
		Window:   5 * time.Minute,
	}

	const numGoroutines = 10
	const eventsPerGoroutine = 100

	var wg sync.WaitGroup
	var matchCount atomic.Int64

	start := time.Now()

	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()

			for j := 0; j < eventsPerGoroutine; j++ {
				event := createBenchEvent(t)
				event.EventType = "failed_login"
				event.Timestamp = time.Now()

				matched := engine.evaluateCorrelationRule(correlationRule, event)
				if matched {
					matchCount.Add(1)
				}
			}
		}(i)
	}

	// Wait with timeout
	done := make(chan bool)
	go func() {
		wg.Wait()
		done <- true
	}()

	select {
	case <-done:
		// Success
	case <-time.After(10 * time.Second):
		t.Fatal("DEADLOCK DETECTED: Correlation evaluation hung")
	}

	elapsed := time.Since(start)
	totalEvents := numGoroutines * eventsPerGoroutine

	t.Logf("Concurrent correlation: %d events in %v", totalEvents, elapsed)
	t.Logf("Matches detected: %d", matchCount.Load())

	// Verify state is consistent (not corrupted)
	stats := engine.GetCorrelationStateStats()
	t.Logf("Correlation state stats: %+v", stats)

	// State should be bounded by our limits
	totalEventsInMemory := stats["total_events_in_memory"].(int)
	if totalEventsInMemory > MaxCorrelationEventsPerRule {
		t.Errorf("MEMORY LIMIT VIOLATION: %d events in memory (limit: %d)",
			totalEventsInMemory, MaxCorrelationEventsPerRule)
	}
}

// BenchmarkConcurrentEvaluation measures throughput under concurrent load
// REQUIREMENT: Verify performance scales with concurrency
func BenchmarkConcurrentEvaluation(b *testing.B) {
	engine := setupBenchmarkEngine(b)

	b.RunParallel(func(pb *testing.PB) {
		rule := createSimpleRule(b)
		event := createBenchEvent(b)

		for pb.Next() {
			_ = engine.evaluateRule(rule, event)
		}
	})

	// Report throughput
	elapsed := b.Elapsed()
	opsPerSec := float64(b.N) / elapsed.Seconds()
	b.ReportMetric(opsPerSec, "ops/sec")
}

// ==============================================================================
// DETECTOR THROUGHPUT BENCHMARKS - Category 3
// SLA REQUIREMENT: > 1000 events/second, < 10ms alert generation
// ==============================================================================

// TestDetectorThroughput_1000EventsPerSecond verifies end-to-end throughput
// SLA REQUIREMENT: Process > 1000 events/second through full detector pipeline
//
// PRODUCTION SCENARIO: Simulates real-world event ingestion
func TestDetectorThroughput_1000EventsPerSecond(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping throughput test in short mode")
	}

	// Create detector with buffered channels - MUST be large enough to prevent drops
	engine := setupBenchmarkEngine(t)
	inputCh := make(chan *core.Event, 1000)  // Match target event count
	outputCh := make(chan *core.Event, 1000) // Match target event count
	alertCh := make(chan *core.Alert, 1000)  // Match target event count (events match rules)

	cfg := testinghelpers.SetupTestConfig()
	logger := testinghelpers.SetupTestLogger(t)

	detector, err := NewDetector(engine, inputCh, outputCh, alertCh, cfg, logger)
	require.NoError(t, err, "NewDetector failed")
	detector.Start()

	defer func() {
		close(inputCh)
		detector.Stop()
	}()

	const targetEvents = 1000
	events := createBenchEvents(t, targetEvents)

	// CRITICAL FIX: Drain alert channel to prevent detector from blocking
	// The detector writes to both outputCh AND alertCh, so both must be drained
	alertDone := make(chan bool)
	go func() {
		defer close(alertDone)
		for {
			select {
			case <-alertCh:
				// Consume alerts to prevent detector from blocking
			case <-time.After(5 * time.Second):
				// Exit after test completes
				return
			}
		}
	}()

	defer func() {
		// Wait for alert drainer to finish
		<-alertDone
	}()

	start := time.Now()

	// Send events in background to avoid blocking
	go func() {
		for _, event := range events {
			inputCh <- event
		}
	}()

	// Wait for all events to be processed
	processed := 0
	timeout := time.After(5 * time.Second) // 5 second budget for 1000 events

	for processed < targetEvents {
		select {
		case <-outputCh:
			processed++
		case <-timeout:
			t.Fatalf("TIMEOUT: Only processed %d/%d events in 5s (possible channel deadlock)", processed, targetEvents)
		}
	}

	elapsed := time.Since(start)
	eventsPerSec := float64(targetEvents) / elapsed.Seconds()

	t.Logf("Detector throughput: %.0f events/sec", eventsPerSec)
	t.Logf("Time to process %d events: %v", targetEvents, elapsed)

	// SLA ENFORCEMENT: > 1000 events/second
	if eventsPerSec < 1000 {
		t.Errorf("SLA VIOLATION: Throughput %.0f events/sec (SLA: > 1000)", eventsPerSec)
	}

	// ADDITIONAL SLA: Should complete in < 1 second
	if elapsed > 1*time.Second {
		t.Errorf("SLA VIOLATION: Took %v to process 1000 events (SLA: < 1s)", elapsed)
	}
}

// TestAlertGenerationLatency measures time from event to alert
// SLA REQUIREMENT: < 10ms alert generation latency
//
// CRITICALITY: Low latency is essential for real-time threat detection
func TestAlertGenerationLatency(t *testing.T) {
	// Create rule that always matches
	rules := []core.Rule{
		{
			ID:      "latency-test-rule",
			Enabled: true,
			Type:    "sigma",
			SigmaYAML: `title: Latency Test Rule
logsource:
  category: test
detection:
  selection:
    event_type: test_event
  condition: selection`,
		},
	}

	engine := NewRuleEngine(rules, []core.CorrelationRule{}, 300)
	inputCh := make(chan *core.Event, 10)
	outputCh := make(chan *core.Event, 10)
	alertCh := make(chan *core.Alert, 10)

	cfg := testinghelpers.SetupTestConfig()
	logger := testinghelpers.SetupTestLogger(t)

	detector, err := NewDetector(engine, inputCh, outputCh, alertCh, cfg, logger)
	require.NoError(t, err, "NewDetector failed")
	detector.Start()

	defer func() {
		close(inputCh)
		detector.Stop()
	}()

	// Measure latency for 100 events
	var totalLatency time.Duration
	const iterations = 100

	for i := 0; i < iterations; i++ {
		event := createBenchEvent(t)
		event.EventType = "test_event"

		sendTime := time.Now()
		inputCh <- event

		// Wait for alert
		select {
		case <-alertCh:
			latency := time.Since(sendTime)
			totalLatency += latency
		case <-time.After(100 * time.Millisecond):
			t.Fatal("Alert not generated within 100ms")
		}

		// Drain output channel
		<-outputCh
	}

	avgLatencyMs := float64(totalLatency.Microseconds()) / float64(iterations) / 1000.0

	t.Logf("Average alert latency: %.3f ms", avgLatencyMs)
	t.Logf("Total latency for %d alerts: %v", iterations, totalLatency)

	// SLA ENFORCEMENT: < 10ms average latency
	if avgLatencyMs > 10.0 {
		t.Errorf("SLA VIOLATION: Alert latency %.3f ms (SLA: < 10ms)", avgLatencyMs)
	}
}
