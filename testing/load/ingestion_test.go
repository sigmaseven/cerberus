package load

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"sync"
	"testing"
	"time"
)

// TestIngestionThroughput_10KEPS tests sustained 10K events per second ingestion
// TASK 43.4: Ingestion throughput load test
func TestIngestionThroughput_10KEPS(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping load test in short mode")
	}

	baseURL := "http://localhost:8080"
	testDuration := 1 * time.Minute // Start with 1 minute, extend to 1 hour for full test
	targetEPS := 10000

	generator := NewEventGenerator()

	// Metrics
	var (
		eventsSent    int64
		eventsSuccess int64
		eventsFailed  int64
		latencies     []time.Duration
		latenciesMu   sync.Mutex
		wg            sync.WaitGroup
	)

	startTime := time.Now()
	endTime := startTime.Add(testDuration)

	// Start sending events at target rate
	interval := time.Second / time.Duration(targetEPS)
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	// Use multiple workers for concurrent ingestion
	numWorkers := 10

	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			client := &http.Client{
				Timeout: 5 * time.Second,
			}

			workerStart := time.Now()
			eventCount := 0

			for time.Now().Before(endTime) {
				event := generator.GenerateEvent()
				eventJSON, _ := json.Marshal(event)

				reqStart := time.Now()
				req, _ := http.NewRequest("POST", fmt.Sprintf("%s/api/v1/events", baseURL), bytes.NewReader(eventJSON))
				req.Header.Set("Content-Type", "application/json")

				resp, err := client.Do(req)
				latency := time.Since(reqStart)

				latenciesMu.Lock()
				latencies = append(latencies, latency)
				eventsSent++
				latenciesMu.Unlock()

				if err != nil || resp.StatusCode != http.StatusCreated {
					eventsFailed++
					if resp != nil {
						resp.Body.Close()
					}
				} else {
					eventsSuccess++
					resp.Body.Close()
				}

				eventCount++
				// Rate limiting: sleep if sending too fast
				expectedTime := workerStart.Add(time.Duration(eventCount) * interval * time.Duration(numWorkers))
				if sleepDuration := time.Until(expectedTime); sleepDuration > 0 {
					time.Sleep(sleepDuration)
				}
			}
		}(i)
	}

	wg.Wait()
	duration := time.Since(startTime)

	// Calculate metrics
	actualEPS := float64(eventsSent) / duration.Seconds()
	successRate := float64(eventsSuccess) / float64(eventsSent) * 100

	// Calculate latency percentiles
	latenciesMu.Lock()
	p50 := percentile(latencies, 50)
	p95 := percentile(latencies, 95)
	p99 := percentile(latencies, 99)
	latenciesMu.Unlock()

	// Report results
	t.Logf("=== Ingestion Throughput Test Results ===")
	t.Logf("Duration: %v", duration)
	t.Logf("Events Sent: %d", eventsSent)
	t.Logf("Events Success: %d (%.2f%%)", eventsSuccess, successRate)
	t.Logf("Events Failed: %d", eventsFailed)
	t.Logf("Actual EPS: %.2f (Target: %d)", actualEPS, targetEPS)
	t.Logf("Latency P50: %v", p50)
	t.Logf("Latency P95: %v", p95)
	t.Logf("Latency P99: %v", p99)

	// Validate results
	if actualEPS < float64(targetEPS)*0.9 {
		t.Errorf("EPS below target: %.2f < %d (90%% threshold)", actualEPS, targetEPS)
	}

	if successRate < 99.0 {
		t.Errorf("Success rate below threshold: %.2f%% < 99%%", successRate)
	}

	if p95 > 300*time.Millisecond {
		t.Errorf("P95 latency exceeds target: %v > 300ms", p95)
	}
}

// percentile calculates the percentile of a slice of durations
func percentile(values []time.Duration, p int) time.Duration {
	if len(values) == 0 {
		return 0
	}
	// Sort values before calculating percentile
	sorted := make([]time.Duration, len(values))
	copy(sorted, values)
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i] < sorted[j]
	})
	index := (len(sorted) * p) / 100
	if index >= len(sorted) {
		index = len(sorted) - 1
	}
	return sorted[index]
}
