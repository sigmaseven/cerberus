package load

import (
	"bytes"
	"encoding/json"
	"net/http"
	"sync"
	"testing"
	"time"
)

// TestAPIResponseTimes tests API response times under load
// TASK 43.5: API response time load test
func TestAPIResponseTimes(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping load test in short mode")
	}

	baseURL := "http://localhost:8080"
	concurrentUsers := 100
	requestsPerSecond := 1000
	testDuration := 5 * time.Minute

	endpoints := []struct {
		method string
		path   string
	}{
		{"GET", "/api/v1/rules"},
		{"GET", "/api/v1/alerts"},
		{"GET", "/api/v1/events"},
		{"POST", "/api/v1/events/search"},
	}

	var (
		requestCount int64
		successCount int64
		failureCount int64
		latencies    []time.Duration
		latenciesMu  sync.Mutex
		wg           sync.WaitGroup
	)

	startTime := time.Now()
	endTime := startTime.Add(testDuration)

	// Start load generation
	for i := 0; i < concurrentUsers; i++ {
		wg.Add(1)
		go func(userID int) {
			defer wg.Done()
			client := &http.Client{
				Timeout: 10 * time.Second,
			}

			reqInterval := time.Second / time.Duration(requestsPerSecond/concurrentUsers)

			for time.Now().Before(endTime) {
				for _, endpoint := range endpoints {
					reqStart := time.Now()

					var req *http.Request
					var err error

					if endpoint.method == "POST" {
						body := map[string]interface{}{
							"query": "field = 'value'",
							"limit": 100,
						}
						bodyJSON, _ := json.Marshal(body)
						req, err = http.NewRequest(endpoint.method, baseURL+endpoint.path, bytes.NewReader(bodyJSON))
						req.Header.Set("Content-Type", "application/json")
					} else {
						req, err = http.NewRequest(endpoint.method, baseURL+endpoint.path, nil)
					}

					if err != nil {
						continue
					}

					// Add authentication token (would need real token in actual test)
					// req.Header.Set("Authorization", "Bearer "+token)

					resp, err := client.Do(req)
					latency := time.Since(reqStart)

					latenciesMu.Lock()
					latencies = append(latencies, latency)
					requestCount++
					latenciesMu.Unlock()

					if err != nil || resp == nil || resp.StatusCode >= 400 {
						failureCount++
					} else {
						successCount++
						resp.Body.Close()
					}

					if resp != nil {
						resp.Body.Close()
					}
				}

				time.Sleep(reqInterval)
			}
		}(i)
	}

	wg.Wait()
	duration := time.Since(startTime)

	// Calculate metrics
	actualRPS := float64(requestCount) / duration.Seconds()
	successRate := float64(successCount) / float64(requestCount) * 100

	latenciesMu.Lock()
	p50 := percentile(latencies, 50)
	p95 := percentile(latencies, 95)
	p99 := percentile(latencies, 99)
	latenciesMu.Unlock()

	// Report results
	t.Logf("=== API Response Time Test Results ===")
	t.Logf("Duration: %v", duration)
	t.Logf("Total Requests: %d", requestCount)
	t.Logf("Successful: %d (%.2f%%)", successCount, successRate)
	t.Logf("Failed: %d", failureCount)
	t.Logf("Actual RPS: %.2f (Target: %d)", actualRPS, requestsPerSecond)
	t.Logf("Latency P50: %v", p50)
	t.Logf("Latency P95: %v", p95)
	t.Logf("Latency P99: %v", p99)

	// Validate results
	if p95 > 300*time.Millisecond {
		t.Errorf("P95 latency exceeds target: %v > 300ms", p95)
	}

	if successRate < 99.0 {
		t.Errorf("Success rate below threshold: %.2f%% < 99%%", successRate)
	}
}
