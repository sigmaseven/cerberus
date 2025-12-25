package load

import (
	"bytes"
	"encoding/json"
	"net/http"
	"sync"
	"testing"
	"time"
)

// TestCQLQueryPerformance tests CQL query performance under load
// TASK 43.6: CQL query performance load test
func TestCQLQueryPerformance(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping load test in short mode")
	}

	baseURL := "http://localhost:8080"
	testQueries := []struct {
		name  string
		query string
	}{
		{"Simple", "field = 'value'"},
		{"Complex", "field1 = 'value1' AND (field2 contains 'substring' OR field3 > 100)"},
		{"Range", "timestamp >= '2025-01-01' AND timestamp <= '2025-01-31'"},
		{"Wildcard", "field like 'prefix%'"},
	}

	var (
		queryCount   int64
		successCount int64
		failureCount int64
		latencies    []time.Duration
		latenciesMu  sync.Mutex
		wg           sync.WaitGroup
	)

	// Target: <1s p95 query time
	targetP95 := 1 * time.Second
	concurrentQueries := 50

	for _, testQuery := range testQueries {
		t.Run(testQuery.name, func(t *testing.T) {
			wg.Add(concurrentQueries)

			for i := 0; i < concurrentQueries; i++ {
				go func() {
					defer wg.Done()
					client := &http.Client{
						Timeout: 10 * time.Second,
					}

					body := map[string]interface{}{
						"query": testQuery.query,
						"limit": 100,
					}
					bodyJSON, _ := json.Marshal(body)

					reqStart := time.Now()
					req, _ := http.NewRequest("POST", baseURL+"/api/v1/events/search", bytes.NewReader(bodyJSON))
					req.Header.Set("Content-Type", "application/json")
					// req.Header.Set("Authorization", "Bearer "+token)

					resp, err := client.Do(req)
					latency := time.Since(reqStart)

					latenciesMu.Lock()
					latencies = append(latencies, latency)
					queryCount++
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
				}()
			}

			wg.Wait()

			// Calculate metrics
			latenciesMu.Lock()
			p50 := percentile(latencies, 50)
			p95 := percentile(latencies, 95)
			p99 := percentile(latencies, 99)
			latenciesMu.Unlock()

			// Report results
			t.Logf("=== CQL Query Performance: %s ===", testQuery.name)
			t.Logf("Query: %s", testQuery.query)
			t.Logf("Queries Executed: %d", queryCount)
			t.Logf("Successful: %d", successCount)
			t.Logf("Failed: %d", failureCount)
			t.Logf("Latency P50: %v", p50)
			t.Logf("Latency P95: %v", p95)
			t.Logf("Latency P99: %v", p99)

			// Validate results
			if p95 > targetP95 {
				t.Errorf("P95 latency exceeds target: %v > %v", p95, targetP95)
			}
		})
	}
}
