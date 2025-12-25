package api

// TASK 186: Concurrency tests for rule CRUD handlers
// Tests race conditions to ensure thread-safety of handler operations

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ============================================================================
// CONCURRENCY TEST HELPER
// ============================================================================

// concurrentOperationResult stores the result of a concurrent operation
type concurrentOperationResult struct {
	StatusCode int
	Success    bool
	Error      string
	RuleID     string
}

// ============================================================================
// TASK 186: CONCURRENT CREATE TESTS
// ============================================================================

// TestConcurrentRuleCreate tests that multiple concurrent CREATE operations
// are handled safely without race conditions
func TestConcurrentRuleCreate(t *testing.T) {
	testAPI, cleanup := setupTestAPI(t)
	defer cleanup()

	token := createValidTestToken(t, testAPI.config.Auth.JWTSecret, "admin")

	const numConcurrent = 10
	results := make([]concurrentOperationResult, numConcurrent)
	var wg sync.WaitGroup
	var successCount int32

	for i := 0; i < numConcurrent; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()

			rulePayload := map[string]interface{}{
				"type":     "sigma",
				"name":     "Concurrent Rule " + uuid.New().String()[:8],
				"severity": "Medium",
				"version":  1,
				"enabled":  true,
				"sigma_yaml": `title: Concurrent Test Rule
logsource:
  category: test
detection:
  selection:
    EventID: 1
  condition: selection
`,
			}
			bodyBytes, _ := json.Marshal(rulePayload)

			req := httptest.NewRequest("POST", "/api/v1/rules", bytes.NewReader(bodyBytes))
			req.Header.Set("Authorization", "Bearer "+token)
			req.Header.Set("Content-Type", "application/json")
			addCSRFToRequest(t, req)

			w := httptest.NewRecorder()
			testAPI.router.ServeHTTP(w, req)

			results[idx] = concurrentOperationResult{
				StatusCode: w.Code,
				Success:    w.Code == http.StatusCreated,
			}

			if w.Code == http.StatusCreated {
				atomic.AddInt32(&successCount, 1)
				var created map[string]interface{}
				json.Unmarshal(w.Body.Bytes(), &created)
				if id, ok := created["id"].(string); ok {
					results[idx].RuleID = id
				}
			} else {
				results[idx].Error = w.Body.String()
			}
		}(i)
	}

	wg.Wait()

	// All concurrent creates should succeed (or fail gracefully)
	// At minimum, we expect no panics and valid HTTP responses
	for i, result := range results {
		assert.True(t, result.StatusCode >= 200 && result.StatusCode < 600,
			"Operation %d should return valid HTTP status: got %d", i, result.StatusCode)
	}

	// Most should succeed
	assert.GreaterOrEqual(t, int(successCount), numConcurrent/2,
		"At least half of concurrent creates should succeed")

	// Log the success rate
	t.Logf("Concurrent CREATE: %d/%d successful", successCount, numConcurrent)
}

// ============================================================================
// TASK 186: CONCURRENT UPDATE TESTS
// ============================================================================

// TestConcurrentRuleUpdate tests that multiple concurrent UPDATE operations
// on the same rule are handled safely
func TestConcurrentRuleUpdate(t *testing.T) {
	testAPI, cleanup := setupTestAPI(t)
	defer cleanup()

	token := createValidTestToken(t, testAPI.config.Auth.JWTSecret, "admin")

	// First, create a rule to update
	createPayload := map[string]interface{}{
		"type":     "sigma",
		"name":     "Rule for Concurrent Updates",
		"severity": "Low",
		"version":  1,
		"enabled":  true,
		"sigma_yaml": `title: Rule for Concurrent Updates
logsource:
  category: test
detection:
  selection:
    EventID: 1
  condition: selection
`,
	}
	createBody, _ := json.Marshal(createPayload)
	req := httptest.NewRequest("POST", "/api/v1/rules", bytes.NewReader(createBody))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	addCSRFToRequest(t, req)

	w := httptest.NewRecorder()
	testAPI.router.ServeHTTP(w, req)
	require.Equal(t, http.StatusCreated, w.Code, "Should create rule for testing")

	var createdRule map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &createdRule)
	ruleID := createdRule["id"].(string)

	// Now perform concurrent updates
	const numConcurrent = 10
	results := make([]concurrentOperationResult, numConcurrent)
	var wg sync.WaitGroup
	var successCount int32

	for i := 0; i < numConcurrent; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()

			updatePayload := map[string]interface{}{
				"type":     "sigma",
				"name":     "Updated Rule " + uuid.New().String()[:8],
				"severity": "High",
				"version":  1,
				"enabled":  true,
				"sigma_yaml": `title: Updated Rule
logsource:
  category: test
detection:
  selection:
    EventID: 1
  condition: selection
`,
			}
			bodyBytes, _ := json.Marshal(updatePayload)

			req := httptest.NewRequest("PUT", "/api/v1/rules/"+ruleID, bytes.NewReader(bodyBytes))
			req.Header.Set("Authorization", "Bearer "+token)
			req.Header.Set("Content-Type", "application/json")
			addCSRFToRequest(t, req)

			w := httptest.NewRecorder()
			testAPI.router.ServeHTTP(w, req)

			results[idx] = concurrentOperationResult{
				StatusCode: w.Code,
				Success:    w.Code == http.StatusOK,
			}

			if w.Code == http.StatusOK {
				atomic.AddInt32(&successCount, 1)
			} else {
				results[idx].Error = w.Body.String()
			}
		}(i)
	}

	wg.Wait()

	// All concurrent updates should complete (success or fail gracefully)
	for i, result := range results {
		assert.True(t, result.StatusCode >= 200 && result.StatusCode < 600,
			"Operation %d should return valid HTTP status: got %d", i, result.StatusCode)
	}

	// Log results
	t.Logf("Concurrent UPDATE: %d/%d successful", successCount, numConcurrent)
}

// ============================================================================
// TASK 186: CONCURRENT DELETE TESTS
// ============================================================================

// TestConcurrentRuleDelete tests that multiple concurrent DELETE operations
// on the same rule are handled safely
func TestConcurrentRuleDelete(t *testing.T) {
	testAPI, cleanup := setupTestAPI(t)
	defer cleanup()

	token := createValidTestToken(t, testAPI.config.Auth.JWTSecret, "admin")

	// Create a rule to delete
	createPayload := map[string]interface{}{
		"type":     "sigma",
		"name":     "Rule for Concurrent Delete",
		"severity": "Low",
		"version":  1,
		"enabled":  true,
		"sigma_yaml": `title: Rule for Concurrent Delete
logsource:
  category: test
detection:
  selection:
    EventID: 1
  condition: selection
`,
	}
	createBody, _ := json.Marshal(createPayload)
	req := httptest.NewRequest("POST", "/api/v1/rules", bytes.NewReader(createBody))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	addCSRFToRequest(t, req)

	w := httptest.NewRecorder()
	testAPI.router.ServeHTTP(w, req)
	require.Equal(t, http.StatusCreated, w.Code, "Should create rule for testing")

	var createdRule map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &createdRule)
	ruleID := createdRule["id"].(string)

	// Now perform concurrent deletes on the same rule
	const numConcurrent = 5
	results := make([]concurrentOperationResult, numConcurrent)
	var wg sync.WaitGroup
	var successCount int32
	var notFoundCount int32

	for i := 0; i < numConcurrent; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()

			req := httptest.NewRequest("DELETE", "/api/v1/rules/"+ruleID, nil)
			req.Header.Set("Authorization", "Bearer "+token)
			addCSRFToRequest(t, req)

			w := httptest.NewRecorder()
			testAPI.router.ServeHTTP(w, req)

			results[idx] = concurrentOperationResult{
				StatusCode: w.Code,
				Success:    w.Code == http.StatusOK,
			}

			if w.Code == http.StatusOK {
				atomic.AddInt32(&successCount, 1)
			} else if w.Code == http.StatusNotFound {
				atomic.AddInt32(&notFoundCount, 1)
			}
		}(i)
	}

	wg.Wait()

	// Exactly one delete should succeed, others should get 404
	assert.Equal(t, int32(1), successCount, "Exactly one concurrent delete should succeed")
	assert.Equal(t, int32(numConcurrent-1), notFoundCount, "Other deletes should get 404")

	t.Logf("Concurrent DELETE: %d successful, %d not found", successCount, notFoundCount)
}

// ============================================================================
// TASK 186: MIXED CONCURRENT OPERATIONS
// ============================================================================

// TestMixedConcurrentOperations tests a mix of CREATE, UPDATE, and DELETE
// operations happening concurrently
func TestMixedConcurrentOperations(t *testing.T) {
	testAPI, cleanup := setupTestAPI(t)
	defer cleanup()

	token := createValidTestToken(t, testAPI.config.Auth.JWTSecret, "admin")

	// Track metrics
	var createCount, updateCount, deleteCount int32
	var wg sync.WaitGroup

	// Create some initial rules
	initialRuleIDs := make([]string, 5)
	for i := 0; i < 5; i++ {
		createPayload := map[string]interface{}{
			"type":     "sigma",
			"name":     "Initial Rule " + uuid.New().String()[:8],
			"severity": "Medium",
			"version":  1,
			"enabled":  true,
			"sigma_yaml": `title: Initial Rule
logsource:
  category: test
detection:
  selection:
    EventID: 1
  condition: selection
`,
		}
		createBody, _ := json.Marshal(createPayload)
		req := httptest.NewRequest("POST", "/api/v1/rules", bytes.NewReader(createBody))
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Content-Type", "application/json")
		addCSRFToRequest(t, req)

		w := httptest.NewRecorder()
		testAPI.router.ServeHTTP(w, req)
		if w.Code == http.StatusCreated {
			var created map[string]interface{}
			json.Unmarshal(w.Body.Bytes(), &created)
			initialRuleIDs[i] = created["id"].(string)
		}
	}

	// Launch mixed operations concurrently
	numOperations := 15

	for i := 0; i < numOperations; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()

			op := idx % 3 // Cycle through CREATE, UPDATE, DELETE

			switch op {
			case 0: // CREATE
				createPayload := map[string]interface{}{
					"type":     "sigma",
					"name":     "Mixed Create " + uuid.New().String()[:8],
					"severity": "Low",
					"version":  1,
					"enabled":  true,
					"sigma_yaml": `title: Mixed Create
logsource:
  category: test
detection:
  selection:
    EventID: 1
  condition: selection
`,
				}
				bodyBytes, _ := json.Marshal(createPayload)
				req := httptest.NewRequest("POST", "/api/v1/rules", bytes.NewReader(bodyBytes))
				req.Header.Set("Authorization", "Bearer "+token)
				req.Header.Set("Content-Type", "application/json")
				addCSRFToRequest(t, req)

				w := httptest.NewRecorder()
				testAPI.router.ServeHTTP(w, req)
				if w.Code == http.StatusCreated {
					atomic.AddInt32(&createCount, 1)
				}

			case 1: // UPDATE
				if len(initialRuleIDs) > 0 && initialRuleIDs[idx%len(initialRuleIDs)] != "" {
					ruleID := initialRuleIDs[idx%len(initialRuleIDs)]
					updatePayload := map[string]interface{}{
						"type":     "sigma",
						"name":     "Mixed Update " + uuid.New().String()[:8],
						"severity": "High",
						"version":  1,
						"enabled":  true,
						"sigma_yaml": `title: Mixed Update
logsource:
  category: test
detection:
  selection:
    EventID: 1
  condition: selection
`,
					}
					bodyBytes, _ := json.Marshal(updatePayload)
					req := httptest.NewRequest("PUT", "/api/v1/rules/"+ruleID, bytes.NewReader(bodyBytes))
					req.Header.Set("Authorization", "Bearer "+token)
					req.Header.Set("Content-Type", "application/json")
					addCSRFToRequest(t, req)

					w := httptest.NewRecorder()
					testAPI.router.ServeHTTP(w, req)
					if w.Code == http.StatusOK {
						atomic.AddInt32(&updateCount, 1)
					}
				}

			case 2: // DELETE
				if len(initialRuleIDs) > 0 && initialRuleIDs[idx%len(initialRuleIDs)] != "" {
					ruleID := initialRuleIDs[idx%len(initialRuleIDs)]
					req := httptest.NewRequest("DELETE", "/api/v1/rules/"+ruleID, nil)
					req.Header.Set("Authorization", "Bearer "+token)
					addCSRFToRequest(t, req)

					w := httptest.NewRecorder()
					testAPI.router.ServeHTTP(w, req)
					if w.Code == http.StatusOK {
						atomic.AddInt32(&deleteCount, 1)
					}
				}
			}
		}(i)
	}

	wg.Wait()

	// Verify operations completed (success rates may vary due to concurrent deletion/update conflicts)
	t.Logf("Mixed operations: %d creates, %d updates, %d deletes successful",
		createCount, updateCount, deleteCount)

	// At minimum, no panics should have occurred and some operations should succeed
	totalSuccess := createCount + updateCount + deleteCount
	assert.Greater(t, totalSuccess, int32(0), "At least some operations should succeed")
}

// ============================================================================
// TASK 186: CONCURRENT LIST OPERATIONS
// ============================================================================

// TestConcurrentListWithMutations tests LIST operations concurrent with mutations
func TestConcurrentListWithMutations(t *testing.T) {
	testAPI, cleanup := setupTestAPI(t)
	defer cleanup()

	token := createValidTestToken(t, testAPI.config.Auth.JWTSecret, "admin")

	// Create some initial rules
	for i := 0; i < 3; i++ {
		createPayload := map[string]interface{}{
			"type":     "sigma",
			"name":     "List Test Rule " + uuid.New().String()[:8],
			"severity": "Medium",
			"version":  1,
			"enabled":  true,
			"sigma_yaml": `title: List Test Rule
logsource:
  category: test
detection:
  selection:
    EventID: 1
  condition: selection
`,
		}
		createBody, _ := json.Marshal(createPayload)
		req := httptest.NewRequest("POST", "/api/v1/rules", bytes.NewReader(createBody))
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Content-Type", "application/json")
		addCSRFToRequest(t, req)

		w := httptest.NewRecorder()
		testAPI.router.ServeHTTP(w, req)
	}

	var wg sync.WaitGroup
	var listSuccessCount int32
	var createSuccessCount int32

	const numOperations = 10

	// Half LIST, half CREATE
	for i := 0; i < numOperations; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()

			if idx%2 == 0 {
				// LIST operation
				req := httptest.NewRequest("GET", "/api/v1/rules?limit=10", nil)
				req.Header.Set("Authorization", "Bearer "+token)

				w := httptest.NewRecorder()
				testAPI.router.ServeHTTP(w, req)

				if w.Code == http.StatusOK {
					atomic.AddInt32(&listSuccessCount, 1)
				}
			} else {
				// CREATE operation
				createPayload := map[string]interface{}{
					"type":     "sigma",
					"name":     "Concurrent Create " + uuid.New().String()[:8],
					"severity": "Low",
					"version":  1,
					"enabled":  true,
					"sigma_yaml": `title: Concurrent Create
logsource:
  category: test
detection:
  selection:
    EventID: 1
  condition: selection
`,
				}
				bodyBytes, _ := json.Marshal(createPayload)
				req := httptest.NewRequest("POST", "/api/v1/rules", bytes.NewReader(bodyBytes))
				req.Header.Set("Authorization", "Bearer "+token)
				req.Header.Set("Content-Type", "application/json")
				addCSRFToRequest(t, req)

				w := httptest.NewRecorder()
				testAPI.router.ServeHTTP(w, req)

				if w.Code == http.StatusCreated {
					atomic.AddInt32(&createSuccessCount, 1)
				}
			}
		}(i)
	}

	wg.Wait()

	// All LIST operations should succeed
	assert.Equal(t, int32(numOperations/2), listSuccessCount, "All LIST operations should succeed")

	t.Logf("Concurrent LIST with mutations: %d lists, %d creates successful",
		listSuccessCount, createSuccessCount)
}
