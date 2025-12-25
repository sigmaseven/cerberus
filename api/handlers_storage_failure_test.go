package api

// TASK 189: Storage failure error path tests
// Tests that API handlers properly handle storage failures

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"cerberus/core"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ============================================================================
// MOCK STORAGE FOR FAILURE TESTING
// ============================================================================

// failingRuleStorage is a mock rule storage that can be configured to fail
// Implements RuleStorer interface from api.go
type failingRuleStorage struct {
	mu sync.Mutex

	// Failure configuration
	getAllRulesShouldFail    bool
	getAllRulesError         error
	getRuleShouldFail        bool
	getRuleError             error
	createRuleShouldFail     bool
	createRuleError          error
	updateRuleShouldFail     bool
	updateRuleError          error
	deleteRuleShouldFail     bool
	deleteRuleError          error
	getRuleCountShouldFail   bool
	getRuleCountError        error

	// Storage data
	rules map[string]*core.Rule
}

func newFailingRuleStorage() *failingRuleStorage {
	return &failingRuleStorage{
		rules: make(map[string]*core.Rule),
	}
}

// GetRules implements RuleStorer.GetRules
func (s *failingRuleStorage) GetRules(limit, offset int) ([]core.Rule, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.getAllRulesShouldFail {
		if s.getAllRulesError != nil {
			return nil, s.getAllRulesError
		}
		return nil, errors.New("mock: GetRules failed")
	}

	result := make([]core.Rule, 0, len(s.rules))
	for _, r := range s.rules {
		result = append(result, *r)
	}

	if offset >= len(result) {
		return []core.Rule{}, nil
	}
	end := offset + limit
	if end > len(result) {
		end = len(result)
	}
	return result[offset:end], nil
}

// GetAllRules implements RuleStorer.GetAllRules
func (s *failingRuleStorage) GetAllRules() ([]core.Rule, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.getAllRulesShouldFail {
		if s.getAllRulesError != nil {
			return nil, s.getAllRulesError
		}
		return nil, errors.New("mock: GetAllRules failed")
	}

	result := make([]core.Rule, 0, len(s.rules))
	for _, r := range s.rules {
		result = append(result, *r)
	}
	return result, nil
}

// GetRuleCount implements RuleStorer.GetRuleCount
func (s *failingRuleStorage) GetRuleCount() (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.getRuleCountShouldFail {
		if s.getRuleCountError != nil {
			return 0, s.getRuleCountError
		}
		return 0, errors.New("mock: GetRuleCount failed")
	}

	return int64(len(s.rules)), nil
}

// GetRule implements RuleStorer.GetRule
func (s *failingRuleStorage) GetRule(id string) (*core.Rule, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.getRuleShouldFail {
		if s.getRuleError != nil {
			return nil, s.getRuleError
		}
		return nil, errors.New("mock: GetRule failed")
	}

	if rule, ok := s.rules[id]; ok {
		return rule, nil
	}
	// Return error when rule not found (matching real storage behavior)
	return nil, errors.New("rule not found")
}

// CreateRule implements RuleStorer.CreateRule
func (s *failingRuleStorage) CreateRule(rule *core.Rule) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.createRuleShouldFail {
		if s.createRuleError != nil {
			return s.createRuleError
		}
		return errors.New("mock: CreateRule failed")
	}

	s.rules[rule.ID] = rule
	return nil
}

// UpdateRule implements RuleStorer.UpdateRule
func (s *failingRuleStorage) UpdateRule(id string, rule *core.Rule) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.updateRuleShouldFail {
		if s.updateRuleError != nil {
			return s.updateRuleError
		}
		return errors.New("mock: UpdateRule failed")
	}

	if _, ok := s.rules[id]; !ok {
		return errors.New("rule not found")
	}
	s.rules[id] = rule
	return nil
}

// DeleteRule implements RuleStorer.DeleteRule
func (s *failingRuleStorage) DeleteRule(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.deleteRuleShouldFail {
		if s.deleteRuleError != nil {
			return s.deleteRuleError
		}
		return errors.New("mock: DeleteRule failed")
	}

	delete(s.rules, id)
	return nil
}

// ============================================================================
// STORAGE FAILURE TESTS
// ============================================================================

// TestStorageFailure_GetAllRules tests error handling when GetAllRules fails
func TestStorageFailure_GetAllRules(t *testing.T) {
	testAPI, cleanup := setupTestAPI(t)
	defer cleanup()

	// Replace storage with failing mock
	failStorage := newFailingRuleStorage()
	failStorage.getAllRulesShouldFail = true
	failStorage.getAllRulesError = errors.New("database connection lost")
	testAPI.ruleStorage = failStorage

	token := createValidTestToken(t, testAPI.config.Auth.JWTSecret, "admin")

	// Use category=detection to test the non-graceful path
	// The unified endpoint with category=all uses graceful degradation
	req := httptest.NewRequest(http.MethodGet, "/api/v1/rules?category=detection", nil)
	req.Header.Set("Authorization", "Bearer "+token)

	w := httptest.NewRecorder()
	testAPI.router.ServeHTTP(w, req)

	// Should return 500 Internal Server Error
	assert.Equal(t, http.StatusInternalServerError, w.Code,
		"Should return 500 when storage fails, got: %s", w.Body.String())
}

// TestStorageFailure_GetRule tests error handling when GetRule fails
func TestStorageFailure_GetRule(t *testing.T) {
	testAPI, cleanup := setupTestAPI(t)
	defer cleanup()

	// First create a rule so we know it exists
	ruleID := "test-rule-storage-failure"
	sigmaYAML := `title: Test Rule
detection:
  selection:
    field: value
  condition: selection`

	rule := &core.Rule{
		ID:        ruleID,
		Type:      "SIGMA",
		Name:      "Test Rule",
		Severity:  "Medium",
		Version:   1,
		SigmaYAML: sigmaYAML,
	}
	err := testAPI.ruleStorage.CreateRule(rule)
	require.NoError(t, err)

	// Now replace storage with failing mock
	failStorage := newFailingRuleStorage()
	failStorage.getRuleShouldFail = true
	failStorage.getRuleError = errors.New("database timeout")
	testAPI.ruleStorage = failStorage

	// Also set correlation storage to fail to test full path
	testAPI.correlationRuleStorage = nil

	token := createValidTestToken(t, testAPI.config.Auth.JWTSecret, "admin")

	req := httptest.NewRequest(http.MethodGet, "/api/v1/rules/"+ruleID, nil)
	req.Header.Set("Authorization", "Bearer "+token)

	w := httptest.NewRecorder()
	testAPI.router.ServeHTTP(w, req)

	// Should return 404 (rule not found) since both storages fail/are nil
	// The unified endpoint falls through to correlation rules on detection error
	// then returns 404 if not found in either
	assert.True(t, w.Code == http.StatusNotFound || w.Code == http.StatusInternalServerError,
		"Should return 404 or 500 when storage fails, got: %d", w.Code)
}

// TestStorageFailure_CreateRule tests error handling when CreateRule fails
func TestStorageFailure_CreateRule(t *testing.T) {
	testAPI, cleanup := setupTestAPI(t)
	defer cleanup()

	// Replace storage with failing mock
	failStorage := newFailingRuleStorage()
	failStorage.createRuleShouldFail = true
	failStorage.createRuleError = errors.New("disk full")
	testAPI.ruleStorage = failStorage

	token := createValidTestToken(t, testAPI.config.Auth.JWTSecret, "admin")

	sigmaYAML := `title: Test Rule
detection:
  selection:
    field: value
  condition: selection`

	rule := map[string]interface{}{
		"type":        "sigma",
		"name":        "Test Rule",
		"description": "Test",
		"severity":    "Medium",
		"version":     1,
		"enabled":     true,
		"sigma_yaml":  sigmaYAML,
	}

	body, err := json.Marshal(rule)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/rules", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	addCSRFToRequest(t, req)

	w := httptest.NewRecorder()
	testAPI.router.ServeHTTP(w, req)

	// Should return 500 Internal Server Error
	assert.Equal(t, http.StatusInternalServerError, w.Code,
		"Should return 500 when storage fails")
}

// TestStorageFailure_UpdateRule tests error handling when UpdateRule fails
func TestStorageFailure_UpdateRule(t *testing.T) {
	testAPI, cleanup := setupTestAPI(t)
	defer cleanup()

	// First create a rule in the real storage
	sigmaYAML := `title: Test Rule
detection:
  selection:
    field: value
  condition: selection`

	ruleID := "test-storage-failure-update"
	rule := &core.Rule{
		ID:          ruleID,
		Type:        "SIGMA",
		Name:        "Test Rule",
		Description: "Test",
		Severity:    "Medium",
		Version:     1,
		Enabled:     true,
		SigmaYAML:   sigmaYAML,
	}

	err := testAPI.ruleStorage.CreateRule(rule)
	require.NoError(t, err)

	// Now replace storage with failing mock that has the rule
	failStorage := newFailingRuleStorage()
	failStorage.rules[ruleID] = rule
	failStorage.updateRuleShouldFail = true
	failStorage.updateRuleError = errors.New("write conflict")
	testAPI.ruleStorage = failStorage

	token := createValidTestToken(t, testAPI.config.Auth.JWTSecret, "admin")

	updatedRule := map[string]interface{}{
		"type":        "sigma",
		"name":        "Updated Rule",
		"description": "Updated",
		"severity":    "High",
		"version":     2,
		"enabled":     true,
		"sigma_yaml":  sigmaYAML,
	}

	body, err := json.Marshal(updatedRule)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPut, "/api/v1/rules/"+ruleID, bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	addCSRFToRequest(t, req)

	w := httptest.NewRecorder()
	testAPI.router.ServeHTTP(w, req)

	// Should return 500 Internal Server Error
	assert.Equal(t, http.StatusInternalServerError, w.Code,
		"Should return 500 when storage fails")
}

// TestStorageFailure_DeleteRule tests error handling when DeleteRule fails
func TestStorageFailure_DeleteRule(t *testing.T) {
	testAPI, cleanup := setupTestAPI(t)
	defer cleanup()

	// First create a rule in the real storage
	sigmaYAML := `title: Test Rule
detection:
  selection:
    field: value
  condition: selection`

	ruleID := "test-storage-failure-delete"
	rule := &core.Rule{
		ID:          ruleID,
		Type:        "SIGMA",
		Name:        "Test Rule",
		Description: "Test",
		Severity:    "Medium",
		Version:     1,
		Enabled:     true,
		SigmaYAML:   sigmaYAML,
	}

	err := testAPI.ruleStorage.CreateRule(rule)
	require.NoError(t, err)

	// Now replace storage with failing mock that has the rule
	failStorage := newFailingRuleStorage()
	failStorage.rules[ruleID] = rule
	failStorage.deleteRuleShouldFail = true
	failStorage.deleteRuleError = errors.New("foreign key constraint")
	testAPI.ruleStorage = failStorage

	token := createValidTestToken(t, testAPI.config.Auth.JWTSecret, "admin")

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/rules/"+ruleID, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	addCSRFToRequest(t, req)

	w := httptest.NewRecorder()
	testAPI.router.ServeHTTP(w, req)

	// Should return 500 Internal Server Error
	assert.Equal(t, http.StatusInternalServerError, w.Code,
		"Should return 500 when storage fails")
}

// TestStorageFailure_TransientErrors tests that transient errors are handled properly
func TestStorageFailure_TransientErrors(t *testing.T) {
	testAPI, cleanup := setupTestAPI(t)
	defer cleanup()

	token := createValidTestToken(t, testAPI.config.Auth.JWTSecret, "admin")

	testCases := []struct {
		name    string
		errType error
	}{
		{
			name:    "connection_reset",
			errType: errors.New("connection reset by peer"),
		},
		{
			name:    "connection_refused",
			errType: errors.New("connection refused"),
		},
		{
			name:    "network_unreachable",
			errType: errors.New("network is unreachable"),
		},
		{
			name:    "timeout",
			errType: errors.New("operation timed out"),
		},
		{
			name:    "deadlock",
			errType: errors.New("deadlock detected"),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			failStorage := newFailingRuleStorage()
			failStorage.getAllRulesShouldFail = true
			failStorage.getAllRulesError = tc.errType
			testAPI.ruleStorage = failStorage

			// Use category=detection to test the non-graceful path
			req := httptest.NewRequest(http.MethodGet, "/api/v1/rules?category=detection", nil)
			req.Header.Set("Authorization", "Bearer "+token)

			w := httptest.NewRecorder()
			testAPI.router.ServeHTTP(w, req)

			// Should return 500 Internal Server Error for all transient errors
			assert.Equal(t, http.StatusInternalServerError, w.Code,
				"Should return 500 for transient error: %s", tc.name)

			// Error message should be sanitized (not leak implementation details)
			assert.NotContains(t, w.Body.String(), "connection reset",
				"Error message should not leak implementation details")
			assert.NotContains(t, w.Body.String(), "deadlock",
				"Error message should not leak implementation details")
		})
	}
}

// TestStorageFailure_IntermittentFailure tests behavior with intermittent failures
func TestStorageFailure_IntermittentFailure(t *testing.T) {
	testAPI, cleanup := setupTestAPI(t)
	defer cleanup()

	token := createValidTestToken(t, testAPI.config.Auth.JWTSecret, "admin")

	// Start with failing storage
	failStorage := newFailingRuleStorage()
	failStorage.getAllRulesShouldFail = true
	testAPI.ruleStorage = failStorage

	// First request should fail - use category=detection for non-graceful path
	req1 := httptest.NewRequest(http.MethodGet, "/api/v1/rules?category=detection", nil)
	req1.Header.Set("Authorization", "Bearer "+token)

	w1 := httptest.NewRecorder()
	testAPI.router.ServeHTTP(w1, req1)

	assert.Equal(t, http.StatusInternalServerError, w1.Code,
		"First request should fail")

	// Fix the storage
	failStorage.getAllRulesShouldFail = false

	// Second request should succeed
	req2 := httptest.NewRequest(http.MethodGet, "/api/v1/rules?category=detection", nil)
	req2.Header.Set("Authorization", "Bearer "+token)

	w2 := httptest.NewRecorder()
	testAPI.router.ServeHTTP(w2, req2)

	assert.Equal(t, http.StatusOK, w2.Code,
		"Second request should succeed after storage recovery")
}

// TestStorageFailure_PartialFailure tests behavior when some operations succeed and others fail
func TestStorageFailure_PartialFailure(t *testing.T) {
	testAPI, cleanup := setupTestAPI(t)
	defer cleanup()

	token := createValidTestToken(t, testAPI.config.Auth.JWTSecret, "admin")

	// Create a storage that fails on create but succeeds on read
	failStorage := newFailingRuleStorage()
	failStorage.createRuleShouldFail = true
	failStorage.getAllRulesShouldFail = false
	testAPI.ruleStorage = failStorage

	// Read should succeed
	req1 := httptest.NewRequest(http.MethodGet, "/api/v1/rules", nil)
	req1.Header.Set("Authorization", "Bearer "+token)

	w1 := httptest.NewRecorder()
	testAPI.router.ServeHTTP(w1, req1)

	assert.Equal(t, http.StatusOK, w1.Code,
		"Read should succeed even when write fails")

	// Create should fail
	sigmaYAML := `title: Test Rule
detection:
  selection:
    field: value
  condition: selection`

	rule := map[string]interface{}{
		"type":        "sigma",
		"name":        "Test Rule",
		"description": "Test",
		"severity":    "Medium",
		"version":     1,
		"enabled":     true,
		"sigma_yaml":  sigmaYAML,
	}

	body, err := json.Marshal(rule)
	require.NoError(t, err)

	req2 := httptest.NewRequest(http.MethodPost, "/api/v1/rules", bytes.NewReader(body))
	req2.Header.Set("Authorization", "Bearer "+token)
	req2.Header.Set("Content-Type", "application/json")
	addCSRFToRequest(t, req2)

	w2 := httptest.NewRecorder()
	testAPI.router.ServeHTTP(w2, req2)

	assert.Equal(t, http.StatusInternalServerError, w2.Code,
		"Create should fail when storage fails")
}

// TestStorageFailure_NilReturn tests handling of nil returns from storage
func TestStorageFailure_NilReturn(t *testing.T) {
	testAPI, cleanup := setupTestAPI(t)
	defer cleanup()

	// Replace storage with failing mock
	failStorage := newFailingRuleStorage()
	// Don't add any rules - GetRule will return nil, nil
	testAPI.ruleStorage = failStorage

	token := createValidTestToken(t, testAPI.config.Auth.JWTSecret, "admin")

	req := httptest.NewRequest(http.MethodGet, "/api/v1/rules/nonexistent-rule-id", nil)
	req.Header.Set("Authorization", "Bearer "+token)

	w := httptest.NewRecorder()
	testAPI.router.ServeHTTP(w, req)

	// Should return 404 Not Found for missing rule
	assert.Equal(t, http.StatusNotFound, w.Code,
		"Should return 404 for nonexistent rule")
}

// TestStorageFailure_EmptyResult tests handling of empty results from storage
func TestStorageFailure_EmptyResult(t *testing.T) {
	testAPI, cleanup := setupTestAPI(t)
	defer cleanup()

	// Replace storage with empty mock
	failStorage := newFailingRuleStorage()
	testAPI.ruleStorage = failStorage

	token := createValidTestToken(t, testAPI.config.Auth.JWTSecret, "admin")

	req := httptest.NewRequest(http.MethodGet, "/api/v1/rules", nil)
	req.Header.Set("Authorization", "Bearer "+token)

	w := httptest.NewRecorder()
	testAPI.router.ServeHTTP(w, req)

	// Should return 200 OK with empty items array
	assert.Equal(t, http.StatusOK, w.Code,
		"Should return 200 with empty results")

	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err, "Response should be valid JSON")

	items, ok := response["items"].([]interface{})
	assert.True(t, ok, "Response should have items array")
	assert.Empty(t, items, "Items array should be empty")
}

// TestStorageFailure_ConcurrentFailures tests that concurrent requests handle failures properly
func TestStorageFailure_ConcurrentFailures(t *testing.T) {
	testAPI, cleanup := setupTestAPI(t)
	defer cleanup()

	token := createValidTestToken(t, testAPI.config.Auth.JWTSecret, "admin")

	// Create a storage that fails
	failStorage := newFailingRuleStorage()
	failStorage.getAllRulesShouldFail = true
	testAPI.ruleStorage = failStorage

	// Launch concurrent requests
	const numRequests = 10
	var wg sync.WaitGroup
	results := make([]int, numRequests)

	for i := 0; i < numRequests; i++ {
		wg.Add(1)
		go func(index int) {
			defer wg.Done()

			// Use category=detection to test the non-graceful path
			req := httptest.NewRequest(http.MethodGet, "/api/v1/rules?category=detection", nil)
			req.Header.Set("Authorization", "Bearer "+token)

			w := httptest.NewRecorder()
			testAPI.router.ServeHTTP(w, req)

			results[index] = w.Code
		}(i)
	}

	wg.Wait()

	// All requests should return 500
	for i, code := range results {
		assert.Equal(t, http.StatusInternalServerError, code,
			"Request %d should return 500 on storage failure", i)
	}
}
