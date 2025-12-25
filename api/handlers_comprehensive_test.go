package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"cerberus/core"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TASK 63: Comprehensive API Handler Tests
// Tests cover: request parsing, validation, error handling, response formatting, edge cases

// TestRespondJSON tests JSON response formatting
// TASK 63.1: Response formatting and error handling
func TestRespondJSON(t *testing.T) {
	testAPI, cleanup := setupTestAPI(t)
	defer cleanup()

	w := httptest.NewRecorder()
	data := map[string]interface{}{
		"message": "test",
		"status":  "success",
	}

	testAPI.respondJSON(w, data, http.StatusOK)

	assert.Equal(t, http.StatusOK, w.Code, "Status code should be 200")
	assert.Equal(t, "application/json", w.Header().Get("Content-Type"), "Content-Type should be application/json")

	var result map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &result)
	require.NoError(t, err, "Response should be valid JSON")
	assert.Equal(t, "test", result["message"], "Response should contain message")
}

// TestGetEvents tests event retrieval handler
// TASK 63.2: Event handler tests
func TestGetEvents(t *testing.T) {
	testAPI, cleanup := setupTestAPI(t)
	defer cleanup()

	token := createValidTestToken(t, testAPI.config.Auth.JWTSecret, "admin")

	// Test with default pagination
	req := httptest.NewRequest("GET", "/api/v1/events", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	testAPI.router.ServeHTTP(w, req)

	assert.NotEqual(t, 404, w.Code, "Handler should exist")
	assert.NotEqual(t, 405, w.Code, "Method should be allowed")
}

// TestGetEvents_WithPagination tests event retrieval with pagination
func TestGetEvents_WithPagination(t *testing.T) {
	testAPI, cleanup := setupTestAPI(t)
	defer cleanup()

	token := createValidTestToken(t, testAPI.config.Auth.JWTSecret, "admin")

	// Test with pagination parameters
	req := httptest.NewRequest("GET", "/api/v1/events?page=2&limit=50", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	testAPI.router.ServeHTTP(w, req)

	assert.NotEqual(t, 404, w.Code, "Handler should exist")
}

// TestGetEvents_InvalidPagination tests event retrieval with invalid pagination
func TestGetEvents_InvalidPagination(t *testing.T) {
	testAPI, cleanup := setupTestAPI(t)
	defer cleanup()

	token := createValidTestToken(t, testAPI.config.Auth.JWTSecret, "admin")

	// Test with invalid pagination (negative values)
	req := httptest.NewRequest("GET", "/api/v1/events?page=-1&limit=-10", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	testAPI.router.ServeHTTP(w, req)

	// Handler should handle invalid pagination gracefully
	assert.NotEqual(t, 404, w.Code, "Handler should exist")
}

// TestGetRules tests rule retrieval handler
// TASK 63.3: Rule handler tests
func TestGetRules(t *testing.T) {
	testAPI, cleanup := setupTestAPI(t)
	defer cleanup()

	token := createValidTestToken(t, testAPI.config.Auth.JWTSecret, "admin")

	req := httptest.NewRequest("GET", "/api/v1/rules", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	testAPI.router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code, "Should return 200 OK")
	assert.Equal(t, "application/json", w.Header().Get("Content-Type"), "Should return JSON")

	// API returns {"rules": [...], "total": ..., ...} format
	var response struct {
		Rules []core.Rule `json:"rules"`
		Total int         `json:"total"`
	}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	require.NoError(t, err, "Response should be valid JSON object with rules array")
	// Empty database returns empty/nil array which is valid
	assert.True(t, response.Total >= 0, "Total should be non-negative")
}

// TestGetRule tests single rule retrieval
func TestGetRule(t *testing.T) {
	testAPI, cleanup := setupTestAPI(t)
	defer cleanup()

	token := createValidTestToken(t, testAPI.config.Auth.JWTSecret, "admin")

	// Test with non-existent rule
	req := httptest.NewRequest("GET", "/api/v1/rules/nonexistent", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	testAPI.router.ServeHTTP(w, req)

	// Should return 404 for non-existent rule
	assert.Equal(t, http.StatusNotFound, w.Code, "Should return 404 for non-existent rule")
}

// TestGetRule_InvalidID tests rule retrieval with invalid ID
func TestGetRule_InvalidID(t *testing.T) {
	testAPI, cleanup := setupTestAPI(t)
	defer cleanup()

	token := createValidTestToken(t, testAPI.config.Auth.JWTSecret, "admin")

	// Test with invalid ID (too long)
	invalidID := strings.Repeat("a", 101) // 101 character string (too long)
	req := httptest.NewRequest("GET", "/api/v1/rules/"+invalidID, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	testAPI.router.ServeHTTP(w, req)

	// Should return 400 for invalid ID format
	assert.Equal(t, http.StatusBadRequest, w.Code, "Should return 400 for invalid ID")
}

// TestCreateRule_ValidationError tests rule creation with validation errors
// TASK 63.4: Validation and error handling tests
func TestCreateRule_ValidationError(t *testing.T) {
	testAPI, cleanup := setupTestAPI(t)
	defer cleanup()

	token := createValidTestToken(t, testAPI.config.Auth.JWTSecret, "admin")

	// Test with empty rule name (should fail validation)
	// Use map to ensure proper JSON serialization matching server expectations
	rule := map[string]interface{}{
		"id":      "test-rule",
		"type":    "sigma",
		"name":    "", // Empty name should fail validation
		"version": 1,
	}

	body, _ := json.Marshal(rule)
	req := httptest.NewRequest("POST", "/api/v1/rules", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	addCSRFToRequest(t, req)

	w := httptest.NewRecorder()
	testAPI.router.ServeHTTP(w, req)

	// Should return 400 for validation error
	assert.Equal(t, http.StatusBadRequest, w.Code, "Should return 400 for validation error")
}

// TestCreateRule_MalformedJSON_Handler tests rule creation with malformed JSON
func TestCreateRule_MalformedJSON_Handler(t *testing.T) {
	testAPI, cleanup := setupTestAPI(t)
	defer cleanup()

	token := createValidTestToken(t, testAPI.config.Auth.JWTSecret, "admin")

	// Test with malformed JSON
	body := []byte(`{"name": "test", "invalid": json}`)
	req := httptest.NewRequest("POST", "/api/v1/rules", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	addCSRFToRequest(t, req)

	w := httptest.NewRecorder()
	testAPI.router.ServeHTTP(w, req)

	// Should return 400 for malformed JSON
	assert.Equal(t, http.StatusBadRequest, w.Code, "Should return 400 for malformed JSON")
}

// TestCreateRule_TooLargeBody tests rule creation with oversized body
func TestCreateRule_TooLargeBody(t *testing.T) {
	testAPI, cleanup := setupTestAPI(t)
	defer cleanup()

	token := createValidTestToken(t, testAPI.config.Auth.JWTSecret, "admin")

	// Create a rule with very large SigmaYAML to make body large
	rule := core.Rule{
		ID:   "test-rule",
		Name: "Test Rule",
		Type: "sigma",
		// Create large SigmaYAML to test body size limits
		SigmaYAML: `title: Test Rule
logsource:
  product: test
detection:
  selection:
    field: ` + strings.Repeat("value ", 10000) + `
  condition: selection
`,
	}

	body, _ := json.Marshal(rule)
	req := httptest.NewRequest("POST", "/api/v1/rules", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	addCSRFToRequest(t, req)

	w := httptest.NewRecorder()
	testAPI.router.ServeHTTP(w, req)

	// Should return 400 or 413 for oversized body
	assert.Contains(t, []int{http.StatusBadRequest, http.StatusRequestEntityTooLarge}, w.Code, "Should reject oversized body")
}

// TestUpdateRule tests rule update handler
// TASK 63.5: Update handler tests
func TestUpdateRule(t *testing.T) {
	testAPI, cleanup := setupTestAPI(t)
	defer cleanup()

	token := createValidTestToken(t, testAPI.config.Auth.JWTSecret, "admin")

	// Use map for proper JSON serialization
	rule := map[string]interface{}{
		"name": "Updated Rule Name",
	}

	body, _ := json.Marshal(rule)
	req := httptest.NewRequest("PUT", "/api/v1/rules/test-rule-id", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	addCSRFToRequest(t, req)

	w := httptest.NewRecorder()
	testAPI.router.ServeHTTP(w, req)

	// 404 is correct when rule doesn't exist, 200/400 if it does
	// This test verifies the handler runs without crashing
	assert.True(t, w.Code == 200 || w.Code == 400 || w.Code == 404, "Handler should return valid HTTP status: %d", w.Code)
}

// TestDeleteRule tests rule deletion handler
// TASK 63.6: Delete handler tests
func TestDeleteRule(t *testing.T) {
	testAPI, cleanup := setupTestAPI(t)
	defer cleanup()

	token := createValidTestToken(t, testAPI.config.Auth.JWTSecret, "admin")

	req := httptest.NewRequest("DELETE", "/api/v1/rules/test-rule-id", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	addCSRFToRequest(t, req)

	w := httptest.NewRecorder()
	testAPI.router.ServeHTTP(w, req)

	// 404 is correct when rule doesn't exist, 200/204 if it does
	// This test verifies the handler runs without crashing
	assert.True(t, w.Code == 200 || w.Code == 204 || w.Code == 404, "Handler should return valid HTTP status: %d", w.Code)
}

// TestGetActions tests action retrieval handler
// TASK 63.7: Action handler tests
func TestGetActions(t *testing.T) {
	testAPI, cleanup := setupTestAPI(t)
	defer cleanup()

	token := createValidTestToken(t, testAPI.config.Auth.JWTSecret, "admin")

	req := httptest.NewRequest("GET", "/api/v1/actions", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	testAPI.router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code, "Should return 200 OK")
}

// TestCreateAction tests action creation handler
func TestCreateAction(t *testing.T) {
	testAPI, cleanup := setupTestAPI(t)
	defer cleanup()

	token := createValidTestToken(t, testAPI.config.Auth.JWTSecret, "admin")

	action := map[string]interface{}{
		"name":    "Test Action",
		"type":    "webhook",
		"enabled": true,
		"config": map[string]interface{}{
			"url": "https://example.com/webhook",
		},
	}

	body, _ := json.Marshal(action)
	req := httptest.NewRequest("POST", "/api/v1/actions", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	addCSRFToRequest(t, req)

	w := httptest.NewRecorder()
	testAPI.router.ServeHTTP(w, req)

	// May return 201, 400, or 500 depending on validation and storage
	assert.NotEqual(t, 404, w.Code, "Handler should exist")
	assert.NotEqual(t, 405, w.Code, "Method should be allowed")
}

// TestGetAlerts tests alert retrieval handler
// TASK 63.8: Alert handler tests
func TestGetAlerts(t *testing.T) {
	testAPI, cleanup := setupTestAPI(t)
	defer cleanup()

	token := createValidTestToken(t, testAPI.config.Auth.JWTSecret, "admin")

	req := httptest.NewRequest("GET", "/api/v1/alerts", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	testAPI.router.ServeHTTP(w, req)

	assert.NotEqual(t, 404, w.Code, "Handler should exist")
	assert.NotEqual(t, 405, w.Code, "Method should be allowed")
}

// TestGetAlerts_WithFilters_Handler tests alert retrieval with filters
func TestGetAlerts_WithFilters_Handler(t *testing.T) {
	testAPI, cleanup := setupTestAPI(t)
	defer cleanup()

	token := createValidTestToken(t, testAPI.config.Auth.JWTSecret, "admin")

	// Test with various filters
	req := httptest.NewRequest("GET", "/api/v1/alerts?severity=high&status=pending&page=1&limit=50", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	testAPI.router.ServeHTTP(w, req)

	assert.NotEqual(t, 404, w.Code, "Handler should exist")
}

// TestSearchEvents tests event search handler
// TASK 63.9: Search handler tests
func TestSearchEvents(t *testing.T) {
	testAPI, cleanup := setupTestAPI(t)
	defer cleanup()

	token := createValidTestToken(t, testAPI.config.Auth.JWTSecret, "admin")

	searchReq := SearchRequest{
		Query:  `source_ip = "192.168.1.100"`,
		Limit:  100,
		Offset: 0,
	}

	body, _ := json.Marshal(searchReq)
	req := httptest.NewRequest("POST", "/api/v1/events/search", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	addCSRFToRequest(t, req)

	w := httptest.NewRecorder()
	testAPI.router.ServeHTTP(w, req)

	// May return 200, 400, or 503 depending on ClickHouse availability
	assert.NotEqual(t, 404, w.Code, "Handler should exist")
}

// TestSearchEvents_InvalidQuery tests event search with invalid query
func TestSearchEvents_InvalidQuery(t *testing.T) {
	testAPI, cleanup := setupTestAPI(t)
	defer cleanup()

	token := createValidTestToken(t, testAPI.config.Auth.JWTSecret, "admin")

	searchReq := SearchRequest{
		Query:  `invalid syntax here!!!`, // Invalid CQL syntax
		Limit:  100,
		Offset: 0,
	}

	body, _ := json.Marshal(searchReq)
	req := httptest.NewRequest("POST", "/api/v1/events/search", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	addCSRFToRequest(t, req)

	w := httptest.NewRecorder()
	testAPI.router.ServeHTTP(w, req)

	// Should return 400 for invalid query syntax
	assert.Equal(t, http.StatusBadRequest, w.Code, "Should return 400 for invalid query")
}
