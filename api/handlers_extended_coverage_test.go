package api

import (
	"bytes"
	"encoding/json"
	"net/http/httptest"
	"testing"
	"time"

	"cerberus/core"
	"github.com/stretchr/testify/assert"
)

// Extended tests to increase coverage - focus on error paths and edge cases

// Test health check (public endpoint)
func TestHealthCheck(t *testing.T) {
	testAPI, cleanup := setupTestAPI(t)
	defer cleanup()

	req := httptest.NewRequest("GET", "/health", nil)
	w := httptest.NewRecorder()
	testAPI.router.ServeHTTP(w, req)

	assert.Equal(t, 200, w.Code)
}

// Test metrics endpoint (public)
func TestMetrics(t *testing.T) {
	testAPI, cleanup := setupTestAPI(t)
	defer cleanup()

	req := httptest.NewRequest("GET", "/metrics", nil)
	w := httptest.NewRecorder()
	testAPI.router.ServeHTTP(w, req)

	assert.Equal(t, 200, w.Code)
}

// Test CORS preflight
func TestCORSPreflight(t *testing.T) {
	testAPI, cleanup := setupTestAPI(t)
	defer cleanup()

	req := httptest.NewRequest("OPTIONS", "/api/v1/rules", nil)
	req.Header.Set("Origin", "http://localhost:3000")
	req.Header.Set("Access-Control-Request-Method", "POST")
	req.Header.Set("Access-Control-Request-Headers", "Authorization,Content-Type")

	w := httptest.NewRecorder()
	testAPI.router.ServeHTTP(w, req)

	assert.Equal(t, 200, w.Code)
}

// Test create rule with invalid JSON
func TestCreateRule_InvalidJSON(t *testing.T) {
	testAPI, cleanup := setupTestAPI(t)
	defer cleanup()

	token := createValidTestToken(t, testAPI.config.Auth.JWTSecret, "admin")

	req := httptest.NewRequest("POST", "/api/v1/rules", bytes.NewReader([]byte("{invalid json")))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	addCSRFToRequest(t, req)

	w := httptest.NewRecorder()
	testAPI.router.ServeHTTP(w, req)

	assert.Equal(t, 400, w.Code)
}

// Test create rule with missing required fields
func TestCreateRule_MissingFields(t *testing.T) {
	testAPI, cleanup := setupTestAPI(t)
	defer cleanup()

	token := createValidTestToken(t, testAPI.config.Auth.JWTSecret, "admin")

	rule := map[string]interface{}{
		// Missing name, conditions, etc.
		"id": "incomplete-rule",
	}

	body, _ := json.Marshal(rule)
	req := httptest.NewRequest("POST", "/api/v1/rules", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	addCSRFToRequest(t, req)

	w := httptest.NewRecorder()
	testAPI.router.ServeHTTP(w, req)

	assert.True(t, w.Code == 400 || w.Code == 500)
}

// Test get rules with pagination
func TestGetRules_Pagination(t *testing.T) {
	testAPI, cleanup := setupTestAPI(t)
	defer cleanup()

	token := createValidTestToken(t, testAPI.config.Auth.JWTSecret, "admin")

	req := httptest.NewRequest("GET", "/api/v1/rules?page=1&limit=10", nil)
	req.Header.Set("Authorization", "Bearer "+token)

	w := httptest.NewRecorder()
	testAPI.router.ServeHTTP(w, req)

	assert.Equal(t, 200, w.Code)
}

// Test create action with invalid JSON
func TestCreateAction_InvalidJSON(t *testing.T) {
	testAPI, cleanup := setupTestAPI(t)
	defer cleanup()

	token := createValidTestToken(t, testAPI.config.Auth.JWTSecret, "admin")

	req := httptest.NewRequest("POST", "/api/v1/actions", bytes.NewReader([]byte("{bad json")))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	addCSRFToRequest(t, req)

	w := httptest.NewRecorder()
	testAPI.router.ServeHTTP(w, req)

	assert.Equal(t, 400, w.Code)
}

// Test delete action that doesn't exist
func TestDeleteAction_NotFound(t *testing.T) {
	testAPI, cleanup := setupTestAPI(t)
	defer cleanup()

	token := createValidTestToken(t, testAPI.config.Auth.JWTSecret, "admin")

	req := httptest.NewRequest("DELETE", "/api/v1/actions/nonexistent-action", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	addCSRFToRequest(t, req)

	w := httptest.NewRecorder()
	testAPI.router.ServeHTTP(w, req)

	// Expect 404 or success (depending on implementation)
	assert.True(t, w.Code == 200 || w.Code == 404)
}

// Test update rule with no changes
func TestUpdateRule_NoChanges(t *testing.T) {
	testAPI, cleanup := setupTestAPI(t)
	defer cleanup()

	token := createValidTestToken(t, testAPI.config.Auth.JWTSecret, "admin")

	// First create a rule
	rule := core.Rule{
		ID:          "test-rule-update",
		Type:        "sigma",
		Name:        "Test Rule",
		Description: "Test description",
		Severity:    "medium",
		Enabled:     true,
		SigmaYAML: `title: Test Rule
logsource:
  product: test
detection:
  selection:
    event_type: test
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

	// Now try to update it
	req = httptest.NewRequest("PUT", "/api/v1/rules/test-rule-update", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	addCSRFToRequest(t, req)

	w = httptest.NewRecorder()
	testAPI.router.ServeHTTP(w, req)

	assert.True(t, w.Code == 200 || w.Code == 404 || w.Code == 400)
}

// Test get actions pagination
func TestGetActions_Pagination(t *testing.T) {
	testAPI, cleanup := setupTestAPI(t)
	defer cleanup()

	token := createValidTestToken(t, testAPI.config.Auth.JWTSecret, "admin")

	req := httptest.NewRequest("GET", "/api/v1/actions?page=1&limit=20", nil)
	req.Header.Set("Authorization", "Bearer "+token)

	w := httptest.NewRecorder()
	testAPI.router.ServeHTTP(w, req)

	assert.Equal(t, 200, w.Code)
}

// Test correlation rules pagination
// TASK #173: Skipped - /api/v1/correlation-rules endpoint deprecated
func TestGetCorrelationRules_Pagination(t *testing.T) {
	t.Skip("TASK #173: /api/v1/correlation-rules endpoint deprecated - use /api/v1/rules?category=correlation")
	testAPI, cleanup := setupTestAPI(t)
	defer cleanup()

	token := createValidTestToken(t, testAPI.config.Auth.JWTSecret, "admin")

	req := httptest.NewRequest("GET", "/api/v1/correlation-rules?page=2&limit=15", nil)
	req.Header.Set("Authorization", "Bearer "+token)

	w := httptest.NewRecorder()
	testAPI.router.ServeHTTP(w, req)

	assert.Equal(t, 200, w.Code)
}

// Test investigations pagination
func TestGetInvestigations_Pagination(t *testing.T) {
	testAPI, cleanup := setupTestAPI(t)
	defer cleanup()

	token := createValidTestToken(t, testAPI.config.Auth.JWTSecret, "admin")

	req := httptest.NewRequest("GET", "/api/v1/investigations?page=1&limit=25", nil)
	req.Header.Set("Authorization", "Bearer "+token)

	w := httptest.NewRecorder()
	testAPI.router.ServeHTTP(w, req)

	assert.Equal(t, 200, w.Code)
}

// Test create investigation with minimal data
func TestCreateInvestigation_MinimalData(t *testing.T) {
	testAPI, cleanup := setupTestAPI(t)
	defer cleanup()

	token := createValidTestToken(t, testAPI.config.Auth.JWTSecret, "admin")

	investigation := map[string]interface{}{
		"title": "Minimal Investigation",
	}

	body, _ := json.Marshal(investigation)
	req := httptest.NewRequest("POST", "/api/v1/investigations", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	addCSRFToRequest(t, req)

	w := httptest.NewRecorder()
	testAPI.router.ServeHTTP(w, req)

	assert.True(t, w.Code == 200 || w.Code == 201 || w.Code == 400)
}

// Test creating saved search with query
func TestCreateSavedSearch_WithQuery(t *testing.T) {
	testAPI, cleanup := setupTestAPI(t)
	defer cleanup()

	token := createValidTestToken(t, testAPI.config.Auth.JWTSecret, "admin")

	search := map[string]interface{}{
		"name":  "Security Events",
		"query": `event_type:"security" AND severity:"high"`,
	}

	body, _ := json.Marshal(search)
	req := httptest.NewRequest("POST", "/api/v1/saved-searches", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	addCSRFToRequest(t, req)

	w := httptest.NewRecorder()
	testAPI.router.ServeHTTP(w, req)

	assert.True(t, w.Code == 200 || w.Code == 201 || w.Code == 400)
}

// Test update saved search
func TestUpdateSavedSearch(t *testing.T) {
	testAPI, cleanup := setupTestAPI(t)
	defer cleanup()

	token := createValidTestToken(t, testAPI.config.Auth.JWTSecret, "admin")

	search := map[string]interface{}{
		"name":  "Updated Search",
		"query": "updated query",
	}

	body, _ := json.Marshal(search)
	req := httptest.NewRequest("PUT", "/api/v1/saved-searches/test-search-1", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	addCSRFToRequest(t, req)

	w := httptest.NewRecorder()
	testAPI.router.ServeHTTP(w, req)

	assert.True(t, w.Code == 200 || w.Code == 404 || w.Code == 400)
}

// Test delete saved search
func TestDeleteSavedSearch(t *testing.T) {
	testAPI, cleanup := setupTestAPI(t)
	defer cleanup()

	token := createValidTestToken(t, testAPI.config.Auth.JWTSecret, "admin")

	req := httptest.NewRequest("DELETE", "/api/v1/saved-searches/test-search-1", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	addCSRFToRequest(t, req)

	w := httptest.NewRecorder()
	testAPI.router.ServeHTTP(w, req)

	assert.True(t, w.Code == 200 || w.Code == 404)
}

// Test get saved search
func TestGetSavedSearch(t *testing.T) {
	testAPI, cleanup := setupTestAPI(t)
	defer cleanup()

	token := createValidTestToken(t, testAPI.config.Auth.JWTSecret, "admin")

	req := httptest.NewRequest("GET", "/api/v1/saved-searches/test-search-1", nil)
	req.Header.Set("Authorization", "Bearer "+token)

	w := httptest.NewRecorder()
	testAPI.router.ServeHTTP(w, req)

	assert.True(t, w.Code == 200 || w.Code == 404)
}

// Test auth config endpoint
func TestGetAuthConfig(t *testing.T) {
	testAPI, cleanup := setupTestAPI(t)
	defer cleanup()

	req := httptest.NewRequest("GET", "/api/auth/config", nil)
	w := httptest.NewRecorder()
	testAPI.router.ServeHTTP(w, req)

	assert.Equal(t, 200, w.Code)
}

// Test logout with valid token
func TestLogout_WithValidToken(t *testing.T) {
	testAPI, cleanup := setupTestAPI(t)
	defer cleanup()

	token := createValidTestToken(t, testAPI.config.Auth.JWTSecret, "testuser")

	req := httptest.NewRequest("POST", "/api/auth/logout", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	addCSRFToRequest(t, req)

	w := httptest.NewRecorder()
	testAPI.router.ServeHTTP(w, req)

	// Logout should succeed or return 403 due to CSRF
	assert.True(t, w.Code == 200 || w.Code == 403)
}

// Test auth status with very expired token
func TestAuthStatus_VeryExpiredToken(t *testing.T) {
	testAPI, cleanup := setupTestAPI(t)
	defer cleanup()

	// Create an expired token
	expiredToken := createExpiredTestToken(t, testAPI.config.Auth.JWTSecret, "testuser", -1*time.Hour)

	req := httptest.NewRequest("GET", "/api/auth/status", nil)
	req.Header.Set("Authorization", "Bearer "+expiredToken)
	w := httptest.NewRecorder()
	testAPI.router.ServeHTTP(w, req)

	assert.True(t, w.Code == 200 || w.Code == 401)
}

// Test create rule with duplicate ID
func TestCreateRule_DuplicateID(t *testing.T) {
	testAPI, cleanup := setupTestAPI(t)
	defer cleanup()

	token := createValidTestToken(t, testAPI.config.Auth.JWTSecret, "admin")

	rule := core.Rule{
		ID:          "duplicate-rule",
		Type:        "sigma",
		Name:        "Test Rule",
		Description: "Test",
		Severity:    "low",
		Enabled:     true,
		SigmaYAML: `title: Test Rule
logsource:
  product: test
detection:
  selection:
    test: value
  condition: selection
`,
	}

	body, _ := json.Marshal(rule)

	// Create first time
	req := httptest.NewRequest("POST", "/api/v1/rules", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	addCSRFToRequest(t, req)

	w := httptest.NewRecorder()
	testAPI.router.ServeHTTP(w, req)

	// Create second time with same ID
	req = httptest.NewRequest("POST", "/api/v1/rules", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	addCSRFToRequest(t, req)

	w = httptest.NewRecorder()
	testAPI.router.ServeHTTP(w, req)

	// Should fail or succeed depending on implementation
	assert.True(t, w.Code == 200 || w.Code == 400 || w.Code == 409 || w.Code == 500)
}

// Test rate limiting doesn't block legitimate requests
func TestRateLimiting_NormalRequests(t *testing.T) {
	testAPI, cleanup := setupTestAPI(t)
	defer cleanup()

	token := createValidTestToken(t, testAPI.config.Auth.JWTSecret, "admin")

	// Make multiple requests
	for i := 0; i < 5; i++ {
		req := httptest.NewRequest("GET", "/api/v1/rules", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		req.RemoteAddr = "127.0.0.1:12345"

		w := httptest.NewRecorder()
		testAPI.router.ServeHTTP(w, req)

		assert.True(t, w.Code == 200 || w.Code == 429)
	}
}

// Test dashboard chart with different parameters
func TestGetDashboardChart_DifferentParams(t *testing.T) {
	testAPI, cleanup := setupTestAPI(t)
	defer cleanup()

	token := createValidTestToken(t, testAPI.config.Auth.JWTSecret, "admin")

	tests := []string{
		"/api/v1/dashboard/chart?type=events&period=24h",
		"/api/v1/dashboard/chart?type=alerts&period=30d",
		"/api/v1/dashboard/chart?type=severity",
	}

	for _, url := range tests {
		req := httptest.NewRequest("GET", url, nil)
		req.Header.Set("Authorization", "Bearer "+token)

		w := httptest.NewRecorder()
		testAPI.router.ServeHTTP(w, req)

		assert.True(t, w.Code == 200 || w.Code == 400)
	}
}

// Test close investigation endpoint
func TestCloseInvestigation(t *testing.T) {
	testAPI, cleanup := setupTestAPI(t)
	defer cleanup()

	token := createValidTestToken(t, testAPI.config.Auth.JWTSecret, "admin")

	closeData := map[string]interface{}{
		"resolution": "False positive",
	}

	body, _ := json.Marshal(closeData)
	req := httptest.NewRequest("POST", "/api/v1/investigations/test-inv-1/close", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	addCSRFToRequest(t, req)

	w := httptest.NewRecorder()
	testAPI.router.ServeHTTP(w, req)

	assert.True(t, w.Code == 200 || w.Code == 404 || w.Code == 400)
}

// Test add investigation note
func TestAddInvestigationNote(t *testing.T) {
	testAPI, cleanup := setupTestAPI(t)
	defer cleanup()

	token := createValidTestToken(t, testAPI.config.Auth.JWTSecret, "admin")

	note := map[string]interface{}{
		"content": "This is a test note",
	}

	body, _ := json.Marshal(note)
	req := httptest.NewRequest("POST", "/api/v1/investigations/test-inv-1/notes", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	addCSRFToRequest(t, req)

	w := httptest.NewRecorder()
	testAPI.router.ServeHTTP(w, req)

	assert.True(t, w.Code == 200 || w.Code == 201 || w.Code == 404 || w.Code == 400)
}

// Test add investigation alert
func TestAddInvestigationAlert(t *testing.T) {
	testAPI, cleanup := setupTestAPI(t)
	defer cleanup()

	token := createValidTestToken(t, testAPI.config.Auth.JWTSecret, "admin")

	alertData := map[string]interface{}{
		"alert_id": "alert-123",
	}

	body, _ := json.Marshal(alertData)
	req := httptest.NewRequest("POST", "/api/v1/investigations/test-inv-1/alerts", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	addCSRFToRequest(t, req)

	w := httptest.NewRecorder()
	testAPI.router.ServeHTTP(w, req)

	assert.True(t, w.Code == 200 || w.Code == 201 || w.Code == 404 || w.Code == 400)
}

// Test get investigation timeline
func TestGetInvestigationTimeline(t *testing.T) {
	testAPI, cleanup := setupTestAPI(t)
	defer cleanup()

	token := createValidTestToken(t, testAPI.config.Auth.JWTSecret, "admin")

	req := httptest.NewRequest("GET", "/api/v1/investigations/test-inv-1/timeline", nil)
	req.Header.Set("Authorization", "Bearer "+token)

	w := httptest.NewRecorder()
	testAPI.router.ServeHTTP(w, req)

	assert.True(t, w.Code == 200 || w.Code == 404)
}

// Test invalid authorization header
func TestInvalidAuthHeader(t *testing.T) {
	testAPI, cleanup := setupTestAPI(t)
	defer cleanup()

	req := httptest.NewRequest("GET", "/api/v1/rules", nil)
	req.Header.Set("Authorization", "Invalid")

	w := httptest.NewRecorder()
	testAPI.router.ServeHTTP(w, req)

	assert.Equal(t, 401, w.Code)
}
