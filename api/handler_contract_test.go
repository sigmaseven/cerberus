package api

// ============================================================================
// Handler Contract Tests - Task 145.5
// ============================================================================
//
// PURPOSE: Document testing philosophy and provide focused HTTP contract tests
//
// TESTING PHILOSOPHY:
// 1. Service Layer Tests (service/*_test.go):
//    - Test business logic with unit tests
//    - Mock storage dependencies
//    - Verify data transformations, validations, error handling
//    - Target: 90%+ coverage
//
// 2. Handler Contract Tests (api/handler_contract_test.go):
//    - Test HTTP contract compliance ONLY
//    - Verify status codes (200, 201, 400, 404, 500)
//    - Verify JSON response structure and required fields
//    - Verify request parsing and basic validation
//    - DO NOT test business logic (that's in service layer)
//
// 3. Integration Tests (api/*_integration_test.go):
//    - Test end-to-end flows with real storage
//    - Verify component integration
//    - Test authentication and authorization
//
// SEPARATION OF CONCERNS:
// - Business Logic -> Service Layer Tests
// - HTTP Contract -> Handler Contract Tests
// - Full Stack -> Integration Tests
//
// This approach prevents duplication and ensures focused, maintainable tests.

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

// ============================================================================
// HTTP Contract Tests - Status Codes
// ============================================================================

// TestHTTPContract_StatusCodes verifies handlers return correct status codes.
func TestHTTPContract_StatusCodes(t *testing.T) {
	testAPI, cleanup := setupTestAPI(t)
	defer cleanup()

	token := createValidTestToken(t, testAPI.config.Auth.JWTSecret, "admin")

	tests := []struct {
		name           string
		method         string
		path           string
		body           map[string]interface{}
		auth           bool
		expectedStatus int
	}{
		{
			name:           "GET /api/v1/rules - 200 OK",
			method:         http.MethodGet,
			path:           "/api/v1/rules",
			auth:           true,
			expectedStatus: http.StatusOK,
		},
		{
			name:           "GET /api/v1/alerts - 200 OK",
			method:         http.MethodGet,
			path:           "/api/v1/alerts",
			auth:           true,
			expectedStatus: http.StatusOK,
		},
		{
			name:           "GET /api/v1/events - 200 OK",
			method:         http.MethodGet,
			path:           "/api/v1/events",
			auth:           true,
			expectedStatus: http.StatusOK,
		},
		{
			name:           "POST /api/v1/rules - 400 Bad Request (malformed JSON)",
			method:         http.MethodPost,
			path:           "/api/v1/rules",
			body:           map[string]interface{}{"invalid": "data"}, // Missing required fields
			auth:           true,
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:           "GET /api/v1/rules/nonexistent - 404 Not Found",
			method:         http.MethodGet,
			path:           "/api/v1/rules/nonexistent-rule-id",
			auth:           true,
			expectedStatus: http.StatusNotFound,
		},
		{
			name:           "GET /api/v1/alerts - 401 Unauthorized (no auth)",
			method:         http.MethodGet,
			path:           "/api/v1/alerts",
			auth:           false,
			expectedStatus: http.StatusUnauthorized,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var req *http.Request
			if tt.body != nil {
				bodyBytes, _ := json.Marshal(tt.body)
				req = httptest.NewRequest(tt.method, tt.path, bytes.NewReader(bodyBytes))
				req.Header.Set("Content-Type", "application/json")
			} else {
				req = httptest.NewRequest(tt.method, tt.path, nil)
			}

			if tt.auth {
				req.Header.Set("Authorization", "Bearer "+token)
			}

			w := httptest.NewRecorder()
			testAPI.router.ServeHTTP(w, req)

			assert.Equal(t, tt.expectedStatus, w.Code, "Status code mismatch for %s", tt.name)
		})
	}
}

// ============================================================================
// HTTP Contract Tests - JSON Response Structure
// ============================================================================

// TestHTTPContract_JSONResponseStructure verifies response JSON schemas.
func TestHTTPContract_JSONResponseStructure(t *testing.T) {
	testAPI, cleanup := setupTestAPI(t)
	defer cleanup()

	token := createValidTestToken(t, testAPI.config.Auth.JWTSecret, "admin")

	t.Run("GET /api/v1/rules - response has required fields", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/rules", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()
		testAPI.router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var response map[string]interface{}
		err := json.Unmarshal(w.Body.Bytes(), &response)
		assert.NoError(t, err, "Response should be valid JSON")

		// Verify required pagination fields
		assert.Contains(t, response, "rules", "Response should contain 'rules' field")
		assert.Contains(t, response, "total", "Response should contain 'total' field")
		assert.Contains(t, response, "page", "Response should contain 'page' field")
		assert.Contains(t, response, "limit", "Response should contain 'limit' field")
	})

	t.Run("GET /api/v1/alerts - response has required fields", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/alerts", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()
		testAPI.router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var response map[string]interface{}
		err := json.Unmarshal(w.Body.Bytes(), &response)
		assert.NoError(t, err, "Response should be valid JSON")

		// Verify required pagination fields
		assert.Contains(t, response, "alerts", "Response should contain 'alerts' field")
		assert.Contains(t, response, "total", "Response should contain 'total' field")
	})

	t.Run("Error responses have consistent structure", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/rules/nonexistent", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()
		testAPI.router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusNotFound, w.Code)

		var errorResponse map[string]interface{}
		err := json.Unmarshal(w.Body.Bytes(), &errorResponse)
		assert.NoError(t, err, "Error response should be valid JSON")
		assert.Contains(t, errorResponse, "error", "Error response should contain 'error' field")
	})
}

// ============================================================================
// HTTP Contract Tests - Content-Type Headers
// ============================================================================

// TestHTTPContract_ContentTypeHeaders verifies Content-Type headers.
func TestHTTPContract_ContentTypeHeaders(t *testing.T) {
	testAPI, cleanup := setupTestAPI(t)
	defer cleanup()

	token := createValidTestToken(t, testAPI.config.Auth.JWTSecret, "admin")

	tests := []struct {
		name                string
		path                string
		expectedContentType string
	}{
		{
			name:                "GET /api/v1/rules",
			path:                "/api/v1/rules",
			expectedContentType: "application/json",
		},
		{
			name:                "GET /api/v1/alerts",
			path:                "/api/v1/alerts",
			expectedContentType: "application/json",
		},
		{
			name:                "GET /api/v1/events",
			path:                "/api/v1/events",
			expectedContentType: "application/json",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, tt.path, nil)
			req.Header.Set("Authorization", "Bearer "+token)
			w := httptest.NewRecorder()
			testAPI.router.ServeHTTP(w, req)

			contentType := w.Header().Get("Content-Type")
			assert.Contains(t, contentType, tt.expectedContentType,
				"Content-Type should be %s", tt.expectedContentType)
		})
	}
}

// ============================================================================
// HTTP Contract Tests - Pagination Parameters
// ============================================================================

// TestHTTPContract_PaginationParsing verifies pagination parameter parsing.
func TestHTTPContract_PaginationParsing(t *testing.T) {
	testAPI, cleanup := setupTestAPI(t)
	defer cleanup()

	token := createValidTestToken(t, testAPI.config.Auth.JWTSecret, "admin")

	tests := []struct {
		name           string
		queryParams    string
		expectedStatus int
	}{
		{
			name:           "Valid pagination parameters",
			queryParams:    "?page=1&limit=20",
			expectedStatus: http.StatusOK,
		},
		{
			name:           "Default pagination (no params)",
			queryParams:    "",
			expectedStatus: http.StatusOK,
		},
		{
			name:           "Large page number",
			queryParams:    "?page=1000&limit=50",
			expectedStatus: http.StatusOK, // Should not error, just return empty
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/api/v1/rules"+tt.queryParams, nil)
			req.Header.Set("Authorization", "Bearer "+token)
			w := httptest.NewRecorder()
			testAPI.router.ServeHTTP(w, req)

			assert.Equal(t, tt.expectedStatus, w.Code)

			// Verify response structure
			if w.Code == http.StatusOK {
				var response map[string]interface{}
				err := json.Unmarshal(w.Body.Bytes(), &response)
				assert.NoError(t, err)
				assert.Contains(t, response, "rules")
			}
		})
	}
}

// ============================================================================
// Documentation - Handler Testing Best Practices
// ============================================================================

/*
HANDLER TESTING BEST PRACTICES:

1. Focus on HTTP Contract:
   - Status codes (200, 201, 400, 404, 500)
   - Response JSON structure
   - Required fields presence
   - Content-Type headers
   - Request parameter parsing

2. DO NOT Test Business Logic:
   - That's what service layer tests are for
   - Handlers should be thin - just HTTP translation
   - Mock the service layer for handler tests

3. Use setupTestAPI() for Real Tests:
   - Provides full API with real routing
   - Includes authentication middleware
   - Uses SQLite for storage (fast, isolated)
   - Auto-cleanup with defer cleanup()

4. Test Error Responses:
   - 400 Bad Request - malformed input
   - 401 Unauthorized - missing/invalid auth
   - 404 Not Found - resource doesn't exist
   - 500 Internal Error - service failures

5. Verify Response Consistency:
   - All success responses have consistent structure
   - All error responses have consistent format
   - Pagination fields always present when applicable

6. Examples of Good Handler Tests:
   - "POST /rules returns 201 with rule ID in response"
   - "GET /rules?page=1&limit=20 includes pagination fields"
   - "GET /rules/nonexistent returns 404 with error field"
   - "DELETE /rules/:id returns 204 with empty body"

7. Examples of BAD Handler Tests (belongs in service layer):
   - "Rule validation rejects invalid severity values" <- Service test
   - "Creating rule with duplicate name returns error" <- Service test
   - "Deleted rules are removed from database" <- Service test
   - "Rule detection logic matches events correctly" <- Engine test

SEE ALSO:
- service/README.md - Service layer testing documentation
- api/test_helpers.go - Shared test utilities
- api/*_integration_test.go - Full stack integration tests
*/
