package api

// TASK 188: Pagination edge case tests for handlers
// Tests edge cases in pagination parameters

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

// ============================================================================
// TASK 188: PAGINATION EDGE CASE TESTS
// ============================================================================

// TestPagination_NegativeLimit tests handling of negative limit parameter
func TestPagination_NegativeLimit(t *testing.T) {
	testAPI, cleanup := setupTestAPI(t)
	defer cleanup()

	token := createValidTestToken(t, testAPI.config.Auth.JWTSecret, "admin")

	req := httptest.NewRequest("GET", "/api/v1/rules?limit=-1", nil)
	req.Header.Set("Authorization", "Bearer "+token)

	w := httptest.NewRecorder()
	testAPI.router.ServeHTTP(w, req)

	// Should return 400 for invalid limit or use default limit
	// Either is acceptable behavior
	assert.True(t, w.Code == http.StatusOK || w.Code == http.StatusBadRequest,
		"Should return 200 (with default limit) or 400 for negative limit, got %d", w.Code)

	if w.Code == http.StatusOK {
		// Verify response has valid structure
		var response map[string]interface{}
		err := json.Unmarshal(w.Body.Bytes(), &response)
		assert.NoError(t, err, "Response should be valid JSON")
	}
}

// TestPagination_LimitZero tests handling of limit=0
func TestPagination_LimitZero(t *testing.T) {
	testAPI, cleanup := setupTestAPI(t)
	defer cleanup()

	token := createValidTestToken(t, testAPI.config.Auth.JWTSecret, "admin")

	req := httptest.NewRequest("GET", "/api/v1/rules?limit=0", nil)
	req.Header.Set("Authorization", "Bearer "+token)

	w := httptest.NewRecorder()
	testAPI.router.ServeHTTP(w, req)

	// Should return 200 with empty results or 400 for invalid limit
	assert.True(t, w.Code == http.StatusOK || w.Code == http.StatusBadRequest,
		"Should return 200 or 400 for zero limit, got %d", w.Code)

	if w.Code == http.StatusOK {
		var response map[string]interface{}
		err := json.Unmarshal(w.Body.Bytes(), &response)
		assert.NoError(t, err, "Response should be valid JSON")
	}
}

// TestPagination_LimitExceedsMaximum tests handling of limit exceeding maximum
func TestPagination_LimitExceedsMaximum(t *testing.T) {
	testAPI, cleanup := setupTestAPI(t)
	defer cleanup()

	token := createValidTestToken(t, testAPI.config.Auth.JWTSecret, "admin")

	// Test limit of 1001 (exceeds common maximum of 1000)
	req := httptest.NewRequest("GET", "/api/v1/rules?limit=1001", nil)
	req.Header.Set("Authorization", "Bearer "+token)

	w := httptest.NewRecorder()
	testAPI.router.ServeHTTP(w, req)

	// Should return 400 for exceeding maximum or cap to maximum
	assert.True(t, w.Code == http.StatusOK || w.Code == http.StatusBadRequest,
		"Should return 200 (capped limit) or 400 for exceeding maximum, got %d", w.Code)

	if w.Code == http.StatusOK {
		var response map[string]interface{}
		err := json.Unmarshal(w.Body.Bytes(), &response)
		assert.NoError(t, err, "Response should be valid JSON")
	}
}

// TestPagination_NegativeOffset tests handling of negative offset
func TestPagination_NegativeOffset(t *testing.T) {
	testAPI, cleanup := setupTestAPI(t)
	defer cleanup()

	token := createValidTestToken(t, testAPI.config.Auth.JWTSecret, "admin")

	req := httptest.NewRequest("GET", "/api/v1/rules?offset=-1", nil)
	req.Header.Set("Authorization", "Bearer "+token)

	w := httptest.NewRecorder()
	testAPI.router.ServeHTTP(w, req)

	// Should return 400 for negative offset or use 0
	assert.True(t, w.Code == http.StatusOK || w.Code == http.StatusBadRequest,
		"Should return 200 (with offset 0) or 400 for negative offset, got %d", w.Code)
}

// TestPagination_OffsetBeyondTotal tests handling of offset beyond total count
func TestPagination_OffsetBeyondTotal(t *testing.T) {
	testAPI, cleanup := setupTestAPI(t)
	defer cleanup()

	token := createValidTestToken(t, testAPI.config.Auth.JWTSecret, "admin")

	// Request with very large offset
	req := httptest.NewRequest("GET", "/api/v1/rules?offset=999999", nil)
	req.Header.Set("Authorization", "Bearer "+token)

	w := httptest.NewRecorder()
	testAPI.router.ServeHTTP(w, req)

	// Should return 200 with empty results
	assert.Equal(t, http.StatusOK, w.Code, "Should return 200 for offset beyond total")

	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err, "Response should be valid JSON")

	// Items array should be empty
	items, ok := response["items"]
	if ok {
		itemsArr, ok := items.([]interface{})
		if ok {
			assert.Empty(t, itemsArr, "Items should be empty when offset exceeds total")
		}
	}
}

// TestPagination_IntegerOverflowOffset tests handling of very large offset values
func TestPagination_IntegerOverflowOffset(t *testing.T) {
	testAPI, cleanup := setupTestAPI(t)
	defer cleanup()

	token := createValidTestToken(t, testAPI.config.Auth.JWTSecret, "admin")

	// Test with max int64 value
	req := httptest.NewRequest("GET", "/api/v1/rules?offset=9223372036854775807", nil)
	req.Header.Set("Authorization", "Bearer "+token)

	w := httptest.NewRecorder()
	testAPI.router.ServeHTTP(w, req)

	// Should return 200 with empty results or 400 for invalid parameter
	assert.True(t, w.Code == http.StatusOK || w.Code == http.StatusBadRequest,
		"Should handle very large offset gracefully, got %d", w.Code)
}

// TestPagination_NonNumericLimit tests handling of non-numeric limit
func TestPagination_NonNumericLimit(t *testing.T) {
	testAPI, cleanup := setupTestAPI(t)
	defer cleanup()

	token := createValidTestToken(t, testAPI.config.Auth.JWTSecret, "admin")

	req := httptest.NewRequest("GET", "/api/v1/rules?limit=abc", nil)
	req.Header.Set("Authorization", "Bearer "+token)

	w := httptest.NewRecorder()
	testAPI.router.ServeHTTP(w, req)

	// Should return 400 for non-numeric limit or use default
	assert.True(t, w.Code == http.StatusOK || w.Code == http.StatusBadRequest,
		"Should return 200 (with default) or 400 for non-numeric limit, got %d", w.Code)
}

// TestPagination_NonNumericOffset tests handling of non-numeric offset
func TestPagination_NonNumericOffset(t *testing.T) {
	testAPI, cleanup := setupTestAPI(t)
	defer cleanup()

	token := createValidTestToken(t, testAPI.config.Auth.JWTSecret, "admin")

	req := httptest.NewRequest("GET", "/api/v1/rules?offset=abc", nil)
	req.Header.Set("Authorization", "Bearer "+token)

	w := httptest.NewRecorder()
	testAPI.router.ServeHTTP(w, req)

	// Should return 400 for non-numeric offset or use default
	assert.True(t, w.Code == http.StatusOK || w.Code == http.StatusBadRequest,
		"Should return 200 (with default) or 400 for non-numeric offset, got %d", w.Code)
}

// TestPagination_TotalPagesZeroItems tests total_pages calculation when total=0
func TestPagination_TotalPagesZeroItems(t *testing.T) {
	testAPI, cleanup := setupTestAPI(t)
	defer cleanup()

	token := createValidTestToken(t, testAPI.config.Auth.JWTSecret, "admin")

	// Request with no items in database
	req := httptest.NewRequest("GET", "/api/v1/rules?limit=10", nil)
	req.Header.Set("Authorization", "Bearer "+token)

	w := httptest.NewRecorder()
	testAPI.router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code, "Should return 200")

	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err, "Response should be valid JSON")

	// Check total_pages if present
	if totalPages, ok := response["total_pages"].(float64); ok {
		assert.GreaterOrEqual(t, totalPages, float64(0), "total_pages should be >= 0")
	}

	// Check total if present
	if total, ok := response["total"].(float64); ok {
		assert.GreaterOrEqual(t, total, float64(0), "total should be >= 0")
	}
}

// TestPagination_FloatValues tests handling of float limit/offset
func TestPagination_FloatValues(t *testing.T) {
	testAPI, cleanup := setupTestAPI(t)
	defer cleanup()

	token := createValidTestToken(t, testAPI.config.Auth.JWTSecret, "admin")

	req := httptest.NewRequest("GET", "/api/v1/rules?limit=10.5&offset=5.5", nil)
	req.Header.Set("Authorization", "Bearer "+token)

	w := httptest.NewRecorder()
	testAPI.router.ServeHTTP(w, req)

	// Should return 400 or handle gracefully by truncating
	assert.True(t, w.Code == http.StatusOK || w.Code == http.StatusBadRequest,
		"Should handle float parameters gracefully, got %d", w.Code)
}

// TestPagination_SpecialCharacters tests handling of special characters in parameters
func TestPagination_SpecialCharacters(t *testing.T) {
	testAPI, cleanup := setupTestAPI(t)
	defer cleanup()

	token := createValidTestToken(t, testAPI.config.Auth.JWTSecret, "admin")

	testCases := []struct {
		name  string
		query string
	}{
		// URL-encoded special characters to test parameter sanitization
		{"sql_injection_limit", "limit=10%3BDROP%20TABLE%20rules%3B--"},
		{"sql_injection_offset", "offset=0%3BDELETE%20FROM%20rules%3B--"},
		{"xss_limit", "limit=%3Cscript%3Ealert(1)%3C%2Fscript%3E"},
		{"null_bytes", "limit=10%00"},
		{"unicode", "limit=1%C0%80"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/api/v1/rules?"+tc.query, nil)
			req.Header.Set("Authorization", "Bearer "+token)

			w := httptest.NewRecorder()
			testAPI.router.ServeHTTP(w, req)

			// Should return 400 or 200 (with sanitized/default values)
			assert.True(t, w.Code == http.StatusOK || w.Code == http.StatusBadRequest,
				"Should handle special characters safely in %s, got %d", tc.name, w.Code)

			// Should not return 500 (internal server error)
			assert.NotEqual(t, http.StatusInternalServerError, w.Code,
				"Should not crash on special characters in %s", tc.name)
		})
	}
}

// TestPagination_MultipleEndpoints tests pagination across different endpoints
func TestPagination_MultipleEndpoints(t *testing.T) {
	testAPI, cleanup := setupTestAPI(t)
	defer cleanup()

	token := createValidTestToken(t, testAPI.config.Auth.JWTSecret, "admin")

	endpoints := []string{
		"/api/v1/rules",
		"/api/v1/actions",
		"/api/v1/alerts",
		"/api/v1/events",
	}

	for _, endpoint := range endpoints {
		t.Run(endpoint, func(t *testing.T) {
			req := httptest.NewRequest("GET", endpoint+"?limit=10&offset=0", nil)
			req.Header.Set("Authorization", "Bearer "+token)

			w := httptest.NewRecorder()
			testAPI.router.ServeHTTP(w, req)

			// Should return 200 or 404 (if endpoint doesn't support pagination)
			assert.True(t, w.Code == http.StatusOK || w.Code == http.StatusNotFound ||
				w.Code == http.StatusBadRequest,
				"Endpoint %s should handle pagination, got %d", endpoint, w.Code)
		})
	}
}

// TestPagination_ConsistencyCheck tests that pagination is consistent
func TestPagination_ConsistencyCheck(t *testing.T) {
	testAPI, cleanup := setupTestAPI(t)
	defer cleanup()

	token := createValidTestToken(t, testAPI.config.Auth.JWTSecret, "admin")

	// First request
	req1 := httptest.NewRequest("GET", "/api/v1/rules?limit=5&offset=0", nil)
	req1.Header.Set("Authorization", "Bearer "+token)

	w1 := httptest.NewRecorder()
	testAPI.router.ServeHTTP(w1, req1)

	// Second request - same parameters
	req2 := httptest.NewRequest("GET", "/api/v1/rules?limit=5&offset=0", nil)
	req2.Header.Set("Authorization", "Bearer "+token)

	w2 := httptest.NewRecorder()
	testAPI.router.ServeHTTP(w2, req2)

	assert.Equal(t, w1.Code, w2.Code, "Same parameters should return same status code")

	// Response bodies should be similar (same total, etc.)
	if w1.Code == http.StatusOK && w2.Code == http.StatusOK {
		var resp1, resp2 map[string]interface{}
		json.Unmarshal(w1.Body.Bytes(), &resp1)
		json.Unmarshal(w2.Body.Bytes(), &resp2)

		// Total should be the same
		if total1, ok := resp1["total"]; ok {
			if total2, ok := resp2["total"]; ok {
				assert.Equal(t, total1, total2, "Total count should be consistent")
			}
		}
	}
}
