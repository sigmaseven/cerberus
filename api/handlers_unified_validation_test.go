package api

// TASK 191: Unified endpoint parameter validation tests
// Tests edge cases in the unified rules endpoint parameters

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
)

// ============================================================================
// CATEGORY PARAMETER TESTS
// ============================================================================

// TestUnifiedEndpoint_CategoryValidation tests category parameter validation
func TestUnifiedEndpoint_CategoryValidation(t *testing.T) {
	testAPI, cleanup := setupTestAPI(t)
	defer cleanup()

	token := createValidTestToken(t, testAPI.config.Auth.JWTSecret, "admin")

	testCases := []struct {
		name           string
		category       string
		expectStatus   int
		expectCategory string
	}{
		// Valid categories
		{"valid_detection", "detection", http.StatusOK, "detection"},
		{"valid_correlation", "correlation", http.StatusOK, "correlation"},
		{"valid_all", "all", http.StatusOK, "all"},
		{"empty_defaults_to_all", "", http.StatusOK, "all"},

		// Invalid categories
		{"invalid_category", "invalid", http.StatusBadRequest, ""},
		{"sql_injection", "detection; DROP TABLE rules;--", http.StatusBadRequest, ""},
		{"xss_category", "<script>alert(1)</script>", http.StatusBadRequest, ""},
		{"numeric_category", "123", http.StatusBadRequest, ""},
		// Note: spaces-only gets trimmed to empty string, which defaults to "all"
		{"spaces_only", "   ", http.StatusOK, "all"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			reqURL := "/api/v1/rules"
			if tc.category != "" {
				// URL-encode the category parameter to handle special chars
				reqURL += "?category=" + url.QueryEscape(tc.category)
			}

			req := httptest.NewRequest(http.MethodGet, reqURL, nil)
			req.Header.Set("Authorization", "Bearer "+token)

			w := httptest.NewRecorder()
			testAPI.router.ServeHTTP(w, req)

			assert.Equal(t, tc.expectStatus, w.Code,
				"Category '%s' should return status %d, got %d", tc.category, tc.expectStatus, w.Code)

			if tc.expectStatus == http.StatusOK && tc.expectCategory != "" {
				var response map[string]interface{}
				err := json.Unmarshal(w.Body.Bytes(), &response)
				assert.NoError(t, err)

				if category, ok := response["category"].(string); ok {
					assert.Equal(t, tc.expectCategory, category,
						"Response category should be '%s'", tc.expectCategory)
				}
			}
		})
	}
}

// TestUnifiedEndpoint_CategoryCaseSensitivity tests category case handling
func TestUnifiedEndpoint_CategoryCaseSensitivity(t *testing.T) {
	testAPI, cleanup := setupTestAPI(t)
	defer cleanup()

	token := createValidTestToken(t, testAPI.config.Auth.JWTSecret, "admin")

	testCases := []struct {
		name     string
		category string
		expect   int
	}{
		{"lowercase_detection", "detection", http.StatusOK},
		{"uppercase_DETECTION", "DETECTION", http.StatusBadRequest},
		{"mixedcase_Detection", "Detection", http.StatusBadRequest},
		{"lowercase_all", "all", http.StatusOK},
		{"uppercase_ALL", "ALL", http.StatusBadRequest},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/api/v1/rules?category="+url.QueryEscape(tc.category), nil)
			req.Header.Set("Authorization", "Bearer "+token)

			w := httptest.NewRecorder()
			testAPI.router.ServeHTTP(w, req)

			assert.Equal(t, tc.expect, w.Code,
				"Category '%s' should return status %d", tc.category, tc.expect)
		})
	}
}

// ============================================================================
// LIFECYCLE STATUS PARAMETER TESTS
// ============================================================================

// TestUnifiedEndpoint_LifecycleStatusValidation tests lifecycle_status parameter
func TestUnifiedEndpoint_LifecycleStatusValidation(t *testing.T) {
	testAPI, cleanup := setupTestAPI(t)
	defer cleanup()

	token := createValidTestToken(t, testAPI.config.Auth.JWTSecret, "admin")

	testCases := []struct {
		name   string
		status string
		expect int
	}{
		// Valid statuses
		{"valid_experimental", "experimental", http.StatusOK},
		{"valid_test", "test", http.StatusOK},
		{"valid_stable", "stable", http.StatusOK},
		{"valid_deprecated", "deprecated", http.StatusOK},
		{"valid_active", "active", http.StatusOK},
		{"empty_allowed", "", http.StatusOK},

		// Invalid statuses
		{"invalid_status", "invalid", http.StatusBadRequest},
		{"sql_injection", "stable; DROP TABLE--", http.StatusBadRequest},
		{"numeric_status", "123", http.StatusBadRequest},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			reqURL := "/api/v1/rules?category=detection"
			if tc.status != "" {
				reqURL += "&lifecycle_status=" + url.QueryEscape(tc.status)
			}

			req := httptest.NewRequest(http.MethodGet, reqURL, nil)
			req.Header.Set("Authorization", "Bearer "+token)

			w := httptest.NewRecorder()
			testAPI.router.ServeHTTP(w, req)

			assert.Equal(t, tc.expect, w.Code,
				"Lifecycle status '%s' should return status %d", tc.status, tc.expect)
		})
	}
}

// ============================================================================
// ENABLED PARAMETER TESTS
// ============================================================================

// TestUnifiedEndpoint_EnabledValidation tests enabled parameter
func TestUnifiedEndpoint_EnabledValidation(t *testing.T) {
	testAPI, cleanup := setupTestAPI(t)
	defer cleanup()

	token := createValidTestToken(t, testAPI.config.Auth.JWTSecret, "admin")

	testCases := []struct {
		name    string
		enabled string
		expect  int
	}{
		// Valid boolean values (Go's strconv.ParseBool accepts these)
		{"valid_true", "true", http.StatusOK},
		{"valid_false", "false", http.StatusOK},
		{"valid_1", "1", http.StatusOK},      // Go accepts "1" as true
		{"valid_0", "0", http.StatusOK},      // Go accepts "0" as false
		{"valid_TRUE", "TRUE", http.StatusOK}, // Case insensitive
		{"empty_allowed", "", http.StatusOK},

		// Invalid values
		{"invalid_yes", "yes", http.StatusBadRequest},
		{"invalid_no", "no", http.StatusBadRequest},
		{"invalid_string", "enabled", http.StatusBadRequest},
		{"sql_injection", "true; DROP TABLE--", http.StatusBadRequest},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			reqURL := "/api/v1/rules?category=detection"
			if tc.enabled != "" {
				reqURL += "&enabled=" + url.QueryEscape(tc.enabled)
			}

			req := httptest.NewRequest(http.MethodGet, reqURL, nil)
			req.Header.Set("Authorization", "Bearer "+token)

			w := httptest.NewRecorder()
			testAPI.router.ServeHTTP(w, req)

			assert.Equal(t, tc.expect, w.Code,
				"Enabled '%s' should return status %d, got %d", tc.enabled, tc.expect, w.Code)
		})
	}
}

// ============================================================================
// LIMIT/OFFSET PARAMETER TESTS
// ============================================================================

// TestUnifiedEndpoint_LimitValidation tests limit parameter
func TestUnifiedEndpoint_LimitValidation(t *testing.T) {
	testAPI, cleanup := setupTestAPI(t)
	defer cleanup()

	token := createValidTestToken(t, testAPI.config.Auth.JWTSecret, "admin")

	testCases := []struct {
		name   string
		limit  string
		expect int
	}{
		// Valid limits
		{"valid_1", "1", http.StatusOK},
		{"valid_50", "50", http.StatusOK},
		{"valid_100", "100", http.StatusOK},
		{"valid_1000", "1000", http.StatusOK},
		{"empty_uses_default", "", http.StatusOK},

		// Invalid limits
		{"invalid_0", "0", http.StatusBadRequest},
		{"invalid_negative", "-1", http.StatusBadRequest},
		{"invalid_1001", "1001", http.StatusBadRequest},
		{"invalid_float", "10.5", http.StatusBadRequest},
		{"invalid_string", "abc", http.StatusBadRequest},
		{"sql_injection", "10; DROP TABLE--", http.StatusBadRequest},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			reqURL := "/api/v1/rules?category=detection"
			if tc.limit != "" {
				reqURL += "&limit=" + url.QueryEscape(tc.limit)
			}

			req := httptest.NewRequest(http.MethodGet, reqURL, nil)
			req.Header.Set("Authorization", "Bearer "+token)

			w := httptest.NewRecorder()
			testAPI.router.ServeHTTP(w, req)

			assert.Equal(t, tc.expect, w.Code,
				"Limit '%s' should return status %d, got %d", tc.limit, tc.expect, w.Code)
		})
	}
}

// TestUnifiedEndpoint_OffsetValidation tests offset parameter
func TestUnifiedEndpoint_OffsetValidation(t *testing.T) {
	testAPI, cleanup := setupTestAPI(t)
	defer cleanup()

	token := createValidTestToken(t, testAPI.config.Auth.JWTSecret, "admin")

	testCases := []struct {
		name   string
		offset string
		expect int
	}{
		// Valid offsets
		{"valid_0", "0", http.StatusOK},
		{"valid_10", "10", http.StatusOK},
		{"valid_large", "999999", http.StatusOK},
		{"empty_uses_default", "", http.StatusOK},

		// Invalid offsets
		{"invalid_negative", "-1", http.StatusBadRequest},
		{"invalid_float", "10.5", http.StatusBadRequest},
		{"invalid_string", "abc", http.StatusBadRequest},
		{"sql_injection", "0; DROP TABLE--", http.StatusBadRequest},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			reqURL := "/api/v1/rules?category=detection"
			if tc.offset != "" {
				reqURL += "&offset=" + url.QueryEscape(tc.offset)
			}

			req := httptest.NewRequest(http.MethodGet, reqURL, nil)
			req.Header.Set("Authorization", "Bearer "+token)

			w := httptest.NewRecorder()
			testAPI.router.ServeHTTP(w, req)

			assert.Equal(t, tc.expect, w.Code,
				"Offset '%s' should return status %d, got %d", tc.offset, tc.expect, w.Code)
		})
	}
}

// ============================================================================
// LOGSOURCE FILTER TESTS
// ============================================================================

// TestUnifiedEndpoint_LogsourceFilters tests logsource filter parameters
func TestUnifiedEndpoint_LogsourceFilters(t *testing.T) {
	testAPI, cleanup := setupTestAPI(t)
	defer cleanup()

	token := createValidTestToken(t, testAPI.config.Auth.JWTSecret, "admin")

	testCases := []struct {
		name    string
		filter  string
		expect  int
	}{
		// Valid logsource categories
		{"valid_process", "logsource_category=process_creation", http.StatusOK},
		{"valid_network", "logsource_category=network_connection", http.StatusOK},
		{"valid_firewall", "logsource_category=firewall", http.StatusOK},

		// Valid logsource products
		{"valid_windows", "logsource_product=windows", http.StatusOK},
		{"valid_linux", "logsource_product=linux", http.StatusOK},

		// Combined filters
		{"combined_filters", "logsource_category=process_creation&logsource_product=windows", http.StatusOK},

		// Empty values (allowed)
		{"empty_category", "logsource_category=", http.StatusOK},
		{"empty_product", "logsource_product=", http.StatusOK},

		// Special characters (should be handled safely)
		{"special_chars", "logsource_category=process%20creation", http.StatusOK},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			url := "/api/v1/rules?category=detection&" + tc.filter

			req := httptest.NewRequest(http.MethodGet, url, nil)
			req.Header.Set("Authorization", "Bearer "+token)

			w := httptest.NewRecorder()
			testAPI.router.ServeHTTP(w, req)

			assert.Equal(t, tc.expect, w.Code,
				"Filter '%s' should return status %d, got %d", tc.filter, tc.expect, w.Code)
		})
	}
}

// ============================================================================
// MULTIPLE PARAMETER COMBINATION TESTS
// ============================================================================

// TestUnifiedEndpoint_ParameterCombinations tests valid parameter combinations
func TestUnifiedEndpoint_ParameterCombinations(t *testing.T) {
	testAPI, cleanup := setupTestAPI(t)
	defer cleanup()

	token := createValidTestToken(t, testAPI.config.Auth.JWTSecret, "admin")

	testCases := []struct {
		name   string
		query  string
		expect int
	}{
		// Valid combinations
		{"all_valid_params", "category=detection&limit=10&offset=0&enabled=true", http.StatusOK},
		{"category_and_limit", "category=correlation&limit=50", http.StatusOK},
		{"all_with_logsource", "category=all&logsource_category=process_creation", http.StatusOK},

		// Mixed valid/invalid (should fail on first invalid)
		{"valid_category_invalid_limit", "category=detection&limit=-1", http.StatusBadRequest},
		{"invalid_category_valid_limit", "category=invalid&limit=10", http.StatusBadRequest},

		// Edge case: duplicate parameters (first value should be used)
		{"duplicate_category", "category=detection&category=correlation", http.StatusOK},
		{"duplicate_limit", "category=detection&limit=10&limit=20", http.StatusOK},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/api/v1/rules?"+tc.query, nil)
			req.Header.Set("Authorization", "Bearer "+token)

			w := httptest.NewRecorder()
			testAPI.router.ServeHTTP(w, req)

			assert.Equal(t, tc.expect, w.Code,
				"Query '%s' should return status %d, got %d", tc.query, tc.expect, w.Code)
		})
	}
}

// ============================================================================
// RESPONSE FORMAT TESTS
// ============================================================================

// TestUnifiedEndpoint_ResponseFormat tests response structure
func TestUnifiedEndpoint_ResponseFormat(t *testing.T) {
	testAPI, cleanup := setupTestAPI(t)
	defer cleanup()

	token := createValidTestToken(t, testAPI.config.Auth.JWTSecret, "admin")

	req := httptest.NewRequest(http.MethodGet, "/api/v1/rules?category=detection&limit=10", nil)
	req.Header.Set("Authorization", "Bearer "+token)

	w := httptest.NewRecorder()
	testAPI.router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err, "Response should be valid JSON")

	// Verify required response fields
	requiredFields := []string{"items", "total", "page", "limit", "total_pages", "category"}
	for _, field := range requiredFields {
		_, ok := response[field]
		assert.True(t, ok, "Response should contain '%s' field", field)
	}

	// Verify items is an array
	items, ok := response["items"].([]interface{})
	assert.True(t, ok, "items should be an array")
	assert.NotNil(t, items, "items should not be nil")

	// Verify pagination fields are numbers
	_, ok = response["total"].(float64)
	assert.True(t, ok, "total should be a number")

	_, ok = response["page"].(float64)
	assert.True(t, ok, "page should be a number")

	_, ok = response["limit"].(float64)
	assert.True(t, ok, "limit should be a number")

	_, ok = response["total_pages"].(float64)
	assert.True(t, ok, "total_pages should be a number")
}

// TestUnifiedEndpoint_EmptyResults tests response when no rules exist
func TestUnifiedEndpoint_EmptyResults(t *testing.T) {
	testAPI, cleanup := setupTestAPI(t)
	defer cleanup()

	token := createValidTestToken(t, testAPI.config.Auth.JWTSecret, "admin")

	req := httptest.NewRequest(http.MethodGet, "/api/v1/rules?category=detection", nil)
	req.Header.Set("Authorization", "Bearer "+token)

	w := httptest.NewRecorder()
	testAPI.router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)

	// Empty result should still have valid structure
	items, ok := response["items"].([]interface{})
	assert.True(t, ok, "items should be an array even when empty")
	assert.Empty(t, items, "items should be empty")

	total, ok := response["total"].(float64)
	assert.True(t, ok, "total should be a number")
	assert.Equal(t, float64(0), total, "total should be 0 for empty results")
}
