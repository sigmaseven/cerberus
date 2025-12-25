package api

// TASK 190: Handler-level security tests for XSS, injection, and path traversal
// Tests security edge cases in API handlers

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

// ============================================================================
// PATH TRAVERSAL TESTS
// ============================================================================

// TestSecurity_PathTraversalInRuleID tests path traversal in rule ID parameter
func TestSecurity_PathTraversalInRuleID(t *testing.T) {
	testAPI, cleanup := setupTestAPI(t)
	defer cleanup()

	token := createValidTestToken(t, testAPI.config.Auth.JWTSecret, "admin")

	// Path traversal payloads that could escape the expected context
	traversalPayloads := []struct {
		name    string
		payload string
	}{
		{"basic_traversal", "../../../etc/passwd"},
		{"encoded_traversal", "..%2F..%2F..%2Fetc%2Fpasswd"},
		{"double_encoded", "..%252F..%252F..%252Fetc%252Fpasswd"},
		{"null_byte", "test%00../../../etc/passwd"},
		{"windows_traversal", "..\\..\\..\\windows\\system32\\config\\sam"},
		{"encoded_backslash", "..%5C..%5C..%5Cwindows%5Csystem32"},
		{"mixed_traversal", "..%2F..\\..%5C..%2Fetc/passwd"},
		{"long_traversal", strings.Repeat("../", 100) + "etc/passwd"},
		{"unicode_traversal", "..%C0%AF..%C0%AF..%C0%AFetc%C0%AFpasswd"},
	}

	for _, tt := range traversalPayloads {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/api/v1/rules/"+tt.payload, nil)
			req.Header.Set("Authorization", "Bearer "+token)

			w := httptest.NewRecorder()
			testAPI.router.ServeHTTP(w, req)

			// Should return 400 (invalid ID), 404 (not found), or 301 (redirect from path cleaning)
			// The router's path cleaning (301 redirect) is itself a security feature
			assert.True(t, w.Code == http.StatusBadRequest || w.Code == http.StatusNotFound ||
				w.Code == http.StatusMovedPermanently,
				"Path traversal '%s' should be rejected, got status %d", tt.name, w.Code)

			// Response should NOT contain file contents
			body := w.Body.String()
			assert.NotContains(t, body, "root:", "Response should not contain /etc/passwd contents")
			assert.NotContains(t, body, "NTLM", "Response should not contain Windows system files")
		})
	}
}

// TestSecurity_PathTraversalInActionID tests path traversal in action ID parameter
func TestSecurity_PathTraversalInActionID(t *testing.T) {
	testAPI, cleanup := setupTestAPI(t)
	defer cleanup()

	token := createValidTestToken(t, testAPI.config.Auth.JWTSecret, "admin")

	req := httptest.NewRequest(http.MethodGet, "/api/v1/actions/../../../etc/passwd", nil)
	req.Header.Set("Authorization", "Bearer "+token)

	w := httptest.NewRecorder()
	testAPI.router.ServeHTTP(w, req)

	// Should be rejected with 400, 404, 405, or 301 (path cleaning redirect)
	assert.True(t, w.Code == http.StatusBadRequest || w.Code == http.StatusNotFound ||
		w.Code == http.StatusMethodNotAllowed || w.Code == http.StatusMovedPermanently,
		"Path traversal in action ID should be rejected, got status %d", w.Code)
}

// ============================================================================
// HEADER INJECTION TESTS
// ============================================================================

// TestSecurity_HeaderInjection tests for HTTP header injection vulnerabilities
func TestSecurity_HeaderInjection(t *testing.T) {
	testAPI, cleanup := setupTestAPI(t)
	defer cleanup()

	token := createValidTestToken(t, testAPI.config.Auth.JWTSecret, "admin")

	// Header injection payloads
	injectionPayloads := []struct {
		name    string
		header  string
		value   string
		checkFn func(t *testing.T, w *httptest.ResponseRecorder)
	}{
		{
			name:   "crlf_injection",
			header: "X-Custom",
			value:  "test\r\nEvil-Header: injected",
			checkFn: func(t *testing.T, w *httptest.ResponseRecorder) {
				// Evil-Header should NOT be in response headers
				assert.Empty(t, w.Header().Get("Evil-Header"),
					"CRLF injection should not allow header injection")
			},
		},
		{
			name:   "newline_injection",
			header: "X-Custom",
			value:  "test\nSet-Cookie: evil=value",
			checkFn: func(t *testing.T, w *httptest.ResponseRecorder) {
				// Check cookies don't contain evil value
				cookies := w.Result().Cookies()
				for _, cookie := range cookies {
					assert.NotEqual(t, "evil", cookie.Name,
						"Newline injection should not set malicious cookies")
				}
			},
		},
	}

	for _, tt := range injectionPayloads {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/api/v1/rules", nil)
			req.Header.Set("Authorization", "Bearer "+token)
			req.Header.Set(tt.header, tt.value)

			w := httptest.NewRecorder()
			testAPI.router.ServeHTTP(w, req)

			// Check for header injection
			tt.checkFn(t, w)
		})
	}
}

// ============================================================================
// CONTENT-TYPE SECURITY TESTS
// ============================================================================

// TestSecurity_ContentTypeEnforcement tests that Content-Type is properly enforced
func TestSecurity_ContentTypeEnforcement(t *testing.T) {
	testAPI, cleanup := setupTestAPI(t)
	defer cleanup()

	token := createValidTestToken(t, testAPI.config.Auth.JWTSecret, "admin")

	sigmaYAML := `title: Test Rule
detection:
  selection:
    field: value
  condition: selection`

	rule := map[string]interface{}{
		"type":       "sigma",
		"name":       "Test Rule",
		"severity":   "Medium",
		"sigma_yaml": sigmaYAML,
	}
	body, _ := json.Marshal(rule)

	testCases := []struct {
		name           string
		contentType    string
		expectAccepted bool
	}{
		{"application_json", "application/json", true},
		{"json_charset", "application/json; charset=utf-8", true},
		{"text_plain", "text/plain", false},
		{"text_html", "text/html", false},
		{"multipart", "multipart/form-data", false},
		{"empty", "", false},
		{"xml", "application/xml", false},
		{"javascript", "application/javascript", false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/api/v1/rules", bytes.NewReader(body))
			req.Header.Set("Authorization", "Bearer "+token)
			if tc.contentType != "" {
				req.Header.Set("Content-Type", tc.contentType)
			}
			addCSRFToRequest(t, req)

			w := httptest.NewRecorder()
			testAPI.router.ServeHTTP(w, req)

			if tc.expectAccepted {
				// Should not be rejected due to content-type
				assert.NotEqual(t, http.StatusUnsupportedMediaType, w.Code,
					"Content-Type %s should be accepted", tc.contentType)
			} else {
				// Should be rejected or at least not process the body as JSON
				// Note: Some frameworks still try to parse, so we check it doesn't succeed fully
				assert.True(t, w.Code == http.StatusBadRequest ||
					w.Code == http.StatusUnsupportedMediaType ||
					w.Code == http.StatusInternalServerError,
					"Content-Type %s should be rejected or fail parsing, got %d", tc.contentType, w.Code)
			}
		})
	}
}

// TestSecurity_ContentSniffing tests that content sniffing is disabled
func TestSecurity_ContentSniffing(t *testing.T) {
	testAPI, cleanup := setupTestAPI(t)
	defer cleanup()

	token := createValidTestToken(t, testAPI.config.Auth.JWTSecret, "admin")

	req := httptest.NewRequest(http.MethodGet, "/api/v1/rules", nil)
	req.Header.Set("Authorization", "Bearer "+token)

	w := httptest.NewRecorder()
	testAPI.router.ServeHTTP(w, req)

	// Check for X-Content-Type-Options header
	xContentTypeOptions := w.Header().Get("X-Content-Type-Options")
	assert.Equal(t, "nosniff", xContentTypeOptions,
		"Response should have X-Content-Type-Options: nosniff header")
}

// ============================================================================
// SECURITY HEADERS TESTS
// ============================================================================

// TestSecurity_ResponseHeaders tests that security headers are set correctly
func TestSecurity_ResponseHeaders(t *testing.T) {
	testAPI, cleanup := setupTestAPI(t)
	defer cleanup()

	token := createValidTestToken(t, testAPI.config.Auth.JWTSecret, "admin")

	req := httptest.NewRequest(http.MethodGet, "/api/v1/rules", nil)
	req.Header.Set("Authorization", "Bearer "+token)

	w := httptest.NewRecorder()
	testAPI.router.ServeHTTP(w, req)

	// Check security headers
	headers := map[string]string{
		"X-Content-Type-Options": "nosniff",
		"X-Frame-Options":        "DENY",
	}

	for header, expectedValue := range headers {
		actualValue := w.Header().Get(header)
		assert.Equal(t, expectedValue, actualValue,
			"Header %s should be set to %s, got %s", header, expectedValue, actualValue)
	}

	// Content-Security-Policy should be present (may have varying values)
	csp := w.Header().Get("Content-Security-Policy")
	assert.NotEmpty(t, csp, "Content-Security-Policy header should be set")
}

// ============================================================================
// INPUT SANITIZATION TESTS
// ============================================================================

// TestSecurity_NullByteInjection tests null byte injection handling
func TestSecurity_NullByteInjection(t *testing.T) {
	testAPI, cleanup := setupTestAPI(t)
	defer cleanup()

	token := createValidTestToken(t, testAPI.config.Auth.JWTSecret, "admin")

	// Null byte injection attempts using URL-encoded nulls
	// Note: Literal null bytes in URLs cause httptest.NewRequest to panic
	// We use URL-encoded versions which the router will decode
	nullPayloads := []struct {
		name    string
		payload string
	}{
		{"encoded_null", "rule%00yaml"},
		{"query_null", "id%00admin"},
		{"double_encoded", "test%2500txt"},
		{"null_in_extension", "file.txt%00.exe"},
		{"null_at_end", "allowed%00hidden"},
	}

	for _, tt := range nullPayloads {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/api/v1/rules/"+tt.payload, nil)
			req.Header.Set("Authorization", "Bearer "+token)

			w := httptest.NewRecorder()
			testAPI.router.ServeHTTP(w, req)

			// Should handle gracefully - not expose internal errors (500)
			// Valid responses: 400 (bad request), 404 (not found), or 200 (handled safely)
			assert.True(t, w.Code == http.StatusBadRequest || w.Code == http.StatusNotFound ||
				w.Code == http.StatusOK,
				"Null byte injection '%s' should be handled gracefully, got status %d", tt.name, w.Code)

			// Must not cause internal server error
			assert.NotEqual(t, http.StatusInternalServerError, w.Code,
				"Null byte injection '%s' should not cause internal error", tt.name)
		})
	}
}

// TestSecurity_ControlCharacters tests control character handling
func TestSecurity_ControlCharacters(t *testing.T) {
	testAPI, cleanup := setupTestAPI(t)
	defer cleanup()

	token := createValidTestToken(t, testAPI.config.Auth.JWTSecret, "admin")

	// Control characters that might cause issues
	controlChars := []struct {
		name string
		char string
	}{
		{"bell", "\x07"},
		{"backspace", "\x08"},
		{"tab", "\x09"},
		{"vertical_tab", "\x0B"},
		{"form_feed", "\x0C"},
		{"escape", "\x1B"},
		{"delete", "\x7F"},
	}

	for _, cc := range controlChars {
		t.Run(cc.name, func(t *testing.T) {
			// Create rule with control character in name
			rule := map[string]interface{}{
				"type":     "sigma",
				"name":     "Test " + cc.char + " Rule",
				"severity": "Medium",
				"sigma_yaml": `title: Test Rule
detection:
  selection:
    field: value
  condition: selection`,
			}
			body, _ := json.Marshal(rule)

			req := httptest.NewRequest(http.MethodPost, "/api/v1/rules", bytes.NewReader(body))
			req.Header.Set("Authorization", "Bearer "+token)
			req.Header.Set("Content-Type", "application/json")
			addCSRFToRequest(t, req)

			w := httptest.NewRecorder()
			testAPI.router.ServeHTTP(w, req)

			// Should either sanitize control chars or reject the request
			// Not cause an internal server error
			assert.NotEqual(t, http.StatusInternalServerError, w.Code,
				"Control character %s should not cause internal error", cc.name)
		})
	}
}

// ============================================================================
// AUTHENTICATION BYPASS TESTS
// ============================================================================

// TestSecurity_AuthBypassAttempts tests various authentication bypass attempts
func TestSecurity_AuthBypassAttempts(t *testing.T) {
	testAPI, cleanup := setupTestAPI(t)
	defer cleanup()

	protectedEndpoints := []struct {
		method string
		path   string
	}{
		{"GET", "/api/v1/rules"},
		{"POST", "/api/v1/rules"},
		{"GET", "/api/v1/alerts"},
		{"GET", "/api/v1/actions"},
		{"GET", "/api/v1/events"},
	}

	bypassAttempts := []struct {
		name       string
		authHeader string
	}{
		{"empty_auth", ""},
		{"bearer_only", "Bearer "},
		{"basic_auth", "Basic dXNlcjpwYXNz"},
		{"malformed_bearer", "Bearer.invalid.token"},
		{"null_token", "Bearer \x00"},
		{"very_long_token", "Bearer " + strings.Repeat("A", 10000)},
		{"json_in_token", "Bearer {\"admin\": true}"},
		{"header_injection", "Bearer token\r\nX-Admin: true"},
	}

	for _, endpoint := range protectedEndpoints {
		for _, attempt := range bypassAttempts {
			t.Run(endpoint.path+"_"+attempt.name, func(t *testing.T) {
				req := httptest.NewRequest(endpoint.method, endpoint.path, nil)
				if attempt.authHeader != "" {
					req.Header.Set("Authorization", attempt.authHeader)
				}

				w := httptest.NewRecorder()
				testAPI.router.ServeHTTP(w, req)

				// Should be rejected with 401 Unauthorized
				assert.Equal(t, http.StatusUnauthorized, w.Code,
					"Auth bypass attempt '%s' on %s should return 401, got %d",
					attempt.name, endpoint.path, w.Code)
			})
		}
	}
}

// TestSecurity_JWTManipulation tests JWT token manipulation attempts
func TestSecurity_JWTManipulation(t *testing.T) {
	testAPI, cleanup := setupTestAPI(t)
	defer cleanup()

	// Create a valid token for reference
	validToken := createValidTestToken(t, testAPI.config.Auth.JWTSecret, "admin")
	parts := strings.Split(validToken, ".")

	manipulatedTokens := []struct {
		name  string
		token string
	}{
		{"none_algorithm", strings.Replace(validToken, parts[0], "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0", 1)},
		{"empty_signature", parts[0] + "." + parts[1] + "."},
		{"modified_payload", parts[0] + ".eyJyb2xlIjoiYWRtaW4ifQ." + parts[2]},
		{"wrong_secret_token", "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwiYWRtaW4iOnRydWV9.TJVA95OrM7E2cBab30RMHrHDcEfxjoYZgeFONFh7HgQ"},
	}

	for _, tt := range manipulatedTokens {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/api/v1/rules", nil)
			req.Header.Set("Authorization", "Bearer "+tt.token)

			w := httptest.NewRecorder()
			testAPI.router.ServeHTTP(w, req)

			// Manipulated tokens should be rejected
			assert.Equal(t, http.StatusUnauthorized, w.Code,
				"JWT manipulation '%s' should be rejected with 401, got %d", tt.name, w.Code)
		})
	}
}

// ============================================================================
// REQUEST SIZE LIMIT TESTS
// ============================================================================

// TestSecurity_RequestBodySizeLimit tests that request body size is limited
func TestSecurity_RequestBodySizeLimit(t *testing.T) {
	testAPI, cleanup := setupTestAPI(t)
	defer cleanup()

	token := createValidTestToken(t, testAPI.config.Auth.JWTSecret, "admin")

	// Create a very large request body (> 1MB)
	largePayload := strings.Repeat("A", 2*1024*1024) // 2MB

	rule := map[string]interface{}{
		"type":        "sigma",
		"name":        "Test Rule",
		"description": largePayload,
		"severity":    "Medium",
		"sigma_yaml": `title: Test
detection:
  selection:
    field: value
  condition: selection`,
	}
	body, _ := json.Marshal(rule)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/rules", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	addCSRFToRequest(t, req)

	w := httptest.NewRecorder()
	testAPI.router.ServeHTTP(w, req)

	// Should be rejected for being too large
	assert.True(t, w.Code == http.StatusRequestEntityTooLarge ||
		w.Code == http.StatusBadRequest ||
		w.Code == http.StatusInternalServerError,
		"Request with 2MB body should be rejected, got status %d", w.Code)
}

// ============================================================================
// UNICODE SECURITY TESTS
// ============================================================================

// TestSecurity_UnicodeNormalization tests Unicode normalization issues
func TestSecurity_UnicodeNormalization(t *testing.T) {
	testAPI, cleanup := setupTestAPI(t)
	defer cleanup()

	token := createValidTestToken(t, testAPI.config.Auth.JWTSecret, "admin")

	// Unicode characters that might be misinterpreted
	// Note: Unicode null (\u0000) causes httptest.NewRequest to panic
	unicodePayloads := []struct {
		name    string
		payload string
	}{
		{"homoglyph_a", "аdmin"}, // Cyrillic 'а' instead of Latin 'a'
		{"zero_width_joiner", "admin\u200Dtest"},
		{"right_to_left_override", "\u202Etest"},
		{"combining_chars", "a\u0300\u0301\u0302\u0303\u0304"},
		{"soft_hyphen", "ad\u00ADmin"},          // Soft hyphen (invisible)
		{"zero_width_space", "test\u200Bhidden"}, // Zero-width space
	}

	for _, tt := range unicodePayloads {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/api/v1/rules/"+tt.payload, nil)
			req.Header.Set("Authorization", "Bearer "+token)

			w := httptest.NewRecorder()
			testAPI.router.ServeHTTP(w, req)

			// Should handle gracefully without exposing internal errors
			assert.NotEqual(t, http.StatusInternalServerError, w.Code,
				"Unicode payload '%s' should not cause internal error", tt.name)
		})
	}
}
