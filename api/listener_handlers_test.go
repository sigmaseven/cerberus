package api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"cerberus/storage"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ============================================================================
// DESIGN NOTE: Listener Handler Testing Strategy
// ============================================================================
//
// LIMITATION: The API struct stores `listenerManager` as a concrete type
// (*ingest.ListenerManager) rather than an interface. This prevents mock injection
// because the real implementation accesses struct fields directly (lm.storage, lm.mu, etc.).
//
// TESTING STRATEGY:
// 1. Test "service unavailable" paths (listenerManager == nil) - these don't require mocks
// 2. Test input validation (invalid UUIDs, malformed JSON, etc.)
// 3. Test template handlers (don't require listenerManager)
// 4. Integration tests with a real ListenerManager would be needed for happy paths
//
// RECOMMENDATION: Refactor API.listenerManager to be an interface type to enable proper
// unit testing with mocks.
//
// ============================================================================

// ============================================================================
// TEST: listDynamicListeners - Service Unavailable
// ============================================================================

func TestListDynamicListeners_ServiceUnavailable(t *testing.T) {
	api, cleanup := setupTestAPI(t)
	defer cleanup()

	// Verify precondition: listenerManager is nil from setupTestAPI
	require.Nil(t, api.listenerManager, "Test requires nil listenerManager")

	// api.listenerManager is nil by default from setupTestAPI

	jwtToken, csrfToken := AuthenticateTestUser(t, api, "admin", "admin123")
	req := MakeAuthenticatedHTTPRequest("GET", "/api/v1/listeners", nil, jwtToken, csrfToken)
	w := httptest.NewRecorder()

	api.router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusServiceUnavailable, w.Code)
	assert.Contains(t, w.Body.String(), "Listener manager not available")
}

// ============================================================================
// TEST: getDynamicListener - Error Cases
// ============================================================================

func TestGetDynamicListener_ErrorCases(t *testing.T) {
	tests := []struct {
		name           string
		listenerID     string
		expectedStatus int
		expectedError  string
	}{
		{
			name:           "service unavailable",
			listenerID:     uuid.New().String(),
			expectedStatus: http.StatusServiceUnavailable,
			expectedError:  "Listener manager not available",
		},
		{
			name:           "invalid UUID format - not a UUID",
			listenerID:     "invalid-uuid",
			expectedStatus: http.StatusBadRequest,
			expectedError:  "Invalid listener ID format",
		},
		{
			name:           "invalid UUID format - empty",
			listenerID:     "",
			expectedStatus: http.StatusNotFound, // Empty ID doesn't match route pattern
			expectedError:  "404",               // Router returns 404 for no match
		},
		// Note: Path traversal attempts with slashes (e.g., "../../../etc/passwd") are
		// handled by the router which returns 404 (no matching route), not the handler.
		// Router interprets slashes as path separators before the handler sees them.
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			api, cleanup := setupTestAPI(t)
			defer cleanup()

			jwtToken, csrfToken := AuthenticateTestUser(t, api, "admin", "admin123")
			req := MakeAuthenticatedHTTPRequest("GET", "/api/v1/listeners/"+tt.listenerID, nil, jwtToken, csrfToken)
			w := httptest.NewRecorder()

			api.router.ServeHTTP(w, req)

			assert.Equal(t, tt.expectedStatus, w.Code)
			assert.Contains(t, w.Body.String(), tt.expectedError)
		})
	}
}

// ============================================================================
// TEST: createDynamicListener - Error Cases
// ============================================================================

func TestCreateDynamicListener_ErrorCases(t *testing.T) {
	tests := []struct {
		name           string
		requestBody    interface{}
		expectedStatus int
		expectedError  string
	}{
		{
			name:           "invalid JSON - validates input before checking service",
			requestBody:    "invalid json",
			expectedStatus: http.StatusBadRequest,
			expectedError:  "", // JSON decode error - returned before service check
		},
		{
			name:           "valid JSON but service unavailable",
			requestBody:    map[string]interface{}{"name": "Test"},
			expectedStatus: http.StatusServiceUnavailable,
			expectedError:  "Listener manager not available",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			api, cleanup := setupTestAPI(t)
			defer cleanup()

			// Marshal request body
			var bodyBytes []byte
			if str, ok := tt.requestBody.(string); ok {
				bodyBytes = []byte(str)
			} else {
				var err error
				bodyBytes, err = json.Marshal(tt.requestBody)
				require.NoError(t, err)
			}

			jwtToken, csrfToken := AuthenticateTestUser(t, api, "admin", "admin123")
			req := MakeAuthenticatedHTTPRequest("POST", "/api/v1/listeners", bodyBytes, jwtToken, csrfToken)
			w := httptest.NewRecorder()

			api.router.ServeHTTP(w, req)

			assert.Equal(t, tt.expectedStatus, w.Code)
			if tt.expectedError != "" {
				assert.Contains(t, w.Body.String(), tt.expectedError)
			}
		})
	}
}

// ============================================================================
// TEST: updateDynamicListener - Error Cases
// ============================================================================

func TestUpdateDynamicListener_ErrorCases(t *testing.T) {
	validID := uuid.New().String()

	tests := []struct {
		name           string
		listenerID     string
		requestBody    interface{}
		expectedStatus int
		expectedError  string
	}{
		{
			name:           "invalid UUID - validated FIRST before JSON body (cheap check first)",
			listenerID:     "invalid-uuid",
			requestBody:    map[string]interface{}{"name": "Test"},
			expectedStatus: http.StatusBadRequest,
			expectedError:  "Invalid listener ID format",
		},
		{
			name:           "invalid JSON - validated after UUID passes",
			listenerID:     validID,
			requestBody:    "invalid json",
			expectedStatus: http.StatusBadRequest,
			// UUID validation passes, then JSON validation fails
		},
		{
			name:           "service unavailable - checked after all input validation",
			listenerID:     validID,
			requestBody:    map[string]interface{}{"name": "Test"},
			expectedStatus: http.StatusServiceUnavailable,
			expectedError:  "Listener manager not available",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			api, cleanup := setupTestAPI(t)
			defer cleanup()

			// Marshal request body
			var bodyBytes []byte
			if str, ok := tt.requestBody.(string); ok {
				bodyBytes = []byte(str)
			} else {
				var err error
				bodyBytes, err = json.Marshal(tt.requestBody)
				require.NoError(t, err)
			}

			jwtToken, csrfToken := AuthenticateTestUser(t, api, "admin", "admin123")
			req := MakeAuthenticatedHTTPRequest("PUT", "/api/v1/listeners/"+tt.listenerID, bodyBytes, jwtToken, csrfToken)
			w := httptest.NewRecorder()

			api.router.ServeHTTP(w, req)

			assert.Equal(t, tt.expectedStatus, w.Code)
			if tt.expectedError != "" {
				assert.Contains(t, w.Body.String(), tt.expectedError)
			}
		})
	}
}

// ============================================================================
// TEST: deleteDynamicListener - Error Cases
// ============================================================================

func TestDeleteDynamicListener_ErrorCases(t *testing.T) {
	validID := uuid.New().String()

	tests := []struct {
		name           string
		listenerID     string
		expectedStatus int
		expectedError  string
	}{
		{
			name:           "service unavailable",
			listenerID:     validID,
			expectedStatus: http.StatusServiceUnavailable,
			expectedError:  "Listener manager not available",
		},
		{
			name:           "invalid UUID",
			listenerID:     "invalid-uuid",
			expectedStatus: http.StatusBadRequest,
			expectedError:  "Invalid listener ID format",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			api, cleanup := setupTestAPI(t)
			defer cleanup()

			jwtToken, csrfToken := AuthenticateTestUser(t, api, "admin", "admin123")
			req := MakeAuthenticatedHTTPRequest("DELETE", "/api/v1/listeners/"+tt.listenerID, nil, jwtToken, csrfToken)
			w := httptest.NewRecorder()

			api.router.ServeHTTP(w, req)

			assert.Equal(t, tt.expectedStatus, w.Code)
			assert.Contains(t, w.Body.String(), tt.expectedError)
		})
	}
}

// ============================================================================
// TEST: startDynamicListener - Error Cases
// ============================================================================

func TestStartDynamicListener_ErrorCases(t *testing.T) {
	validID := uuid.New().String()

	tests := []struct {
		name           string
		listenerID     string
		expectedStatus int
		expectedError  string
	}{
		{
			name:           "service unavailable",
			listenerID:     validID,
			expectedStatus: http.StatusServiceUnavailable,
			expectedError:  "Listener manager not available",
		},
		{
			name:           "invalid UUID",
			listenerID:     "invalid-uuid",
			expectedStatus: http.StatusBadRequest,
			expectedError:  "Invalid listener ID format",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			api, cleanup := setupTestAPI(t)
			defer cleanup()

			jwtToken, csrfToken := AuthenticateTestUser(t, api, "admin", "admin123")
			req := MakeAuthenticatedHTTPRequest("POST", "/api/v1/listeners/"+tt.listenerID+"/start", nil, jwtToken, csrfToken)
			w := httptest.NewRecorder()

			api.router.ServeHTTP(w, req)

			assert.Equal(t, tt.expectedStatus, w.Code)
			assert.Contains(t, w.Body.String(), tt.expectedError)
		})
	}
}

// ============================================================================
// TEST: stopDynamicListener - Error Cases
// ============================================================================

func TestStopDynamicListener_ErrorCases(t *testing.T) {
	validID := uuid.New().String()

	tests := []struct {
		name           string
		listenerID     string
		expectedStatus int
		expectedError  string
	}{
		{
			name:           "service unavailable",
			listenerID:     validID,
			expectedStatus: http.StatusServiceUnavailable,
			expectedError:  "Listener manager not available",
		},
		{
			name:           "invalid UUID",
			listenerID:     "invalid-uuid",
			expectedStatus: http.StatusBadRequest,
			expectedError:  "Invalid listener ID format",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			api, cleanup := setupTestAPI(t)
			defer cleanup()

			jwtToken, csrfToken := AuthenticateTestUser(t, api, "admin", "admin123")
			req := MakeAuthenticatedHTTPRequest("POST", "/api/v1/listeners/"+tt.listenerID+"/stop", nil, jwtToken, csrfToken)
			w := httptest.NewRecorder()

			api.router.ServeHTTP(w, req)

			assert.Equal(t, tt.expectedStatus, w.Code)
			assert.Contains(t, w.Body.String(), tt.expectedError)
		})
	}
}

// ============================================================================
// TEST: restartDynamicListener - Error Cases
// ============================================================================

func TestRestartDynamicListener_ErrorCases(t *testing.T) {
	validID := uuid.New().String()

	tests := []struct {
		name           string
		listenerID     string
		expectedStatus int
		expectedError  string
	}{
		{
			name:           "service unavailable",
			listenerID:     validID,
			expectedStatus: http.StatusServiceUnavailable,
			expectedError:  "Listener manager not available",
		},
		{
			name:           "invalid UUID",
			listenerID:     "invalid-uuid",
			expectedStatus: http.StatusBadRequest,
			expectedError:  "Invalid listener ID format",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			api, cleanup := setupTestAPI(t)
			defer cleanup()

			jwtToken, csrfToken := AuthenticateTestUser(t, api, "admin", "admin123")
			req := MakeAuthenticatedHTTPRequest("POST", "/api/v1/listeners/"+tt.listenerID+"/restart", nil, jwtToken, csrfToken)
			w := httptest.NewRecorder()

			api.router.ServeHTTP(w, req)

			assert.Equal(t, tt.expectedStatus, w.Code)
			assert.Contains(t, w.Body.String(), tt.expectedError)
		})
	}
}

// ============================================================================
// TEST: getDynamicListenerStats - Error Cases
// ============================================================================

func TestGetDynamicListenerStats_ErrorCases(t *testing.T) {
	validID := uuid.New().String()

	tests := []struct {
		name           string
		listenerID     string
		expectedStatus int
		expectedError  string
	}{
		{
			name:           "service unavailable",
			listenerID:     validID,
			expectedStatus: http.StatusServiceUnavailable,
			expectedError:  "Listener manager not available",
		},
		{
			name:           "invalid UUID",
			listenerID:     "invalid-uuid",
			expectedStatus: http.StatusBadRequest,
			expectedError:  "Invalid listener ID format",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			api, cleanup := setupTestAPI(t)
			defer cleanup()

			jwtToken, csrfToken := AuthenticateTestUser(t, api, "admin", "admin123")
			req := MakeAuthenticatedHTTPRequest("GET", "/api/v1/listeners/"+tt.listenerID+"/stats", nil, jwtToken, csrfToken)
			w := httptest.NewRecorder()

			api.router.ServeHTTP(w, req)

			assert.Equal(t, tt.expectedStatus, w.Code)
			assert.Contains(t, w.Body.String(), tt.expectedError)
		})
	}
}

// ============================================================================
// TEST: getListenerTemplates
// ============================================================================

func TestGetListenerTemplates(t *testing.T) {
	api, cleanup := setupTestAPI(t)
	defer cleanup()

	jwtToken, csrfToken := AuthenticateTestUser(t, api, "admin", "admin123")
	req := MakeAuthenticatedHTTPRequest("GET", "/api/v1/listener-templates", nil, jwtToken, csrfToken)
	w := httptest.NewRecorder()

	api.router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var templates []ListenerTemplate
	err := json.Unmarshal(w.Body.Bytes(), &templates)
	require.NoError(t, err)
	// Built-in templates should be available
	assert.Greater(t, len(templates), 0)

	// Verify template structure
	for _, tmpl := range templates {
		assert.NotEmpty(t, tmpl.ID)
		assert.NotEmpty(t, tmpl.Name)
		assert.NotEmpty(t, tmpl.Description)
		assert.NotEmpty(t, tmpl.Category)
		assert.NotNil(t, tmpl.Config)
	}
}

// ============================================================================
// TEST: getListenerTemplate - Success and Error Cases
// ============================================================================

func TestGetListenerTemplate(t *testing.T) {
	tests := []struct {
		name           string
		templateID     string
		expectedStatus int
		checkResponse  func(t *testing.T, w *httptest.ResponseRecorder)
	}{
		{
			name:           "success - valid template",
			templateID:     "palo-alto-syslog",
			expectedStatus: http.StatusOK,
			checkResponse: func(t *testing.T, w *httptest.ResponseRecorder) {
				var tmpl ListenerTemplate
				err := json.Unmarshal(w.Body.Bytes(), &tmpl)
				require.NoError(t, err)
				assert.Equal(t, "palo-alto-syslog", tmpl.ID)
				assert.NotEmpty(t, tmpl.Name)
			},
		},
		// Note: Empty template ID test removed - router returns 404 for empty path segments
		// Note: Path traversal test removed - router returns 404 for paths with slashes
		{
			name:           "error - invalid template ID format (too long)",
			templateID:     "a-very-long-template-id-that-exceeds-the-maximum-allowed-length-of-fifty-characters",
			expectedStatus: http.StatusBadRequest,
			checkResponse: func(t *testing.T, w *httptest.ResponseRecorder) {
				assert.Contains(t, w.Body.String(), "Invalid template ID format")
			},
		},
		{
			name:           "error - template not found",
			templateID:     "non-existent-template",
			expectedStatus: http.StatusNotFound,
			checkResponse: func(t *testing.T, w *httptest.ResponseRecorder) {
				assert.Contains(t, w.Body.String(), "Template not found")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			api, cleanup := setupTestAPI(t)
			defer cleanup()

			jwtToken, csrfToken := AuthenticateTestUser(t, api, "admin", "admin123")
			req := MakeAuthenticatedHTTPRequest("GET", "/api/v1/listener-templates/"+tt.templateID, nil, jwtToken, csrfToken)
			w := httptest.NewRecorder()

			api.router.ServeHTTP(w, req)

			assert.Equal(t, tt.expectedStatus, w.Code)
			if tt.checkResponse != nil {
				tt.checkResponse(t, w)
			}
		})
	}
}

// ============================================================================
// TEST: createListenerFromTemplate - Error Cases
// ============================================================================

func TestCreateListenerFromTemplate_ErrorCases(t *testing.T) {
	tests := []struct {
		name           string
		templateID     string
		requestBody    interface{}
		expectedStatus int
		expectedError  string
	}{
		{
			name:           "invalid template ID format (uppercase)",
			templateID:     "INVALID-UPPERCASE",
			requestBody:    nil,
			expectedStatus: http.StatusBadRequest,
			expectedError:  "Invalid template ID format",
		},
		{
			name:           "invalid template ID format (too long)",
			templateID:     "a-very-long-template-id-that-exceeds-the-maximum-allowed-length-of-fifty-characters",
			requestBody:    nil,
			expectedStatus: http.StatusBadRequest,
			expectedError:  "Invalid template ID format",
		},
		{
			name:           "template not found - checked before service availability",
			templateID:     "non-existent-template",
			requestBody:    nil,
			expectedStatus: http.StatusNotFound,
			expectedError:  "Template not found",
		},
		{
			name:           "service unavailable - valid template with nil manager",
			templateID:     "palo-alto-syslog", // Valid template ID
			requestBody:    nil,
			expectedStatus: http.StatusServiceUnavailable,
			expectedError:  "Listener manager not available",
		},
		// Note: Path traversal tests removed - router returns 404 for paths with slashes
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			api, cleanup := setupTestAPI(t)
			defer cleanup()

			// Marshal request body if present
			var bodyBytes []byte
			if tt.requestBody != nil {
				if str, ok := tt.requestBody.(string); ok {
					bodyBytes = []byte(str)
				} else {
					var err error
					bodyBytes, err = json.Marshal(tt.requestBody)
					require.NoError(t, err)
				}
			}

			jwtToken, csrfToken := AuthenticateTestUser(t, api, "admin", "admin123")
			req := MakeAuthenticatedHTTPRequest("POST", "/api/v1/listeners/from-template/"+tt.templateID, bodyBytes, jwtToken, csrfToken)
			w := httptest.NewRecorder()

			api.router.ServeHTTP(w, req)

			assert.Equal(t, tt.expectedStatus, w.Code)
			if tt.expectedError != "" {
				assert.Contains(t, w.Body.String(), tt.expectedError)
			}
		})
	}
}

// ============================================================================
// TEST: Input Validation Order Security
// ============================================================================
// This test verifies that input validation happens BEFORE service availability
// checks. This is critical to prevent service state leakage to attackers.

// TestAuthenticationBeforeValidation_Security verifies authentication happens BEFORE input validation
// SECURITY: Unauthenticated requests must return 401 before any input processing
func TestAuthenticationBeforeValidation_Security(t *testing.T) {
	api, cleanup := setupTestAPI(t)
	defer cleanup()

	// Test: Unauthenticated requests with invalid input should return 401 (not 400)
	// This proves auth happens BEFORE input validation (prevents information leakage)
	invalidUUID := "not-a-valid-uuid"
	invalidJSON := "invalid json body"

	testCases := []struct {
		name   string
		method string
		path   string
		body   []byte
	}{
		{"GET listener without auth", "GET", "/api/v1/listeners/" + invalidUUID, nil},
		{"POST create without auth", "POST", "/api/v1/listeners", []byte(invalidJSON)},
		{"PUT update without auth", "PUT", "/api/v1/listeners/" + invalidUUID, []byte(invalidJSON)},
		{"DELETE listener without auth", "DELETE", "/api/v1/listeners/" + invalidUUID, nil},
		{"POST start without auth", "POST", "/api/v1/listeners/" + invalidUUID + "/start", nil},
		{"POST stop without auth", "POST", "/api/v1/listeners/" + invalidUUID + "/stop", nil},
		{"POST restart without auth", "POST", "/api/v1/listeners/" + invalidUUID + "/restart", nil},
		{"GET stats without auth", "GET", "/api/v1/listeners/" + invalidUUID + "/stats", nil},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var req *http.Request
			if tc.body != nil {
				req = httptest.NewRequest(tc.method, tc.path, bytes.NewReader(tc.body))
			} else {
				req = httptest.NewRequest(tc.method, tc.path, nil)
			}
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()

			api.router.ServeHTTP(w, req)

			// SECURITY ASSERTION: Must return 401 (auth required) BEFORE checking input
			// If we get 400 (bad input), authentication happened AFTER validation (vulnerability)
			assert.Equal(t, http.StatusUnauthorized, w.Code,
				"SECURITY: Must authenticate BEFORE validating input. Got %d for %s %s",
				w.Code, tc.method, tc.path)
		})
	}
}

// TestInputValidation_AfterAuth verifies input validation happens after successful auth
func TestInputValidation_AfterAuth(t *testing.T) {
	// Setup API with nil listenerManager (simulates unavailable service)
	api, cleanup := setupTestAPI(t)
	defer cleanup()

	jwtToken, csrfToken := AuthenticateTestUser(t, api, "admin", "admin123")

	// Test: Invalid UUID should return 400 Bad Request, NOT 503 Service Unavailable
	// This proves that input validation happens BEFORE service state check
	invalidUUID := "not-a-valid-uuid-format"

	testCases := []struct {
		name           string
		method         string
		path           string
		expectBadInput bool // true if 400 expected, false if input is valid but service unavailable
	}{
		{"GET listener", "GET", "/api/v1/listeners/" + invalidUUID, true},
		{"DELETE listener", "DELETE", "/api/v1/listeners/" + invalidUUID, true},
		{"PUT listener", "PUT", "/api/v1/listeners/" + invalidUUID, true},
		{"POST start", "POST", "/api/v1/listeners/" + invalidUUID + "/start", true},
		{"POST stop", "POST", "/api/v1/listeners/" + invalidUUID + "/stop", true},
		{"POST restart", "POST", "/api/v1/listeners/" + invalidUUID + "/restart", true},
		{"GET stats", "GET", "/api/v1/listeners/" + invalidUUID + "/stats", true},
		// List endpoint: pagination params are clamped (not rejected), so valid input + unavailable service = 503
		// This test verifies pagination is parsed BEFORE service check (ordering is correct)
		{"GET list", "GET", "/api/v1/listeners?page=1&limit=10", false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var body []byte
			if tc.method == "PUT" {
				body = []byte(`{"name": "test"}`)
			}
			req := MakeAuthenticatedHTTPRequest(tc.method, tc.path, body, jwtToken, csrfToken)
			w := httptest.NewRecorder()

			api.router.ServeHTTP(w, req)

			if tc.expectBadInput {
				// SECURITY ASSERTION: Must return 400 (invalid input), NOT 503 (service unavailable)
				// If we get 503, the handler is leaking service state before validating input
				assert.Equal(t, http.StatusBadRequest, w.Code,
					"SECURITY VIOLATION: Handler must validate input BEFORE checking service state. "+
						"Got %d instead of 400 for %s %s", w.Code, tc.method, tc.path)
				assert.Contains(t, w.Body.String(), "Invalid listener ID format",
					"Expected 'Invalid listener ID format' error message")
			} else {
				// For endpoints where input is valid (e.g., list with valid pagination),
				// we verify the handler reaches the service check (returns 503)
				// This confirms input was parsed successfully BEFORE checking service state
				assert.Equal(t, http.StatusServiceUnavailable, w.Code,
					"Expected 503 Service Unavailable for valid input with nil manager. "+
						"Got %d for %s %s", w.Code, tc.method, tc.path)
				assert.Contains(t, w.Body.String(), "Listener manager not available",
					"Expected 'Listener manager not available' error message")
			}
		})
	}
}

// ============================================================================
// TEST: UUID Validation Edge Cases (Security)
// ============================================================================

func TestListenerHandlers_UUIDValidationSecurity(t *testing.T) {
	api, cleanup := setupTestAPI(t)
	defer cleanup()

	jwtToken, csrfToken := AuthenticateTestUser(t, api, "admin", "admin123")

	// Test various invalid UUID formats for security
	// Note: URL-encoded path traversal attempts cause 301 redirects and are tested separately
	// We only test INVALID formats here - valid UUIDs should pass format validation
	maliciousUUIDs := []string{
		"not-a-uuid",                            // invalid format
		"00000000-0000-0000-0000-00000000000",   // too short (35 chars)
		"00000000-0000-0000-0000-0000000000000", // too long (37 chars)
		"xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",  // invalid characters
	}
	// Note: "12345678-1234-1234-1234-123456789012" is a VALID UUID format
	// Valid UUIDs pass validation and proceed to service check (503) - that's correct behavior

	endpoints := []struct {
		path   string
		method string
	}{
		{"/api/v1/listeners/%s", "GET"},
		{"/api/v1/listeners/%s/start", "POST"},
		{"/api/v1/listeners/%s/stop", "POST"},
		{"/api/v1/listeners/%s/restart", "POST"},
		{"/api/v1/listeners/%s/stats", "GET"},
	}

	for _, endpoint := range endpoints {
		for _, maliciousUUID := range maliciousUUIDs {
			t.Run(fmt.Sprintf("%s_%s with %q", endpoint.method, endpoint.path, maliciousUUID), func(t *testing.T) {
				path := fmt.Sprintf(endpoint.path, maliciousUUID)
				req := MakeAuthenticatedHTTPRequest(endpoint.method, path, nil, jwtToken, csrfToken)
				w := httptest.NewRecorder()

				api.router.ServeHTTP(w, req)

				// Should return 400 Bad Request or 503 Service Unavailable
				// 503 is returned first if manager is nil, 400 if UUID validation happens
				// Also accept 404 for paths that don't match the route pattern (e.g., path traversal may create invalid paths)
				validStatus := w.Code == http.StatusBadRequest ||
					w.Code == http.StatusServiceUnavailable ||
					w.Code == http.StatusNotFound
				assert.True(t, validStatus,
					"Expected 400, 404, or 503, got %d for path: %s", w.Code, path)

				// If we got 400, it should be about invalid UUID format
				if w.Code == http.StatusBadRequest {
					assert.Contains(t, w.Body.String(), "Invalid listener ID format")
				}
			})
		}
	}
}

// ============================================================================
// RBAC PERMISSION TESTS FOR LISTENER HANDLERS
// ============================================================================
// These tests verify that RBAC permissions are correctly enforced for each
// listener endpoint. We test that users without the required permissions
// receive 403 Forbidden responses.

// setupListenerRBAC creates a test API with RBAC enabled and test users
// with different roles for permission testing.
// - viewer: read events/alerts/rules only (NO read:listeners)
// - analyst: read events/alerts/rules + read:listeners (can view listeners)
// - engineer: analyst + write:listeners (can create/modify/delete, but NOT start/stop)
// - testuser/admin: full admin access (can create/modify/delete/start/stop)
func setupListenerRBAC(t *testing.T) (*API, func()) {
	api, cleanup := setupTestAPI(t)

	ctx := context.Background()
	userStorage := api.userStorage.(*storage.SQLiteUserStorage)
	roleStorage := api.roleStorage.(*storage.SQLiteRoleStorage)

	// Dynamically look up role IDs by name (don't hardcode - IDs may vary)
	roles, err := roleStorage.ListRoles(ctx)
	require.NoError(t, err, "Failed to list roles")

	var viewerRoleID, analystRoleID, engineerRoleID int64
	for _, role := range roles {
		switch role.Name {
		case storage.RoleViewer:
			viewerRoleID = role.ID
		case storage.RoleAnalyst:
			analystRoleID = role.ID
		case storage.RoleEngineer:
			engineerRoleID = role.ID
		}
	}
	require.NotZero(t, viewerRoleID, "Viewer role not found in database")
	require.NotZero(t, analystRoleID, "Analyst role not found in database")
	require.NotZero(t, engineerRoleID, "Engineer role not found in database")

	// Create viewer user - does NOT have read:listeners permission
	viewer := &storage.User{
		Username: "viewer",
		Password: "viewer123",
		RoleID:   &viewerRoleID,
		Active:   true,
	}
	err = userStorage.CreateUser(ctx, viewer)
	require.NoError(t, err, "Failed to create viewer test user")

	// Create analyst user - HAS read:listeners permission
	analyst := &storage.User{
		Username: "analyst",
		Password: "analyst123",
		RoleID:   &analystRoleID,
		Active:   true,
	}
	err = userStorage.CreateUser(ctx, analyst)
	require.NoError(t, err, "Failed to create analyst test user")

	// Create engineer user - HAS write:listeners but NOT admin:system
	engineer := &storage.User{
		Username: "engineer",
		Password: "engineer123",
		RoleID:   &engineerRoleID,
		Active:   true,
	}
	err = userStorage.CreateUser(ctx, engineer)
	require.NoError(t, err, "Failed to create engineer test user")

	return api, cleanup
}

// TestRBAC_ListenerRead_AnalystCanAccess tests that analyst role can read listeners
// Note: viewer role does NOT have read:listeners permission, analyst does
func TestRBAC_ListenerRead_AnalystCanAccess(t *testing.T) {
	api, cleanup := setupListenerRBAC(t)
	defer cleanup()

	// Authenticate as analyst (role WITH read:listeners permission)
	jwtToken, csrfToken := AuthenticateTestUser(t, api, "analyst", "analyst123")

	req := MakeAuthenticatedHTTPRequest("GET", "/api/v1/listeners", nil, jwtToken, csrfToken)
	w := httptest.NewRecorder()

	api.router.ServeHTTP(w, req)

	// Should return 503 (service unavailable because listenerManager is nil)
	// NOT 403 (forbidden) - this proves the permission check passed
	assert.Equal(t, http.StatusServiceUnavailable, w.Code,
		"Analyst with read:listeners should pass permission check (get 503, not 403)")
}

// TestRBAC_ListenerRead_ViewerDenied tests that viewer role cannot read listeners
// Viewer role only has read:events, read:alerts, read:rules - NOT read:listeners
func TestRBAC_ListenerRead_ViewerDenied(t *testing.T) {
	api, cleanup := setupListenerRBAC(t)
	defer cleanup()

	// Authenticate as viewer (role WITHOUT read:listeners permission)
	jwtToken, csrfToken := AuthenticateTestUser(t, api, "viewer", "viewer123")

	req := MakeAuthenticatedHTTPRequest("GET", "/api/v1/listeners", nil, jwtToken, csrfToken)
	w := httptest.NewRecorder()

	api.router.ServeHTTP(w, req)

	// Should return 403 (forbidden) because viewer lacks read:listeners
	assert.Equal(t, http.StatusForbidden, w.Code,
		"Viewer without read:listeners should be denied (403)")
}

// TestRBAC_ListenerWrite_ViewerDenied tests that viewer role cannot create listeners
func TestRBAC_ListenerWrite_ViewerDenied(t *testing.T) {
	api, cleanup := setupListenerRBAC(t)
	defer cleanup()

	// Authenticate as viewer
	jwtToken, csrfToken := AuthenticateTestUser(t, api, "viewer", "viewer123")

	listenerData := map[string]interface{}{
		"name":     "Test Listener",
		"type":     "syslog",
		"protocol": "udp",
		"host":     "0.0.0.0",
		"port":     5514,
	}
	body, _ := json.Marshal(listenerData)

	req := MakeAuthenticatedHTTPRequest("POST", "/api/v1/listeners", body, jwtToken, csrfToken)
	w := httptest.NewRecorder()

	api.router.ServeHTTP(w, req)

	// Viewer role should not have write:listeners permission
	assert.Equal(t, http.StatusForbidden, w.Code,
		"Viewer without write:listeners should be denied (403)")
	assert.Contains(t, w.Body.String(), "Insufficient permissions")
}

// TestRBAC_ListenerAdmin_ViewerDenied tests that viewer role cannot start/stop listeners
func TestRBAC_ListenerAdmin_ViewerDenied(t *testing.T) {
	api, cleanup := setupListenerRBAC(t)
	defer cleanup()

	// Authenticate as viewer
	jwtToken, csrfToken := AuthenticateTestUser(t, api, "viewer", "viewer123")
	validUUID := uuid.New().String()

	// Test start - requires admin:system permission
	req := MakeAuthenticatedHTTPRequest("POST", "/api/v1/listeners/"+validUUID+"/start", nil, jwtToken, csrfToken)
	w := httptest.NewRecorder()
	api.router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusForbidden, w.Code, "Viewer cannot start listeners")

	// Test stop - requires admin:system permission
	req = MakeAuthenticatedHTTPRequest("POST", "/api/v1/listeners/"+validUUID+"/stop", nil, jwtToken, csrfToken)
	w = httptest.NewRecorder()
	api.router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusForbidden, w.Code, "Viewer cannot stop listeners")

	// Test restart - requires admin:system permission
	req = MakeAuthenticatedHTTPRequest("POST", "/api/v1/listeners/"+validUUID+"/restart", nil, jwtToken, csrfToken)
	w = httptest.NewRecorder()
	api.router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusForbidden, w.Code, "Viewer cannot restart listeners")
}

// TestRBAC_ListenerAdmin_AdminCanAccess tests that admin role can start/stop listeners
func TestRBAC_ListenerAdmin_AdminCanAccess(t *testing.T) {
	api, cleanup := setupListenerRBAC(t)
	defer cleanup()

	// Authenticate as admin
	jwtToken, csrfToken := AuthenticateTestUser(t, api, "admin", "admin123")
	validUUID := uuid.New().String()

	// Test start - admin should pass permission check (get 503 not 403)
	req := MakeAuthenticatedHTTPRequest("POST", "/api/v1/listeners/"+validUUID+"/start", nil, jwtToken, csrfToken)
	w := httptest.NewRecorder()
	api.router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusServiceUnavailable, w.Code,
		"Admin should pass permission check for start (get 503, not 403)")

	// Test stop
	req = MakeAuthenticatedHTTPRequest("POST", "/api/v1/listeners/"+validUUID+"/stop", nil, jwtToken, csrfToken)
	w = httptest.NewRecorder()
	api.router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusServiceUnavailable, w.Code,
		"Admin should pass permission check for stop (get 503, not 403)")

	// Test restart
	req = MakeAuthenticatedHTTPRequest("POST", "/api/v1/listeners/"+validUUID+"/restart", nil, jwtToken, csrfToken)
	w = httptest.NewRecorder()
	api.router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusServiceUnavailable, w.Code,
		"Admin should pass permission check for restart (get 503, not 403)")
}

// TestRBAC_ListenerDelete_ViewerDenied tests that viewer role cannot delete listeners
func TestRBAC_ListenerDelete_ViewerDenied(t *testing.T) {
	api, cleanup := setupListenerRBAC(t)
	defer cleanup()

	// Authenticate as viewer
	jwtToken, csrfToken := AuthenticateTestUser(t, api, "viewer", "viewer123")
	validUUID := uuid.New().String()

	req := MakeAuthenticatedHTTPRequest("DELETE", "/api/v1/listeners/"+validUUID, nil, jwtToken, csrfToken)
	w := httptest.NewRecorder()

	api.router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusForbidden, w.Code,
		"Viewer without write:listeners should be denied delete (403)")
}

// TestRBAC_ListenerUpdate_ViewerDenied tests that viewer role cannot update listeners
func TestRBAC_ListenerUpdate_ViewerDenied(t *testing.T) {
	api, cleanup := setupListenerRBAC(t)
	defer cleanup()

	// Authenticate as viewer
	jwtToken, csrfToken := AuthenticateTestUser(t, api, "viewer", "viewer123")
	validUUID := uuid.New().String()

	updateData := map[string]interface{}{
		"name": "Updated Name",
	}
	body, _ := json.Marshal(updateData)

	req := MakeAuthenticatedHTTPRequest("PUT", "/api/v1/listeners/"+validUUID, body, jwtToken, csrfToken)
	w := httptest.NewRecorder()

	api.router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusForbidden, w.Code,
		"Viewer without write:listeners should be denied update (403)")
}

// TestRBAC_ListenerFromTemplate_ViewerDenied tests viewer cannot create from template
func TestRBAC_ListenerFromTemplate_ViewerDenied(t *testing.T) {
	api, cleanup := setupListenerRBAC(t)
	defer cleanup()

	// Authenticate as viewer
	jwtToken, csrfToken := AuthenticateTestUser(t, api, "viewer", "viewer123")

	req := MakeAuthenticatedHTTPRequest("POST", "/api/v1/listeners/from-template/palo-alto-syslog", nil, jwtToken, csrfToken)
	w := httptest.NewRecorder()

	api.router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusForbidden, w.Code,
		"Viewer without write:listeners should be denied create from template (403)")
}

// TestRBAC_ListenerStats_AnalystCanAccess tests that analyst can access listener stats
// Stats endpoint requires read:listeners permission
func TestRBAC_ListenerStats_AnalystCanAccess(t *testing.T) {
	api, cleanup := setupListenerRBAC(t)
	defer cleanup()

	// Authenticate as analyst (has read:listeners permission)
	jwtToken, csrfToken := AuthenticateTestUser(t, api, "analyst", "analyst123")
	validUUID := uuid.New().String()

	req := MakeAuthenticatedHTTPRequest("GET", "/api/v1/listeners/"+validUUID+"/stats", nil, jwtToken, csrfToken)
	w := httptest.NewRecorder()

	api.router.ServeHTTP(w, req)

	// Should pass permission check (get 503 service unavailable, not 403 forbidden)
	assert.Equal(t, http.StatusServiceUnavailable, w.Code,
		"Analyst with read:listeners should pass permission check for stats (get 503, not 403)")
}

// TestRBAC_ListenerTemplates_AnalystCanAccess tests template endpoints accessibility
// Templates require read:listeners permission (analyst, engineer, admin)
func TestRBAC_ListenerTemplates_AnalystCanAccess(t *testing.T) {
	api, cleanup := setupListenerRBAC(t)
	defer cleanup()

	// Template list requires read:listeners permission
	jwtToken, csrfToken := AuthenticateTestUser(t, api, "analyst", "analyst123")

	req := MakeAuthenticatedHTTPRequest("GET", "/api/v1/listener-templates", nil, jwtToken, csrfToken)
	w := httptest.NewRecorder()

	api.router.ServeHTTP(w, req)

	// Templates endpoint doesn't require listenerManager, should return 200
	assert.Equal(t, http.StatusOK, w.Code,
		"Analyst with read:listeners should be able to list templates")
}

// TestRBAC_ListenerTemplates_ViewerDenied tests that viewer cannot access templates
func TestRBAC_ListenerTemplates_ViewerDenied(t *testing.T) {
	api, cleanup := setupListenerRBAC(t)
	defer cleanup()

	// Viewer does NOT have read:listeners permission
	jwtToken, csrfToken := AuthenticateTestUser(t, api, "viewer", "viewer123")

	req := MakeAuthenticatedHTTPRequest("GET", "/api/v1/listener-templates", nil, jwtToken, csrfToken)
	w := httptest.NewRecorder()

	api.router.ServeHTTP(w, req)

	// Viewer should be denied (403)
	assert.Equal(t, http.StatusForbidden, w.Code,
		"Viewer without read:listeners should be denied access to templates")
}

// ============================================================================
// ENGINEER ROLE TESTS - Verify correct permission boundaries
// ============================================================================
// Engineer has: read:listeners, write:listeners
// Engineer lacks: admin:system (cannot start/stop/restart)
// These tests verify the CORRECT permission is being checked

// TestRBAC_EngineerCanRead tests engineer can read listeners
func TestRBAC_EngineerCanRead(t *testing.T) {
	api, cleanup := setupListenerRBAC(t)
	defer cleanup()

	jwtToken, csrfToken := AuthenticateTestUser(t, api, "engineer", "engineer123")

	req := MakeAuthenticatedHTTPRequest("GET", "/api/v1/listeners", nil, jwtToken, csrfToken)
	w := httptest.NewRecorder()
	api.router.ServeHTTP(w, req)

	// Engineer has read:listeners, should pass permission check (get 503, not 403)
	assert.Equal(t, http.StatusServiceUnavailable, w.Code,
		"Engineer with read:listeners should pass permission check (get 503, not 403)")
}

// TestRBAC_EngineerCanWrite tests engineer can create/update/delete listeners
func TestRBAC_EngineerCanWrite(t *testing.T) {
	api, cleanup := setupListenerRBAC(t)
	defer cleanup()

	jwtToken, csrfToken := AuthenticateTestUser(t, api, "engineer", "engineer123")
	validUUID := uuid.New().String()

	// Test CREATE - requires write:listeners
	listenerData := map[string]interface{}{
		"name":     "Test Listener",
		"type":     "syslog",
		"protocol": "udp",
		"host":     "0.0.0.0",
		"port":     5514,
	}
	body, _ := json.Marshal(listenerData)
	req := MakeAuthenticatedHTTPRequest("POST", "/api/v1/listeners", body, jwtToken, csrfToken)
	w := httptest.NewRecorder()
	api.router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusServiceUnavailable, w.Code,
		"Engineer with write:listeners should pass CREATE permission check (get 503, not 403)")

	// Test UPDATE - requires write:listeners
	updateData := map[string]interface{}{"name": "Updated"}
	body, _ = json.Marshal(updateData)
	req = MakeAuthenticatedHTTPRequest("PUT", "/api/v1/listeners/"+validUUID, body, jwtToken, csrfToken)
	w = httptest.NewRecorder()
	api.router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusServiceUnavailable, w.Code,
		"Engineer with write:listeners should pass UPDATE permission check (get 503, not 403)")

	// Test DELETE - requires write:listeners
	req = MakeAuthenticatedHTTPRequest("DELETE", "/api/v1/listeners/"+validUUID, nil, jwtToken, csrfToken)
	w = httptest.NewRecorder()
	api.router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusServiceUnavailable, w.Code,
		"Engineer with write:listeners should pass DELETE permission check (get 503, not 403)")
}

// TestRBAC_EngineerCannotAdmin tests engineer CANNOT start/stop/restart
// This is the key test: verifies admin:system is required, not write:listeners
func TestRBAC_EngineerCannotAdmin(t *testing.T) {
	api, cleanup := setupListenerRBAC(t)
	defer cleanup()

	jwtToken, csrfToken := AuthenticateTestUser(t, api, "engineer", "engineer123")
	validUUID := uuid.New().String()

	// Test START - requires admin:system (engineer only has write:listeners)
	req := MakeAuthenticatedHTTPRequest("POST", "/api/v1/listeners/"+validUUID+"/start", nil, jwtToken, csrfToken)
	w := httptest.NewRecorder()
	api.router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusForbidden, w.Code,
		"PERMISSION BOUNDARY: Engineer has write:listeners but lacks admin:system - MUST be denied for start")

	// Test STOP - requires admin:system
	req = MakeAuthenticatedHTTPRequest("POST", "/api/v1/listeners/"+validUUID+"/stop", nil, jwtToken, csrfToken)
	w = httptest.NewRecorder()
	api.router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusForbidden, w.Code,
		"PERMISSION BOUNDARY: Engineer has write:listeners but lacks admin:system - MUST be denied for stop")

	// Test RESTART - requires admin:system
	req = MakeAuthenticatedHTTPRequest("POST", "/api/v1/listeners/"+validUUID+"/restart", nil, jwtToken, csrfToken)
	w = httptest.NewRecorder()
	api.router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusForbidden, w.Code,
		"PERMISSION BOUNDARY: Engineer has write:listeners but lacks admin:system - MUST be denied for restart")
}

// TestRBAC_AnalystCanReadButNotWrite verifies analyst permission boundary
// Analyst has: read:listeners
// Analyst lacks: write:listeners, admin:system
func TestRBAC_AnalystCanReadButNotWrite(t *testing.T) {
	api, cleanup := setupListenerRBAC(t)
	defer cleanup()

	jwtToken, csrfToken := AuthenticateTestUser(t, api, "analyst", "analyst123")
	validUUID := uuid.New().String()

	// Test READ - analyst can read
	req := MakeAuthenticatedHTTPRequest("GET", "/api/v1/listeners", nil, jwtToken, csrfToken)
	w := httptest.NewRecorder()
	api.router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusServiceUnavailable, w.Code,
		"Analyst with read:listeners should pass READ permission check")

	// Test CREATE - analyst CANNOT create
	listenerData := map[string]interface{}{
		"name": "Test", "type": "syslog", "protocol": "udp", "host": "0.0.0.0", "port": 5514,
	}
	body, _ := json.Marshal(listenerData)
	req = MakeAuthenticatedHTTPRequest("POST", "/api/v1/listeners", body, jwtToken, csrfToken)
	w = httptest.NewRecorder()
	api.router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusForbidden, w.Code,
		"PERMISSION BOUNDARY: Analyst has read:listeners but lacks write:listeners - MUST be denied for create")

	// Test DELETE - analyst CANNOT delete
	req = MakeAuthenticatedHTTPRequest("DELETE", "/api/v1/listeners/"+validUUID, nil, jwtToken, csrfToken)
	w = httptest.NewRecorder()
	api.router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusForbidden, w.Code,
		"PERMISSION BOUNDARY: Analyst has read:listeners but lacks write:listeners - MUST be denied for delete")
}

// TestRBAC_ListenerEndpoints_UnauthenticatedDenied tests all endpoints require auth
func TestRBAC_ListenerEndpoints_UnauthenticatedDenied(t *testing.T) {
	api, cleanup := setupListenerRBAC(t)
	defer cleanup()

	validUUID := uuid.New().String()

	endpoints := []struct {
		method string
		path   string
	}{
		{"GET", "/api/v1/listeners"},
		{"POST", "/api/v1/listeners"},
		{"GET", "/api/v1/listeners/" + validUUID},
		{"PUT", "/api/v1/listeners/" + validUUID},
		{"DELETE", "/api/v1/listeners/" + validUUID},
		{"POST", "/api/v1/listeners/" + validUUID + "/start"},
		{"POST", "/api/v1/listeners/" + validUUID + "/stop"},
		{"POST", "/api/v1/listeners/" + validUUID + "/restart"},
		{"GET", "/api/v1/listeners/" + validUUID + "/stats"},
		{"GET", "/api/v1/listener-templates"},
		{"GET", "/api/v1/listener-templates/palo-alto-syslog"},
		{"POST", "/api/v1/listeners/from-template/palo-alto-syslog"},
	}

	for _, ep := range endpoints {
		t.Run(fmt.Sprintf("%s_%s", ep.method, ep.path), func(t *testing.T) {
			req := httptest.NewRequest(ep.method, ep.path, nil)
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()

			api.router.ServeHTTP(w, req)

			// Should be 401 Unauthorized for unauthenticated requests
			assert.Equal(t, http.StatusUnauthorized, w.Code,
				"Unauthenticated request to %s %s should be denied", ep.method, ep.path)
		})
	}
}
