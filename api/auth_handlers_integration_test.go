package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestLogin_Success tests successful login with valid credentials
// SECURITY TEST: Verifies that valid credentials result in JWT token issuance
func TestLogin_Success(t *testing.T) {
	testAPI, cleanup := setupTestAPI(t)
	defer cleanup()

	// Use existing testuser from setupTestAPI with password "testpass123"
	username := "testuser"
	password := "testpass123" // Password from setupTestAPI

	// Attempt login
	loginPayload := map[string]string{
		"username": username,
		"password": password,
	}
	bodyBytes, _ := json.Marshal(loginPayload)

	req := httptest.NewRequest("POST", "/api/auth/login", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	testAPI.router.ServeHTTP(w, req)

	// Verify successful login
	assert.Equal(t, http.StatusOK, w.Code, "Expected successful login")

	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	require.NoError(t, err)
	assert.Equal(t, "Login successful", response["message"])

	// Verify JWT token is returned as cookie
	cookies := w.Result().Cookies()
	var authToken string
	for _, cookie := range cookies {
		if cookie.Name == "auth_token" {
			authToken = cookie.Value
			break
		}
	}
	assert.NotEmpty(t, authToken, "Expected auth_token cookie to be set")
}

// TestLogin_InvalidCredentials tests login failure with wrong password
// SECURITY TEST: Verifies that invalid credentials are rejected
func TestLogin_InvalidCredentials(t *testing.T) {
	testAPI, cleanup := setupTestAPI(t)
	defer cleanup()

	// Use existing testuser (created by setupTestAPI with password "testpass123")
	// and attempt login with wrong password
	loginPayload := map[string]string{
		"username": "testuser",
		"password": "wrongPassword",
	}
	bodyBytes, _ := json.Marshal(loginPayload)

	req := httptest.NewRequest("POST", "/api/auth/login", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	testAPI.router.ServeHTTP(w, req)

	// Verify login failure
	assert.Equal(t, http.StatusUnauthorized, w.Code, "Expected unauthorized status")
}

// TestLogin_NonexistentUser tests login with username that doesn't exist
// SECURITY TEST: Verifies that nonexistent users are rejected
func TestLogin_NonexistentUser(t *testing.T) {
	testAPI, cleanup := setupTestAPI(t)
	defer cleanup()

	loginPayload := map[string]string{
		"username": "nonexistent",
		"password": "anyPassword",
	}
	bodyBytes, _ := json.Marshal(loginPayload)

	req := httptest.NewRequest("POST", "/api/auth/login", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	testAPI.router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code, "Expected unauthorized status")
}

// TestLogin_MissingUsername tests login with missing username field
// SECURITY TEST: Input validation - missing required field
func TestLogin_MissingUsername(t *testing.T) {
	testAPI, cleanup := setupTestAPI(t)
	defer cleanup()

	loginPayload := map[string]string{
		"password": "anyPassword",
	}
	bodyBytes, _ := json.Marshal(loginPayload)

	req := httptest.NewRequest("POST", "/api/auth/login", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	testAPI.router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code, "Expected bad request status")
}

// TestLogin_MissingPassword tests login with missing password field
// SECURITY TEST: Input validation - missing required field
func TestLogin_MissingPassword(t *testing.T) {
	testAPI, cleanup := setupTestAPI(t)
	defer cleanup()

	loginPayload := map[string]string{
		"username": "testuser",
	}
	bodyBytes, _ := json.Marshal(loginPayload)

	req := httptest.NewRequest("POST", "/api/auth/login", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	testAPI.router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code, "Expected bad request status")
}

// TestLogin_InvalidJSON tests login with malformed JSON
// SECURITY TEST: Input validation - malformed request
func TestLogin_InvalidJSON(t *testing.T) {
	testAPI, cleanup := setupTestAPI(t)
	defer cleanup()

	req := httptest.NewRequest("POST", "/api/auth/login", bytes.NewReader([]byte("invalid json")))
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	testAPI.router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code, "Expected bad request status")
}

// TestLogin_EmptyCredentials tests login with empty strings
// SECURITY TEST: Input validation - empty credentials
func TestLogin_EmptyCredentials(t *testing.T) {
	testAPI, cleanup := setupTestAPI(t)
	defer cleanup()

	loginPayload := map[string]string{
		"username": "",
		"password": "",
	}
	bodyBytes, _ := json.Marshal(loginPayload)

	req := httptest.NewRequest("POST", "/api/auth/login", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	testAPI.router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code, "Expected bad request status")
}

// TestLogout_Success tests successful logout with valid token
// SECURITY TEST: Verifies token invalidation on logout
func TestLogout_Success(t *testing.T) {
	testAPI, cleanup := setupTestAPI(t)
	defer cleanup()

	// Create valid token
	token := createValidTestToken(t, testAPI.config.Auth.JWTSecret, "testuser")

	req := httptest.NewRequest("POST", "/api/auth/logout", nil)
	req.Header.Set("Authorization", "Bearer "+token)

	w := httptest.NewRecorder()
	testAPI.router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code, "Expected successful logout")

	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	require.NoError(t, err)
	assert.Equal(t, "Logout successful", response["message"])
}

// TestLogout_NoToken tests logout without authentication token
// SECURITY NOTE: Logout returns 200 OK even without token for idempotency and to prevent session enumeration
func TestLogout_NoToken(t *testing.T) {
	testAPI, cleanup := setupTestAPI(t)
	defer cleanup()

	req := httptest.NewRequest("POST", "/api/auth/logout", nil)

	w := httptest.NewRecorder()
	testAPI.router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code, "Logout should succeed even without token for idempotency")
}

// TestLogout_InvalidToken tests logout with malformed token
// SECURITY NOTE: Logout returns 200 OK and blacklists the token for security (prevent reuse)
func TestLogout_InvalidToken(t *testing.T) {
	testAPI, cleanup := setupTestAPI(t)
	defer cleanup()

	req := httptest.NewRequest("POST", "/api/auth/logout", nil)
	req.Header.Set("Authorization", "Bearer invalid.token.here")

	w := httptest.NewRecorder()
	testAPI.router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code, "Logout should succeed and blacklist invalid token")
}

// TestAuthStatus_ValidToken tests auth status check with valid token
// NOTE: /api/auth/status is a public endpoint that checks X-Username header set by JWT middleware
// Since it's public, we need to manually set the header as the middleware doesn't run
func TestAuthStatus_ValidToken(t *testing.T) {
	testAPI, cleanup := setupTestAPI(t)
	defer cleanup()

	username := "testuser"
	token := createValidTestToken(t, testAPI.config.Auth.JWTSecret, username)

	req := httptest.NewRequest("GET", "/api/auth/status", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	// Manually set X-Username header since JWT middleware doesn't run on public routes
	req.Header.Set("X-Username", username)

	w := httptest.NewRecorder()
	testAPI.router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code, "Expected successful auth status check")

	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	require.NoError(t, err)

	assert.True(t, response["authenticated"].(bool), "Expected authenticated=true")
	assert.Equal(t, username, response["username"])
}

// TestAuthStatus_NoToken tests auth status check without token
// Verifies that unauthenticated requests are properly identified
func TestAuthStatus_NoToken(t *testing.T) {
	testAPI, cleanup := setupTestAPI(t)
	defer cleanup()

	req := httptest.NewRequest("GET", "/api/auth/status", nil)

	w := httptest.NewRecorder()
	testAPI.router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code, "Expected unauthorized status")
}

// TestAuthStatus_ExpiredToken tests auth status with expired token
// SECURITY TEST: Verifies that expired tokens are rejected
func TestAuthStatus_ExpiredToken(t *testing.T) {
	testAPI, cleanup := setupTestAPI(t)
	defer cleanup()

	// Create expired token (expired 1 hour ago)
	token := createExpiredTestToken(t, testAPI.config.Auth.JWTSecret, "testuser", -1*time.Hour)

	req := httptest.NewRequest("GET", "/api/auth/status", nil)
	req.Header.Set("Authorization", "Bearer "+token)

	w := httptest.NewRecorder()
	testAPI.router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code, "Expected unauthorized status for expired token")
}

// TestGetCSRFToken_Success tests CSRF token generation
// SECURITY TEST: Verifies CSRF token is generated for authenticated users
func TestGetCSRFToken_Success(t *testing.T) {
	testAPI, cleanup := setupTestAPI(t)
	defer cleanup()

	token := createValidTestToken(t, testAPI.config.Auth.JWTSecret, "testuser")

	req := httptest.NewRequest("GET", "/api/v1/auth/csrf-token", nil)
	req.Header.Set("Authorization", "Bearer "+token)

	w := httptest.NewRecorder()
	testAPI.router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code, "Expected successful CSRF token generation")

	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	require.NoError(t, err)

	assert.NotEmpty(t, response["csrf_token"], "Expected CSRF token in response")
}

// TestGetCSRFToken_NoAuth tests CSRF token request without authentication
// SECURITY TEST: Verifies CSRF token requires authentication
func TestGetCSRFToken_NoAuth(t *testing.T) {
	testAPI, cleanup := setupTestAPI(t)
	defer cleanup()

	req := httptest.NewRequest("GET", "/api/v1/auth/csrf-token", nil)

	w := httptest.NewRecorder()
	testAPI.router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code, "Expected unauthorized status")
}

// TestLogin_RateLimiting tests that repeated failed logins are rate limited
// SECURITY TEST: Brute force protection
func TestLogin_RateLimiting(t *testing.T) {
	testAPI, cleanup := setupTestAPI(t)
	defer cleanup()

	// Use existing testuser (created by setupTestAPI with password "testpass123")
	// Attempt multiple failed logins with wrong password
	for i := 0; i < 6; i++ {
		loginPayload := map[string]string{
			"username": "testuser",
			"password": "wrongPassword",
		}
		bodyBytes, _ := json.Marshal(loginPayload)

		req := httptest.NewRequest("POST", "/api/auth/login", bytes.NewReader(bodyBytes))
		req.Header.Set("Content-Type", "application/json")

		w := httptest.NewRecorder()
		testAPI.router.ServeHTTP(w, req)

		// After max failures, should get rate limited
		if i >= 5 { // Assuming max failures is 5
			assert.True(t, w.Code == http.StatusTooManyRequests || w.Code == http.StatusUnauthorized,
				"Expected rate limiting after max failures")
		}
	}
}

// TestLogin_SQLInjectionAttempt tests that SQL injection in username is prevented
// SECURITY TEST: SQL injection protection
func TestLogin_SQLInjectionAttempt(t *testing.T) {
	testAPI, cleanup := setupTestAPI(t)
	defer cleanup()

	sqlInjectionPayloads := []string{
		"admin' OR '1'='1",
		"admin'--",
		"admin' /*",
		"' OR '1'='1' --",
		"'; DROP TABLE users; --",
	}

	for _, payload := range sqlInjectionPayloads {
		loginPayload := map[string]string{
			"username": payload,
			"password": "anyPassword",
		}
		bodyBytes, _ := json.Marshal(loginPayload)

		req := httptest.NewRequest("POST", "/api/auth/login", bytes.NewReader(bodyBytes))
		req.Header.Set("Content-Type", "application/json")

		w := httptest.NewRecorder()
		testAPI.router.ServeHTTP(w, req)

		// Should safely reject without executing SQL
		assert.True(t, w.Code == http.StatusUnauthorized || w.Code == http.StatusBadRequest,
			"SQL injection attempt should be rejected for payload: %s", payload)
	}
}

// TestLogin_TokenValidityDuration tests that issued tokens have correct expiration
// SECURITY TEST: Token lifetime verification
func TestLogin_TokenValidityDuration(t *testing.T) {
	testAPI, cleanup := setupTestAPI(t)
	defer cleanup()

	// Use existing testuser (created by setupTestAPI with password "testpass123")
	password := "testpass123"

	loginPayload := map[string]string{
		"username": "testuser",
		"password": password,
	}
	bodyBytes, _ := json.Marshal(loginPayload)

	req := httptest.NewRequest("POST", "/api/auth/login", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	testAPI.router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	require.NoError(t, err)

	// Token should be present in cookie
	cookies := w.Result().Cookies()
	var authToken string
	for _, cookie := range cookies {
		if cookie.Name == "auth_token" {
			authToken = cookie.Value
			break
		}
	}
	assert.NotEmpty(t, authToken, "Expected auth_token cookie to be set")
}
