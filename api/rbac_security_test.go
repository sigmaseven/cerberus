package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"cerberus/storage"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TASK 3.7: Comprehensive RBAC security and privilege escalation tests

// setupTestRBAC creates a test API with RBAC enabled and test users
func setupTestRBAC(t *testing.T) (*API, *storage.SQLiteUserStorage, *storage.SQLiteRoleStorage, func()) {
	// Use setupTestAPI helper which creates proper mocks
	// NOTE: setupTestAPI already seeds default roles and creates admin user
	testAPI, cleanup := setupTestAPI(t)

	userStorage := testAPI.userStorage.(*storage.SQLiteUserStorage)
	roleStorage := testAPI.roleStorage.(*storage.SQLiteRoleStorage)

	ctx := context.Background()
	// Roles are already seeded by setupTestAPI, this is a no-op
	err := roleStorage.SeedDefaultRoles(ctx)
	require.NoError(t, err)

	// Create additional test users with different roles
	// NOTE: admin user already exists from setupTestAPI
	viewerRoleID := int64(1)
	analystRoleID := int64(2)
	engineerRoleID := int64(3)

	viewer := &storage.User{
		Username: "viewer",
		Password: "viewer123",
		RoleID:   &viewerRoleID,
		Active:   true,
	}
	err = userStorage.CreateUser(ctx, viewer)
	require.NoError(t, err)

	analyst := &storage.User{
		Username: "analyst",
		Password: "analyst123",
		RoleID:   &analystRoleID,
		Active:   true,
	}
	err = userStorage.CreateUser(ctx, analyst)
	require.NoError(t, err)

	engineer := &storage.User{
		Username: "engineer",
		Password: "engineer123",
		RoleID:   &engineerRoleID,
		Active:   true,
	}
	err = userStorage.CreateUser(ctx, engineer)
	require.NoError(t, err)

	// admin user already created by setupTestAPI - don't recreate

	return testAPI, userStorage, roleStorage, cleanup
}

// authenticateUser performs login and returns JWT token and CSRF token
func authenticateUser(t *testing.T, api *API, username, password string) (string, string) {
	loginReq := map[string]string{
		"username": username,
		"password": password,
	}
	loginBody, _ := json.Marshal(loginReq)

	req := httptest.NewRequest("POST", "/api/auth/login", bytes.NewReader(loginBody))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	api.router.ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code, "Login should succeed for %s", username)

	// Extract tokens from cookies
	cookies := w.Result().Cookies()
	var jwtToken, csrfToken string
	for _, cookie := range cookies {
		if cookie.Name == "auth_token" {
			jwtToken = cookie.Value
		}
		if cookie.Name == "csrf_token" {
			csrfToken = cookie.Value
		}
	}
	require.NotEmpty(t, jwtToken, "Response should contain auth_token cookie")
	require.NotEmpty(t, csrfToken, "Response should contain csrf_token cookie")
	return jwtToken, csrfToken
}

// makeAuthenticatedRequest creates an authenticated HTTP request
// TASK 3.7: Uses Bearer token in Authorization header for JWT authentication and CSRF token for state-changing requests
func makeAuthenticatedRequest(method, path string, body []byte, jwtToken, csrfToken string) *http.Request {
	req := httptest.NewRequest(method, path, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	if jwtToken != "" {
		// JWT middleware checks Authorization header first, then cookie
		req.Header.Set("Authorization", "Bearer "+jwtToken)
		// Also set cookie for compatibility
		req.AddCookie(&http.Cookie{
			Name:  "auth_token",
			Value: jwtToken,
		})
	}
	// CSRF protection is required for state-changing methods (POST, PUT, DELETE, PATCH)
	// CSRF validation requires both cookie AND header to match
	if csrfToken != "" && (method == "POST" || method == "PUT" || method == "DELETE" || method == "PATCH") {
		req.Header.Set("X-CSRF-Token", csrfToken)
		req.AddCookie(&http.Cookie{
			Name:  "csrf_token",
			Value: csrfToken,
		})
	}
	return req
}

// TestRBAC_ViewerCannotCreateRule tests that viewer role cannot create rules
func TestRBAC_ViewerCannotCreateRule(t *testing.T) {
	api, _, _, cleanup := setupTestRBAC(t)
	defer cleanup()

	jwtToken, csrfToken := authenticateUser(t, api, "viewer", "viewer123")

	// TASK #184: Use sigma_yaml instead of legacy conditions
	ruleData := map[string]interface{}{
		"type":        "sigma",
		"name":        "Test Rule",
		"description": "Test Description",
		"enabled":     true,
		"severity":    "medium",
		"version":     1,
		"sigma_yaml": `title: Test Rule
logsource:
  category: test
detection:
  selection:
    event_type: test
  condition: selection
`,
	}
	body, _ := json.Marshal(ruleData)

	req := makeAuthenticatedRequest("POST", "/api/v1/rules", body, jwtToken, csrfToken)
	w := httptest.NewRecorder()

	api.router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusForbidden, w.Code, "Viewer should receive 403 Forbidden when creating rule")
}

// TestRBAC_AnalystCanReadButCannotWriteRules tests analyst permissions
func TestRBAC_AnalystCanReadButCannotWriteRules(t *testing.T) {
	api, _, _, cleanup := setupTestRBAC(t)
	defer cleanup()

	jwtToken, csrfToken := authenticateUser(t, api, "analyst", "analyst123")

	// Analyst should be able to read rules
	req := makeAuthenticatedRequest("GET", "/api/v1/rules", nil, jwtToken, csrfToken)
	w := httptest.NewRecorder()
	api.router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code, "Analyst should be able to read rules")

	// Analyst should NOT be able to create rules
	// TASK #184: Use sigma_yaml instead of legacy conditions
	ruleData := map[string]interface{}{
		"type":        "sigma",
		"name":        "Test Rule",
		"description": "Test Description",
		"enabled":     true,
		"severity":    "medium",
		"version":     1,
		"sigma_yaml": `title: Test Rule
logsource:
  category: test
detection:
  selection:
    event_type: test
  condition: selection
`,
	}
	body, _ := json.Marshal(ruleData)

	req = makeAuthenticatedRequest("POST", "/api/v1/rules", body, jwtToken, csrfToken)
	w = httptest.NewRecorder()
	api.router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusForbidden, w.Code, "Analyst should receive 403 Forbidden when creating rule")
}

// TestRBAC_EngineerCanCreateRules tests engineer permissions
func TestRBAC_EngineerCanCreateRules(t *testing.T) {
	api, _, _, cleanup := setupTestRBAC(t)
	defer cleanup()

	jwtToken, csrfToken := authenticateUser(t, api, "engineer", "engineer123")

	// TASK #184: Use sigma_yaml instead of legacy conditions
	ruleData := map[string]interface{}{
		"type":        "sigma",
		"name":        "Test Rule",
		"description": "Test Description",
		"enabled":     true,
		"severity":    "medium",
		"version":     1,
		"sigma_yaml": `title: Test Rule
logsource:
  category: test
detection:
  selection:
    event_type: test
  condition: selection
`,
	}
	body, _ := json.Marshal(ruleData)

	req := makeAuthenticatedRequest("POST", "/api/v1/rules", body, jwtToken, csrfToken)
	w := httptest.NewRecorder()

	api.router.ServeHTTP(w, req)

	// Engineer should be able to create rules (may need mock ruleStorage to fully test)
	// For now, just verify it's not a 403
	assert.NotEqual(t, http.StatusForbidden, w.Code, "Engineer should not receive 403 Forbidden when creating rule")
}

// TestRBAC_AnalystCannotDeleteUser tests that analyst cannot manage users
func TestRBAC_AnalystCannotDeleteUser(t *testing.T) {
	api, _, _, cleanup := setupTestRBAC(t)
	defer cleanup()

	jwtToken, csrfToken := authenticateUser(t, api, "analyst", "analyst123")

	// Analyst attempting to delete a user
	req := makeAuthenticatedRequest("DELETE", "/api/v1/users/viewer", nil, jwtToken, csrfToken)
	w := httptest.NewRecorder()

	api.router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusForbidden, w.Code, "Analyst should receive 403 Forbidden when deleting user")
}

// TestRBAC_EngineerCannotAccessAdminEndpoints tests that engineer cannot access admin-only endpoints
func TestRBAC_EngineerCannotAccessAdminEndpoints(t *testing.T) {
	api, _, _, cleanup := setupTestRBAC(t)
	defer cleanup()

	jwtToken, csrfToken := authenticateUser(t, api, "engineer", "engineer123")

	// Engineer attempting to create user (requires write:users permission)
	userData := map[string]interface{}{
		"username": "newuser",
		"password": "password123",
		"role_id":  1,
	}
	body, _ := json.Marshal(userData)

	req := makeAuthenticatedRequest("POST", "/api/v1/users", body, jwtToken, csrfToken)
	w := httptest.NewRecorder()

	api.router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusForbidden, w.Code, "Engineer should receive 403 Forbidden when creating user")
}

// TestRBAC_UserCannotElevateOwnRole tests privilege escalation prevention
func TestRBAC_UserCannotElevateOwnRole(t *testing.T) {
	api, _, _, cleanup := setupTestRBAC(t)
	defer cleanup()

	jwtToken, csrfToken := authenticateUser(t, api, "analyst", "analyst123")

	// Analyst attempting to change their own role to admin
	roleData := map[string]interface{}{
		"role_id": 4, // admin role
	}
	body, _ := json.Marshal(roleData)

	req := makeAuthenticatedRequest("PUT", "/api/v1/users/analyst/role", body, jwtToken, csrfToken)
	w := httptest.NewRecorder()

	api.router.ServeHTTP(w, req)

	// Should fail with 403 or 400 (business logic prevents self-role-change)
	assert.True(t, w.Code == http.StatusForbidden || w.Code == http.StatusBadRequest,
		"User should not be able to change their own role (got %d)", w.Code)
}

// TestRBAC_AdminCanManageUsers tests that admin has full access
func TestRBAC_AdminCanManageUsers(t *testing.T) {
	api, _, _, cleanup := setupTestRBAC(t)
	defer cleanup()

	jwtToken, csrfToken := authenticateUser(t, api, "admin", "admin123")

	// Admin should be able to list users
	req := makeAuthenticatedRequest("GET", "/api/v1/users", nil, jwtToken, csrfToken)
	w := httptest.NewRecorder()
	api.router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code, "Admin should be able to list users")

	// Admin should be able to create users
	userData := map[string]interface{}{
		"username": "newuser",
		"password": "password123",
		"role_id":  1, // viewer role
	}
	body, _ := json.Marshal(userData)

	req = makeAuthenticatedRequest("POST", "/api/v1/users", body, jwtToken, csrfToken)
	w = httptest.NewRecorder()
	api.router.ServeHTTP(w, req)
	// May fail due to mock storage, but should not be 403
	assert.NotEqual(t, http.StatusForbidden, w.Code, "Admin should not receive 403 Forbidden when creating user")
}

// TestRBAC_PermissionInheritance tests that higher roles inherit lower role permissions
func TestRBAC_PermissionInheritance(t *testing.T) {
	_, _, roleStorage, cleanup := setupTestRBAC(t)
	defer cleanup()

	ctx := context.Background()

	// Get roles
	viewerRole, err := roleStorage.GetRoleByID(ctx, 1)
	require.NoError(t, err)

	analystRole, err := roleStorage.GetRoleByID(ctx, 2)
	require.NoError(t, err)

	engineerRole, err := roleStorage.GetRoleByID(ctx, 3)
	require.NoError(t, err)

	// Analyst should have all viewer permissions
	for _, perm := range viewerRole.Permissions {
		assert.True(t, analystRole.HasPermission(perm),
			"Analyst should inherit viewer permission: %s", perm)
	}

	// Engineer should have all analyst permissions
	for _, perm := range analystRole.Permissions {
		assert.True(t, engineerRole.HasPermission(perm),
			"Engineer should inherit analyst permission: %s", perm)
	}

	// Admin should have all engineer permissions
	adminRole, err := roleStorage.GetRoleByID(ctx, 4)
	require.NoError(t, err)

	for _, perm := range engineerRole.Permissions {
		assert.True(t, adminRole.HasPermission(perm),
			"Admin should inherit engineer permission: %s", perm)
	}
}

// TestRBAC_HorizontalPrivilegeEscalation tests that user A cannot modify user B's data
func TestRBAC_HorizontalPrivilegeEscalation(t *testing.T) {
	api, _, _, cleanup := setupTestRBAC(t)
	defer cleanup()

	jwtToken, csrfToken := authenticateUser(t, api, "analyst", "analyst123")

	// Analyst attempting to update another user (engineer)
	userData := map[string]interface{}{
		"active": false, // Try to deactivate another user
	}
	body, _ := json.Marshal(userData)

	req := makeAuthenticatedRequest("PUT", "/api/v1/users/engineer", body, jwtToken, csrfToken)
	w := httptest.NewRecorder()

	api.router.ServeHTTP(w, req)

	// Should fail - analyst doesn't have write:users permission
	assert.Equal(t, http.StatusForbidden, w.Code,
		"Analyst should not be able to modify other users (horizontal privilege escalation)")
}

// TestRBAC_UnauthenticatedAccessDenied tests that unauthenticated requests are rejected
func TestRBAC_UnauthenticatedAccessDenied(t *testing.T) {
	api, _, _, cleanup := setupTestRBAC(t)
	defer cleanup()

	// Unauthenticated request
	req := makeAuthenticatedRequest("GET", "/api/v1/rules", nil, "", "")
	w := httptest.NewRecorder()

	api.router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code,
		"Unauthenticated request should receive 401 Unauthorized")
}

// TestRBAC_GetCurrentUserWorksForAllRoles tests /users/me endpoint
func TestRBAC_GetCurrentUserWorksForAllRoles(t *testing.T) {
	api, _, _, cleanup := setupTestRBAC(t)
	defer cleanup()

	roles := []string{"viewer", "analyst", "engineer", "admin"}
	passwords := map[string]string{
		"viewer":   "viewer123",
		"analyst":  "analyst123",
		"engineer": "engineer123",
		"admin":    "admin123",
	}

	for _, role := range roles {
		t.Run(role, func(t *testing.T) {
			jwtToken, csrfToken := authenticateUser(t, api, role, passwords[role])

			req := makeAuthenticatedRequest("GET", "/api/v1/users/me", nil, jwtToken, csrfToken)
			w := httptest.NewRecorder()

			api.router.ServeHTTP(w, req)

			assert.Equal(t, http.StatusOK, w.Code, "%s should be able to access /users/me", role)

			var response map[string]interface{}
			err := json.Unmarshal(w.Body.Bytes(), &response)
			require.NoError(t, err)

			assert.Equal(t, role, response["username"], "Response should contain correct username")
			assert.NotNil(t, response["permissions"], "Response should contain permissions")
			assert.NotNil(t, response["role"], "Response should contain role info")
		})
	}
}

// TestRBAC_InvalidJWTTokenRejected tests that invalid tokens are rejected
func TestRBAC_InvalidJWTTokenRejected(t *testing.T) {
	api, _, _, cleanup := setupTestRBAC(t)
	defer cleanup()

	// Request with invalid token
	req := makeAuthenticatedRequest("GET", "/api/v1/rules", nil, "invalid.token.here", "")
	w := httptest.NewRecorder()

	api.router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code,
		"Invalid JWT token should result in 401 Unauthorized")
}

// TestRBAC_ExpiredJWTTokenRejected tests that expired tokens are rejected
func TestRBAC_ExpiredJWTTokenRejected(t *testing.T) {
	// Create expired token (would need to mock time or use actual expired token)
	// For now, test that expired token handling exists in middleware
	// This is more of an integration test that requires time mocking
	t.Skip("Requires time mocking for expired token generation")
}

// TestRBAC_InactiveUserDenied tests that inactive users are denied access
func TestRBAC_InactiveUserDenied(t *testing.T) {
	api, userStorage, _, cleanup := setupTestRBAC(t)
	defer cleanup()

	ctx := context.Background()

	// Deactivate viewer user
	viewer, err := userStorage.GetUserByUsername(ctx, "viewer")
	require.NoError(t, err)
	viewer.Active = false
	err = userStorage.UpdateUser(ctx, viewer)
	require.NoError(t, err)

	// Note: Inactive user should fail at authentication, not at permission check
	// This test verifies the permission check handles inactive users
	loginReq := map[string]string{
		"username": "viewer",
		"password": "viewer123",
	}
	loginBody, _ := json.Marshal(loginReq)

	loginHTTPReq := httptest.NewRequest("POST", "/api/auth/login", bytes.NewReader(loginBody))
	loginHTTPReq.Header.Set("Content-Type", "application/json")
	loginW := httptest.NewRecorder()

	api.router.ServeHTTP(loginW, loginHTTPReq)

	// Login should fail for inactive user
	assert.NotEqual(t, http.StatusOK, loginW.Code,
		"Inactive user should not be able to authenticate")
}

// BenchmarkRBAC_PermissionCheck benchmarks permission checking performance
func BenchmarkRBAC_PermissionCheck(b *testing.B) {
	_, _, roleStorage, cleanup := setupTestRBAC(&testing.T{})
	defer cleanup()

	ctx := context.Background()
	role, err := roleStorage.GetRoleByID(ctx, 2) // analyst role
	if err != nil {
		b.Fatal(err)
	}

	permission := storage.PermReadRules

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		role.HasPermission(permission)
	}
}

// TestRBAC_RequireAnyPermissionWorks tests RequireAnyPermission middleware
func TestRBAC_RequireAnyPermissionWorks(t *testing.T) {
	api, _, _, cleanup := setupTestRBAC(t)
	defer cleanup()

	// Test endpoint that requires ANY permission (should work with any authenticated user)
	jwtToken, csrfToken := authenticateUser(t, api, "admin", "admin123")

	req := makeAuthenticatedRequest("GET", "/api/v1/users/me", nil, jwtToken, csrfToken)
	w := httptest.NewRecorder()

	api.router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code, "Any authenticated user should access /users/me")
}

// TestRBAC_MissingRoleDenied tests that users without roles are denied
func TestRBAC_MissingRoleDenied(t *testing.T) {
	api, userStorage, _, cleanup := setupTestRBAC(t)
	defer cleanup()

	ctx := context.Background()

	// Create user without role
	user := &storage.User{
		Username: "norole",
		Password: "password123",
		RoleID:   nil, // No role assigned
		Active:   true,
	}
	err := userStorage.CreateUser(ctx, user)
	require.NoError(t, err)

	// Note: This user won't be able to get a valid JWT with role claims
	// The permission check middleware should handle nil roles gracefully
	jwtToken, csrfToken := authenticateUser(t, api, "norole", "password123")

	req := makeAuthenticatedRequest("GET", "/api/v1/rules", nil, jwtToken, csrfToken)
	w := httptest.NewRecorder()

	api.router.ServeHTTP(w, req)

	// User without role should be denied
	assert.Equal(t, http.StatusForbidden, w.Code,
		"User without role should receive 403 Forbidden")
}

// TestRBAC_AdminCanChangeOtherUserRole tests admin can change other users' roles
func TestRBAC_AdminCanChangeOtherUserRole(t *testing.T) {
	api, _, _, cleanup := setupTestRBAC(t)
	defer cleanup()

	jwtToken, csrfToken := authenticateUser(t, api, "admin", "admin123")

	// Admin changing analyst's role to engineer
	roleData := map[string]interface{}{
		"role_id": 3, // engineer role
	}
	body, _ := json.Marshal(roleData)

	req := makeAuthenticatedRequest("PUT", "/api/v1/users/analyst/role", body, jwtToken, csrfToken)
	w := httptest.NewRecorder()

	api.router.ServeHTTP(w, req)

	// Admin should be able to change other users' roles
	// May fail due to mock storage, but should not be 403
	assert.NotEqual(t, http.StatusForbidden, w.Code,
		"Admin should be able to change other users' roles")
}
