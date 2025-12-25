package api

import (
	"testing"

	"cerberus/storage"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TASK 31.1: Unit tests for RBAC types and role permission mappings

// TestGetDefaultRoles verifies that all default roles have correct permission sets
func TestGetDefaultRoles(t *testing.T) {
	roles := storage.GetDefaultRoles()

	require.Len(t, roles, 4, "Should have 4 default roles")

	// Test Viewer role
	viewer := findRole(roles, storage.RoleViewer)
	require.NotNil(t, viewer, "Viewer role should exist")
	assert.Contains(t, viewer.Permissions, storage.PermReadEvents, "Viewer should have read:events")
	assert.Contains(t, viewer.Permissions, storage.PermReadAlerts, "Viewer should have read:alerts")
	assert.Contains(t, viewer.Permissions, storage.PermReadRules, "Viewer should have read:rules")
	assert.NotContains(t, viewer.Permissions, storage.PermWriteRules, "Viewer should NOT have write:rules")
	assert.NotContains(t, viewer.Permissions, storage.PermAcknowledgeAlerts, "Viewer should NOT have alert:acknowledge")

	// Test Analyst role
	analyst := findRole(roles, storage.RoleAnalyst)
	require.NotNil(t, analyst, "Analyst role should exist")
	assert.Contains(t, analyst.Permissions, storage.PermReadEvents, "Analyst should have read:events")
	assert.Contains(t, analyst.Permissions, storage.PermReadAlerts, "Analyst should have read:alerts")
	assert.Contains(t, analyst.Permissions, storage.PermReadRules, "Analyst should have read:rules")
	assert.Contains(t, analyst.Permissions, storage.PermAcknowledgeAlerts, "Analyst should have alert:acknowledge")
	assert.Contains(t, analyst.Permissions, storage.PermCommentAlerts, "Analyst should have alert:comment")
	assert.NotContains(t, analyst.Permissions, storage.PermWriteRules, "Analyst should NOT have write:rules")

	// Test Engineer role
	engineer := findRole(roles, storage.RoleEngineer)
	require.NotNil(t, engineer, "Engineer role should exist")
	assert.Contains(t, engineer.Permissions, storage.PermReadEvents, "Engineer should have read:events")
	assert.Contains(t, engineer.Permissions, storage.PermReadAlerts, "Engineer should have read:alerts")
	assert.Contains(t, engineer.Permissions, storage.PermAcknowledgeAlerts, "Engineer should have alert:acknowledge")
	assert.Contains(t, engineer.Permissions, storage.PermReadRules, "Engineer should have read:rules")
	assert.Contains(t, engineer.Permissions, storage.PermWriteRules, "Engineer should have write:rules")
	assert.Contains(t, engineer.Permissions, storage.PermWriteActions, "Engineer should have write:actions")
	assert.NotContains(t, engineer.Permissions, storage.PermWriteUsers, "Engineer should NOT have write:users")

	// Test Admin role
	admin := findRole(roles, storage.RoleAdmin)
	require.NotNil(t, admin, "Admin role should exist")
	assert.Contains(t, admin.Permissions, storage.PermReadEvents, "Admin should have read:events")
	assert.Contains(t, admin.Permissions, storage.PermReadAlerts, "Admin should have read:alerts")
	assert.Contains(t, admin.Permissions, storage.PermReadRules, "Admin should have read:rules")
	assert.Contains(t, admin.Permissions, storage.PermWriteRules, "Admin should have write:rules")
	assert.Contains(t, admin.Permissions, storage.PermWriteUsers, "Admin should have write:users")
	assert.Contains(t, admin.Permissions, storage.PermAdminSystem, "Admin should have admin:system")
}

// TestGetRolePermissions verifies GetRolePermissions returns correct permissions for each role
func TestGetRolePermissions(t *testing.T) {
	// Test Viewer permissions
	viewerPerms, err := storage.GetRolePermissions(storage.RoleViewer)
	require.NoError(t, err, "Should retrieve Viewer permissions")
	assert.Contains(t, viewerPerms, storage.PermReadEvents, "Viewer should have read:events")
	assert.Contains(t, viewerPerms, storage.PermReadAlerts, "Viewer should have read:alerts")
	assert.Contains(t, viewerPerms, storage.PermReadRules, "Viewer should have read:rules")
	assert.NotContains(t, viewerPerms, storage.PermWriteRules, "Viewer should NOT have write:rules")

	// Test Analyst permissions
	analystPerms, err := storage.GetRolePermissions(storage.RoleAnalyst)
	require.NoError(t, err, "Should retrieve Analyst permissions")
	assert.Contains(t, analystPerms, storage.PermReadEvents, "Analyst should have read:events")
	assert.Contains(t, analystPerms, storage.PermAcknowledgeAlerts, "Analyst should have alert:acknowledge")
	assert.Contains(t, analystPerms, storage.PermCommentAlerts, "Analyst should have alert:comment")

	// Test Engineer permissions
	engineerPerms, err := storage.GetRolePermissions(storage.RoleEngineer)
	require.NoError(t, err, "Should retrieve Engineer permissions")
	assert.Contains(t, engineerPerms, storage.PermWriteRules, "Engineer should have write:rules")
	assert.Contains(t, engineerPerms, storage.PermWriteActions, "Engineer should have write:actions")
	assert.NotContains(t, engineerPerms, storage.PermWriteUsers, "Engineer should NOT have write:users")

	// Test Admin permissions
	adminPerms, err := storage.GetRolePermissions(storage.RoleAdmin)
	require.NoError(t, err, "Should retrieve Admin permissions")
	assert.Contains(t, adminPerms, storage.PermWriteUsers, "Admin should have write:users")
	assert.Contains(t, adminPerms, storage.PermAdminSystem, "Admin should have admin:system")

	// Test invalid role name
	_, err = storage.GetRolePermissions("invalid_role")
	assert.Error(t, err, "Should return error for invalid role name")
	assert.Contains(t, err.Error(), "invalid role name", "Error should mention invalid role name")
}

// TestPermissionInheritance verifies permission inheritance is correct
func TestPermissionInheritance(t *testing.T) {
	roles := storage.GetDefaultRoles()

	viewer := findRole(roles, storage.RoleViewer)
	analyst := findRole(roles, storage.RoleAnalyst)
	engineer := findRole(roles, storage.RoleEngineer)
	admin := findRole(roles, storage.RoleAdmin)

	// Engineer should include Analyst permissions
	for _, perm := range analyst.Permissions {
		assert.Contains(t, engineer.Permissions, perm, "Engineer should inherit Analyst permission: %s", perm)
	}

	// Analyst should include Viewer permissions
	for _, perm := range viewer.Permissions {
		assert.Contains(t, analyst.Permissions, perm, "Analyst should inherit Viewer permission: %s", perm)
	}

	// Admin should include all Engineer permissions
	for _, perm := range engineer.Permissions {
		assert.Contains(t, admin.Permissions, perm, "Admin should inherit Engineer permission: %s", perm)
	}
}

// TestCheckPermission verifies CheckPermission correctly validates role permissions
func TestCheckPermission(t *testing.T) {
	roles := storage.GetDefaultRoles()

	viewer := findRole(roles, storage.RoleViewer)
	analyst := findRole(roles, storage.RoleAnalyst)
	engineer := findRole(roles, storage.RoleEngineer)
	admin := findRole(roles, storage.RoleAdmin)

	// Test Viewer permissions
	assert.True(t, CheckPermission(viewer, storage.PermReadEvents), "Viewer should have read:events")
	assert.True(t, CheckPermission(viewer, storage.PermReadAlerts), "Viewer should have read:alerts")
	assert.False(t, CheckPermission(viewer, storage.PermWriteRules), "Viewer should NOT have write:rules")
	assert.False(t, CheckPermission(viewer, storage.PermAcknowledgeAlerts), "Viewer should NOT have alert:acknowledge")

	// Test Analyst permissions
	assert.True(t, CheckPermission(analyst, storage.PermReadEvents), "Analyst should have read:events")
	assert.True(t, CheckPermission(analyst, storage.PermAcknowledgeAlerts), "Analyst should have alert:acknowledge")
	assert.True(t, CheckPermission(analyst, storage.PermCommentAlerts), "Analyst should have alert:comment")
	assert.False(t, CheckPermission(analyst, storage.PermWriteRules), "Analyst should NOT have write:rules")

	// Test Engineer permissions
	assert.True(t, CheckPermission(engineer, storage.PermReadRules), "Engineer should have read:rules")
	assert.True(t, CheckPermission(engineer, storage.PermWriteRules), "Engineer should have write:rules")
	assert.True(t, CheckPermission(engineer, storage.PermWriteActions), "Engineer should have write:actions")
	assert.False(t, CheckPermission(engineer, storage.PermWriteUsers), "Engineer should NOT have write:users")

	// Test Admin permissions
	assert.True(t, CheckPermission(admin, storage.PermReadEvents), "Admin should have read:events")
	assert.True(t, CheckPermission(admin, storage.PermWriteRules), "Admin should have write:rules")
	assert.True(t, CheckPermission(admin, storage.PermWriteUsers), "Admin should have write:users")
	assert.True(t, CheckPermission(admin, storage.PermAdminSystem), "Admin should have admin:system")

	// Test nil role
	assert.False(t, CheckPermission(nil, storage.PermReadEvents), "Nil role should not have any permissions")
}

// TestGetRequiredPermission verifies GetRequiredPermission matches endpoints to correct permissions
func TestGetRequiredPermission(t *testing.T) {
	// Test exact matches
	perm, err := GetRequiredPermission("GET", "/api/v1/events")
	require.NoError(t, err)
	assert.Equal(t, storage.PermReadEvents, perm, "GET /api/v1/events should require read:events")

	perm, err = GetRequiredPermission("POST", "/api/v1/rules")
	require.NoError(t, err)
	assert.Equal(t, storage.PermWriteRules, perm, "POST /api/v1/rules should require write:rules")

	perm, err = GetRequiredPermission("POST", "/api/v1/alerts/123/acknowledge")
	require.NoError(t, err)
	assert.Equal(t, storage.PermAcknowledgeAlerts, perm, "POST /api/v1/alerts/{id}/acknowledge should require alert:acknowledge")

	// Test path parameter matching
	perm, err = GetRequiredPermission("GET", "/api/v1/rules/rule-123")
	require.NoError(t, err)
	assert.Equal(t, storage.PermReadRules, perm, "GET /api/v1/rules/{id} should require read:rules")

	perm, err = GetRequiredPermission("DELETE", "/api/v1/users/testuser")
	require.NoError(t, err)
	assert.Equal(t, storage.PermWriteUsers, perm, "DELETE /api/v1/users/{username} should require write:users")

	// Test unknown endpoint
	_, err = GetRequiredPermission("GET", "/api/v1/unknown")
	assert.Error(t, err, "Unknown endpoint should return error")
	assert.Contains(t, err.Error(), "no permission mapping found", "Error should mention no mapping found")
}

// TestMatchesPathPattern verifies path pattern matching works correctly
func TestMatchesPathPattern(t *testing.T) {
	// Test exact match
	assert.True(t, matchesPathPattern("/api/v1/rules", "/api/v1/rules"), "Exact path should match")

	// Test path parameter matching
	assert.True(t, matchesPathPattern("/api/v1/rules/123", "/api/v1/rules/{id}"), "Path with {id} should match")
	assert.True(t, matchesPathPattern("/api/v1/users/testuser", "/api/v1/users/{username}"), "Path with {username} should match")
	assert.True(t, matchesPathPattern("/api/v1/alerts/alert-123/acknowledge", "/api/v1/alerts/{id}/acknowledge"), "Nested path with {id} should match")

	// Test non-matching paths
	assert.False(t, matchesPathPattern("/api/v1/rules", "/api/v1/alerts"), "Different paths should not match")
	assert.False(t, matchesPathPattern("/api/v1/rules/123/details", "/api/v1/rules/{id}"), "Different path length should not match")
}

// Helper function to find a role by name
func findRole(roles []storage.Role, name string) *storage.Role {
	for i := range roles {
		if roles[i].Name == name {
			return &roles[i]
		}
	}
	return nil
}
