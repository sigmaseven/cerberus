package storage

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestGetDefaultRoles_ListenerPermissions verifies that listener permissions
// are correctly assigned to each role per Task 118 requirements.
func TestGetDefaultRoles_ListenerPermissions(t *testing.T) {
	roles := GetDefaultRoles()
	require.Len(t, roles, 4, "Should have 4 default roles")

	// Create a map for easy role lookup
	roleMap := make(map[string]Role)
	for _, role := range roles {
		roleMap[role.Name] = role
	}

	t.Run("Viewer has PermReadListeners", func(t *testing.T) {
		viewer, ok := roleMap[RoleViewer]
		require.True(t, ok, "Viewer role should exist")
		assert.True(t, viewer.HasPermission(PermReadListeners),
			"Viewer should have PermReadListeners for monitoring (Task 118)")
		assert.False(t, viewer.HasPermission(PermWriteListeners),
			"Viewer should NOT have PermWriteListeners")
	})

	t.Run("Analyst has PermReadListeners", func(t *testing.T) {
		analyst, ok := roleMap[RoleAnalyst]
		require.True(t, ok, "Analyst role should exist")
		assert.True(t, analyst.HasPermission(PermReadListeners),
			"Analyst should have PermReadListeners")
		assert.False(t, analyst.HasPermission(PermWriteListeners),
			"Analyst should NOT have PermWriteListeners")
	})

	t.Run("Engineer has both listener permissions", func(t *testing.T) {
		engineer, ok := roleMap[RoleEngineer]
		require.True(t, ok, "Engineer role should exist")
		assert.True(t, engineer.HasPermission(PermReadListeners),
			"Engineer should have PermReadListeners")
		assert.True(t, engineer.HasPermission(PermWriteListeners),
			"Engineer should have PermWriteListeners")
	})

	t.Run("Admin has both listener permissions", func(t *testing.T) {
		admin, ok := roleMap[RoleAdmin]
		require.True(t, ok, "Admin role should exist")
		assert.True(t, admin.HasPermission(PermReadListeners),
			"Admin should have PermReadListeners")
		assert.True(t, admin.HasPermission(PermWriteListeners),
			"Admin should have PermWriteListeners")
	})
}

// TestGetRolePermissions_ListenerPermissions verifies the GetRolePermissions helper
func TestGetRolePermissions_ListenerPermissions(t *testing.T) {
	tests := []struct {
		role      string
		wantRead  bool
		wantWrite bool
	}{
		{RoleViewer, true, false},
		{RoleAnalyst, true, false},
		{RoleEngineer, true, true},
		{RoleAdmin, true, true},
	}

	for _, tt := range tests {
		t.Run(tt.role, func(t *testing.T) {
			perms, err := GetRolePermissions(tt.role)
			require.NoError(t, err)

			hasRead := false
			hasWrite := false
			for _, p := range perms {
				if p == PermReadListeners {
					hasRead = true
				}
				if p == PermWriteListeners {
					hasWrite = true
				}
			}

			assert.Equal(t, tt.wantRead, hasRead,
				"Role %s: PermReadListeners mismatch", tt.role)
			assert.Equal(t, tt.wantWrite, hasWrite,
				"Role %s: PermWriteListeners mismatch", tt.role)
		})
	}
}

// TestGetRolePermissions_InvalidRole verifies error handling for invalid roles
func TestGetRolePermissions_InvalidRole(t *testing.T) {
	_, err := GetRolePermissions("nonexistent")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid role name")
}
