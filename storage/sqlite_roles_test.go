package storage

import (
	"context"
	"database/sql"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap/zaptest"
	_ "modernc.org/sqlite"
)

// setupRolesTestDB creates an in-memory SQLite database for roles tests
func setupRolesTestDB(t *testing.T) *SQLite {
	db, err := sql.Open("sqlite", ":memory:")
	require.NoError(t, err)

	_, err = db.Exec("PRAGMA foreign_keys=ON")
	require.NoError(t, err)

	// Create roles, users, and user_roles tables
	schema := `
	CREATE TABLE IF NOT EXISTS roles (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		name TEXT UNIQUE NOT NULL,
		description TEXT,
		permissions TEXT NOT NULL,
		created_at DATETIME NOT NULL,
		updated_at DATETIME NOT NULL
	);
	CREATE INDEX IF NOT EXISTS idx_roles_name ON roles(name);

	CREATE TABLE IF NOT EXISTS role_permissions (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		role_id INTEGER NOT NULL,
		permission TEXT NOT NULL,
		created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
		FOREIGN KEY (role_id) REFERENCES roles(id) ON DELETE CASCADE,
		UNIQUE(role_id, permission)
	);
	CREATE INDEX IF NOT EXISTS idx_role_permissions_role_id ON role_permissions(role_id);
	CREATE INDEX IF NOT EXISTS idx_role_permissions_permission ON role_permissions(permission);

	CREATE TABLE IF NOT EXISTS users (
		username TEXT PRIMARY KEY,
		password_hash TEXT NOT NULL,
		roles TEXT,
		role_id INTEGER,
		active INTEGER NOT NULL DEFAULT 1,
		created_at DATETIME NOT NULL,
		updated_at DATETIME NOT NULL,
		FOREIGN KEY (role_id) REFERENCES roles(id) ON DELETE RESTRICT
	);
	CREATE INDEX IF NOT EXISTS idx_users_role_id ON users(role_id);

	CREATE TABLE IF NOT EXISTS user_roles (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		user_id TEXT NOT NULL,
		role_id INTEGER NOT NULL,
		assigned_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
		assigned_by TEXT,
		FOREIGN KEY (user_id) REFERENCES users(username) ON DELETE CASCADE,
		FOREIGN KEY (role_id) REFERENCES roles(id) ON DELETE RESTRICT,
		UNIQUE(user_id, role_id)
	);
	CREATE INDEX IF NOT EXISTS idx_user_roles_user_id ON user_roles(user_id);
	CREATE INDEX IF NOT EXISTS idx_user_roles_role_id ON user_roles(role_id);
	`
	_, err = db.Exec(schema)
	require.NoError(t, err)

	sqlite := &SQLite{
		DB:     db,
		Path:   ":memory:",
		Logger: zaptest.NewLogger(t).Sugar(),
	}

	return sqlite
}

// TestSQLiteRoleStorage_CreateRole tests role creation
func TestSQLiteRoleStorage_CreateRole(t *testing.T) {
	sqlite := setupRolesTestDB(t)
	defer sqlite.DB.Close()

	storage := NewSQLiteRoleStorage(sqlite, sqlite.Logger)
	ctx := context.Background()

	tests := []struct {
		name      string
		role      *Role
		expectErr bool
	}{
		{
			name: "Valid role",
			role: &Role{
				Name:        "test-role",
				Description: "Test role",
				Permissions: []Permission{PermReadEvents, PermReadAlerts},
			},
			expectErr: false,
		},
		{
			name: "Duplicate role name",
			role: &Role{
				Name:        "test-role",
				Description: "Duplicate",
				Permissions: []Permission{PermReadEvents},
			},
			expectErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := storage.CreateRole(ctx, tt.role)
			if tt.expectErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.Greater(t, tt.role.ID, int64(0))

				// Verify role was created
				retrieved, err := storage.GetRoleByID(ctx, tt.role.ID)
				require.NoError(t, err)
				assert.Equal(t, tt.role.Name, retrieved.Name)
				assert.Equal(t, tt.role.Description, retrieved.Description)
				assert.Equal(t, len(tt.role.Permissions), len(retrieved.Permissions))
			}
		})
	}
}

// TestSQLiteRoleStorage_PermissionManagement tests permission management
func TestSQLiteRoleStorage_PermissionManagement(t *testing.T) {
	sqlite := setupRolesTestDB(t)
	defer sqlite.DB.Close()

	storage := NewSQLiteRoleStorage(sqlite, sqlite.Logger)
	ctx := context.Background()

	// Create role
	role := &Role{
		Name:        "permission-test-role",
		Description: "Permission test",
		Permissions: []Permission{PermReadEvents},
	}
	err := storage.CreateRole(ctx, role)
	require.NoError(t, err)

	// Update role to add permission
	retrieved, err := storage.GetRoleByID(ctx, role.ID)
	require.NoError(t, err)
	retrieved.Permissions = append(retrieved.Permissions, PermReadAlerts)
	err = storage.UpdateRole(ctx, retrieved)
	require.NoError(t, err)

	// Verify permission was added
	retrieved, err = storage.GetRoleByID(ctx, role.ID)
	require.NoError(t, err)
	assert.Contains(t, retrieved.Permissions, PermReadAlerts)

	// Update role to remove permission
	retrieved.Permissions = []Permission{PermReadEvents}
	err = storage.UpdateRole(ctx, retrieved)
	require.NoError(t, err)

	// Verify permission was removed
	retrieved, err = storage.GetRoleByID(ctx, role.ID)
	require.NoError(t, err)
	assert.NotContains(t, retrieved.Permissions, PermReadAlerts)
}

// TestSQLiteRoleStorage_UserRoleAssociations tests user-role many-to-many associations
func TestSQLiteRoleStorage_UserRoleAssociations(t *testing.T) {
	sqlite := setupRolesTestDB(t)
	defer sqlite.DB.Close()

	storage := NewSQLiteRoleStorage(sqlite, sqlite.Logger)
	ctx := context.Background()

	// Create roles
	role1 := &Role{
		Name:        "role1",
		Description: "Role 1",
		Permissions: []Permission{PermReadEvents},
	}
	err := storage.CreateRole(ctx, role1)
	require.NoError(t, err)

	role2 := &Role{
		Name:        "role2",
		Description: "Role 2",
		Permissions: []Permission{PermReadAlerts},
	}
	err = storage.CreateRole(ctx, role2)
	require.NoError(t, err)

	// Create users and assign roles via user_roles table
	user1 := "user1"
	user2 := "user2"
	_, err = sqlite.DB.Exec(`INSERT INTO users (username, password_hash, role_id, created_at, updated_at) 
	                          VALUES (?, ?, ?, ?, ?)`, user1, "hash1", role1.ID, time.Now(), time.Now())
	require.NoError(t, err)
	_, err = sqlite.DB.Exec(`INSERT INTO users (username, password_hash, role_id, created_at, updated_at) 
	                          VALUES (?, ?, ?, ?, ?)`, user2, "hash2", role1.ID, time.Now(), time.Now())
	require.NoError(t, err)

	// Also assign role2 to user1 via user_roles junction table
	_, err = sqlite.DB.Exec(`INSERT INTO user_roles (user_id, role_id, assigned_at) 
	                          VALUES (?, ?, ?)`, user1, role2.ID, time.Now())
	require.NoError(t, err)

	// Verify user roles via direct query
	query := `SELECT COUNT(*) FROM user_roles WHERE user_id = ?`
	var count int
	err = sqlite.DB.QueryRow(query, user1).Scan(&count)
	require.NoError(t, err)
	assert.Equal(t, 1, count) // user1 has role2 via user_roles table

	// Verify role users via direct query
	query = `SELECT COUNT(*) FROM user_roles WHERE role_id = ?`
	err = sqlite.DB.QueryRow(query, role1.ID).Scan(&count)
	require.NoError(t, err)
	assert.Equal(t, 0, count) // No entries in user_roles for role1 (users have it via role_id column)
}

// TestSQLiteRoleStorage_ForeignKeyCascade tests foreign key cascade behavior
func TestSQLiteRoleStorage_ForeignKeyCascade(t *testing.T) {
	sqlite := setupRolesTestDB(t)
	defer sqlite.DB.Close()

	storage := NewSQLiteRoleStorage(sqlite, sqlite.Logger)
	ctx := context.Background()

	// Verify foreign keys are enabled
	var fkEnabled int
	err := sqlite.DB.QueryRow("PRAGMA foreign_keys").Scan(&fkEnabled)
	require.NoError(t, err)
	require.Equal(t, 1, fkEnabled)

	// Create role and user
	role := &Role{
		Name:        "cascade-test-role",
		Description: "Cascade test",
		Permissions: []Permission{PermReadEvents},
	}
	err = storage.CreateRole(ctx, role)
	require.NoError(t, err)

	user := "cascade-user"
	_, err = sqlite.DB.Exec(`INSERT INTO users (username, password_hash, role_id, created_at, updated_at) 
	                          VALUES (?, ?, ?, ?, ?)`, user, "hash", role.ID, time.Now(), time.Now())
	require.NoError(t, err)

	// Verify association exists via direct query
	query := `SELECT role_id FROM users WHERE username = ?`
	var assignedRoleID sql.NullInt64
	err = sqlite.DB.QueryRow(query, user).Scan(&assignedRoleID)
	require.NoError(t, err)
	assert.True(t, assignedRoleID.Valid)
	assert.Equal(t, role.ID, assignedRoleID.Int64)

	// Note: Cannot delete role if users reference it (RESTRICT foreign key)
	// Test would fail with foreign key constraint
	err = storage.DeleteRole(ctx, role.ID)
	require.Error(t, err)                                 // Should fail due to RESTRICT constraint
	assert.Contains(t, err.Error(), "cannot delete role") // Role is in use
}

// TestSQLiteRoleStorage_ConcurrentRoleAssignments tests concurrent role assignments
func TestSQLiteRoleStorage_ConcurrentRoleAssignments(t *testing.T) {
	sqlite := setupRolesTestDB(t)
	defer sqlite.DB.Close()

	storage := NewSQLiteRoleStorage(sqlite, sqlite.Logger)
	ctx := context.Background()

	// Create role
	role := &Role{
		Name:        "concurrent-role",
		Description: "Concurrent test",
		Permissions: []Permission{PermReadEvents},
	}
	err := storage.CreateRole(ctx, role)
	require.NoError(t, err)

	// Concurrently create roles (test role creation concurrency)
	const numGoroutines = 10
	const rolesPerGoroutine = 5
	var wg sync.WaitGroup
	errors := make(chan error, numGoroutines*rolesPerGoroutine)

	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(goroutineID int) {
			defer wg.Done()
			for j := 0; j < rolesPerGoroutine; j++ {
				roleName := fmt.Sprintf("concurrent-role-%d-%d", goroutineID, j)
				testRole := &Role{
					Name:        roleName,
					Description: "Concurrent test role",
					Permissions: []Permission{PermReadEvents},
				}
				err := storage.CreateRole(ctx, testRole)
				if err != nil {
					errors <- err
				}
			}
		}(i)
	}

	wg.Wait()
	close(errors)

	// Verify no errors occurred
	for err := range errors {
		require.NoError(t, err)
	}

	// Verify roles were created
	roles, err := storage.ListRoles(ctx)
	require.NoError(t, err)
	assert.GreaterOrEqual(t, len(roles), numGoroutines*rolesPerGoroutine)
}
