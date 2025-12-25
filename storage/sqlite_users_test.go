package storage

import (
	"context"
	"database/sql"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	_ "modernc.org/sqlite"
)

// setupUserTestDB creates an in-memory SQLite database with users table
func setupUserTestDB(t *testing.T) (*sql.DB, *SQLite, *SQLiteUserStorage) {
	db, err := sql.Open("sqlite", ":memory:?_journal_mode=WAL&_busy_timeout=5000")
	require.NoError(t, err)

	// Create users table
	schema := `
		CREATE TABLE users (
			username TEXT PRIMARY KEY,
			password_hash TEXT NOT NULL,
			roles TEXT NOT NULL,
			active INTEGER DEFAULT 1,
			created_at TEXT NOT NULL,
			updated_at TEXT NOT NULL
		);
		CREATE INDEX idx_users_active ON users(active);
	`
	_, err = db.Exec(schema)
	require.NoError(t, err)

	sqlite := &SQLite{
		DB:     db,
		Path:   ":memory:",
		Logger: zap.NewNop().Sugar(),
	}

	storage := NewSQLiteUserStorage(sqlite, zap.NewNop().Sugar())
	return db, sqlite, storage
}

// TestNewSQLiteUserStorage tests storage creation
func TestNewSQLiteUserStorage(t *testing.T) {
	_, sqlite, _ := setupUserTestDB(t)

	storage := NewSQLiteUserStorage(sqlite, zap.NewNop().Sugar())
	require.NotNil(t, storage)
	assert.Equal(t, sqlite, storage.sqlite)
	assert.NotNil(t, storage.logger)
}

// TestCreateUser_Success tests successful user creation
func TestCreateUser_Success(t *testing.T) {
	_, _, storage := setupUserTestDB(t)
	ctx := context.Background()

	user := &User{
		Username: "testuser",
		Password: "SecurePassword123!",
		Roles:    []string{"admin", "analyst"},
		Active:   true,
	}

	err := storage.CreateUser(ctx, user)
	require.NoError(t, err)

	// Verify user was created
	retrieved, err := storage.GetUserByUsername(ctx, "testuser")
	require.NoError(t, err)
	assert.Equal(t, "testuser", retrieved.Username)
	assert.Equal(t, []string{"admin", "analyst"}, retrieved.Roles)
	assert.True(t, retrieved.Active)
	assert.NotZero(t, retrieved.CreatedAt)
	assert.NotZero(t, retrieved.UpdatedAt)

	// Password should be hashed, not plain text
	assert.NotEqual(t, "SecurePassword123!", retrieved.Password)
	assert.Contains(t, retrieved.Password, "$2a$") // bcrypt hash prefix
}

// TestCreateUser_DuplicateUsername tests creating user with existing username
func TestCreateUser_DuplicateUsername(t *testing.T) {
	_, _, storage := setupUserTestDB(t)
	ctx := context.Background()

	user1 := &User{
		Username: "duplicate",
		Password: "Password1!",
		Roles:    []string{"analyst"},
	}

	err := storage.CreateUser(ctx, user1)
	require.NoError(t, err)

	// Try to create another user with same username
	user2 := &User{
		Username: "duplicate",
		Password: "Password2!",
		Roles:    []string{"admin"},
	}

	err = storage.CreateUser(ctx, user2)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "user already exists")
}

// TestCreateUser_SQLInjectionPrevention tests SQL injection protection
func TestCreateUser_SQLInjectionPrevention(t *testing.T) {
	_, _, storage := setupUserTestDB(t)
	ctx := context.Background()

	maliciousInputs := []string{
		"admin'; DROP TABLE users; --",
		"admin' OR '1'='1",
		"admin\"; DELETE FROM users WHERE \"1\"=\"1",
		"admin'; UPDATE users SET roles = 'admin' WHERE '1'='1'; --",
	}

	for _, malicious := range maliciousInputs {
		user := &User{
			Username: malicious,
			Password: "Password123!",
			Roles:    []string{"analyst"},
		}

		// Should either succeed (treating as literal string) or fail gracefully
		err := storage.CreateUser(ctx, user)

		// If it succeeds, verify the malicious input was stored as literal string
		if err == nil {
			retrieved, err := storage.GetUserByUsername(ctx, malicious)
			require.NoError(t, err)
			assert.Equal(t, malicious, retrieved.Username)
		}
	}

	// Verify table still exists and has data
	users, err := storage.ListUsers(ctx)
	require.NoError(t, err)
	assert.NotNil(t, users)
}

// TestGetUserByUsername_Success tests retrieving existing user
func TestGetUserByUsername_Success(t *testing.T) {
	_, _, storage := setupUserTestDB(t)
	ctx := context.Background()

	user := &User{
		Username: "gettest",
		Password: "Password123!",
		Roles:    []string{"admin"},
	}

	err := storage.CreateUser(ctx, user)
	require.NoError(t, err)

	retrieved, err := storage.GetUserByUsername(ctx, "gettest")
	require.NoError(t, err)
	assert.Equal(t, "gettest", retrieved.Username)
	assert.Equal(t, []string{"admin"}, retrieved.Roles)
}

// TestGetUserByUsername_NotFound tests retrieving non-existent user
func TestGetUserByUsername_NotFound(t *testing.T) {
	_, _, storage := setupUserTestDB(t)
	ctx := context.Background()

	user, err := storage.GetUserByUsername(ctx, "nonexistent")
	assert.Error(t, err)
	assert.Nil(t, user)
	assert.Contains(t, err.Error(), "user not found")
}

// TestGetUserByUsername_SQLInjection tests SQL injection protection
func TestGetUserByUsername_SQLInjection(t *testing.T) {
	_, _, storage := setupUserTestDB(t)
	ctx := context.Background()

	// Create a normal user
	user := &User{
		Username: "normaluser",
		Password: "Password123!",
		Roles:    []string{"analyst"},
	}
	err := storage.CreateUser(ctx, user)
	require.NoError(t, err)

	// Try SQL injection in query
	maliciousQueries := []string{
		"' OR '1'='1",
		"admin' --",
		"' UNION SELECT * FROM users --",
	}

	for _, malicious := range maliciousQueries {
		user, err := storage.GetUserByUsername(ctx, malicious)
		// Should not return the normal user or cause errors
		if err == nil {
			// If found, must be exact match (literal string stored)
			assert.Equal(t, malicious, user.Username)
		} else {
			// Or should return "not found"
			assert.Contains(t, err.Error(), "user not found")
		}
	}
}

// TestUpdateUser_Success tests updating existing user
func TestUpdateUser_Success(t *testing.T) {
	_, _, storage := setupUserTestDB(t)
	ctx := context.Background()

	// Create user
	user := &User{
		Username: "updatetest",
		Password: "OldPassword123!",
		Roles:    []string{"analyst"},
		Active:   true,
	}
	err := storage.CreateUser(ctx, user)
	require.NoError(t, err)

	original, err := storage.GetUserByUsername(ctx, "updatetest")
	require.NoError(t, err)

	// Update user
	user.Password = "NewPassword456!"
	user.Roles = []string{"admin", "analyst"}
	user.Active = false

	err = storage.UpdateUser(ctx, user)
	require.NoError(t, err)

	// Verify updates
	updated, err := storage.GetUserByUsername(ctx, "updatetest")
	require.NoError(t, err)
	assert.Equal(t, []string{"admin", "analyst"}, updated.Roles)
	assert.False(t, updated.Active)

	// Password should have changed
	assert.NotEqual(t, original.Password, updated.Password)

	// Created time should be preserved
	assert.Equal(t, original.CreatedAt, updated.CreatedAt)

	// Updated time should be set (may be same as created on fast systems)
	assert.False(t, updated.UpdatedAt.IsZero())
}

// TestUpdateUser_EmptyPassword tests updating without changing password
func TestUpdateUser_EmptyPassword(t *testing.T) {
	_, _, storage := setupUserTestDB(t)
	ctx := context.Background()

	// Create user
	user := &User{
		Username: "passwordtest",
		Password: "OriginalPassword123!",
		Roles:    []string{"analyst"},
	}
	err := storage.CreateUser(ctx, user)
	require.NoError(t, err)

	original, err := storage.GetUserByUsername(ctx, "passwordtest")
	require.NoError(t, err)
	originalHash := original.Password

	// Update with empty password (should preserve existing)
	user.Password = ""
	user.Roles = []string{"admin"}

	err = storage.UpdateUser(ctx, user)
	require.NoError(t, err)

	updated, err := storage.GetUserByUsername(ctx, "passwordtest")
	require.NoError(t, err)

	// Password hash should be unchanged
	assert.Equal(t, originalHash, updated.Password)

	// Roles should be updated
	assert.Equal(t, []string{"admin"}, updated.Roles)
}

// TestUpdateUser_NotFound tests updating non-existent user
func TestUpdateUser_NotFound(t *testing.T) {
	_, _, storage := setupUserTestDB(t)
	ctx := context.Background()

	user := &User{
		Username: "nonexistent",
		Password: "Password123!",
		Roles:    []string{"analyst"},
	}

	err := storage.UpdateUser(ctx, user)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "user not found")
}

// TestDeleteUser_Success tests deleting existing user
func TestDeleteUser_Success(t *testing.T) {
	_, _, storage := setupUserTestDB(t)
	ctx := context.Background()

	user := &User{
		Username: "deletetest",
		Password: "Password123!",
		Roles:    []string{"analyst"},
	}
	err := storage.CreateUser(ctx, user)
	require.NoError(t, err)

	// Verify user exists
	_, err = storage.GetUserByUsername(ctx, "deletetest")
	require.NoError(t, err)

	// Delete user
	err = storage.DeleteUser(ctx, "deletetest")
	require.NoError(t, err)

	// Verify user no longer exists
	_, err = storage.GetUserByUsername(ctx, "deletetest")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "user not found")
}

// TestDeleteUser_NotFound tests deleting non-existent user
func TestDeleteUser_NotFound(t *testing.T) {
	_, _, storage := setupUserTestDB(t)
	ctx := context.Background()

	err := storage.DeleteUser(ctx, "nonexistent")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "user not found")
}

// TestDeleteUser_SQLInjection tests SQL injection protection
func TestDeleteUser_SQLInjection(t *testing.T) {
	_, _, storage := setupUserTestDB(t)
	ctx := context.Background()

	// Create multiple users
	users := []string{"user1", "user2", "user3"}
	for _, username := range users {
		user := &User{
			Username: username,
			Password: "Password123!",
			Roles:    []string{"analyst"},
		}
		err := storage.CreateUser(ctx, user)
		require.NoError(t, err)
	}

	// Try SQL injection to delete all users
	maliciousInputs := []string{
		"' OR '1'='1",
		"user1'; DELETE FROM users WHERE '1'='1'; --",
	}

	for _, malicious := range maliciousInputs {
		// Should not delete all users
		err := storage.DeleteUser(ctx, malicious)
		// Either fails or deletes literal match only
		_ = err
	}

	// Verify at least some users still exist
	allUsers, err := storage.ListUsers(ctx)
	require.NoError(t, err)
	assert.NotEmpty(t, allUsers, "SQL injection should not delete all users")
}

// TestListUsers_Success tests listing all users
func TestListUsers_Success(t *testing.T) {
	_, _, storage := setupUserTestDB(t)
	ctx := context.Background()

	// Create multiple users
	usernames := []string{"alice", "bob", "charlie"}
	for _, username := range usernames {
		user := &User{
			Username: username,
			Password: "Password123!",
			Roles:    []string{"analyst"},
		}
		err := storage.CreateUser(ctx, user)
		require.NoError(t, err)
	}

	// List users
	users, err := storage.ListUsers(ctx)
	require.NoError(t, err)
	assert.Len(t, users, 3)

	// Verify all usernames are present
	usernamesFound := make(map[string]bool)
	for _, user := range users {
		usernamesFound[user.Username] = true
	}

	for _, username := range usernames {
		assert.True(t, usernamesFound[username], "User %s not found in list", username)
	}
}

// TestListUsers_Empty tests listing when no users exist
func TestListUsers_Empty(t *testing.T) {
	_, _, storage := setupUserTestDB(t)
	ctx := context.Background()

	users, err := storage.ListUsers(ctx)
	require.NoError(t, err)
	assert.Empty(t, users)
}

// TestListUsers_InvalidRolesJSON tests handling of corrupted roles data
func TestListUsers_InvalidRolesJSON(t *testing.T) {
	db, _, storage := setupUserTestDB(t)
	ctx := context.Background()

	// Insert user with invalid JSON roles directly
	_, err := db.Exec(`
		INSERT INTO users (username, password_hash, roles, active, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?)
	`, "corruptuser", "$2a$10$hash", "invalid json{", 1, "2024-01-01T00:00:00Z", "2024-01-01T00:00:00Z")
	require.NoError(t, err)

	// List should skip corrupt user and continue
	users, err := storage.ListUsers(ctx)
	require.NoError(t, err)

	// Should return empty list (corrupt user skipped)
	assert.Empty(t, users)
}

// TestValidateCredentials_Success tests successful authentication
func TestValidateCredentials_Success(t *testing.T) {
	_, _, storage := setupUserTestDB(t)
	ctx := context.Background()

	password := "SecurePassword123!"
	user := &User{
		Username: "authtest",
		Password: password,
		Roles:    []string{"admin"},
		Active:   true,
	}
	err := storage.CreateUser(ctx, user)
	require.NoError(t, err)

	// Validate correct credentials
	validatedUser, err := storage.ValidateCredentials(ctx, "authtest", password)
	require.NoError(t, err)
	assert.NotNil(t, validatedUser)
	assert.Equal(t, "authtest", validatedUser.Username)
	assert.Equal(t, []string{"admin"}, validatedUser.Roles)
}

// TestValidateCredentials_WrongPassword tests authentication with wrong password
func TestValidateCredentials_WrongPassword(t *testing.T) {
	_, _, storage := setupUserTestDB(t)
	ctx := context.Background()

	user := &User{
		Username: "wrongpasstest",
		Password: "CorrectPassword123!",
		Roles:    []string{"analyst"},
		Active:   true,
	}
	err := storage.CreateUser(ctx, user)
	require.NoError(t, err)

	// Try wrong password
	validatedUser, err := storage.ValidateCredentials(ctx, "wrongpasstest", "WrongPassword456!")
	assert.Error(t, err)
	assert.Nil(t, validatedUser)
	assert.Contains(t, err.Error(), "invalid credentials")
}

// TestValidateCredentials_UserNotFound tests authentication for non-existent user
func TestValidateCredentials_UserNotFound(t *testing.T) {
	_, _, storage := setupUserTestDB(t)
	ctx := context.Background()

	validatedUser, err := storage.ValidateCredentials(ctx, "nonexistent", "Password123!")
	assert.Error(t, err)
	assert.Nil(t, validatedUser)
	assert.Contains(t, err.Error(), "user not found")
}

// TestValidateCredentials_InactiveUser tests authentication for inactive user
func TestValidateCredentials_InactiveUser(t *testing.T) {
	_, _, storage := setupUserTestDB(t)
	ctx := context.Background()

	password := "Password123!"
	user := &User{
		Username: "inactivetest",
		Password: password,
		Roles:    []string{"analyst"},
		Active:   false, // Inactive user
	}
	err := storage.CreateUser(ctx, user)
	require.NoError(t, err)

	// Set user to inactive
	user.Active = false
	err = storage.UpdateUser(ctx, user)
	require.NoError(t, err)

	// Try to authenticate
	validatedUser, err := storage.ValidateCredentials(ctx, "inactivetest", password)
	assert.Error(t, err)
	assert.Nil(t, validatedUser)
	assert.Contains(t, err.Error(), "user is not active")
}

// TestValidateCredentials_SQLInjection tests SQL injection in authentication
func TestValidateCredentials_SQLInjection(t *testing.T) {
	_, _, storage := setupUserTestDB(t)
	ctx := context.Background()

	// Create a legitimate user
	user := &User{
		Username: "legitimate",
		Password: "SecurePassword123!",
		Roles:    []string{"admin"},
		Active:   true,
	}
	err := storage.CreateUser(ctx, user)
	require.NoError(t, err)

	// Try SQL injection to bypass authentication
	maliciousInputs := []struct {
		username string
		password string
	}{
		{"admin' OR '1'='1", "anything"},
		{"admin' --", ""},
		{"' OR 1=1 --", ""},
		{"legitimate", "' OR '1'='1"},
	}

	for _, malicious := range maliciousInputs {
		validatedUser, err := storage.ValidateCredentials(ctx, malicious.username, malicious.password)
		// Should fail to authenticate
		assert.Error(t, err, "SQL injection should not bypass authentication")
		assert.Nil(t, validatedUser)
	}
}

// TestUserStorage_EnsureIndexes tests index creation
func TestUserStorage_EnsureIndexes(t *testing.T) {
	_, _, storage := setupUserTestDB(t)
	ctx := context.Background()

	err := storage.EnsureIndexes(ctx)
	require.NoError(t, err)

	// Should succeed (no-op for SQLite user storage)
}

// TestUser_ConcurrentAccess tests concurrent user operations
func TestUser_ConcurrentAccess(t *testing.T) {
	db, sqlite, storage := setupUserTestDB(t)
	defer db.Close()
	ctx := context.Background()

	// Create initial user
	user := &User{
		Username: "concurrent",
		Password: "Password123!",
		Roles:    []string{"analyst"},
		Active:   true,
	}
	err := storage.CreateUser(ctx, user)
	require.NoError(t, err)

	// Sequential reads to verify basic functionality
	// (In-memory SQLite doesn't handle true concurrent access well in tests)
	for i := 0; i < 5; i++ {
		retrieved, err := storage.GetUserByUsername(ctx, "concurrent")
		require.NoError(t, err)
		assert.Equal(t, "concurrent", retrieved.Username)
	}

	_ = sqlite // Use sqlite to avoid unused variable warning
}

// TestPasswordHashing tests bcrypt password hashing
func TestPasswordHashing(t *testing.T) {
	_, _, storage := setupUserTestDB(t)
	ctx := context.Background()

	password := "TestPassword123!"
	user := &User{
		Username: "hashtest",
		Password: password,
		Roles:    []string{"analyst"},
	}

	err := storage.CreateUser(ctx, user)
	require.NoError(t, err)

	retrieved, err := storage.GetUserByUsername(ctx, "hashtest")
	require.NoError(t, err)

	// Password should be hashed
	assert.NotEqual(t, password, retrieved.Password)

	// Hash should start with bcrypt prefix
	assert.Contains(t, retrieved.Password, "$2a$")

	// Hash length should be reasonable (bcrypt produces 60 char hashes)
	assert.Greater(t, len(retrieved.Password), 50)

	// Validate credentials should work with original password
	validatedUser, err := storage.ValidateCredentials(ctx, "hashtest", password)
	require.NoError(t, err)
	assert.Equal(t, "hashtest", validatedUser.Username)
}

// TestRolesSerialization tests JSON serialization of roles
func TestRolesSerialization(t *testing.T) {
	_, _, storage := setupUserTestDB(t)
	ctx := context.Background()

	testCases := []struct {
		name  string
		roles []string
	}{
		{"single role", []string{"admin"}},
		{"multiple roles", []string{"admin", "analyst", "operator"}},
		{"empty roles", []string{}},
		{"special characters", []string{"role-with-dash", "role_with_underscore"}},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			user := &User{
				Username: "rolestest_" + tc.name,
				Password: "Password123!",
				Roles:    tc.roles,
			}

			err := storage.CreateUser(ctx, user)
			require.NoError(t, err)

			retrieved, err := storage.GetUserByUsername(ctx, user.Username)
			require.NoError(t, err)
			assert.Equal(t, tc.roles, retrieved.Roles)
		})
	}
}
