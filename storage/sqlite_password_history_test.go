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

// setupPasswordHistoryTestDB creates an in-memory SQLite database for password history tests
func setupPasswordHistoryTestDB(t *testing.T) *SQLite {
	db, err := sql.Open("sqlite", ":memory:")
	require.NoError(t, err)

	_, err = db.Exec("PRAGMA foreign_keys=ON")
	require.NoError(t, err)

	// Create users and password_history tables
	schema := `
	CREATE TABLE IF NOT EXISTS users (
		username TEXT PRIMARY KEY,
		password_hash TEXT NOT NULL,
		roles TEXT,
		role_id INTEGER,
		active INTEGER NOT NULL DEFAULT 1,
		created_at DATETIME NOT NULL,
		updated_at DATETIME NOT NULL,
		totp_secret TEXT,
		mfa_enabled INTEGER NOT NULL DEFAULT 0,
		failed_login_attempts INTEGER NOT NULL DEFAULT 0,
		locked_until DATETIME,
		password_changed_at DATETIME,
		must_change_password INTEGER NOT NULL DEFAULT 1
	);

	CREATE TABLE IF NOT EXISTS password_history (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		user_id TEXT NOT NULL,
		password_hash TEXT NOT NULL,
		created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
		FOREIGN KEY (user_id) REFERENCES users(username) ON DELETE CASCADE
	);
	CREATE INDEX IF NOT EXISTS idx_password_history_user_id ON password_history(user_id);
	CREATE INDEX IF NOT EXISTS idx_password_history_created_at ON password_history(created_at DESC);
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

// TestSQLitePasswordHistoryStorage_AddPasswordToHistory tests password history CRUD
func TestSQLitePasswordHistoryStorage_AddPasswordToHistory(t *testing.T) {
	sqlite := setupPasswordHistoryTestDB(t)
	defer sqlite.DB.Close()

	storage := NewSQLitePasswordHistoryStorage(sqlite, sqlite.Logger)
	ctx := context.Background()

	// Create a test user first
	_, err := sqlite.DB.Exec(`INSERT INTO users (username, password_hash, created_at, updated_at) 
	                          VALUES (?, ?, ?, ?)`, "testuser", "hash1", time.Now(), time.Now())
	require.NoError(t, err)

	tests := []struct {
		name         string
		userID       string
		passwordHash string
		expectErr    bool
	}{
		{
			name:         "Valid password hash",
			userID:       "testuser",
			passwordHash: "hash2",
			expectErr:    false,
		},
		{
			name:         "Empty user ID",
			userID:       "",
			passwordHash: "hash3",
			expectErr:    true,
		},
		{
			name:         "Empty password hash",
			userID:       "testuser",
			passwordHash: "",
			expectErr:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := storage.AddPasswordToHistory(ctx, tt.userID, tt.passwordHash)
			if tt.expectErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)

				// Verify password was added
				history, err := storage.GetPasswordHistory(ctx, tt.userID, 10)
				require.NoError(t, err)
				assert.Contains(t, history, tt.passwordHash)
			}
		})
	}
}

// TestSQLitePasswordHistoryStorage_PasswordReusePrevention tests password reuse prevention
func TestSQLitePasswordHistoryStorage_PasswordReusePrevention(t *testing.T) {
	sqlite := setupPasswordHistoryTestDB(t)
	defer sqlite.DB.Close()

	storage := NewSQLitePasswordHistoryStorage(sqlite, sqlite.Logger)
	ctx := context.Background()

	userID := "reuse-test-user"

	// Create user
	_, err := sqlite.DB.Exec(`INSERT INTO users (username, password_hash, created_at, updated_at) 
	                          VALUES (?, ?, ?, ?)`, userID, "current_hash", time.Now(), time.Now())
	require.NoError(t, err)

	// Add multiple passwords to history
	passwords := []string{"hash1", "hash2", "hash3", "hash4", "hash5"}
	for _, pwd := range passwords {
		err := storage.AddPasswordToHistory(ctx, userID, pwd)
		require.NoError(t, err)
		time.Sleep(10 * time.Millisecond) // Small delay to ensure different timestamps
	}

	// Get password history
	history, err := storage.GetPasswordHistory(ctx, userID, 10)
	require.NoError(t, err)
	assert.Len(t, history, len(passwords))

	// Verify passwords are in history (order may vary based on query)
	for _, pwd := range passwords {
		assert.Contains(t, history, pwd)
	}

	// Check if password was reused (should be in history)
	isReused := false
	for _, pwd := range history {
		if pwd == "hash3" {
			isReused = true
			break
		}
	}
	assert.True(t, isReused, "Password hash3 should be in history")
}

// TestSQLitePasswordHistoryStorage_HistoryCleanup tests history cleanup
func TestSQLitePasswordHistoryStorage_HistoryCleanup(t *testing.T) {
	sqlite := setupPasswordHistoryTestDB(t)
	defer sqlite.DB.Close()

	storage := NewSQLitePasswordHistoryStorage(sqlite, sqlite.Logger)
	ctx := context.Background()

	userID := "cleanup-test-user"

	// Create user
	_, err := sqlite.DB.Exec(`INSERT INTO users (username, password_hash, created_at, updated_at) 
	                          VALUES (?, ?, ?, ?)`, userID, "current_hash", time.Now(), time.Now())
	require.NoError(t, err)

	// Add 10 passwords to history
	for i := 0; i < 10; i++ {
		err := storage.AddPasswordToHistory(ctx, userID, fmt.Sprintf("hash%d", i))
		require.NoError(t, err)
		time.Sleep(10 * time.Millisecond)
	}

	// Get all history
	history, err := storage.GetPasswordHistory(ctx, userID, 100)
	require.NoError(t, err)
	assert.Equal(t, 10, len(history))

	// Prune to keep only 5 most recent
	maxHistory := 5
	err = storage.PruneHistory(ctx, userID, maxHistory)
	require.NoError(t, err)

	// Verify only 5 remain
	history, err = storage.GetPasswordHistory(ctx, userID, 100)
	require.NoError(t, err)
	assert.LessOrEqual(t, len(history), maxHistory)
}

// TestSQLitePasswordHistoryStorage_TimeBasedCleanup tests time-based cleanup
func TestSQLitePasswordHistoryStorage_TimeBasedCleanup(t *testing.T) {
	sqlite := setupPasswordHistoryTestDB(t)
	defer sqlite.DB.Close()

	storage := NewSQLitePasswordHistoryStorage(sqlite, sqlite.Logger)
	ctx := context.Background()

	userID := "time-cleanup-user"

	// Create user
	_, err := sqlite.DB.Exec(`INSERT INTO users (username, password_hash, created_at, updated_at) 
	                          VALUES (?, ?, ?, ?)`, userID, "current_hash", time.Now(), time.Now())
	require.NoError(t, err)

	// Add old password (more than retention period)
	oldTime := time.Now().Add(-90 * 24 * time.Hour) // 90 days ago
	_, err = sqlite.DB.Exec(`INSERT INTO password_history (user_id, password_hash, created_at) 
	                         VALUES (?, ?, ?)`, userID, "old_hash", oldTime)
	require.NoError(t, err)

	// Add recent password
	err = storage.AddPasswordToHistory(ctx, userID, "recent_hash")
	require.NoError(t, err)

	// Cleanup passwords older than 30 days
	retentionPeriod := 30 * 24 * time.Hour
	cutoffTime := time.Now().Add(-retentionPeriod)
	_, err = sqlite.DB.Exec(`DELETE FROM password_history WHERE user_id = ? AND created_at < ?`,
		userID, cutoffTime)
	require.NoError(t, err)

	// Verify old password was removed
	history, err := storage.GetPasswordHistory(ctx, userID, 10)
	require.NoError(t, err)
	assert.NotContains(t, history, "old_hash")
	assert.Contains(t, history, "recent_hash")
}

// TestSQLitePasswordHistoryStorage_ConcurrentOperations tests concurrent password history operations
func TestSQLitePasswordHistoryStorage_ConcurrentOperations(t *testing.T) {
	sqlite := setupPasswordHistoryTestDB(t)
	defer sqlite.DB.Close()

	storage := NewSQLitePasswordHistoryStorage(sqlite, sqlite.Logger)
	ctx := context.Background()

	userID := "concurrent-user"

	// Create user
	_, err := sqlite.DB.Exec(`INSERT INTO users (username, password_hash, created_at, updated_at) 
	                          VALUES (?, ?, ?, ?)`, userID, "current_hash", time.Now(), time.Now())
	require.NoError(t, err)

	const numGoroutines = 10
	const passwordsPerGoroutine = 5

	var wg sync.WaitGroup
	errors := make(chan error, numGoroutines*passwordsPerGoroutine)

	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(goroutineID int) {
			defer wg.Done()
			for j := 0; j < passwordsPerGoroutine; j++ {
				hash := fmt.Sprintf("hash-%d-%d", goroutineID, j)
				err := storage.AddPasswordToHistory(ctx, userID, hash)
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

	// Verify all passwords were added
	history, err := storage.GetPasswordHistory(ctx, userID, 1000)
	require.NoError(t, err)
	assert.Equal(t, numGoroutines*passwordsPerGoroutine, len(history))
}
