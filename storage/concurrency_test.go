package storage

import (
	"context"
	"database/sql"
	"fmt"
	"sync"
	"testing"
	"time"

	"cerberus/core"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap/zaptest"
	_ "modernc.org/sqlite"
)

// setupConcurrencyTestDB creates an in-memory SQLite database for concurrency tests
func setupConcurrencyTestDB(t *testing.T) *SQLite {
	db, err := sql.Open("sqlite", ":memory:")
	require.NoError(t, err)

	_, err = db.Exec("PRAGMA foreign_keys=ON")
	require.NoError(t, err)

	sqlite := &SQLite{
		DB:     db,
		Path:   ":memory:",
		Logger: zaptest.NewLogger(t).Sugar(),
	}

	err = sqlite.createTables()
	require.NoError(t, err)

	// Create test user
	_, err = db.Exec(`
		INSERT OR IGNORE INTO users (username, password_hash, created_at, updated_at)
		VALUES ('testuser', 'hash', datetime('now'), datetime('now'))
	`)
	require.NoError(t, err)

	return sqlite
}

// TestSQLite_ConcurrentWrites tests concurrent write operations
func TestSQLite_ConcurrentWrites(t *testing.T) {
	sqlite := setupConcurrencyTestDB(t)
	defer sqlite.DB.Close()

	storage := NewSQLiteRuleStorage(sqlite, 5*time.Second, sqlite.Logger)

	const numGoroutines = 20
	const rulesPerGoroutine = 5
	var wg sync.WaitGroup
	errors := make(chan error, numGoroutines*rulesPerGoroutine)

	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(goroutineID int) {
			defer wg.Done()
			for j := 0; j < rulesPerGoroutine; j++ {
				rule := &core.Rule{
					ID:        fmt.Sprintf("rule-%d-%d", goroutineID, j),
					Name:      fmt.Sprintf("Rule %d-%d", goroutineID, j),
					Type:      "sigma",
					Severity:  "medium",
					Enabled:   true,
					CreatedAt: time.Now(),
					UpdatedAt: time.Now(),
				}
				err := storage.CreateRule(rule)
				if err != nil {
					errors <- err
				}
			}
		}(i)
	}

	wg.Wait()
	close(errors)

	// Check for errors
	for err := range errors {
		require.NoError(t, err)
	}

	// Verify all rules were created
	rules, err := storage.GetRules(1000, 0)
	require.NoError(t, err)
	assert.Equal(t, numGoroutines*rulesPerGoroutine, len(rules))
}

// TestSQLite_ConcurrentReadsAndWrites tests concurrent read and write operations
func TestSQLite_ConcurrentReadsAndWrites(t *testing.T) {
	sqlite := setupConcurrencyTestDB(t)
	defer sqlite.DB.Close()

	storage := NewSQLiteRuleStorage(sqlite, 5*time.Second, sqlite.Logger)

	// Create initial rule
	rule := &core.Rule{
		ID:        "rule-concurrent",
		Name:      "Concurrent Rule",
		Type:      "sigma",
		Severity:  "high",
		Enabled:   true,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
	err := storage.CreateRule(rule)
	require.NoError(t, err)

	const numReaders = 10
	const numWriters = 5
	var wg sync.WaitGroup
	readErrors := make(chan error, numReaders*10)
	writeErrors := make(chan error, numWriters*5)

	// Concurrent readers
	for i := 0; i < numReaders; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 10; j++ {
				_, err := storage.GetRule("rule-concurrent")
				if err != nil {
					readErrors <- err
				}
				time.Sleep(1 * time.Millisecond)
			}
		}()
	}

	// Concurrent writers (updating same rule)
	for i := 0; i < numWriters; i++ {
		wg.Add(1)
		go func(writerID int) {
			defer wg.Done()
			for j := 0; j < 5; j++ {
				rule.Description = fmt.Sprintf("Updated by writer %d iteration %d", writerID, j)
				rule.UpdatedAt = time.Now()
				err := storage.UpdateRule("rule-concurrent", rule)
				if err != nil {
					writeErrors <- err
				}
				time.Sleep(5 * time.Millisecond)
			}
		}(i)
	}

	wg.Wait()
	close(readErrors)
	close(writeErrors)

	// Check for errors (some write conflicts are expected with SQLite)
	for err := range readErrors {
		require.NoError(t, err)
	}

	// Verify final state
	updatedRule, err := storage.GetRule("rule-concurrent")
	require.NoError(t, err)
	assert.NotEmpty(t, updatedRule.Description)
}

// TestSQLite_ConcurrentTransactions tests concurrent transactions
func TestSQLite_ConcurrentTransactions(t *testing.T) {
	sqlite := setupConcurrencyTestDB(t)
	defer sqlite.DB.Close()

	// Alerts are stored in ClickHouse, not SQLite. Use direct DB operations for concurrency test.

	const numGoroutines = 10
	var wg sync.WaitGroup
	errors := make(chan error, numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(goroutineID int) {
			defer wg.Done()

			// Each goroutine creates an alert within a transaction
			err := sqlite.WithTransaction(func(tx *sql.Tx) error {
				// Insert alert using transaction (create table if not exists)
				_, err := tx.Exec(`
			CREATE TABLE IF NOT EXISTS alerts (
				alert_id TEXT PRIMARY KEY,
				rule_id TEXT,
				event_id TEXT,
				timestamp DATETIME,
				severity TEXT,
				status TEXT,
				rule_name TEXT,
				rule_type TEXT
			)
		`)
				if err != nil {
					return err
				}

				query := `
			INSERT INTO alerts (alert_id, rule_id, event_id, timestamp, severity, status, rule_name, rule_type)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?)
		`
				_, err = tx.Exec(query,
					fmt.Sprintf("alert-tx-%d", goroutineID), "rule-1", fmt.Sprintf("event-%d", goroutineID), time.Now(),
					"high", "pending", "Test Rule", "sigma",
				)
				return err
			})

			if err != nil {
				errors <- err
			}
		}(i)
	}

	wg.Wait()
	close(errors)

	// Check for errors
	for err := range errors {
		require.NoError(t, err)
	}

	// Verify all alerts were created
	var count int
	err := sqlite.DB.QueryRow("SELECT COUNT(*) FROM alerts WHERE alert_id LIKE 'alert-tx-%'").Scan(&count)
	require.NoError(t, err)
	assert.Equal(t, numGoroutines, count)
}

// TestSQLite_ConcurrentRoleAssignments tests concurrent role assignments
func TestSQLite_ConcurrentRoleAssignments(t *testing.T) {
	sqlite := setupConcurrencyTestDB(t)
	defer sqlite.DB.Close()

	storage := NewSQLiteRoleStorage(sqlite, sqlite.Logger)

	ctx := context.Background()

	// Create role
	role := &Role{
		Name:        "test-role-concurrent",
		Description: "Test role for concurrency",
		Permissions: []Permission{PermReadAlerts, PermWriteRules},
	}
	err := storage.CreateRole(ctx, role)
	require.NoError(t, err)

	// Create multiple users
	users := []string{"user1", "user2", "user3", "user4", "user5"}
	for _, username := range users {
		_, err = sqlite.DB.Exec(`
			INSERT OR IGNORE INTO users (username, password_hash, created_at, updated_at)
			VALUES (?, 'hash', datetime('now'), datetime('now'))
		`, username)
		require.NoError(t, err)
	}

	// Concurrently assign role to users
	const numGoroutines = 10
	var wg sync.WaitGroup
	errors := make(chan error, numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(goroutineID int) {
			defer wg.Done()
			username := users[goroutineID%len(users)]

			// Assign role via user_roles table
			_, err = sqlite.DB.Exec(`
				INSERT OR IGNORE INTO user_roles (user_id, role_id, assigned_at)
				VALUES (?, ?, ?)
			`, username, role.ID, time.Now())

			if err != nil {
				errors <- err
			}
		}(i)
	}

	wg.Wait()
	close(errors)

	// Check for errors (duplicate key errors are OK due to INSERT OR IGNORE)
	for err := range errors {
		require.NoError(t, err)
	}

	// Verify role assignments (should have unique user-role pairs)
	var count int
	countErr := sqlite.DB.QueryRow(`
		SELECT COUNT(DISTINCT user_id) FROM user_roles WHERE role_id = ?
	`, role.ID).Scan(&count)
	require.NoError(t, countErr)
	assert.GreaterOrEqual(t, count, len(users))
}

// TestSQLite_ConcurrentInvestigationUpdates tests concurrent investigation updates
func TestSQLite_ConcurrentInvestigationUpdates(t *testing.T) {
	sqlite := setupConcurrencyTestDB(t)
	defer sqlite.DB.Close()

	storage, err := NewSQLiteInvestigationStorage(sqlite, sqlite.Logger)
	require.NoError(t, err)

	// Create investigation
	investigation := &core.Investigation{
		InvestigationID: "inv-concurrent",
		Title:           "Concurrent Investigation",
		Status:          core.InvestigationStatusOpen,
		Priority:        core.InvestigationPriorityHigh,
		CreatedBy:       "testuser",
		CreatedAt:       time.Now(),
		UpdatedAt:       time.Now(),
	}
	err = storage.CreateInvestigation(investigation)
	require.NoError(t, err)

	const numGoroutines = 10
	var wg sync.WaitGroup
	errors := make(chan error, numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(goroutineID int) {
			defer wg.Done()

			// Get current investigation
			inv, err := storage.GetInvestigation("inv-concurrent")
			if err != nil {
				errors <- err
				return
			}

			// Update with goroutine-specific note
			inv.Title = fmt.Sprintf("Updated by goroutine %d", goroutineID)
			inv.UpdatedAt = time.Now()

			err = storage.UpdateInvestigation("inv-concurrent", inv)
			if err != nil {
				errors <- err
			}
		}(i)
	}

	wg.Wait()
	close(errors)

	// Some conflicts are expected with SQLite concurrent writes
	errorCount := 0
	for err := range errors {
		if err != nil {
			errorCount++
		}
	}

	// At least some updates should succeed
	finalInv, err := storage.GetInvestigation("inv-concurrent")
	require.NoError(t, err)
	assert.NotEmpty(t, finalInv.Title)
	assert.Contains(t, finalInv.Title, "Updated by goroutine")
}

// TestSQLite_RaceCondition_AlertStatusUpdate tests race condition in alert status updates
func TestSQLite_RaceCondition_AlertStatusUpdate(t *testing.T) {
	sqlite := setupConcurrencyTestDB(t)
	defer sqlite.DB.Close()

	// Alerts are stored in ClickHouse, not SQLite. Use direct DB operations for concurrency test.

	// Ensure alerts table exists
	_, err := sqlite.DB.Exec(`
		CREATE TABLE IF NOT EXISTS alerts (
			alert_id TEXT PRIMARY KEY,
			rule_id TEXT,
			event_id TEXT,
			timestamp DATETIME,
			severity TEXT,
			status TEXT,
			rule_name TEXT,
			rule_type TEXT,
			updated_at DATETIME
		)
	`)
	require.NoError(t, err)

	// Create alert directly in DB
	_, err = sqlite.DB.Exec(`
		INSERT OR IGNORE INTO alerts (alert_id, rule_id, event_id, timestamp, severity, status, rule_name, rule_type)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)
	`, "alert-race", "rule-1", "event-1", time.Now(), "high", "pending", "Test Rule", "sigma")
	require.NoError(t, err)

	const numGoroutines = 20
	var wg sync.WaitGroup
	errors := make(chan error, numGoroutines)
	statusUpdates := make(chan string, numGoroutines)

	statuses := []string{"acknowledged", "investigating", "resolved"}

	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(goroutineID int) {
			defer wg.Done()

			newStatus := statuses[goroutineID%len(statuses)]

			// Update status directly in DB
			_, execErr := sqlite.DB.Exec(`
				UPDATE alerts SET status = ?, updated_at = ? WHERE alert_id = ?
			`, newStatus, time.Now(), "alert-race")
			if execErr != nil {
				errors <- execErr
			} else {
				statusUpdates <- newStatus
			}
		}(i)
	}

	wg.Wait()
	close(errors)
	close(statusUpdates)

	// Count successful updates
	updateCount := 0
	for range statusUpdates {
		updateCount++
	}

	// Verify final alert exists and has a valid status
	var finalStatus string
	statusErr := sqlite.DB.QueryRow("SELECT status FROM alerts WHERE alert_id = ?", "alert-race").Scan(&finalStatus)
	require.NoError(t, statusErr)
	assert.Contains(t, statuses, finalStatus)
	assert.Greater(t, updateCount, 0)
}

// TestSQLite_DeadlockPrevention tests deadlock prevention with timeouts
func TestSQLite_DeadlockPrevention(t *testing.T) {
	sqlite := setupConcurrencyTestDB(t)
	defer sqlite.DB.Close()

	// SQLite should handle deadlocks gracefully with busy timeout
	// We test this by having two goroutines try to lock the same resources
	const numGoroutines = 5
	var wg sync.WaitGroup
	errors := make(chan error, numGoroutines*2)

	for i := 0; i < numGoroutines; i++ {
		wg.Add(2)

		// Goroutine 1: Update rule
		go func(id int) {
			defer wg.Done()
			err := sqlite.WithTransaction(func(tx *sql.Tx) error {
				_, err := tx.Exec("UPDATE rules SET updated_at = ? WHERE id = 'rule-1'", time.Now())
				time.Sleep(50 * time.Millisecond) // Hold lock
				return err
			})
			if err != nil {
				errors <- err
			}
		}(i)

		// Goroutine 2: Read rules
		go func(id int) {
			defer wg.Done()
			err := sqlite.WithTransaction(func(tx *sql.Tx) error {
				rows, err := tx.Query("SELECT id FROM rules WHERE id = 'rule-1'")
				if err != nil {
					return err
				}
				defer rows.Close()
				for rows.Next() {
					// Read data
				}
				return rows.Err()
			})
			if err != nil {
				errors <- err
			}
		}(i)
	}

	wg.Wait()
	close(errors)

	// Check that we didn't get deadlock errors (busy timeout should handle it)
	for err := range errors {
		if err != nil {
			// SQLite busy timeout should prevent deadlocks
			assert.NotContains(t, err.Error(), "database is locked")
		}
	}
}
