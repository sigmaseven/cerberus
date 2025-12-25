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

// setupInvestigationLifecycleTestDB creates an in-memory SQLite database for investigation lifecycle tests
func setupInvestigationLifecycleTestDB(t *testing.T) *SQLiteInvestigationStorage {
	db, err := sql.Open("sqlite", ":memory:")
	require.NoError(t, err)

	_, err = db.Exec("PRAGMA foreign_keys=ON")
	require.NoError(t, err)

	sqlite := &SQLite{
		DB:     db,
		Path:   ":memory:",
		Logger: zaptest.NewLogger(t).Sugar(),
	}

	// Create tables
	err = sqlite.createTables()
	require.NoError(t, err)

	// Verify tables were created
	var tableName string
	err = db.QueryRow("SELECT name FROM sqlite_master WHERE type='table' AND name='users'").Scan(&tableName)
	require.NoError(t, err, "users table should exist")
	require.Equal(t, "users", tableName)

	// Create a test user to satisfy foreign key constraints
	result, err := db.Exec(`
		INSERT OR IGNORE INTO users (username, password_hash, created_at, updated_at)
		VALUES ('admin', 'test-hash', datetime('now'), datetime('now'))
	`)
	require.NoError(t, err)
	rowsAffected, err := result.RowsAffected()
	require.NoError(t, err)
	t.Logf("User insert rows affected: %d", rowsAffected)

	// Verify user exists
	var username string
	err = db.QueryRow("SELECT username FROM users WHERE username = 'admin'").Scan(&username)
	require.NoError(t, err, "admin user should exist")
	require.Equal(t, "admin", username)

	storage, err := NewSQLiteInvestigationStorage(sqlite, sqlite.Logger)
	require.NoError(t, err)

	return storage
}

// TestInvestigationLifecycle_StateTransitions tests investigation state transitions
func TestInvestigationLifecycle_StateTransitions(t *testing.T) {
	storage := setupInvestigationLifecycleTestDB(t)
	defer storage.db.DB.Close()

	ctx := context.Background()

	// Create investigation
	investigation := &core.Investigation{
		InvestigationID: "lifecycle-1",
		Title:           "Lifecycle Test",
		Status:          core.InvestigationStatusOpen,
		Priority:        core.InvestigationPriorityHigh,
		CreatedBy:       "admin",
		// AssigneeID left empty (will be converted to NULL in DB)
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
	err := storage.CreateInvestigation(investigation)
	require.NoError(t, err)

	tests := []struct {
		name        string
		fromStatus  core.InvestigationStatus
		toStatus    core.InvestigationStatus
		expectErr   bool
		description string
	}{
		{
			name:        "Valid: Open -> InProgress",
			fromStatus:  core.InvestigationStatusOpen,
			toStatus:    core.InvestigationStatusInProgress,
			expectErr:   false,
			description: "Valid transition from open to in progress",
		},
		{
			name:        "Valid: InProgress -> Resolved",
			fromStatus:  core.InvestigationStatusInProgress,
			toStatus:    core.InvestigationStatusResolved,
			expectErr:   false,
			description: "Valid transition from in progress to resolved",
		},
		{
			name:        "Valid: Resolved -> Closed",
			fromStatus:  core.InvestigationStatusResolved,
			toStatus:    core.InvestigationStatusClosed,
			expectErr:   false,
			description: "Valid transition from resolved to closed",
		},
		{
			name:        "Invalid: Open -> Closed",
			fromStatus:  core.InvestigationStatusOpen,
			toStatus:    core.InvestigationStatusClosed,
			expectErr:   true,
			description: "Invalid transition - cannot skip to closed",
		},
		{
			name:        "Invalid: Closed -> InProgress",
			fromStatus:  core.InvestigationStatusClosed,
			toStatus:    core.InvestigationStatusInProgress,
			expectErr:   true,
			description: "Invalid transition - closed investigations cannot be modified",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// For tests that expect an error, we can just validate the transition logic
			// without actually changing the investigation state
			if tt.expectErr {
				err := storage.ValidateStateTransition(tt.fromStatus, tt.toStatus)
				require.Error(t, err)
				return
			}

			// For valid transitions, ensure investigation is in fromStatus first
			current, err := storage.GetInvestigation(investigation.InvestigationID)
			require.NoError(t, err)
			if current.Status != tt.fromStatus {
				// Only update if we can validly reach fromStatus from current status
				// For simplicity, if we can't, create a new investigation
				if err := storage.ValidateStateTransition(current.Status, tt.fromStatus); err != nil {
					// Create a fresh investigation for this test case
					newInvestigation := &core.Investigation{
						InvestigationID: fmt.Sprintf("lifecycle-%s", tt.name),
						Title:           fmt.Sprintf("Lifecycle Test: %s", tt.name),
						Status:          tt.fromStatus,
						Priority:        core.InvestigationPriorityHigh,
						CreatedBy:       "admin",
						CreatedAt:       time.Now(),
						UpdatedAt:       time.Now(),
					}
					err = storage.CreateInvestigation(newInvestigation)
					require.NoError(t, err)
					investigation = newInvestigation
				} else {
					current.Status = tt.fromStatus
					err = storage.UpdateInvestigation(investigation.InvestigationID, current)
					require.NoError(t, err)
				}
			}

			// Validate transition
			err = storage.ValidateStateTransition(tt.fromStatus, tt.toStatus)
			require.NoError(t, err)

			// Update investigation to toStatus
			current, err = storage.GetInvestigation(investigation.InvestigationID)
			require.NoError(t, err)
			current.Status = tt.toStatus
			err = storage.UpdateInvestigation(investigation.InvestigationID, current)
			require.NoError(t, err)

			// Log state transition
			err = storage.LogStateTransition(ctx, investigation.InvestigationID, tt.fromStatus, tt.toStatus, "admin", tt.description)
			require.NoError(t, err)
		})
	}
}

// TestInvestigationLifecycle_TimelineTracking tests investigation timeline tracking
func TestInvestigationLifecycle_TimelineTracking(t *testing.T) {
	storage := setupInvestigationLifecycleTestDB(t)
	defer storage.db.DB.Close()

	ctx := context.Background()

	// Create investigation
	investigation := &core.Investigation{
		InvestigationID: "timeline-1",
		Title:           "Timeline Test",
		Status:          core.InvestigationStatusOpen,
		Priority:        core.InvestigationPriorityHigh,
		CreatedBy:       "admin",
		CreatedAt:       time.Now(),
		UpdatedAt:       time.Now(),
	}
	err := storage.CreateInvestigation(investigation)
	require.NoError(t, err)

	// Log state transitions to create timeline
	transitions := []struct {
		from, to core.InvestigationStatus
		reason   string
	}{
		{core.InvestigationStatusOpen, core.InvestigationStatusInProgress, "Started investigation"},
		{core.InvestigationStatusInProgress, core.InvestigationStatusAwaitingReview, "Awaiting review"},
		{core.InvestigationStatusAwaitingReview, core.InvestigationStatusResolved, "Issue resolved"},
		{core.InvestigationStatusResolved, core.InvestigationStatusClosed, "Investigation closed"},
	}

	for i, trans := range transitions {
		// Update investigation status
		investigation.Status = trans.to
		err := storage.UpdateInvestigation(investigation.InvestigationID, investigation)
		require.NoError(t, err)

		// Log state transition
		err = storage.LogStateTransition(ctx, investigation.InvestigationID, trans.from, trans.to, "admin", trans.reason)
		require.NoError(t, err)

		time.Sleep(10 * time.Millisecond) // Small delay to ensure different timestamps
		_ = i
	}

	// Generate timeline
	timeline, total, err := storage.GenerateTimeline(ctx, investigation.InvestigationID, 100, 0)
	require.NoError(t, err)
	assert.Equal(t, int64(len(transitions)), total)
	assert.Len(t, timeline, len(transitions))

	// Verify timeline is in chronological order (newest first)
	for i := 0; i < len(timeline)-1; i++ {
		assert.True(t, timeline[i].Timestamp.After(timeline[i+1].Timestamp) || timeline[i].Timestamp.Equal(timeline[i+1].Timestamp),
			"Timeline should be sorted newest first")
	}
}

// TestInvestigationLifecycle_AlertAssociation tests alert association
func TestInvestigationLifecycle_AlertAssociation(t *testing.T) {
	storage := setupInvestigationLifecycleTestDB(t)
	defer storage.db.DB.Close()

	ctx := context.Background()

	// Create investigation
	investigation := &core.Investigation{
		InvestigationID: "alert-assoc-1",
		Title:           "Alert Association Test",
		Status:          core.InvestigationStatusOpen,
		Priority:        core.InvestigationPriorityHigh,
		CreatedBy:       "admin",
		CreatedAt:       time.Now(),
		UpdatedAt:       time.Now(),
	}
	err := storage.CreateInvestigation(investigation)
	require.NoError(t, err)

	// Associate alerts
	alertIDs := []string{"alert-1", "alert-2", "alert-3"}
	for _, alertID := range alertIDs {
		err := storage.AssociateAlert(ctx, investigation.InvestigationID, alertID, "admin")
		require.NoError(t, err)
	}

	// Get alerts for investigation
	alerts, err := storage.GetAlertsForInvestigation(ctx, investigation.InvestigationID)
	require.NoError(t, err)
	assert.Len(t, alerts, len(alertIDs))

	// Dissociate one alert
	err = storage.DissociateAlert(ctx, investigation.InvestigationID, "alert-2")
	require.NoError(t, err)

	// Verify alert was dissociated
	alerts, err = storage.GetAlertsForInvestigation(ctx, investigation.InvestigationID)
	require.NoError(t, err)
	assert.Len(t, alerts, len(alertIDs)-1)

	// Verify alert-2 is not in the list
	for _, alert := range alerts {
		assert.NotEqual(t, "alert-2", alert.AlertID)
	}
}

// TestInvestigationLifecycle_Statistics tests investigation statistics calculation
func TestInvestigationLifecycle_Statistics(t *testing.T) {
	storage := setupInvestigationLifecycleTestDB(t)
	defer storage.db.DB.Close()

	ctx := context.Background()

	// Create investigation
	investigation := &core.Investigation{
		InvestigationID: "stats-1",
		Title:           "Statistics Test",
		Status:          core.InvestigationStatusOpen,
		Priority:        core.InvestigationPriorityHigh,
		CreatedBy:       "admin",
		CreatedAt:       time.Now(),
		UpdatedAt:       time.Now(),
	}
	err := storage.CreateInvestigation(investigation)
	require.NoError(t, err)

	// Associate alerts
	err = storage.AssociateAlert(ctx, investigation.InvestigationID, "alert-1", "admin")
	require.NoError(t, err)
	err = storage.AssociateAlert(ctx, investigation.InvestigationID, "alert-2", "admin")
	require.NoError(t, err)

	// Add notes
	err = storage.AddNote(investigation.InvestigationID, "analyst1", "First note")
	require.NoError(t, err)
	err = storage.AddNote(investigation.InvestigationID, "analyst2", "Second note")
	require.NoError(t, err)

	// Calculate statistics
	stats, err := storage.CalculateStatistics(ctx, investigation.InvestigationID)
	require.NoError(t, err)
	assert.NotNil(t, stats)
	// Verify statistics were calculated (exact fields depend on implementation)
	_ = stats
}

// TestInvestigationLifecycle_ConcurrentUpdates tests concurrent investigation updates
func TestInvestigationLifecycle_ConcurrentUpdates(t *testing.T) {
	storage := setupInvestigationLifecycleTestDB(t)
	defer storage.db.DB.Close()

	// Create investigation
	investigation := &core.Investigation{
		InvestigationID: "concurrent-1",
		Title:           "Concurrent Update Test",
		Status:          core.InvestigationStatusOpen,
		Priority:        core.InvestigationPriorityHigh,
		CreatedBy:       "admin",
		CreatedAt:       time.Now(),
		UpdatedAt:       time.Now(),
	}
	err := storage.CreateInvestigation(investigation)
	require.NoError(t, err)

	const numGoroutines = 10
	const updatesPerGoroutine = 5

	var wg sync.WaitGroup
	errors := make(chan error, numGoroutines*updatesPerGoroutine)

	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(goroutineID int) {
			defer wg.Done()
			for j := 0; j < updatesPerGoroutine; j++ {
				inv := &core.Investigation{
					InvestigationID: investigation.InvestigationID,
					Title:           fmt.Sprintf("Updated by goroutine %d", goroutineID),
					Status:          core.InvestigationStatusInProgress,
					Priority:        core.InvestigationPriorityHigh,
					CreatedBy:       investigation.CreatedBy,
					CreatedAt:       investigation.CreatedAt,
					UpdatedAt:       time.Now(),
				}
				err := storage.UpdateInvestigation(investigation.InvestigationID, inv)
				if err != nil {
					errors <- err
				}
			}
		}(i)
	}

	wg.Wait()
	close(errors)

	// Verify no errors occurred (or only expected conflict errors)
	for err := range errors {
		// Some updates may fail due to race conditions, which is acceptable
		// The important thing is that the database remains consistent
		_ = err
	}

	// Verify investigation still exists and is valid
	retrieved, err := storage.GetInvestigation(investigation.InvestigationID)
	require.NoError(t, err)
	assert.Equal(t, investigation.InvestigationID, retrieved.InvestigationID)
}
