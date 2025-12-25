package storage

import (
	"context"
	"database/sql"
	"fmt"
	"sync"
	"testing"
	"time"

	"cerberus/soar"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap/zaptest"
	_ "modernc.org/sqlite"
)

// setupPlaybookExecutionsTestDB creates an in-memory SQLite database for playbook execution tests
func setupPlaybookExecutionsTestDB(t *testing.T) *SQLite {
	db, err := sql.Open("sqlite", ":memory:")
	require.NoError(t, err)

	_, err = db.Exec("PRAGMA foreign_keys=ON")
	require.NoError(t, err)

	// Create playbook_executions table
	schema := `
	CREATE TABLE IF NOT EXISTS playbook_executions (
		id TEXT PRIMARY KEY,
		playbook_id TEXT NOT NULL,
		alert_id TEXT NOT NULL,
		current_step_index INTEGER NOT NULL DEFAULT 0,
		status TEXT NOT NULL DEFAULT 'running',
		started_at DATETIME NOT NULL,
		completed_at DATETIME,
		error_message TEXT,
		step_results TEXT,
		metadata TEXT
	);
	CREATE INDEX IF NOT EXISTS idx_playbook_executions_playbook_id ON playbook_executions(playbook_id);
	CREATE INDEX IF NOT EXISTS idx_playbook_executions_alert_id ON playbook_executions(alert_id);
	CREATE INDEX IF NOT EXISTS idx_playbook_executions_status ON playbook_executions(status);
	CREATE INDEX IF NOT EXISTS idx_playbook_executions_started_at ON playbook_executions(started_at DESC);
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

// TestSQLitePlaybookExecutionStorage_CreatePlaybookExecution tests execution creation
func TestSQLitePlaybookExecutionStorage_CreatePlaybookExecution(t *testing.T) {
	sqlite := setupPlaybookExecutionsTestDB(t)
	defer sqlite.DB.Close()

	storage, err := NewSQLitePlaybookExecutionStorage(sqlite, sqlite.Logger)
	require.NoError(t, err)

	ctx := context.Background()

	tests := []struct {
		name        string
		executionID string
		playbookID  string
		alertID     string
		expectErr   bool
	}{
		{
			name:        "Valid execution",
			executionID: "exec-1",
			playbookID:  "playbook-1",
			alertID:     "alert-1",
			expectErr:   false,
		},
		{
			name:        "Duplicate execution ID",
			executionID: "exec-1",
			playbookID:  "playbook-2",
			alertID:     "alert-2",
			expectErr:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := storage.CreatePlaybookExecution(ctx, tt.executionID, tt.playbookID, tt.alertID)
			if tt.expectErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)

				// Verify execution was created
				execution, err := storage.GetExecution(ctx, tt.executionID)
				require.NoError(t, err)
				assert.Equal(t, tt.executionID, execution.ID)
				assert.Equal(t, tt.playbookID, execution.PlaybookID)
				assert.Equal(t, tt.alertID, execution.AlertID)
				assert.Equal(t, "running", execution.Status)
			}
		})
	}
}

// TestSQLitePlaybookExecutionStorage_UpdateExecutionStatus tests status tracking
func TestSQLitePlaybookExecutionStorage_UpdateExecutionStatus(t *testing.T) {
	sqlite := setupPlaybookExecutionsTestDB(t)
	defer sqlite.DB.Close()

	storage, err := NewSQLitePlaybookExecutionStorage(sqlite, sqlite.Logger)
	require.NoError(t, err)

	ctx := context.Background()

	executionID := "status-test-exec"
	err = storage.CreatePlaybookExecution(ctx, executionID, "playbook-1", "alert-1")
	require.NoError(t, err)

	statuses := []soar.ActionStatus{soar.ActionStatusPending, soar.ActionStatusRunning, soar.ActionStatusCompleted, soar.ActionStatusFailed}

	for _, status := range statuses {
		if status == soar.ActionStatusCompleted || status == soar.ActionStatusFailed {
			err := storage.CompleteExecution(ctx, executionID, status, "", nil)
			require.NoError(t, err)
		} else {
			err := storage.UpdateExecutionStep(ctx, executionID, 0, status)
			require.NoError(t, err)
		}

		// Verify status was updated
		execution, err := storage.GetExecution(ctx, executionID)
		require.NoError(t, err)
		assert.Equal(t, string(status), execution.Status)
	}
}

// TestSQLitePlaybookExecutionStorage_StepResults tests step results storage
func TestSQLitePlaybookExecutionStorage_StepResults(t *testing.T) {
	sqlite := setupPlaybookExecutionsTestDB(t)
	defer sqlite.DB.Close()

	storage, err := NewSQLitePlaybookExecutionStorage(sqlite, sqlite.Logger)
	require.NoError(t, err)

	ctx := context.Background()

	executionID := "step-results-exec"
	err = storage.CreatePlaybookExecution(ctx, executionID, "playbook-1", "alert-1")
	require.NoError(t, err)

	// Update execution step
	err = storage.UpdateExecutionStep(ctx, executionID, 2, soar.ActionStatusCompleted)
	require.NoError(t, err)

	// Complete execution with step results
	err = storage.CompleteExecution(ctx, executionID, soar.ActionStatusCompleted, "", nil)
	require.NoError(t, err)

	// Verify execution was completed
	execution, err := storage.GetExecution(ctx, executionID)
	require.NoError(t, err)
	assert.Equal(t, string(soar.ActionStatusCompleted), execution.Status)
}

// TestSQLitePlaybookExecutionStorage_TimelineQueries tests execution timeline queries
func TestSQLitePlaybookExecutionStorage_TimelineQueries(t *testing.T) {
	sqlite := setupPlaybookExecutionsTestDB(t)
	defer sqlite.DB.Close()

	storage, err := NewSQLitePlaybookExecutionStorage(sqlite, sqlite.Logger)
	require.NoError(t, err)

	ctx := context.Background()

	playbookID := "timeline-playbook"

	// Create executions at different times
	baseTime := time.Now().Add(-48 * time.Hour)
	for i := 0; i < 5; i++ {
		executionID := fmt.Sprintf("exec-%d", i)
		err := storage.CreatePlaybookExecution(ctx, executionID, playbookID, fmt.Sprintf("alert-%d", i))
		require.NoError(t, err)

		// Update started_at to different times
		startTime := baseTime.Add(time.Duration(i) * time.Hour)
		_, err = sqlite.DB.Exec(`UPDATE playbook_executions SET started_at = ? WHERE id = ?`,
			startTime, executionID)
		require.NoError(t, err)
	}

	// Query executions by time range
	startTime := baseTime.Add(-1 * time.Hour)
	endTime := baseTime.Add(6 * time.Hour)
	query := `SELECT COUNT(*) FROM playbook_executions 
	          WHERE playbook_id = ? AND started_at BETWEEN ? AND ?`
	var count int
	err = sqlite.DB.QueryRow(query, playbookID, startTime, endTime).Scan(&count)
	require.NoError(t, err)
	assert.Equal(t, 5, count)
}

// TestSQLitePlaybookExecutionStorage_ConcurrentExecutionLogging tests concurrent execution logging
func TestSQLitePlaybookExecutionStorage_ConcurrentExecutionLogging(t *testing.T) {
	sqlite := setupPlaybookExecutionsTestDB(t)
	defer sqlite.DB.Close()

	storage, err := NewSQLitePlaybookExecutionStorage(sqlite, sqlite.Logger)
	require.NoError(t, err)

	ctx := context.Background()

	const numGoroutines = 10
	const executionsPerGoroutine = 5

	var wg sync.WaitGroup
	errors := make(chan error, numGoroutines*executionsPerGoroutine)

	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(goroutineID int) {
			defer wg.Done()
			for j := 0; j < executionsPerGoroutine; j++ {
				executionID := fmt.Sprintf("exec-%d-%d", goroutineID, j)
				playbookID := fmt.Sprintf("playbook-%d", goroutineID)
				alertID := fmt.Sprintf("alert-%d-%d", goroutineID, j)
				err := storage.CreatePlaybookExecution(ctx, executionID, playbookID, alertID)
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

	// Verify all executions were created
	query := `SELECT COUNT(*) FROM playbook_executions`
	var count int
	err = sqlite.DB.QueryRow(query).Scan(&count)
	require.NoError(t, err)
	assert.Equal(t, numGoroutines*executionsPerGoroutine, count)
}

// =============================================================================
// Execution Statistics Tests - TASK 94
// =============================================================================

func TestSQLitePlaybookExecutionStorage_GetExecutionStats_Empty(t *testing.T) {
	sqlite := setupPlaybookExecutionsTestDB(t)
	defer sqlite.DB.Close()

	storage, err := NewSQLitePlaybookExecutionStorage(sqlite, zaptest.NewLogger(t).Sugar())
	require.NoError(t, err)

	ctx := context.Background()
	stats, err := storage.GetExecutionStats(ctx)
	require.NoError(t, err)

	// Verify zero stats for empty database
	assert.Equal(t, int64(0), stats.TotalExecutions)
	assert.Equal(t, int64(0), stats.SuccessfulCount)
	assert.Equal(t, int64(0), stats.FailedCount)
	assert.Equal(t, int64(0), stats.RunningCount)
	assert.Equal(t, float64(0), stats.AverageDurationMs)
	assert.Nil(t, stats.LastExecutionTime)
	assert.NotNil(t, stats.StatusDistribution)
	assert.NotNil(t, stats.TopPlaybooks)
	assert.Len(t, stats.TopPlaybooks, 0)
}

func TestSQLitePlaybookExecutionStorage_GetExecutionStats_WithData(t *testing.T) {
	sqlite := setupPlaybookExecutionsTestDB(t)
	defer sqlite.DB.Close()

	storage, err := NewSQLitePlaybookExecutionStorage(sqlite, zaptest.NewLogger(t).Sugar())
	require.NoError(t, err)

	ctx := context.Background()

	// Create executions with various statuses
	now := time.Now()
	completedTime := now.Add(5 * time.Second)

	// Insert test data directly for controlled testing
	_, err = sqlite.DB.Exec(`
		INSERT INTO playbook_executions (id, playbook_id, alert_id, current_step_index, status, started_at, completed_at)
		VALUES
			('exec-1', 'pb-1', 'alert-1', 3, 'completed', ?, ?),
			('exec-2', 'pb-1', 'alert-2', 2, 'completed', ?, ?),
			('exec-3', 'pb-2', 'alert-3', 1, 'failed', ?, ?),
			('exec-4', 'pb-2', 'alert-4', 0, 'running', ?, NULL),
			('exec-5', 'pb-3', 'alert-5', 3, 'completed', ?, ?)
	`, now.Format(time.RFC3339), completedTime.Format(time.RFC3339),
		now.Format(time.RFC3339), completedTime.Format(time.RFC3339),
		now.Format(time.RFC3339), completedTime.Format(time.RFC3339),
		now.Format(time.RFC3339),
		now.Format(time.RFC3339), completedTime.Format(time.RFC3339))
	require.NoError(t, err)

	stats, err := storage.GetExecutionStats(ctx)
	require.NoError(t, err)

	// Verify counts
	assert.Equal(t, int64(5), stats.TotalExecutions)
	assert.Equal(t, int64(3), stats.SuccessfulCount)
	assert.Equal(t, int64(1), stats.FailedCount)
	assert.Equal(t, int64(1), stats.RunningCount)

	// Verify average duration excludes running (NULL completed_at)
	// 4 completed executions with 5 seconds each = 5000ms average
	assert.Greater(t, stats.AverageDurationMs, float64(0))

	// Verify last execution time
	assert.NotNil(t, stats.LastExecutionTime)

	// Verify status distribution
	assert.Equal(t, int64(3), stats.StatusDistribution["completed"])
	assert.Equal(t, int64(1), stats.StatusDistribution["failed"])
	assert.Equal(t, int64(1), stats.StatusDistribution["running"])

	// Verify top playbooks
	assert.Len(t, stats.TopPlaybooks, 3)
	// pb-1 and pb-2 should have count=2, pb-3 should have count=1
}

func TestSQLitePlaybookExecutionStorage_GetExecutionStatsByPlaybook(t *testing.T) {
	sqlite := setupPlaybookExecutionsTestDB(t)
	defer sqlite.DB.Close()

	storage, err := NewSQLitePlaybookExecutionStorage(sqlite, zaptest.NewLogger(t).Sugar())
	require.NoError(t, err)

	ctx := context.Background()
	now := time.Now()
	completedTime := now.Add(5 * time.Second)

	// Insert test data
	_, err = sqlite.DB.Exec(`
		INSERT INTO playbook_executions (id, playbook_id, alert_id, current_step_index, status, started_at, completed_at)
		VALUES
			('exec-1', 'pb-target', 'alert-1', 3, 'completed', ?, ?),
			('exec-2', 'pb-target', 'alert-2', 2, 'failed', ?, ?),
			('exec-3', 'pb-other', 'alert-3', 1, 'completed', ?, ?)
	`, now.Format(time.RFC3339), completedTime.Format(time.RFC3339),
		now.Format(time.RFC3339), completedTime.Format(time.RFC3339),
		now.Format(time.RFC3339), completedTime.Format(time.RFC3339))
	require.NoError(t, err)

	// Get stats for specific playbook
	stats, err := storage.GetExecutionStatsByPlaybook(ctx, "pb-target")
	require.NoError(t, err)

	// Verify counts only include pb-target
	assert.Equal(t, int64(2), stats.TotalExecutions)
	assert.Equal(t, int64(1), stats.SuccessfulCount)
	assert.Equal(t, int64(1), stats.FailedCount)
	assert.Equal(t, int64(0), stats.RunningCount)
	assert.NotNil(t, stats.LastExecutionTime)

	// Status distribution should only have completed and failed
	assert.Equal(t, int64(1), stats.StatusDistribution["completed"])
	assert.Equal(t, int64(1), stats.StatusDistribution["failed"])
}

func TestSQLitePlaybookExecutionStorage_GetExecutionStatsByPlaybook_EmptyID(t *testing.T) {
	sqlite := setupPlaybookExecutionsTestDB(t)
	defer sqlite.DB.Close()

	storage, err := NewSQLitePlaybookExecutionStorage(sqlite, zaptest.NewLogger(t).Sugar())
	require.NoError(t, err)

	ctx := context.Background()
	_, err = storage.GetExecutionStatsByPlaybook(ctx, "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "playbook ID cannot be empty")
}

func TestSQLitePlaybookExecutionStorage_GetExecutionStats_RunningExcludedFromAverage(t *testing.T) {
	sqlite := setupPlaybookExecutionsTestDB(t)
	defer sqlite.DB.Close()

	storage, err := NewSQLitePlaybookExecutionStorage(sqlite, zaptest.NewLogger(t).Sugar())
	require.NoError(t, err)

	ctx := context.Background()
	now := time.Now()

	// Insert only running executions (no completed_at)
	_, err = sqlite.DB.Exec(`
		INSERT INTO playbook_executions (id, playbook_id, alert_id, current_step_index, status, started_at)
		VALUES ('exec-1', 'pb-1', 'alert-1', 0, 'running', ?)
	`, now.Format(time.RFC3339))
	require.NoError(t, err)

	stats, err := storage.GetExecutionStats(ctx)
	require.NoError(t, err)

	// Average should be 0 because all executions are running (no completed_at)
	assert.Equal(t, float64(0), stats.AverageDurationMs)
	assert.Equal(t, int64(1), stats.RunningCount)
}
