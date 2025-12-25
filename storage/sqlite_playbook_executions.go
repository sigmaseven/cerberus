package storage

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"cerberus/soar"

	"go.uber.org/zap"
)

// SQLitePlaybookExecutionStorage handles playbook execution state persistence
// TASK 25.4: Playbook execution state persistence and recovery
type SQLitePlaybookExecutionStorage struct {
	db     *SQLite
	logger *zap.SugaredLogger
}

// NewSQLitePlaybookExecutionStorage creates a new playbook execution storage
func NewSQLitePlaybookExecutionStorage(db *SQLite, logger *zap.SugaredLogger) (*SQLitePlaybookExecutionStorage, error) {
	storage := &SQLitePlaybookExecutionStorage{
		db:     db,
		logger: logger,
	}

	if err := storage.ensureTable(); err != nil {
		return nil, fmt.Errorf("failed to ensure playbook_executions table: %w", err)
	}

	return storage, nil
}

// ensureTable creates the playbook_executions table if it doesn't exist
// TASK 25.4: Database schema for playbook execution state tracking
func (spes *SQLitePlaybookExecutionStorage) ensureTable() error {
	query := `
	CREATE TABLE IF NOT EXISTS playbook_executions (
		id TEXT PRIMARY KEY,
		playbook_id TEXT NOT NULL,
		alert_id TEXT NOT NULL,
		current_step_index INTEGER NOT NULL DEFAULT 0,
		status TEXT NOT NULL DEFAULT 'running',
		started_at DATETIME NOT NULL,
		completed_at DATETIME,
		error_message TEXT,
		step_results TEXT,  -- JSON map of step results
		metadata TEXT       -- JSON metadata
	);

	CREATE INDEX IF NOT EXISTS idx_playbook_executions_playbook_id ON playbook_executions(playbook_id);
	CREATE INDEX IF NOT EXISTS idx_playbook_executions_alert_id ON playbook_executions(alert_id);
	CREATE INDEX IF NOT EXISTS idx_playbook_executions_status ON playbook_executions(status);
	CREATE INDEX IF NOT EXISTS idx_playbook_executions_started_at ON playbook_executions(started_at DESC);
	`

	_, err := spes.db.DB.Exec(query)
	if err != nil {
		return fmt.Errorf("failed to create playbook_executions table: %w", err)
	}

	spes.logger.Info("Playbook executions table ensured in SQLite")
	return nil
}

// CreatePlaybookExecution creates a new playbook execution record
// TASK 25.4: Store execution state at playbook start
func (spes *SQLitePlaybookExecutionStorage) CreatePlaybookExecution(ctx context.Context, executionID, playbookID, alertID string) error {
	query := `
		INSERT INTO playbook_executions (id, playbook_id, alert_id, current_step_index, status, started_at)
		VALUES (?, ?, ?, ?, ?, ?)
	`

	_, err := spes.db.DB.ExecContext(ctx, query,
		executionID,
		playbookID,
		alertID,
		0, // Start at step 0
		"running",
		time.Now().Format(time.RFC3339),
	)

	if err != nil {
		return fmt.Errorf("failed to create playbook execution: %w", err)
	}

	spes.logger.Debugf("Created playbook execution record: %s", executionID)
	return nil
}

// UpdateExecutionStep updates the current step index and status
// TASK 25.4: Update current_step_index after each step completes
func (spes *SQLitePlaybookExecutionStorage) UpdateExecutionStep(ctx context.Context, executionID string, stepIndex int, status soar.ActionStatus) error {
	query := `
		UPDATE playbook_executions
		SET current_step_index = ?, status = ?
		WHERE id = ?
	`

	result, err := spes.db.DB.ExecContext(ctx, query, stepIndex, string(status), executionID)
	if err != nil {
		return fmt.Errorf("failed to update execution step: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}
	if rowsAffected == 0 {
		return fmt.Errorf("execution %s not found", executionID)
	}

	return nil
}

// CompleteExecution marks an execution as completed or failed
// TASK 25.4: Store final status and error on completion
func (spes *SQLitePlaybookExecutionStorage) CompleteExecution(ctx context.Context, executionID string, status soar.ActionStatus, errorMsg string, stepResults map[string]*soar.ActionResult) error {
	stepResultsJSON, _ := json.Marshal(stepResults)

	query := `
		UPDATE playbook_executions
		SET status = ?, completed_at = ?, error_message = ?, step_results = ?
		WHERE id = ?
	`

	var errorMsgPtr interface{}
	if errorMsg != "" {
		errorMsgPtr = errorMsg
	}

	result, err := spes.db.DB.ExecContext(ctx, query,
		string(status),
		time.Now().Format(time.RFC3339),
		errorMsgPtr,
		string(stepResultsJSON),
		executionID,
	)

	if err != nil {
		return fmt.Errorf("failed to complete execution: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}
	if rowsAffected == 0 {
		return fmt.Errorf("execution %s not found", executionID)
	}

	return nil
}

// GetPendingExecutions retrieves all pending/running executions
// TASK 25.4: Resume playbook execution after crash/restart
func (spes *SQLitePlaybookExecutionStorage) GetPendingExecutions(ctx context.Context) ([]*PlaybookExecutionRecord, error) {
	query := `
		SELECT id, playbook_id, alert_id, current_step_index, status, started_at, completed_at, error_message, step_results, metadata
		FROM playbook_executions
		WHERE status IN ('running', 'pending')
		ORDER BY started_at ASC
	`

	rows, err := spes.db.ReadDB.QueryContext(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("failed to query pending executions: %w", err)
	}
	defer rows.Close()

	var executions []*PlaybookExecutionRecord
	for rows.Next() {
		var exec PlaybookExecutionRecord
		var completedAt sql.NullString
		var errorMsg sql.NullString
		var stepResultsJSON sql.NullString
		var metadataJSON sql.NullString
		var startedAt string

		err := rows.Scan(
			&exec.ID,
			&exec.PlaybookID,
			&exec.AlertID,
			&exec.CurrentStepIndex,
			&exec.Status,
			&startedAt,
			&completedAt,
			&errorMsg,
			&stepResultsJSON,
			&metadataJSON,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan execution: %w", err)
		}

		exec.StartedAt, _ = time.Parse(time.RFC3339, startedAt)
		if completedAt.Valid {
			exec.CompletedAt, _ = time.Parse(time.RFC3339, completedAt.String)
		}
		if errorMsg.Valid {
			exec.ErrorMessage = errorMsg.String
		}

		if stepResultsJSON.Valid && stepResultsJSON.String != "" {
			json.Unmarshal([]byte(stepResultsJSON.String), &exec.StepResults)
		}

		if metadataJSON.Valid && metadataJSON.String != "" {
			json.Unmarshal([]byte(metadataJSON.String), &exec.Metadata)
		}

		executions = append(executions, &exec)
	}

	return executions, nil
}

// GetExecution retrieves a specific execution by ID
func (spes *SQLitePlaybookExecutionStorage) GetExecution(ctx context.Context, executionID string) (*PlaybookExecutionRecord, error) {
	query := `
		SELECT id, playbook_id, alert_id, current_step_index, status, started_at, completed_at, error_message, step_results, metadata
		FROM playbook_executions
		WHERE id = ?
	`

	var exec PlaybookExecutionRecord
	var completedAt sql.NullString
	var errorMsg sql.NullString
	var stepResultsJSON sql.NullString
	var metadataJSON sql.NullString
	var startedAt string

	err := spes.db.ReadDB.QueryRowContext(ctx, query, executionID).Scan(
		&exec.ID,
		&exec.PlaybookID,
		&exec.AlertID,
		&exec.CurrentStepIndex,
		&exec.Status,
		&startedAt,
		&completedAt,
		&errorMsg,
		&stepResultsJSON,
		&metadataJSON,
	)

	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("execution %s not found", executionID)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get execution: %w", err)
	}

	exec.StartedAt, _ = time.Parse(time.RFC3339, startedAt)
	if completedAt.Valid {
		exec.CompletedAt, _ = time.Parse(time.RFC3339, completedAt.String)
	}
	if errorMsg.Valid {
		exec.ErrorMessage = errorMsg.String
	}

	if stepResultsJSON.Valid && stepResultsJSON.String != "" {
		json.Unmarshal([]byte(stepResultsJSON.String), &exec.StepResults)
	}

	if metadataJSON.Valid && metadataJSON.String != "" {
		json.Unmarshal([]byte(metadataJSON.String), &exec.Metadata)
	}

	return &exec, nil
}

// GetExecutionsByPlaybookID retrieves all executions for a specific playbook
// TASK 35.5: Support filtering by playbook_id
func (spes *SQLitePlaybookExecutionStorage) GetExecutionsByPlaybookID(ctx context.Context, playbookID string, limit, offset int) ([]*PlaybookExecutionRecord, int64, error) {
	// Count total
	countQuery := `
		SELECT COUNT(*) FROM playbook_executions
		WHERE playbook_id = ?
	`
	var totalCount int64
	err := spes.db.ReadDB.QueryRowContext(ctx, countQuery, playbookID).Scan(&totalCount)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to count executions: %w", err)
	}

	// Get executions with pagination
	query := `
		SELECT id, playbook_id, alert_id, current_step_index, status, started_at, completed_at, error_message, step_results, metadata
		FROM playbook_executions
		WHERE playbook_id = ?
		ORDER BY started_at DESC
		LIMIT ? OFFSET ?
	`

	rows, err := spes.db.ReadDB.QueryContext(ctx, query, playbookID, limit, offset)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to query executions: %w", err)
	}
	defer rows.Close()

	var executions []*PlaybookExecutionRecord
	for rows.Next() {
		var exec PlaybookExecutionRecord
		var completedAt sql.NullString
		var errorMsg sql.NullString
		var stepResultsJSON sql.NullString
		var metadataJSON sql.NullString
		var startedAt string

		err := rows.Scan(
			&exec.ID,
			&exec.PlaybookID,
			&exec.AlertID,
			&exec.CurrentStepIndex,
			&exec.Status,
			&startedAt,
			&completedAt,
			&errorMsg,
			&stepResultsJSON,
			&metadataJSON,
		)
		if err != nil {
			return nil, 0, fmt.Errorf("failed to scan execution: %w", err)
		}

		exec.StartedAt, _ = time.Parse(time.RFC3339, startedAt)
		if completedAt.Valid {
			exec.CompletedAt, _ = time.Parse(time.RFC3339, completedAt.String)
		}
		if errorMsg.Valid {
			exec.ErrorMessage = errorMsg.String
		}

		if stepResultsJSON.Valid && stepResultsJSON.String != "" {
			json.Unmarshal([]byte(stepResultsJSON.String), &exec.StepResults)
		}

		if metadataJSON.Valid && metadataJSON.String != "" {
			json.Unmarshal([]byte(metadataJSON.String), &exec.Metadata)
		}

		executions = append(executions, &exec)
	}

	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("error iterating executions: %w", err)
	}

	return executions, totalCount, nil
}

// ListExecutions retrieves executions with optional filters
// TASK 35.5: Support filtering by playbook_id, alert_id, status with pagination
func (spes *SQLitePlaybookExecutionStorage) ListExecutions(ctx context.Context, filters map[string]interface{}, limit, offset int) ([]*PlaybookExecutionRecord, int64, error) {
	whereClauses := []string{}
	params := []interface{}{}

	if playbookID, ok := filters["playbook_id"].(string); ok && playbookID != "" {
		whereClauses = append(whereClauses, "playbook_id = ?")
		params = append(params, playbookID)
	}

	if alertID, ok := filters["alert_id"].(string); ok && alertID != "" {
		whereClauses = append(whereClauses, "alert_id = ?")
		params = append(params, alertID)
	}

	if status, ok := filters["status"].(string); ok && status != "" {
		whereClauses = append(whereClauses, "status = ?")
		params = append(params, status)
	}

	whereClause := ""
	if len(whereClauses) > 0 {
		whereClause = "WHERE " + strings.Join(whereClauses, " AND ")
	}

	// Count total
	// #nosec G201 - whereClause is built from static SQL fragments; user inputs are parameterized in countParams
	countQuery := fmt.Sprintf("SELECT COUNT(*) FROM playbook_executions %s", whereClause)
	var totalCount int64
	var countParams []interface{}
	countParams = append(countParams, params...)
	err := spes.db.ReadDB.QueryRowContext(ctx, countQuery, countParams...).Scan(&totalCount)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to count executions: %w", err)
	}

	// Get executions with pagination
	// #nosec G201 - whereClause is built from static SQL fragments; user inputs are parameterized in params
	query := fmt.Sprintf(`
		SELECT id, playbook_id, alert_id, current_step_index, status, started_at, completed_at, error_message, step_results, metadata
		FROM playbook_executions
		%s
		ORDER BY started_at DESC
		LIMIT ? OFFSET ?
	`, whereClause)

	params = append(params, limit, offset)

	rows, err := spes.db.ReadDB.QueryContext(ctx, query, params...)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to query executions: %w", err)
	}
	defer rows.Close()

	var executions []*PlaybookExecutionRecord
	for rows.Next() {
		var exec PlaybookExecutionRecord
		var completedAt sql.NullString
		var errorMsg sql.NullString
		var stepResultsJSON sql.NullString
		var metadataJSON sql.NullString
		var startedAt string

		err := rows.Scan(
			&exec.ID,
			&exec.PlaybookID,
			&exec.AlertID,
			&exec.CurrentStepIndex,
			&exec.Status,
			&startedAt,
			&completedAt,
			&errorMsg,
			&stepResultsJSON,
			&metadataJSON,
		)
		if err != nil {
			return nil, 0, fmt.Errorf("failed to scan execution: %w", err)
		}

		exec.StartedAt, _ = time.Parse(time.RFC3339, startedAt)
		if completedAt.Valid {
			exec.CompletedAt, _ = time.Parse(time.RFC3339, completedAt.String)
		}
		if errorMsg.Valid {
			exec.ErrorMessage = errorMsg.String
		}

		if stepResultsJSON.Valid && stepResultsJSON.String != "" {
			json.Unmarshal([]byte(stepResultsJSON.String), &exec.StepResults)
		}

		if metadataJSON.Valid && metadataJSON.String != "" {
			json.Unmarshal([]byte(metadataJSON.String), &exec.Metadata)
		}

		executions = append(executions, &exec)
	}

	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("error iterating executions: %w", err)
	}

	return executions, totalCount, nil
}

// PlaybookExecutionRecord represents a playbook execution record in the database
type PlaybookExecutionRecord struct {
	ID               string
	PlaybookID       string
	AlertID          string
	CurrentStepIndex int
	Status           string
	StartedAt        time.Time
	CompletedAt      time.Time
	ErrorMessage     string
	StepResults      map[string]*soar.ActionResult
	Metadata         map[string]interface{}
}

// PlaybookExecutionStats represents aggregated execution statistics.
// AverageDurationMs is in milliseconds and excludes currently running executions
// (only completed executions with non-NULL completed_at are included in the average).
// StatusDistribution maps execution status names to their occurrence counts.
// TopPlaybooks contains the top 10 most-executed playbooks ordered by count descending.
// Statistics represent a snapshot and may be briefly inconsistent during concurrent updates.
// TASK 94: Execution statistics for the stats endpoint
type PlaybookExecutionStats struct {
	TotalExecutions    int64                      `json:"total_executions"`
	SuccessfulCount    int64                      `json:"successful_count"`
	FailedCount        int64                      `json:"failed_count"`
	RunningCount       int64                      `json:"running_count"`
	AverageDurationMs  float64                    `json:"average_duration_ms"`
	LastExecutionTime  *time.Time                 `json:"last_execution_time,omitempty"`
	StatusDistribution map[string]int64           `json:"status_distribution"`
	TopPlaybooks       []PlaybookExecutionSummary `json:"top_playbooks"`
}

// GetExecutionStats retrieves aggregated execution statistics
// TASK 94.2: Complex execution statistics with duration calculations and NULL handling
func (spes *SQLitePlaybookExecutionStorage) GetExecutionStats(ctx context.Context) (*PlaybookExecutionStats, error) {
	stats := &PlaybookExecutionStats{
		StatusDistribution: make(map[string]int64),
		TopPlaybooks:       make([]PlaybookExecutionSummary, 0),
	}

	// Query 2: Execution statistics with status counts and average duration
	// CRITICAL: Exclude running executions from average (only use completed_at IS NOT NULL)
	// Use COALESCE to handle empty tables (SUM returns NULL when no rows)
	err := spes.db.ReadDB.QueryRowContext(ctx, `
		SELECT
			COUNT(*) as total,
			COALESCE(SUM(CASE WHEN status = 'completed' THEN 1 ELSE 0 END), 0) as successful,
			COALESCE(SUM(CASE WHEN status = 'failed' THEN 1 ELSE 0 END), 0) as failed,
			COALESCE(SUM(CASE WHEN status = 'running' THEN 1 ELSE 0 END), 0) as running,
			COALESCE(AVG(CASE
				WHEN completed_at IS NOT NULL
				THEN (JULIANDAY(completed_at) - JULIANDAY(started_at)) * 86400000
				ELSE NULL
			END), 0) as avg_duration_ms,
			MAX(started_at) as last_execution
		FROM playbook_executions
	`).Scan(
		&stats.TotalExecutions,
		&stats.SuccessfulCount,
		&stats.FailedCount,
		&stats.RunningCount,
		&stats.AverageDurationMs,
		&sql.NullString{}, // We'll handle last_execution separately
	)
	if err != nil {
		return nil, fmt.Errorf("failed to query execution stats: %w", err)
	}

	// Query last execution time separately to handle NULL properly
	var lastExecStr sql.NullString
	err = spes.db.ReadDB.QueryRowContext(ctx, `
		SELECT MAX(started_at) FROM playbook_executions
	`).Scan(&lastExecStr)
	if err != nil && err != sql.ErrNoRows {
		return nil, fmt.Errorf("failed to query last execution time: %w", err)
	}
	if lastExecStr.Valid && lastExecStr.String != "" {
		parsedTime, parseErr := time.Parse(time.RFC3339, lastExecStr.String)
		if parseErr == nil {
			stats.LastExecutionTime = &parsedTime
		}
	}

	// Query 4: Status distribution
	rows, err := spes.db.ReadDB.QueryContext(ctx, `
		SELECT status, COUNT(*) as count
		FROM playbook_executions
		GROUP BY status
	`)
	if err != nil {
		return nil, fmt.Errorf("failed to query status distribution: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var status string
		var count int64
		if err := rows.Scan(&status, &count); err != nil {
			return nil, fmt.Errorf("failed to scan status distribution: %w", err)
		}
		stats.StatusDistribution[status] = count
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating status distribution: %w", err)
	}

	// Query 5: Top triggered playbooks (limit 10)
	// Use secondary sort by playbook_id for deterministic ordering when counts tie
	topRows, err := spes.db.ReadDB.QueryContext(ctx, `
		SELECT playbook_id, COUNT(*) as count
		FROM playbook_executions
		GROUP BY playbook_id
		ORDER BY count DESC, playbook_id ASC
		LIMIT 10
	`)
	if err != nil {
		return nil, fmt.Errorf("failed to query top playbooks: %w", err)
	}
	defer topRows.Close()

	for topRows.Next() {
		var summary PlaybookExecutionSummary
		if err := topRows.Scan(&summary.ID, &summary.ExecutionCount); err != nil {
			return nil, fmt.Errorf("failed to scan top playbook: %w", err)
		}
		// Note: Name would need to be joined from playbooks table if needed
		stats.TopPlaybooks = append(stats.TopPlaybooks, summary)
	}
	if err := topRows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating top playbooks: %w", err)
	}

	return stats, nil
}

// GetExecutionStatsByPlaybook retrieves execution statistics for a specific playbook
// TASK 94.3: Per-playbook execution statistics
func (spes *SQLitePlaybookExecutionStorage) GetExecutionStatsByPlaybook(ctx context.Context, playbookID string) (*PlaybookExecutionStats, error) {
	if playbookID == "" {
		return nil, fmt.Errorf("playbook ID cannot be empty")
	}

	stats := &PlaybookExecutionStats{
		StatusDistribution: make(map[string]int64),
		TopPlaybooks:       make([]PlaybookExecutionSummary, 0),
	}

	// Execution statistics for specific playbook
	// Use COALESCE to handle empty results (SUM returns NULL when no rows match)
	err := spes.db.ReadDB.QueryRowContext(ctx, `
		SELECT
			COUNT(*) as total,
			COALESCE(SUM(CASE WHEN status = 'completed' THEN 1 ELSE 0 END), 0) as successful,
			COALESCE(SUM(CASE WHEN status = 'failed' THEN 1 ELSE 0 END), 0) as failed,
			COALESCE(SUM(CASE WHEN status = 'running' THEN 1 ELSE 0 END), 0) as running,
			COALESCE(AVG(CASE
				WHEN completed_at IS NOT NULL
				THEN (JULIANDAY(completed_at) - JULIANDAY(started_at)) * 86400000
				ELSE NULL
			END), 0) as avg_duration_ms
		FROM playbook_executions
		WHERE playbook_id = ?
	`, playbookID).Scan(
		&stats.TotalExecutions,
		&stats.SuccessfulCount,
		&stats.FailedCount,
		&stats.RunningCount,
		&stats.AverageDurationMs,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to query playbook execution stats: %w", err)
	}

	// Last execution time for this playbook
	var lastExecStr sql.NullString
	err = spes.db.ReadDB.QueryRowContext(ctx, `
		SELECT MAX(started_at) FROM playbook_executions WHERE playbook_id = ?
	`, playbookID).Scan(&lastExecStr)
	if err != nil && err != sql.ErrNoRows {
		return nil, fmt.Errorf("failed to query last execution time: %w", err)
	}
	if lastExecStr.Valid && lastExecStr.String != "" {
		parsedTime, parseErr := time.Parse(time.RFC3339, lastExecStr.String)
		if parseErr == nil {
			stats.LastExecutionTime = &parsedTime
		}
	}

	// Status distribution for this playbook
	rows, err := spes.db.ReadDB.QueryContext(ctx, `
		SELECT status, COUNT(*) as count
		FROM playbook_executions
		WHERE playbook_id = ?
		GROUP BY status
	`, playbookID)
	if err != nil {
		return nil, fmt.Errorf("failed to query status distribution: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var status string
		var count int64
		if err := rows.Scan(&status, &count); err != nil {
			return nil, fmt.Errorf("failed to scan status distribution: %w", err)
		}
		stats.StatusDistribution[status] = count
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating status distribution: %w", err)
	}

	return stats, nil
}
