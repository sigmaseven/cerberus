package storage

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"cerberus/soar"

	"github.com/google/uuid"
	"go.uber.org/zap"
)

// generateUUID generates a new UUID string
func generateUUID() string {
	return uuid.New().String()
}

// Sentinel errors for approval storage
var (
	ErrApprovalNotFound      = errors.New("approval request not found")
	ErrApprovalAlreadyExists = errors.New("approval request already exists")
	ErrApprovalExpired       = errors.New("approval request has expired")
	ErrApprovalResolved      = errors.New("approval request already resolved")
	ErrSelfApprovalDenied    = errors.New("self-approval is not allowed")
	ErrOptimisticLockFailed  = errors.New("approval was modified by another user")
	ErrNotAuthorizedApprover = errors.New("user is not an authorized approver")
)

// SQLiteApprovalStorage handles approval persistence in SQLite
type SQLiteApprovalStorage struct {
	db     *SQLite
	logger *zap.SugaredLogger
}

// NewSQLiteApprovalStorage creates a new SQLite approval storage handler
func NewSQLiteApprovalStorage(db *SQLite, logger *zap.SugaredLogger) (*SQLiteApprovalStorage, error) {
	storage := &SQLiteApprovalStorage{
		db:     db,
		logger: logger,
	}

	if err := storage.ensureTables(); err != nil {
		return nil, fmt.Errorf("failed to ensure approval tables: %w", err)
	}

	return storage, nil
}

// ensureTables creates the approval tables if they don't exist
func (sas *SQLiteApprovalStorage) ensureTables() error {
	query := `
	-- Approval requests table
	CREATE TABLE IF NOT EXISTS approval_requests (
		id TEXT PRIMARY KEY,
		execution_id TEXT NOT NULL,
		playbook_id TEXT NOT NULL,
		playbook_name TEXT NOT NULL,
		step_id TEXT NOT NULL,
		step_name TEXT NOT NULL,
		alert_id TEXT,
		requested_by TEXT NOT NULL,
		status TEXT NOT NULL DEFAULT 'pending',
		mode TEXT NOT NULL DEFAULT 'any',
		required_approvers TEXT,   -- JSON array of user IDs
		min_approvers INTEGER DEFAULT 1,
		approval_count INTEGER DEFAULT 0,
		rejection_count INTEGER DEFAULT 0,
		escalation_level INTEGER DEFAULT 0,
		context TEXT,              -- JSON object with alert/step details
		created_at DATETIME NOT NULL,
		updated_at DATETIME NOT NULL,
		expires_at DATETIME NOT NULL,
		resolved_at DATETIME,
		version INTEGER DEFAULT 1,
		FOREIGN KEY (playbook_id) REFERENCES playbooks(id) ON DELETE CASCADE
	);

	-- Approval actions table (log of all approval/rejection actions)
	CREATE TABLE IF NOT EXISTS approval_actions (
		id TEXT PRIMARY KEY,
		approval_id TEXT NOT NULL,
		user_id TEXT NOT NULL,
		username TEXT NOT NULL,
		action TEXT NOT NULL,      -- approve, reject, escalate, comment
		comment TEXT,
		created_at DATETIME NOT NULL,
		FOREIGN KEY (approval_id) REFERENCES approval_requests(id) ON DELETE CASCADE
	);

	-- Indexes for approval_requests
	CREATE INDEX IF NOT EXISTS idx_approval_requests_status ON approval_requests(status);
	CREATE INDEX IF NOT EXISTS idx_approval_requests_execution_id ON approval_requests(execution_id);
	CREATE INDEX IF NOT EXISTS idx_approval_requests_playbook_id ON approval_requests(playbook_id);
	CREATE INDEX IF NOT EXISTS idx_approval_requests_alert_id ON approval_requests(alert_id);
	CREATE INDEX IF NOT EXISTS idx_approval_requests_expires_at ON approval_requests(expires_at);
	CREATE INDEX IF NOT EXISTS idx_approval_requests_created_at ON approval_requests(created_at DESC);
	CREATE INDEX IF NOT EXISTS idx_approval_requests_requested_by ON approval_requests(requested_by);
	-- Compound index for expiration queries (status + expires_at for efficient pending approval lookup)
	-- Drop and recreate to ensure correct column order (status first for WHERE, then expires_at for range)
	DROP INDEX IF EXISTS idx_approval_requests_status_expires;
	CREATE INDEX idx_approval_requests_status_expires ON approval_requests(status, expires_at);

	-- Indexes for approval_actions
	CREATE INDEX IF NOT EXISTS idx_approval_actions_approval_id ON approval_actions(approval_id);
	CREATE INDEX IF NOT EXISTS idx_approval_actions_user_id ON approval_actions(user_id);
	CREATE INDEX IF NOT EXISTS idx_approval_actions_created_at ON approval_actions(created_at DESC);
	`

	_, err := sas.db.DB.Exec(query)
	if err != nil {
		return fmt.Errorf("failed to create approval tables: %w", err)
	}

	sas.logger.Info("Approval tables ensured in SQLite")
	return nil
}

// CreateApprovalRequest creates a new approval request
func (sas *SQLiteApprovalStorage) CreateApprovalRequest(request *soar.ApprovalRequest) error {
	if request.ID == "" {
		return errors.New("approval request ID cannot be empty")
	}

	return sas.db.WithTransaction(func(tx *sql.Tx) error {
		// Set timestamps
		now := time.Now()
		request.CreatedAt = now
		request.UpdatedAt = now
		request.Version = 1

		// Serialize JSON fields
		requiredApproversJSON, err := json.Marshal(request.RequiredApprovers)
		if err != nil {
			return fmt.Errorf("failed to marshal required_approvers: %w", err)
		}
		contextJSON, err := json.Marshal(request.Context)
		if err != nil {
			return fmt.Errorf("failed to marshal context: %w", err)
		}

		query := `
			INSERT INTO approval_requests (
				id, execution_id, playbook_id, playbook_name, step_id, step_name,
				alert_id, requested_by, status, mode, required_approvers, min_approvers,
				approval_count, rejection_count, escalation_level, context,
				created_at, updated_at, expires_at, version
			) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		`

		_, err = tx.Exec(query,
			request.ID,
			request.ExecutionID,
			request.PlaybookID,
			request.PlaybookName,
			request.StepID,
			request.StepName,
			nullIfEmpty(request.AlertID),
			request.RequestedBy,
			string(request.Status),
			string(request.Mode),
			string(requiredApproversJSON),
			request.MinApprovers,
			request.ApprovalCount,
			request.RejectionCount,
			request.EscalationLevel,
			nullIfEmpty(string(contextJSON)),
			request.CreatedAt.Format(time.RFC3339),
			request.UpdatedAt.Format(time.RFC3339),
			request.ExpiresAt.Format(time.RFC3339),
			request.Version,
		)

		if err != nil {
			if strings.Contains(err.Error(), "UNIQUE constraint failed") {
				return ErrApprovalAlreadyExists
			}
			return fmt.Errorf("failed to insert approval request: %w", err)
		}

		sas.logger.Infof("Created approval request %s for playbook %s step %s",
			request.ID, request.PlaybookName, request.StepName)
		return nil
	})
}

// GetApprovalRequest retrieves an approval request by ID
func (sas *SQLiteApprovalStorage) GetApprovalRequest(id string) (*soar.ApprovalRequest, error) {
	if id == "" {
		return nil, errors.New("approval request ID cannot be empty")
	}

	query := `
		SELECT id, execution_id, playbook_id, playbook_name, step_id, step_name,
			   alert_id, requested_by, status, mode, required_approvers, min_approvers,
			   approval_count, rejection_count, escalation_level, context,
			   created_at, updated_at, expires_at, resolved_at, version
		FROM approval_requests
		WHERE id = ?
	`

	return sas.scanApprovalRequest(sas.db.ReadDB.QueryRow(query, id))
}

// GetApprovalRequestByExecution retrieves approval request for a specific execution and step
func (sas *SQLiteApprovalStorage) GetApprovalRequestByExecution(executionID, stepID string) (*soar.ApprovalRequest, error) {
	query := `
		SELECT id, execution_id, playbook_id, playbook_name, step_id, step_name,
			   alert_id, requested_by, status, mode, required_approvers, min_approvers,
			   approval_count, rejection_count, escalation_level, context,
			   created_at, updated_at, expires_at, resolved_at, version
		FROM approval_requests
		WHERE execution_id = ? AND step_id = ?
	`

	return sas.scanApprovalRequest(sas.db.ReadDB.QueryRow(query, executionID, stepID))
}

// GetApprovalRequests retrieves approval requests with filters
func (sas *SQLiteApprovalStorage) GetApprovalRequests(filter *soar.ApprovalFilter) ([]soar.ApprovalRequest, int64, error) {
	var conditions []string
	var args []interface{}

	// Build WHERE conditions
	if len(filter.Status) > 0 {
		placeholders := make([]string, len(filter.Status))
		for i, s := range filter.Status {
			placeholders[i] = "?"
			args = append(args, string(s))
		}
		conditions = append(conditions, fmt.Sprintf("status IN (%s)", strings.Join(placeholders, ",")))
	}

	if filter.PlaybookID != "" {
		conditions = append(conditions, "playbook_id = ?")
		args = append(args, filter.PlaybookID)
	}

	if filter.AlertID != "" {
		conditions = append(conditions, "alert_id = ?")
		args = append(args, filter.AlertID)
	}

	if filter.RequestedBy != "" {
		conditions = append(conditions, "requested_by = ?")
		args = append(args, filter.RequestedBy)
	}

	// Filter by approver - check if user is in required_approvers JSON array
	// Use JSON extraction to prevent SQL injection (SQLite JSON1 extension)
	if filter.ApproverID != "" {
		conditions = append(conditions, "EXISTS (SELECT 1 FROM json_each(required_approvers) WHERE value = ?)")
		args = append(args, filter.ApproverID)
	}

	whereClause := ""
	if len(conditions) > 0 {
		whereClause = "WHERE " + strings.Join(conditions, " AND ")
	}

	// Get total count
	countQuery := "SELECT COUNT(*) FROM approval_requests " + whereClause
	var total int64
	err := sas.db.ReadDB.QueryRow(countQuery, args...).Scan(&total)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to count approval requests: %w", err)
	}

	// Get paginated results
	query := fmt.Sprintf(`
		SELECT id, execution_id, playbook_id, playbook_name, step_id, step_name,
			   alert_id, requested_by, status, mode, required_approvers, min_approvers,
			   approval_count, rejection_count, escalation_level, context,
			   created_at, updated_at, expires_at, resolved_at, version
		FROM approval_requests
		%s
		ORDER BY created_at DESC
		LIMIT ? OFFSET ?
	`, whereClause)

	limit := filter.Limit
	if limit <= 0 {
		limit = 50
	}
	offset := filter.Offset
	if offset < 0 {
		offset = 0
	}
	args = append(args, limit, offset)

	rows, err := sas.db.ReadDB.Query(query, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to query approval requests: %w", err)
	}
	defer rows.Close()

	requests := make([]soar.ApprovalRequest, 0)
	for rows.Next() {
		request, err := sas.scanApprovalRequestFromRows(rows)
		if err != nil {
			return nil, 0, err
		}
		requests = append(requests, *request)
	}

	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("error iterating approval requests: %w", err)
	}

	return requests, total, nil
}

// GetPendingApprovals retrieves pending approval requests for a specific approver
func (sas *SQLiteApprovalStorage) GetPendingApprovals(approverID string, limit, offset int) ([]soar.ApprovalRequest, error) {
	// Use JSON extraction to prevent SQL injection (SQLite JSON1 extension)
	query := `
		SELECT id, execution_id, playbook_id, playbook_name, step_id, step_name,
			   alert_id, requested_by, status, mode, required_approvers, min_approvers,
			   approval_count, rejection_count, escalation_level, context,
			   created_at, updated_at, expires_at, resolved_at, version
		FROM approval_requests
		WHERE status = 'pending'
		  AND expires_at > datetime('now')
		  AND EXISTS (SELECT 1 FROM json_each(required_approvers) WHERE value = ?)
		ORDER BY created_at DESC
		LIMIT ? OFFSET ?
	`

	rows, err := sas.db.ReadDB.Query(query, approverID, limit, offset)
	if err != nil {
		return nil, fmt.Errorf("failed to query pending approvals: %w", err)
	}
	defer rows.Close()

	requests := make([]soar.ApprovalRequest, 0)
	for rows.Next() {
		request, err := sas.scanApprovalRequestFromRows(rows)
		if err != nil {
			return nil, err
		}
		requests = append(requests, *request)
	}

	return requests, nil
}

// ProcessApprovalAction processes an approval or rejection action with optimistic locking
func (sas *SQLiteApprovalStorage) ProcessApprovalAction(
	approvalID string,
	userID string,
	username string,
	action soar.ApprovalActionType,
	comment string,
	expectedVersion int,
) (*soar.ApprovalRequest, error) {
	var updatedRequest *soar.ApprovalRequest

	err := sas.db.WithTransaction(func(tx *sql.Tx) error {
		// Get current approval request with lock
		var request soar.ApprovalRequest
		var requiredApproversJSON, contextJSON, alertID, resolvedAt sql.NullString
		var createdAt, updatedAt, expiresAt string

		err := tx.QueryRow(`
			SELECT id, execution_id, playbook_id, playbook_name, step_id, step_name,
				   alert_id, requested_by, status, mode, required_approvers, min_approvers,
				   approval_count, rejection_count, escalation_level, context,
				   created_at, updated_at, expires_at, resolved_at, version
			FROM approval_requests
			WHERE id = ?
		`, approvalID).Scan(
			&request.ID, &request.ExecutionID, &request.PlaybookID, &request.PlaybookName,
			&request.StepID, &request.StepName, &alertID, &request.RequestedBy,
			&request.Status, &request.Mode, &requiredApproversJSON, &request.MinApprovers,
			&request.ApprovalCount, &request.RejectionCount, &request.EscalationLevel,
			&contextJSON, &createdAt, &updatedAt, &expiresAt, &resolvedAt, &request.Version,
		)

		if err == sql.ErrNoRows {
			return ErrApprovalNotFound
		}
		if err != nil {
			return fmt.Errorf("failed to get approval request: %w", err)
		}

		// Parse JSON and timestamps
		if alertID.Valid {
			request.AlertID = alertID.String
		}
		if requiredApproversJSON.Valid {
			if err := json.Unmarshal([]byte(requiredApproversJSON.String), &request.RequiredApprovers); err != nil {
				return fmt.Errorf("failed to parse required_approvers: %w", err)
			}
		}
		if contextJSON.Valid {
			if err := json.Unmarshal([]byte(contextJSON.String), &request.Context); err != nil {
				return fmt.Errorf("failed to parse context: %w", err)
			}
		}

		request.CreatedAt, _ = time.Parse(time.RFC3339, createdAt)
		request.UpdatedAt, _ = time.Parse(time.RFC3339, updatedAt)
		request.ExpiresAt, _ = time.Parse(time.RFC3339, expiresAt)
		if resolvedAt.Valid {
			t, _ := time.Parse(time.RFC3339, resolvedAt.String)
			request.ResolvedAt = &t
		}

		// Optimistic locking check
		if request.Version != expectedVersion {
			return ErrOptimisticLockFailed
		}

		// Check if already resolved
		if request.Status != soar.ApprovalStatusPending && request.Status != soar.ApprovalStatusEscalated {
			return ErrApprovalResolved
		}

		// Check if expired
		if time.Now().After(request.ExpiresAt) {
			return ErrApprovalExpired
		}

		// Check if user is authorized approver
		isAuthorized := false
		for _, approver := range request.RequiredApprovers {
			if approver == userID {
				isAuthorized = true
				break
			}
		}
		if !isAuthorized && len(request.RequiredApprovers) > 0 {
			return ErrNotAuthorizedApprover
		}

		// Check for self-action (requester cannot approve, reject, or escalate their own request)
		// This enforces separation of duties - only commenting is allowed on own requests
		if userID == request.RequestedBy && action != soar.ApprovalActionComment {
			return ErrSelfApprovalDenied
		}

		// Check if user has already taken a decisive action on this approval
		// Users can only approve, reject, or escalate once per approval
		var existingActionCount int
		err = tx.QueryRow(`
			SELECT COUNT(*) FROM approval_actions
			WHERE approval_id = ? AND user_id = ? AND action IN ('approve', 'reject', 'escalate')
		`, approvalID, userID).Scan(&existingActionCount)
		if err != nil {
			return fmt.Errorf("failed to check existing actions: %w", err)
		}
		if existingActionCount > 0 && action != soar.ApprovalActionComment {
			return errors.New("user has already taken action on this approval")
		}

		// Record the action
		actionID := generateUUID()
		_, err = tx.Exec(`
			INSERT INTO approval_actions (id, approval_id, user_id, username, action, comment, created_at)
			VALUES (?, ?, ?, ?, ?, ?, ?)
		`, actionID, approvalID, userID, username, string(action), nullIfEmpty(comment), time.Now().Format(time.RFC3339))
		if err != nil {
			return fmt.Errorf("failed to insert approval action: %w", err)
		}

		// Update counts and determine new status
		newStatus := request.Status
		now := time.Now()

		switch action {
		case soar.ApprovalActionApprove:
			request.ApprovalCount++
			// Check if approval threshold is met
			if sas.isApprovalMet(&request) {
				newStatus = soar.ApprovalStatusApproved
				request.ResolvedAt = &now
			}

		case soar.ApprovalActionReject:
			request.RejectionCount++
			// Rejection logic by mode:
			// - "any" mode: Single rejection = instant reject (fast fail for speed)
			// - "majority" mode: Majority rejections needed = reject
			// - "all" mode: Single rejection = instant reject (security-first, one veto blocks)
			// DESIGN NOTE: In "all" mode, a single rejection is intentionally treated as a veto.
			// This is appropriate for SOAR workflows where unanimous consent is required for
			// security-sensitive actions (e.g., blocking IPs, isolating hosts). A single "no"
			// should halt the action, following the principle of "when in doubt, don't".
			if request.Mode == soar.ApprovalModeAny ||
				(request.Mode == soar.ApprovalModeMajority && request.RejectionCount > len(request.RequiredApprovers)/2) ||
				(request.Mode == soar.ApprovalModeAll) {
				newStatus = soar.ApprovalStatusRejected
				request.ResolvedAt = &now
			}

		case soar.ApprovalActionEscalate:
			request.EscalationLevel++
			newStatus = soar.ApprovalStatusEscalated

		case soar.ApprovalActionComment:
			// Comments don't change status or counts
		}

		request.Status = newStatus
		request.UpdatedAt = now
		request.Version++

		// Update the approval request with optimistic locking
		resolvedAtStr := sql.NullString{}
		if request.ResolvedAt != nil {
			resolvedAtStr.Valid = true
			resolvedAtStr.String = request.ResolvedAt.Format(time.RFC3339)
		}

		result, err := tx.Exec(`
			UPDATE approval_requests
			SET status = ?, approval_count = ?, rejection_count = ?, escalation_level = ?,
			    updated_at = ?, resolved_at = ?, version = ?
			WHERE id = ? AND version = ?
		`,
			string(request.Status),
			request.ApprovalCount,
			request.RejectionCount,
			request.EscalationLevel,
			request.UpdatedAt.Format(time.RFC3339),
			resolvedAtStr,
			request.Version,
			approvalID,
			expectedVersion,
		)
		if err != nil {
			return fmt.Errorf("failed to update approval request: %w", err)
		}

		// Check if update succeeded (optimistic locking)
		rowsAffected, _ := result.RowsAffected()
		if rowsAffected == 0 {
			return ErrOptimisticLockFailed
		}

		updatedRequest = &request
		return nil
	})

	if err != nil {
		return nil, err
	}

	sas.logger.Infof("Processed %s action on approval %s by user %s, new status: %s",
		action, approvalID, username, updatedRequest.Status)

	return updatedRequest, nil
}

// isApprovalMet checks if the approval threshold has been met based on mode
func (sas *SQLiteApprovalStorage) isApprovalMet(request *soar.ApprovalRequest) bool {
	switch request.Mode {
	case soar.ApprovalModeAny:
		return request.ApprovalCount >= 1

	case soar.ApprovalModeAll:
		return request.ApprovalCount >= len(request.RequiredApprovers)

	case soar.ApprovalModeMajority:
		// Use ceiling division to calculate majority: (n + 1) / 2
		// For 2 approvers: (2+1)/2 = 1 (either one is majority)
		// For 3 approvers: (3+1)/2 = 2 (need 2 of 3)
		// For 4 approvers: (4+1)/2 = 2 (need 2 of 4)
		needed := (len(request.RequiredApprovers) + 1) / 2
		if request.MinApprovers > 0 && request.MinApprovers > needed {
			needed = request.MinApprovers
		}
		return request.ApprovalCount >= needed

	default:
		return request.ApprovalCount >= request.MinApprovers
	}
}

// GetApprovalActions retrieves all actions for an approval request
func (sas *SQLiteApprovalStorage) GetApprovalActions(approvalID string) ([]soar.ApprovalAction, error) {
	query := `
		SELECT id, approval_id, user_id, username, action, comment, created_at
		FROM approval_actions
		WHERE approval_id = ?
		ORDER BY created_at ASC
	`

	rows, err := sas.db.ReadDB.Query(query, approvalID)
	if err != nil {
		return nil, fmt.Errorf("failed to query approval actions: %w", err)
	}
	defer rows.Close()

	actions := make([]soar.ApprovalAction, 0)
	for rows.Next() {
		var action soar.ApprovalAction
		var comment sql.NullString
		var createdAt string

		err := rows.Scan(
			&action.ID, &action.ApprovalID, &action.UserID, &action.Username,
			&action.Action, &comment, &createdAt,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan approval action: %w", err)
		}

		if comment.Valid {
			action.Comment = comment.String
		}
		action.CreatedAt, _ = time.Parse(time.RFC3339, createdAt)

		actions = append(actions, action)
	}

	return actions, nil
}

// ExpireApprovals marks expired pending approvals as expired
func (sas *SQLiteApprovalStorage) ExpireApprovals() (int64, error) {
	result, err := sas.db.DB.Exec(`
		UPDATE approval_requests
		SET status = 'expired', updated_at = ?, resolved_at = ?
		WHERE status = 'pending' AND expires_at < datetime('now')
	`, time.Now().Format(time.RFC3339), time.Now().Format(time.RFC3339))

	if err != nil {
		return 0, fmt.Errorf("failed to expire approvals: %w", err)
	}

	count, _ := result.RowsAffected()
	if count > 0 {
		sas.logger.Infof("Expired %d approval requests", count)
	}
	return count, nil
}

// CancelApprovalRequest cancels a pending approval request
func (sas *SQLiteApprovalStorage) CancelApprovalRequest(id string, userID string) error {
	return sas.db.WithTransaction(func(tx *sql.Tx) error {
		result, err := tx.Exec(`
			UPDATE approval_requests
			SET status = 'cancelled', updated_at = ?, resolved_at = ?
			WHERE id = ? AND status = 'pending'
		`, time.Now().Format(time.RFC3339), time.Now().Format(time.RFC3339), id)

		if err != nil {
			return fmt.Errorf("failed to cancel approval: %w", err)
		}

		rowsAffected, _ := result.RowsAffected()
		if rowsAffected == 0 {
			return ErrApprovalNotFound
		}

		// Record cancellation action
		actionID := generateUUID()
		_, err = tx.Exec(`
			INSERT INTO approval_actions (id, approval_id, user_id, username, action, comment, created_at)
			VALUES (?, ?, ?, ?, 'cancel', 'Approval cancelled', ?)
		`, actionID, id, userID, userID, time.Now().Format(time.RFC3339))

		if err != nil {
			return fmt.Errorf("failed to record cancel action: %w", err)
		}

		sas.logger.Infof("Cancelled approval request %s by user %s", id, userID)
		return nil
	})
}

// GetApprovalStats returns approval statistics
func (sas *SQLiteApprovalStorage) GetApprovalStats() (*soar.ApprovalStats, error) {
	stats := &soar.ApprovalStats{}

	// Get counts by status
	rows, err := sas.db.ReadDB.Query(`
		SELECT status, COUNT(*)
		FROM approval_requests
		GROUP BY status
	`)
	if err != nil {
		return nil, fmt.Errorf("failed to get approval stats: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var status string
		var count int
		if err := rows.Scan(&status, &count); err != nil {
			return nil, fmt.Errorf("failed to scan status count: %w", err)
		}
		switch soar.ApprovalStatus(status) {
		case soar.ApprovalStatusPending:
			stats.TotalPending = count
		case soar.ApprovalStatusApproved:
			stats.TotalApproved = count
		case soar.ApprovalStatusRejected:
			stats.TotalRejected = count
		case soar.ApprovalStatusExpired:
			stats.TotalExpired = count
		case soar.ApprovalStatusEscalated:
			stats.TotalEscalated = count
		}
	}

	// Calculate average response time for resolved approvals
	err = sas.db.ReadDB.QueryRow(`
		SELECT COALESCE(
			AVG((julianday(resolved_at) - julianday(created_at)) * 24 * 60),
			0
		)
		FROM approval_requests
		WHERE resolved_at IS NOT NULL AND status IN ('approved', 'rejected')
	`).Scan(&stats.AvgResponseTimeMinutes)
	if err != nil {
		sas.logger.Warnf("Failed to calculate avg response time: %v", err)
	}

	return stats, nil
}

// scanApprovalRequest scans a single approval request from a row
func (sas *SQLiteApprovalStorage) scanApprovalRequest(row *sql.Row) (*soar.ApprovalRequest, error) {
	var request soar.ApprovalRequest
	var requiredApproversJSON, contextJSON, alertID, resolvedAt sql.NullString
	var createdAt, updatedAt, expiresAt string

	err := row.Scan(
		&request.ID, &request.ExecutionID, &request.PlaybookID, &request.PlaybookName,
		&request.StepID, &request.StepName, &alertID, &request.RequestedBy,
		&request.Status, &request.Mode, &requiredApproversJSON, &request.MinApprovers,
		&request.ApprovalCount, &request.RejectionCount, &request.EscalationLevel,
		&contextJSON, &createdAt, &updatedAt, &expiresAt, &resolvedAt, &request.Version,
	)

	if err == sql.ErrNoRows {
		return nil, ErrApprovalNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("failed to scan approval request: %w", err)
	}

	// Parse nullable fields
	if alertID.Valid {
		request.AlertID = alertID.String
	}
	if requiredApproversJSON.Valid {
		if err := json.Unmarshal([]byte(requiredApproversJSON.String), &request.RequiredApprovers); err != nil {
			return nil, fmt.Errorf("failed to parse required_approvers: %w", err)
		}
	}
	if contextJSON.Valid {
		if err := json.Unmarshal([]byte(contextJSON.String), &request.Context); err != nil {
			return nil, fmt.Errorf("failed to parse context: %w", err)
		}
	}

	// Parse timestamps
	request.CreatedAt, _ = time.Parse(time.RFC3339, createdAt)
	request.UpdatedAt, _ = time.Parse(time.RFC3339, updatedAt)
	request.ExpiresAt, _ = time.Parse(time.RFC3339, expiresAt)
	if resolvedAt.Valid {
		t, _ := time.Parse(time.RFC3339, resolvedAt.String)
		request.ResolvedAt = &t
	}

	return &request, nil
}

// scanApprovalRequestFromRows scans an approval request from rows iterator
func (sas *SQLiteApprovalStorage) scanApprovalRequestFromRows(rows *sql.Rows) (*soar.ApprovalRequest, error) {
	var request soar.ApprovalRequest
	var requiredApproversJSON, contextJSON, alertID, resolvedAt sql.NullString
	var createdAt, updatedAt, expiresAt string

	err := rows.Scan(
		&request.ID, &request.ExecutionID, &request.PlaybookID, &request.PlaybookName,
		&request.StepID, &request.StepName, &alertID, &request.RequestedBy,
		&request.Status, &request.Mode, &requiredApproversJSON, &request.MinApprovers,
		&request.ApprovalCount, &request.RejectionCount, &request.EscalationLevel,
		&contextJSON, &createdAt, &updatedAt, &expiresAt, &resolvedAt, &request.Version,
	)

	if err != nil {
		return nil, fmt.Errorf("failed to scan approval request: %w", err)
	}

	// Parse nullable fields
	if alertID.Valid {
		request.AlertID = alertID.String
	}
	if requiredApproversJSON.Valid {
		if err := json.Unmarshal([]byte(requiredApproversJSON.String), &request.RequiredApprovers); err != nil {
			return nil, fmt.Errorf("failed to parse required_approvers: %w", err)
		}
	}
	if contextJSON.Valid {
		if err := json.Unmarshal([]byte(contextJSON.String), &request.Context); err != nil {
			return nil, fmt.Errorf("failed to parse context: %w", err)
		}
	}

	// Parse timestamps
	request.CreatedAt, _ = time.Parse(time.RFC3339, createdAt)
	request.UpdatedAt, _ = time.Parse(time.RFC3339, updatedAt)
	request.ExpiresAt, _ = time.Parse(time.RFC3339, expiresAt)
	if resolvedAt.Valid {
		t, _ := time.Parse(time.RFC3339, resolvedAt.String)
		request.ResolvedAt = &t
	}

	return &request, nil
}

// ApprovalStorageInterface defines the interface for approval storage
type ApprovalStorageInterface interface {
	CreateApprovalRequest(request *soar.ApprovalRequest) error
	GetApprovalRequest(id string) (*soar.ApprovalRequest, error)
	GetApprovalRequestByExecution(executionID, stepID string) (*soar.ApprovalRequest, error)
	GetApprovalRequests(filter *soar.ApprovalFilter) ([]soar.ApprovalRequest, int64, error)
	GetPendingApprovals(approverID string, limit, offset int) ([]soar.ApprovalRequest, error)
	ProcessApprovalAction(approvalID, userID, username string, action soar.ApprovalActionType, comment string, expectedVersion int) (*soar.ApprovalRequest, error)
	GetApprovalActions(approvalID string) ([]soar.ApprovalAction, error)
	ExpireApprovals() (int64, error)
	CancelApprovalRequest(id, userID string) error
	GetApprovalStats() (*soar.ApprovalStats, error)
}

// Verify interface implementation at compile time
var _ ApprovalStorageInterface = (*SQLiteApprovalStorage)(nil)
