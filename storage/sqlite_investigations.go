package storage

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"cerberus/core"

	"go.uber.org/zap"
)

// SQLiteInvestigationStorage handles investigation CRUD operations in SQLite
type SQLiteInvestigationStorage struct {
	db     *SQLite
	logger *zap.SugaredLogger
}

// NewSQLiteInvestigationStorage creates a new SQLite investigation storage handler
func NewSQLiteInvestigationStorage(db *SQLite, logger *zap.SugaredLogger) (*SQLiteInvestigationStorage, error) {
	storage := &SQLiteInvestigationStorage{
		db:     db,
		logger: logger,
	}

	// Ensure investigations table exists
	if err := storage.ensureTable(); err != nil {
		return nil, fmt.Errorf("failed to ensure investigations table: %w", err)
	}

	return storage, nil
}

// ensureTable creates the investigations table if it doesn't exist
func (sis *SQLiteInvestigationStorage) ensureTable() error {
	query := `
	CREATE TABLE IF NOT EXISTS investigations (
		investigation_id TEXT PRIMARY KEY,
		title TEXT NOT NULL,
		description TEXT,
		priority TEXT NOT NULL DEFAULT 'medium',
		status TEXT NOT NULL DEFAULT 'open',
		assignee_id TEXT,
		created_by TEXT,
		created_at DATETIME NOT NULL,
		updated_at DATETIME NOT NULL,
		closed_at DATETIME,
		alert_ids TEXT,  -- JSON array
		event_ids TEXT,  -- JSON array
		mitre_tactics TEXT,    -- JSON array
		mitre_techniques TEXT, -- JSON array
		artifacts TEXT,  -- JSON object
		notes TEXT,      -- JSON array
		verdict TEXT,
		resolution_category TEXT,
		summary TEXT,
		affected_assets TEXT,  -- JSON array
		ml_feedback TEXT,      -- JSON object
		tags TEXT,             -- JSON array
		-- SECURITY FIX GAP-003: Add foreign key constraints for referential integrity
		-- REQUIREMENT: TEST_IMPROVEMENTS_PART2.md GAP-003 (DATA-001)
		-- REQUIREMENT: docs/requirements/storage-acid-requirements.md Section 3.1.2
		-- CRITICAL: Prevents orphaned investigations referencing deleted users
		-- ON DELETE SET NULL: When a user is deleted, set assignee_id/created_by to NULL
		-- This preserves investigation data while removing invalid user references
		FOREIGN KEY (assignee_id) REFERENCES users(username) ON DELETE SET NULL,
		FOREIGN KEY (created_by) REFERENCES users(username) ON DELETE SET NULL
	);

	CREATE INDEX IF NOT EXISTS idx_investigations_status ON investigations(status);
	CREATE INDEX IF NOT EXISTS idx_investigations_priority ON investigations(priority);
	CREATE INDEX IF NOT EXISTS idx_investigations_assignee ON investigations(assignee_id);
	CREATE INDEX IF NOT EXISTS idx_investigations_created_at ON investigations(created_at DESC);
	CREATE INDEX IF NOT EXISTS idx_investigations_verdict ON investigations(verdict);

	-- Investigation-Alert junction table (TASK 28.2: Alert association)
	CREATE TABLE IF NOT EXISTS investigation_alerts (
		investigation_id TEXT NOT NULL,
		alert_id TEXT NOT NULL,
		associated_at DATETIME NOT NULL,
		associated_by TEXT,
		PRIMARY KEY (investigation_id, alert_id),
		FOREIGN KEY (investigation_id) REFERENCES investigations(investigation_id) ON DELETE CASCADE,
		FOREIGN KEY (alert_id) REFERENCES alerts(alert_id) ON DELETE CASCADE
	);
	CREATE INDEX IF NOT EXISTS idx_investigation_alerts_investigation ON investigation_alerts(investigation_id);
	CREATE INDEX IF NOT EXISTS idx_investigation_alerts_alert ON investigation_alerts(alert_id);

	-- Investigation state transitions audit table (TASK 28.1: State transition tracking)
	CREATE TABLE IF NOT EXISTS investigation_state_transitions (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		investigation_id TEXT NOT NULL,
		from_status TEXT NOT NULL,
		to_status TEXT NOT NULL,
		changed_by TEXT,
		changed_at DATETIME NOT NULL,
		reason TEXT,
		FOREIGN KEY (investigation_id) REFERENCES investigations(investigation_id) ON DELETE CASCADE
	);
	CREATE INDEX IF NOT EXISTS idx_state_transitions_investigation ON investigation_state_transitions(investigation_id);
	CREATE INDEX IF NOT EXISTS idx_state_transitions_changed_at ON investigation_state_transitions(changed_at DESC);
	`

	_, err := sis.db.DB.Exec(query)
	if err != nil {
		return fmt.Errorf("failed to create investigations table: %w", err)
	}

	sis.logger.Info("Investigations table ensured in SQLite")
	return nil
}

// CreateInvestigation creates a new investigation
func (sis *SQLiteInvestigationStorage) CreateInvestigation(investigation *core.Investigation) error {
	// Serialize complex fields to JSON
	alertIDsJSON, _ := json.Marshal(investigation.AlertIDs)
	eventIDsJSON, _ := json.Marshal(investigation.EventIDs)
	mitreTacticsJSON, _ := json.Marshal(investigation.MitreTactics)
	mitreTechniquesJSON, _ := json.Marshal(investigation.MitreTechniques)
	artifactsJSON, _ := json.Marshal(investigation.Artifacts)
	notesJSON, _ := json.Marshal(investigation.Notes)
	affectedAssetsJSON, _ := json.Marshal(investigation.AffectedAssets)
	mlFeedbackJSON, _ := json.Marshal(investigation.MLFeedback)
	tagsJSON, _ := json.Marshal(investigation.Tags)

	query := `
		INSERT INTO investigations (
			investigation_id, title, description, priority, status,
			assignee_id, created_by, created_at, updated_at, closed_at,
			alert_ids, event_ids, mitre_tactics, mitre_techniques,
			artifacts, notes, verdict, resolution_category, summary,
			affected_assets, ml_feedback, tags
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`

	// Convert empty strings and "system" fallback to NULL for foreign key fields
	// "system" is not a real user, so it would violate FK constraint
	var assigneeID interface{}
	if investigation.AssigneeID == "" || investigation.AssigneeID == "system" {
		assigneeID = nil
	} else {
		assigneeID = investigation.AssigneeID
	}

	var createdBy interface{}
	if investigation.CreatedBy == "" || investigation.CreatedBy == "system" {
		createdBy = nil
	} else {
		createdBy = investigation.CreatedBy
	}

	_, err := sis.db.DB.Exec(query,
		investigation.InvestigationID,
		investigation.Title,
		investigation.Description,
		investigation.Priority,
		investigation.Status,
		assigneeID,
		createdBy,
		investigation.CreatedAt,
		investigation.UpdatedAt,
		investigation.ClosedAt,
		string(alertIDsJSON),
		string(eventIDsJSON),
		string(mitreTacticsJSON),
		string(mitreTechniquesJSON),
		string(artifactsJSON),
		string(notesJSON),
		investigation.Verdict,
		investigation.ResolutionCategory,
		investigation.Summary,
		string(affectedAssetsJSON),
		string(mlFeedbackJSON),
		string(tagsJSON),
	)

	if err != nil {
		return fmt.Errorf("failed to insert investigation: %w", err)
	}

	sis.logger.Infof("Investigation created: ID=%s, Title=%s", investigation.InvestigationID, investigation.Title)
	return nil
}

// GetInvestigation retrieves an investigation by ID
func (sis *SQLiteInvestigationStorage) GetInvestigation(investigationID string) (*core.Investigation, error) {
	query := `
		SELECT
			investigation_id, title, description, priority, status,
			assignee_id, created_by, created_at, updated_at, closed_at,
			alert_ids, event_ids, mitre_tactics, mitre_techniques,
			artifacts, notes, verdict, resolution_category, summary,
			affected_assets, ml_feedback, tags
		FROM investigations
		WHERE investigation_id = ?
	`

	var investigation core.Investigation
	var alertIDsJSON, eventIDsJSON, mitreTacticsJSON, mitreTechniquesJSON string
	var artifactsJSON, notesJSON, affectedAssetsJSON, mlFeedbackJSON, tagsJSON string
	var closedAt sql.NullTime
	var assigneeID sql.NullString
	var createdBy sql.NullString

	err := sis.db.ReadDB.QueryRow(query, investigationID).Scan(
		&investigation.InvestigationID,
		&investigation.Title,
		&investigation.Description,
		&investigation.Priority,
		&investigation.Status,
		&assigneeID,
		&createdBy,
		&investigation.CreatedAt,
		&investigation.UpdatedAt,
		&closedAt,
		&alertIDsJSON,
		&eventIDsJSON,
		&mitreTacticsJSON,
		&mitreTechniquesJSON,
		&artifactsJSON,
		&notesJSON,
		&investigation.Verdict,
		&investigation.ResolutionCategory,
		&investigation.Summary,
		&affectedAssetsJSON,
		&mlFeedbackJSON,
		&tagsJSON,
	)

	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("investigation not found: %s", investigationID)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to query investigation: %w", err)
	}

	// Handle nullable fields
	if assigneeID.Valid {
		investigation.AssigneeID = assigneeID.String
	} else {
		investigation.AssigneeID = ""
	}
	if createdBy.Valid {
		investigation.CreatedBy = createdBy.String
	} else {
		investigation.CreatedBy = ""
	}

	// Deserialize JSON fields
	json.Unmarshal([]byte(alertIDsJSON), &investigation.AlertIDs)
	json.Unmarshal([]byte(eventIDsJSON), &investigation.EventIDs)
	json.Unmarshal([]byte(mitreTacticsJSON), &investigation.MitreTactics)
	json.Unmarshal([]byte(mitreTechniquesJSON), &investigation.MitreTechniques)
	json.Unmarshal([]byte(artifactsJSON), &investigation.Artifacts)
	json.Unmarshal([]byte(notesJSON), &investigation.Notes)
	json.Unmarshal([]byte(affectedAssetsJSON), &investigation.AffectedAssets)
	json.Unmarshal([]byte(mlFeedbackJSON), &investigation.MLFeedback)
	json.Unmarshal([]byte(tagsJSON), &investigation.Tags)

	if closedAt.Valid {
		investigation.ClosedAt = &closedAt.Time
	}

	return &investigation, nil
}

// UpdateInvestigation updates an existing investigation
// TASK 42.2: Wrapped in explicit transaction for atomicity
func (sis *SQLiteInvestigationStorage) UpdateInvestigation(id string, investigation *core.Investigation) error {
	// Get current investigation to check status transition
	current, err := sis.GetInvestigation(id)
	if err != nil {
		return fmt.Errorf("failed to get current investigation: %w", err)
	}

	// TASK 28.1: Validate state transition if status changed
	statusChanged := investigation.Status != current.Status
	var userID string
	if statusChanged {
		if err := sis.ValidateStateTransition(current.Status, investigation.Status); err != nil {
			return err
		}
		// Get userID for state transition logging
		userID = investigation.AssigneeID // Use assignee as changed_by if available
		if userID == "" {
			userID = investigation.CreatedBy
		}
	}

	// Update timestamp
	investigation.UpdatedAt = time.Now()
	// Ensure ID matches
	investigation.InvestigationID = id

	// Serialize complex fields
	alertIDsJSON, _ := json.Marshal(investigation.AlertIDs)
	eventIDsJSON, _ := json.Marshal(investigation.EventIDs)
	mitreTacticsJSON, _ := json.Marshal(investigation.MitreTactics)
	mitreTechniquesJSON, _ := json.Marshal(investigation.MitreTechniques)
	artifactsJSON, _ := json.Marshal(investigation.Artifacts)
	notesJSON, _ := json.Marshal(investigation.Notes)
	affectedAssetsJSON, _ := json.Marshal(investigation.AffectedAssets)
	mlFeedbackJSON, _ := json.Marshal(investigation.MLFeedback)
	tagsJSON, _ := json.Marshal(investigation.Tags)

	// Convert empty strings and "system" fallback to NULL for foreign key fields
	// "system" is not a real user, so it would violate FK constraint
	var assigneeIDValue interface{}
	if investigation.AssigneeID == "" || investigation.AssigneeID == "system" {
		assigneeIDValue = nil
	} else {
		assigneeIDValue = investigation.AssigneeID
	}

	// TASK 42.2: Wrap in transaction for atomicity (UPDATE + state transition logging)
	return sis.db.WithTransaction(func(tx *sql.Tx) error {
		// Statement 1: Update investigation
		updateQuery := `
			UPDATE investigations
			SET
				title = ?,
				description = ?,
				priority = ?,
				status = ?,
				assignee_id = ?,
				updated_at = ?,
				closed_at = ?,
				alert_ids = ?,
				event_ids = ?,
				mitre_tactics = ?,
				mitre_techniques = ?,
				artifacts = ?,
				notes = ?,
				verdict = ?,
				resolution_category = ?,
				summary = ?,
				affected_assets = ?,
				ml_feedback = ?,
				tags = ?
			WHERE investigation_id = ?
		`

		result, err := tx.Exec(updateQuery,
			investigation.Title,
			investigation.Description,
			investigation.Priority,
			investigation.Status,
			assigneeIDValue,
			investigation.UpdatedAt,
			investigation.ClosedAt,
			string(alertIDsJSON),
			string(eventIDsJSON),
			string(mitreTacticsJSON),
			string(mitreTechniquesJSON),
			string(artifactsJSON),
			string(notesJSON),
			investigation.Verdict,
			investigation.ResolutionCategory,
			investigation.Summary,
			string(affectedAssetsJSON),
			string(mlFeedbackJSON),
			string(tagsJSON),
			investigation.InvestigationID,
		)

		if err != nil {
			return fmt.Errorf("failed to update investigation: %w", err)
		}

		rowsAffected, _ := result.RowsAffected()
		if rowsAffected == 0 {
			return fmt.Errorf("investigation not found: %s", investigation.InvestigationID)
		}

		// Statement 2: Log state transition if status changed
		if statusChanged {
			logQuery := `
				INSERT INTO investigation_state_transitions (investigation_id, from_status, to_status, changed_by, changed_at, reason)
				VALUES (?, ?, ?, ?, ?, ?)
			`
			_, err = tx.Exec(logQuery,
				id,
				string(current.Status),
				string(investigation.Status),
				userID,
				time.Now().UTC().Format(time.RFC3339),
				"", // reason - empty for now
			)
			if err != nil {
				return fmt.Errorf("failed to log state transition: %w", err)
			}
		}

		sis.logger.Infof("Investigation updated: ID=%s", investigation.InvestigationID)
		return nil
	})
}

// GetInvestigations retrieves all investigations with pagination and optional filtering
func (sis *SQLiteInvestigationStorage) GetInvestigations(limit, offset int, filters map[string]interface{}) ([]core.Investigation, error) {
	query := `
		SELECT
			investigation_id, title, description, priority, status,
			assignee_id, created_by, created_at, updated_at, closed_at,
			alert_ids, event_ids, mitre_tactics, mitre_techniques,
			artifacts, notes, verdict, resolution_category, summary,
			affected_assets, ml_feedback, tags
		FROM investigations
	`

	// Build WHERE clause from filters (TASK 47: Enhanced filtering support)
	whereClauses := []string{}
	args := []interface{}{}

	// Status filter (support multiple statuses)
	if statuses, ok := filters["statuses"]; ok && statuses != nil {
		if statusList, ok := statuses.([]core.InvestigationStatus); ok && len(statusList) > 0 {
			placeholders := make([]string, len(statusList))
			for i, s := range statusList {
				placeholders[i] = "?"
				args = append(args, string(s))
			}
			whereClauses = append(whereClauses, fmt.Sprintf("status IN (%s)", strings.Join(placeholders, ",")))
		} else if statusStr, ok := statuses.(string); ok && statusStr != "" {
			// Legacy single status support
			whereClauses = append(whereClauses, "status = ?")
			args = append(args, statusStr)
		}
	} else if status, ok := filters["status"]; ok && status != nil {
		// Legacy status filter
		if statusStr, ok := status.(string); ok && statusStr != "" {
			whereClauses = append(whereClauses, "status = ?")
			args = append(args, statusStr)
		}
	}

	// Priority filter (support multiple priorities)
	if priorities, ok := filters["priorities"]; ok && priorities != nil {
		if priorityList, ok := priorities.([]core.InvestigationPriority); ok && len(priorityList) > 0 {
			placeholders := make([]string, len(priorityList))
			for i, p := range priorityList {
				placeholders[i] = "?"
				args = append(args, string(p))
			}
			whereClauses = append(whereClauses, fmt.Sprintf("priority IN (%s)", strings.Join(placeholders, ",")))
		} else if priorityStr, ok := priorities.(string); ok && priorityStr != "" {
			// Legacy single priority support
			whereClauses = append(whereClauses, "priority = ?")
			args = append(args, priorityStr)
		}
	} else if priority, ok := filters["priority"]; ok && priority != nil {
		// Legacy priority filter
		if priorityStr, ok := priority.(string); ok && priorityStr != "" {
			whereClauses = append(whereClauses, "priority = ?")
			args = append(args, priorityStr)
		}
	}

	// Assignee ID filter (support multiple assignees)
	if assigneeIDs, ok := filters["assignee_ids"]; ok && assigneeIDs != nil {
		if assigneeList, ok := assigneeIDs.([]string); ok && len(assigneeList) > 0 {
			placeholders := make([]string, len(assigneeList))
			for i, id := range assigneeList {
				placeholders[i] = "?"
				args = append(args, id)
			}
			whereClauses = append(whereClauses, fmt.Sprintf("assignee_id IN (%s)", strings.Join(placeholders, ",")))
		} else if assigneeStr, ok := assigneeIDs.(string); ok && assigneeStr != "" {
			// Legacy single assignee support
			whereClauses = append(whereClauses, "assignee_id = ?")
			args = append(args, assigneeStr)
		}
	} else if assigneeID, ok := filters["assignee_id"]; ok && assigneeID != nil {
		// Legacy assignee filter
		if assigneeStr, ok := assigneeID.(string); ok && assigneeStr != "" {
			whereClauses = append(whereClauses, "assignee_id = ?")
			args = append(args, assigneeStr)
		}
	}

	// Created by filter (support multiple creators)
	if createdBy, ok := filters["created_by"]; ok && createdBy != nil {
		if createdByList, ok := createdBy.([]string); ok && len(createdByList) > 0 {
			placeholders := make([]string, len(createdByList))
			for i, id := range createdByList {
				placeholders[i] = "?"
				args = append(args, id)
			}
			whereClauses = append(whereClauses, fmt.Sprintf("created_by IN (%s)", strings.Join(placeholders, ",")))
		} else if createdByStr, ok := createdBy.(string); ok && createdByStr != "" {
			whereClauses = append(whereClauses, "created_by = ?")
			args = append(args, createdByStr)
		}
	}

	// Search filter (title and description)
	if search, ok := filters["search"]; ok && search != nil {
		if searchStr, ok := search.(string); ok && searchStr != "" {
			escapedQuery := strings.ReplaceAll(searchStr, "\\", "\\\\")
			escapedQuery = strings.ReplaceAll(escapedQuery, "%", "\\%")
			escapedQuery = strings.ReplaceAll(escapedQuery, "_", "\\_")
			searchPattern := "%" + escapedQuery + "%"
			whereClauses = append(whereClauses, "(title LIKE ? ESCAPE '\\' OR description LIKE ? ESCAPE '\\')")
			args = append(args, searchPattern, searchPattern)
		}
	}

	// Date filters
	if createdAfter, ok := filters["created_after"]; ok && createdAfter != nil {
		if t, ok := createdAfter.(*time.Time); ok && t != nil {
			whereClauses = append(whereClauses, "created_at >= ?")
			args = append(args, t)
		}
	}
	if createdBefore, ok := filters["created_before"]; ok && createdBefore != nil {
		if t, ok := createdBefore.(*time.Time); ok && t != nil {
			whereClauses = append(whereClauses, "created_at <= ?")
			args = append(args, t)
		}
	}
	if updatedAfter, ok := filters["updated_after"]; ok && updatedAfter != nil {
		if t, ok := updatedAfter.(*time.Time); ok && t != nil {
			whereClauses = append(whereClauses, "updated_at >= ?")
			args = append(args, t)
		}
	}
	if updatedBefore, ok := filters["updated_before"]; ok && updatedBefore != nil {
		if t, ok := updatedBefore.(*time.Time); ok && t != nil {
			whereClauses = append(whereClauses, "updated_at <= ?")
			args = append(args, t)
		}
	}
	if closedAfter, ok := filters["closed_after"]; ok && closedAfter != nil {
		if t, ok := closedAfter.(*time.Time); ok && t != nil {
			whereClauses = append(whereClauses, "closed_at >= ?")
			args = append(args, t)
		}
	}
	if closedBefore, ok := filters["closed_before"]; ok && closedBefore != nil {
		if t, ok := closedBefore.(*time.Time); ok && t != nil {
			whereClauses = append(whereClauses, "closed_at <= ?")
			args = append(args, t)
		}
	}

	if len(whereClauses) > 0 {
		query += " WHERE " + strings.Join(whereClauses, " AND ")
	}

	// Sorting (TASK 47: Support configurable sorting)
	sortBy := "created_at"
	sortOrder := "DESC"
	if sb, ok := filters["sort_by"]; ok && sb != nil {
		if sortByStr, ok := sb.(string); ok && sortByStr != "" {
			// Whitelist allowed sort fields
			switch sortByStr {
			case "created_at", "updated_at", "priority", "status", "title":
				sortBy = sortByStr
			}
		}
	}
	if so, ok := filters["sort_order"]; ok && so != nil {
		if sortOrderStr, ok := so.(string); ok && (sortOrderStr == "asc" || sortOrderStr == "desc") {
			sortOrder = strings.ToUpper(sortOrderStr)
		}
	}

	query += fmt.Sprintf(" ORDER BY %s %s LIMIT ? OFFSET ?", sortBy, sortOrder)
	args = append(args, limit, offset)

	rows, err := sis.db.ReadDB.Query(query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to query investigations: %w", err)
	}
	defer rows.Close()

	investigations := make([]core.Investigation, 0)
	for rows.Next() {
		var investigation core.Investigation
		var alertIDsJSON, eventIDsJSON, mitreTacticsJSON, mitreTechniquesJSON string
		var artifactsJSON, notesJSON, affectedAssetsJSON, mlFeedbackJSON, tagsJSON string
		var closedAt sql.NullTime
		var assigneeID, createdBy sql.NullString

		err := rows.Scan(
			&investigation.InvestigationID,
			&investigation.Title,
			&investigation.Description,
			&investigation.Priority,
			&investigation.Status,
			&assigneeID,
			&createdBy,
			&investigation.CreatedAt,
			&investigation.UpdatedAt,
			&closedAt,
			&alertIDsJSON,
			&eventIDsJSON,
			&mitreTacticsJSON,
			&mitreTechniquesJSON,
			&artifactsJSON,
			&notesJSON,
			&investigation.Verdict,
			&investigation.ResolutionCategory,
			&investigation.Summary,
			&affectedAssetsJSON,
			&mlFeedbackJSON,
			&tagsJSON,
		)
		if err != nil {
			sis.logger.Errorf("Failed to scan investigation: %v", err)
			continue
		}

		// Handle nullable fields
		if assigneeID.Valid {
			investigation.AssigneeID = assigneeID.String
		}
		if createdBy.Valid {
			investigation.CreatedBy = createdBy.String
		}

		// Deserialize JSON fields
		json.Unmarshal([]byte(alertIDsJSON), &investigation.AlertIDs)
		json.Unmarshal([]byte(eventIDsJSON), &investigation.EventIDs)
		json.Unmarshal([]byte(mitreTacticsJSON), &investigation.MitreTactics)
		json.Unmarshal([]byte(mitreTechniquesJSON), &investigation.MitreTechniques)
		json.Unmarshal([]byte(artifactsJSON), &investigation.Artifacts)
		json.Unmarshal([]byte(notesJSON), &investigation.Notes)
		json.Unmarshal([]byte(affectedAssetsJSON), &investigation.AffectedAssets)
		json.Unmarshal([]byte(mlFeedbackJSON), &investigation.MLFeedback)
		json.Unmarshal([]byte(tagsJSON), &investigation.Tags)

		if closedAt.Valid {
			investigation.ClosedAt = &closedAt.Time
		}

		investigations = append(investigations, investigation)
	}

	return investigations, nil
}

// DeleteInvestigation deletes an investigation
func (sis *SQLiteInvestigationStorage) DeleteInvestigation(investigationID string) error {
	query := "DELETE FROM investigations WHERE investigation_id = ?"

	result, err := sis.db.DB.Exec(query, investigationID)
	if err != nil {
		return fmt.Errorf("failed to delete investigation: %w", err)
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return fmt.Errorf("investigation not found: %s", investigationID)
	}

	sis.logger.Infof("Investigation deleted: ID=%s", investigationID)
	return nil
}

// GetInvestigationCount returns total investigation count with optional filtering
// TASK 47: Enhanced filtering support (reuses same filter logic as GetInvestigations)
func (sis *SQLiteInvestigationStorage) GetInvestigationCount(filters map[string]interface{}) (int64, error) {
	query := "SELECT COUNT(*) FROM investigations"

	// Build WHERE clause from filters (TASK 47: Enhanced filtering support - same logic as GetInvestigations)
	whereClauses := []string{}
	args := []interface{}{}

	// Status filter (support multiple statuses)
	if statuses, ok := filters["statuses"]; ok && statuses != nil {
		if statusList, ok := statuses.([]core.InvestigationStatus); ok && len(statusList) > 0 {
			placeholders := make([]string, len(statusList))
			for i, s := range statusList {
				placeholders[i] = "?"
				args = append(args, string(s))
			}
			whereClauses = append(whereClauses, fmt.Sprintf("status IN (%s)", strings.Join(placeholders, ",")))
		} else if statusStr, ok := statuses.(string); ok && statusStr != "" {
			whereClauses = append(whereClauses, "status = ?")
			args = append(args, statusStr)
		}
	} else if status, ok := filters["status"]; ok && status != nil {
		if statusStr, ok := status.(string); ok && statusStr != "" {
			whereClauses = append(whereClauses, "status = ?")
			args = append(args, statusStr)
		}
	}

	// Priority filter (support multiple priorities)
	if priorities, ok := filters["priorities"]; ok && priorities != nil {
		if priorityList, ok := priorities.([]core.InvestigationPriority); ok && len(priorityList) > 0 {
			placeholders := make([]string, len(priorityList))
			for i, p := range priorityList {
				placeholders[i] = "?"
				args = append(args, string(p))
			}
			whereClauses = append(whereClauses, fmt.Sprintf("priority IN (%s)", strings.Join(placeholders, ",")))
		} else if priorityStr, ok := priorities.(string); ok && priorityStr != "" {
			whereClauses = append(whereClauses, "priority = ?")
			args = append(args, priorityStr)
		}
	} else if priority, ok := filters["priority"]; ok && priority != nil {
		if priorityStr, ok := priority.(string); ok && priorityStr != "" {
			whereClauses = append(whereClauses, "priority = ?")
			args = append(args, priorityStr)
		}
	}

	// Assignee ID filter (support multiple assignees)
	if assigneeIDs, ok := filters["assignee_ids"]; ok && assigneeIDs != nil {
		if assigneeList, ok := assigneeIDs.([]string); ok && len(assigneeList) > 0 {
			placeholders := make([]string, len(assigneeList))
			for i, id := range assigneeList {
				placeholders[i] = "?"
				args = append(args, id)
			}
			whereClauses = append(whereClauses, fmt.Sprintf("assignee_id IN (%s)", strings.Join(placeholders, ",")))
		} else if assigneeStr, ok := assigneeIDs.(string); ok && assigneeStr != "" {
			whereClauses = append(whereClauses, "assignee_id = ?")
			args = append(args, assigneeStr)
		}
	} else if assigneeID, ok := filters["assignee_id"]; ok && assigneeID != nil {
		if assigneeStr, ok := assigneeID.(string); ok && assigneeStr != "" {
			whereClauses = append(whereClauses, "assignee_id = ?")
			args = append(args, assigneeStr)
		}
	}

	// Created by filter
	if createdBy, ok := filters["created_by"]; ok && createdBy != nil {
		if createdByList, ok := createdBy.([]string); ok && len(createdByList) > 0 {
			placeholders := make([]string, len(createdByList))
			for i, id := range createdByList {
				placeholders[i] = "?"
				args = append(args, id)
			}
			whereClauses = append(whereClauses, fmt.Sprintf("created_by IN (%s)", strings.Join(placeholders, ",")))
		} else if createdByStr, ok := createdBy.(string); ok && createdByStr != "" {
			whereClauses = append(whereClauses, "created_by = ?")
			args = append(args, createdByStr)
		}
	}

	// Search filter (title and description)
	if search, ok := filters["search"]; ok && search != nil {
		if searchStr, ok := search.(string); ok && searchStr != "" {
			escapedQuery := strings.ReplaceAll(searchStr, "\\", "\\\\")
			escapedQuery = strings.ReplaceAll(escapedQuery, "%", "\\%")
			escapedQuery = strings.ReplaceAll(escapedQuery, "_", "\\_")
			searchPattern := "%" + escapedQuery + "%"
			whereClauses = append(whereClauses, "(title LIKE ? ESCAPE '\\' OR description LIKE ? ESCAPE '\\')")
			args = append(args, searchPattern, searchPattern)
		}
	}

	// Date filters
	if createdAfter, ok := filters["created_after"]; ok && createdAfter != nil {
		if t, ok := createdAfter.(*time.Time); ok && t != nil {
			whereClauses = append(whereClauses, "created_at >= ?")
			args = append(args, t)
		}
	}
	if createdBefore, ok := filters["created_before"]; ok && createdBefore != nil {
		if t, ok := createdBefore.(*time.Time); ok && t != nil {
			whereClauses = append(whereClauses, "created_at <= ?")
			args = append(args, t)
		}
	}
	if updatedAfter, ok := filters["updated_after"]; ok && updatedAfter != nil {
		if t, ok := updatedAfter.(*time.Time); ok && t != nil {
			whereClauses = append(whereClauses, "updated_at >= ?")
			args = append(args, t)
		}
	}
	if updatedBefore, ok := filters["updated_before"]; ok && updatedBefore != nil {
		if t, ok := updatedBefore.(*time.Time); ok && t != nil {
			whereClauses = append(whereClauses, "updated_at <= ?")
			args = append(args, t)
		}
	}
	if closedAfter, ok := filters["closed_after"]; ok && closedAfter != nil {
		if t, ok := closedAfter.(*time.Time); ok && t != nil {
			whereClauses = append(whereClauses, "closed_at >= ?")
			args = append(args, t)
		}
	}
	if closedBefore, ok := filters["closed_before"]; ok && closedBefore != nil {
		if t, ok := closedBefore.(*time.Time); ok && t != nil {
			whereClauses = append(whereClauses, "closed_at <= ?")
			args = append(args, t)
		}
	}

	if len(whereClauses) > 0 {
		query += " WHERE " + strings.Join(whereClauses, " AND ")
	}

	var count int64
	err := sis.db.ReadDB.QueryRow(query, args...).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("failed to count investigations: %w", err)
	}

	return count, nil
}

// GetInvestigationsByStatus retrieves investigations filtered by status
func (sis *SQLiteInvestigationStorage) GetInvestigationsByStatus(status string, limit, offset int) ([]core.Investigation, error) {
	filters := map[string]interface{}{"status": status}
	return sis.GetInvestigations(limit, offset, filters)
}

// AddNote adds a note to an investigation
func (sis *SQLiteInvestigationStorage) AddNote(investigationID, analystID, content string) error {
	// Get current investigation
	investigation, err := sis.GetInvestigation(investigationID)
	if err != nil {
		return err
	}

	// Create new note
	note := core.InvestigationNote{
		ID:        fmt.Sprintf("note_%d", time.Now().UnixNano()),
		AnalystID: analystID,
		Content:   content,
		CreatedAt: time.Now(),
	}

	// Add new note
	investigation.Notes = append(investigation.Notes, note)

	// Update investigation
	return sis.UpdateInvestigation(investigationID, investigation)
}

// UpdateStatus updates the status of an investigation
func (sis *SQLiteInvestigationStorage) UpdateStatus(investigationID string, status core.InvestigationStatus) error {
	now := time.Now()
	var closedAt *time.Time

	// Set closed_at if status is resolved or closed
	if status == core.InvestigationStatusResolved || status == core.InvestigationStatusClosed {
		closedAt = &now
	}

	query := `
		UPDATE investigations
		SET status = ?, updated_at = ?, closed_at = ?
		WHERE investigation_id = ?
	`

	result, err := sis.db.DB.Exec(query, status, now, closedAt, investigationID)
	if err != nil {
		return fmt.Errorf("failed to update investigation status: %w", err)
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return fmt.Errorf("investigation not found: %s", investigationID)
	}

	sis.logger.Infof("Investigation status updated: ID=%s, Status=%s", investigationID, status)
	return nil
}

// AssignInvestigation assigns an investigation to an analyst
func (sis *SQLiteInvestigationStorage) AssignInvestigation(investigationID, assigneeID string) error {
	query := `
		UPDATE investigations
		SET assignee_id = ?, updated_at = ?
		WHERE investigation_id = ?
	`

	result, err := sis.db.DB.Exec(query, assigneeID, time.Now(), investigationID)
	if err != nil {
		return fmt.Errorf("failed to assign investigation: %w", err)
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return fmt.Errorf("investigation not found: %s", investigationID)
	}

	sis.logger.Infof("Investigation assigned: ID=%s, AssigneeID=%s", investigationID, assigneeID)
	return nil
}

// CloseInvestigation closes an investigation with verdict and resolution details
// TASK 28.5: Validate closure requirements before closing
func (sis *SQLiteInvestigationStorage) CloseInvestigation(id string, verdict core.InvestigationVerdict, resolutionCategory, summary string, affectedAssets []string, mlFeedback *core.MLFeedback) error {
	// Get current investigation
	investigation, err := sis.GetInvestigation(id)
	if err != nil {
		return fmt.Errorf("failed to get investigation: %w", err)
	}

	// Update investigation with closure details
	investigation.Verdict = verdict
	investigation.ResolutionCategory = resolutionCategory
	investigation.Summary = summary
	investigation.AffectedAssets = affectedAssets
	investigation.MLFeedback = mlFeedback
	investigation.Status = core.InvestigationStatusClosed
	now := time.Now()
	investigation.ClosedAt = &now

	// TASK 28.5: Validate closure requirements
	if err := sis.ValidateClosureRequirements(investigation); err != nil {
		return err
	}

	// Save updated investigation (will trigger state transition validation)
	return sis.UpdateInvestigation(id, investigation)
}

// AddAlert adds an alert ID to an investigation
func (sis *SQLiteInvestigationStorage) AddAlert(investigationID, alertID string) error {
	// Get current investigation
	investigation, err := sis.GetInvestigation(investigationID)
	if err != nil {
		return err
	}

	// Check if alert already exists
	for _, id := range investigation.AlertIDs {
		if id == alertID {
			return nil // Already added, no error
		}
	}

	// Add alert ID
	investigation.AlertIDs = append(investigation.AlertIDs, alertID)
	investigation.UpdatedAt = time.Now()

	// Save updated investigation
	return sis.UpdateInvestigation(investigationID, investigation)
}

// GetInvestigationsByAlertID retrieves all investigations containing a specific alert ID
func (sis *SQLiteInvestigationStorage) GetInvestigationsByAlertID(alertID string) ([]core.Investigation, error) {
	query := `
		SELECT
			investigation_id, title, description, priority, status,
			assignee_id, created_by, created_at, updated_at, closed_at,
			alert_ids, event_ids, mitre_tactics, mitre_techniques,
			artifacts, notes, verdict, resolution_category, summary,
			affected_assets, ml_feedback, tags
		FROM investigations
		WHERE alert_ids LIKE ?
		ORDER BY created_at DESC
	`

	// Search for alert ID in JSON array (SQLite text search)
	searchPattern := fmt.Sprintf("%%\"%s\"%%", alertID)
	rows, err := sis.db.ReadDB.Query(query, searchPattern)
	if err != nil {
		return nil, fmt.Errorf("failed to query investigations by alert ID: %w", err)
	}
	defer rows.Close()

	investigations := make([]core.Investigation, 0)
	for rows.Next() {
		var investigation core.Investigation
		var alertIDsJSON, eventIDsJSON, mitreTacticsJSON, mitreTechniquesJSON string
		var artifactsJSON, notesJSON, affectedAssetsJSON, mlFeedbackJSON, tagsJSON string
		var closedAt sql.NullTime
		var assigneeID, createdBy sql.NullString

		err := rows.Scan(
			&investigation.InvestigationID,
			&investigation.Title,
			&investigation.Description,
			&investigation.Priority,
			&investigation.Status,
			&assigneeID,
			&createdBy,
			&investigation.CreatedAt,
			&investigation.UpdatedAt,
			&closedAt,
			&alertIDsJSON,
			&eventIDsJSON,
			&mitreTacticsJSON,
			&mitreTechniquesJSON,
			&artifactsJSON,
			&notesJSON,
			&investigation.Verdict,
			&investigation.ResolutionCategory,
			&investigation.Summary,
			&affectedAssetsJSON,
			&mlFeedbackJSON,
			&tagsJSON,
		)
		if err != nil {
			sis.logger.Errorf("Failed to scan investigation: %v", err)
			continue
		}

		// Handle nullable fields
		if assigneeID.Valid {
			investigation.AssigneeID = assigneeID.String
		}
		if createdBy.Valid {
			investigation.CreatedBy = createdBy.String
		}

		// Deserialize JSON fields
		json.Unmarshal([]byte(alertIDsJSON), &investigation.AlertIDs)
		json.Unmarshal([]byte(eventIDsJSON), &investigation.EventIDs)
		json.Unmarshal([]byte(mitreTacticsJSON), &investigation.MitreTactics)
		json.Unmarshal([]byte(mitreTechniquesJSON), &investigation.MitreTechniques)
		json.Unmarshal([]byte(artifactsJSON), &investigation.Artifacts)
		json.Unmarshal([]byte(notesJSON), &investigation.Notes)
		json.Unmarshal([]byte(affectedAssetsJSON), &investigation.AffectedAssets)
		json.Unmarshal([]byte(mlFeedbackJSON), &investigation.MLFeedback)
		json.Unmarshal([]byte(tagsJSON), &investigation.Tags)

		if closedAt.Valid {
			investigation.ClosedAt = &closedAt.Time
		}

		investigations = append(investigations, investigation)
	}

	return investigations, nil
}

// GetInvestigationsByAssignee retrieves all investigations assigned to a specific analyst
func (sis *SQLiteInvestigationStorage) GetInvestigationsByAssignee(assigneeID string, limit int, offset int) ([]core.Investigation, error) {
	filters := map[string]interface{}{"assignee_id": assigneeID}
	return sis.GetInvestigations(limit, offset, filters)
}

// EnsureIndexes ensures all indexes are created (called during initialization)
func (sis *SQLiteInvestigationStorage) EnsureIndexes() error {
	// Indexes are already created in ensureTable(), but we can add this as a no-op
	// for interface compatibility
	return nil
}

// InvestigationStatistics represents statistical data about investigations
type InvestigationStatistics struct {
	Total                  int64            `json:"total"`
	OpenCount              int64            `json:"open_count"`
	ClosedCount            int64            `json:"closed_count"`
	ByStatus               map[string]int64 `json:"by_status"`
	ByPriority             map[string]int64 `json:"by_priority"`
	AvgResolutionTimeHours float64          `json:"avg_resolution_time_hours"`
}

// GetInvestigationStatistics retrieves comprehensive statistics about investigations
func (sis *SQLiteInvestigationStorage) GetInvestigationStatistics() (interface{}, error) {
	stats := &InvestigationStatistics{
		ByStatus:   make(map[string]int64),
		ByPriority: make(map[string]int64),
	}

	// Get total count
	totalQuery := "SELECT COUNT(*) FROM investigations"
	err := sis.db.ReadDB.QueryRow(totalQuery).Scan(&stats.Total)
	if err != nil {
		return nil, fmt.Errorf("failed to get total investigation count: %w", err)
	}

	// Get counts by status
	statusQuery := `
		SELECT status, COUNT(*) as count
		FROM investigations
		GROUP BY status
	`
	statusRows, err := sis.db.ReadDB.Query(statusQuery)
	if err != nil {
		return nil, fmt.Errorf("failed to get investigation counts by status: %w", err)
	}
	defer statusRows.Close()

	for statusRows.Next() {
		var status string
		var count int64
		if err := statusRows.Scan(&status, &count); err != nil {
			return nil, fmt.Errorf("failed to scan status row: %w", err)
		}
		stats.ByStatus[status] = count

		// Aggregate open vs closed counts
		// Open includes: open, in_progress, awaiting_review
		// Closed includes: closed, resolved, false_positive
		switch status {
		case "open", "in_progress", "awaiting_review":
			stats.OpenCount += count
		case "closed", "resolved", "false_positive":
			stats.ClosedCount += count
		}
	}

	if err := statusRows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating status rows: %w", err)
	}

	// Get counts by priority
	priorityQuery := `
		SELECT priority, COUNT(*) as count
		FROM investigations
		GROUP BY priority
	`
	priorityRows, err := sis.db.ReadDB.Query(priorityQuery)
	if err != nil {
		return nil, fmt.Errorf("failed to get investigation counts by priority: %w", err)
	}
	defer priorityRows.Close()

	for priorityRows.Next() {
		var priority string
		var count int64
		if err := priorityRows.Scan(&priority, &count); err != nil {
			return nil, fmt.Errorf("failed to scan priority row: %w", err)
		}
		stats.ByPriority[priority] = count
	}

	if err := priorityRows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating priority rows: %w", err)
	}

	// Calculate average resolution time for closed investigations
	// Resolution time is the difference between created_at and closed_at
	avgResolutionQuery := `
		SELECT AVG(
			CAST((julianday(closed_at) - julianday(created_at)) * 24 AS REAL)
		) as avg_hours
		FROM investigations
		WHERE closed_at IS NOT NULL
	`
	var avgHours sql.NullFloat64
	err = sis.db.ReadDB.QueryRow(avgResolutionQuery).Scan(&avgHours)
	if err != nil {
		// Log warning but don't fail the entire request
		sis.logger.Warnf("Failed to calculate average resolution time: %v", err)
		stats.AvgResolutionTimeHours = 0.0
	} else if avgHours.Valid {
		stats.AvgResolutionTimeHours = avgHours.Float64
	} else {
		stats.AvgResolutionTimeHours = 0.0
	}

	return stats, nil
}
