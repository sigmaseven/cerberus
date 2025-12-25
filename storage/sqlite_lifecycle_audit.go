package storage

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"go.uber.org/zap"
)

// LifecycleAuditEntry represents an audit entry for rule lifecycle changes
type LifecycleAuditEntry struct {
	ID             int64                  `json:"id"`
	RuleID         string                 `json:"rule_id"`
	OldStatus      string                 `json:"old_status"`
	NewStatus      string                 `json:"new_status"`
	Reason         string                 `json:"reason"`
	ChangedBy      string                 `json:"changed_by"`
	ChangedAt      time.Time              `json:"changed_at"`
	AdditionalData map[string]interface{} `json:"additional_data,omitempty"`
}

// SQLiteLifecycleAuditStorage handles lifecycle audit persistence
type SQLiteLifecycleAuditStorage struct {
	sqlite *SQLite
	logger *zap.SugaredLogger
}

// NewSQLiteLifecycleAuditStorage creates lifecycle audit storage
func NewSQLiteLifecycleAuditStorage(sqlite *SQLite, logger *zap.SugaredLogger) *SQLiteLifecycleAuditStorage {
	return &SQLiteLifecycleAuditStorage{
		sqlite: sqlite,
		logger: logger,
	}
}

// CreateAuditEntry creates a new lifecycle audit entry
// SECURITY: Uses parameterized queries to prevent SQL injection
// PERFORMANCE: Single insert operation with proper indexing
func (s *SQLiteLifecycleAuditStorage) CreateAuditEntry(entry *LifecycleAuditEntry) error {
	if entry == nil {
		return fmt.Errorf("audit entry cannot be nil")
	}

	// Validate required fields
	if entry.RuleID == "" {
		return fmt.Errorf("rule_id is required")
	}
	if entry.OldStatus == "" {
		return fmt.Errorf("old_status is required")
	}
	if entry.NewStatus == "" {
		return fmt.Errorf("new_status is required")
	}
	if entry.ChangedBy == "" {
		return fmt.Errorf("changed_by is required")
	}

	// Set timestamp if not provided
	if entry.ChangedAt.IsZero() {
		entry.ChangedAt = time.Now().UTC()
	}

	// Serialize additional data if present
	var additionalDataJSON sql.NullString
	if entry.AdditionalData != nil && len(entry.AdditionalData) > 0 {
		data, err := json.Marshal(entry.AdditionalData)
		if err != nil {
			return fmt.Errorf("failed to marshal additional data: %w", err)
		}
		additionalDataJSON = sql.NullString{String: string(data), Valid: true}
	}

	query := `
		INSERT INTO lifecycle_audit (
			rule_id, old_status, new_status, reason, changed_by, changed_at, additional_data
		) VALUES (?, ?, ?, ?, ?, ?, ?)
	`

	result, err := s.sqlite.WriteDB.Exec(
		query,
		entry.RuleID,
		entry.OldStatus,
		entry.NewStatus,
		entry.Reason,
		entry.ChangedBy,
		entry.ChangedAt.Format(time.RFC3339),
		additionalDataJSON,
	)
	if err != nil {
		return fmt.Errorf("failed to create audit entry: %w", err)
	}

	id, err := result.LastInsertId()
	if err == nil {
		entry.ID = id
	}

	s.logger.Infow("Lifecycle audit entry created",
		"rule_id", entry.RuleID,
		"old_status", entry.OldStatus,
		"new_status", entry.NewStatus,
		"changed_by", entry.ChangedBy,
	)

	return nil
}

// GetAuditHistory retrieves lifecycle audit history for a rule
// Returns entries in reverse chronological order (newest first)
func (s *SQLiteLifecycleAuditStorage) GetAuditHistory(ruleID string, limit, offset int) ([]LifecycleAuditEntry, error) {
	if ruleID == "" {
		return nil, fmt.Errorf("rule_id is required")
	}

	// Apply reasonable limits
	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	if offset < 0 {
		offset = 0
	}

	query := `
		SELECT id, rule_id, old_status, new_status, reason, changed_by, changed_at, additional_data
		FROM lifecycle_audit
		WHERE rule_id = ?
		ORDER BY changed_at DESC
		LIMIT ? OFFSET ?
	`

	rows, err := s.sqlite.ReadDB.Query(query, ruleID, limit, offset)
	if err != nil {
		return nil, fmt.Errorf("failed to query audit history: %w", err)
	}
	defer rows.Close()

	return s.scanAuditEntries(rows)
}

// GetAuditHistoryCount returns total count of audit entries for a rule
func (s *SQLiteLifecycleAuditStorage) GetAuditHistoryCount(ruleID string) (int64, error) {
	if ruleID == "" {
		return 0, fmt.Errorf("rule_id is required")
	}

	var count int64
	query := "SELECT COUNT(*) FROM lifecycle_audit WHERE rule_id = ?"
	err := s.sqlite.ReadDB.QueryRow(query, ruleID).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("failed to count audit entries: %w", err)
	}

	return count, nil
}

// GetAuditEntriesByUser retrieves audit entries created by a specific user
func (s *SQLiteLifecycleAuditStorage) GetAuditEntriesByUser(username string, limit, offset int) ([]LifecycleAuditEntry, error) {
	if username == "" {
		return nil, fmt.Errorf("username is required")
	}

	// Apply reasonable limits
	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	if offset < 0 {
		offset = 0
	}

	query := `
		SELECT id, rule_id, old_status, new_status, reason, changed_by, changed_at, additional_data
		FROM lifecycle_audit
		WHERE changed_by = ?
		ORDER BY changed_at DESC
		LIMIT ? OFFSET ?
	`

	rows, err := s.sqlite.ReadDB.Query(query, username, limit, offset)
	if err != nil {
		return nil, fmt.Errorf("failed to query audit entries by user: %w", err)
	}
	defer rows.Close()

	return s.scanAuditEntries(rows)
}

// GetRecentAuditEntries retrieves most recent audit entries across all rules
func (s *SQLiteLifecycleAuditStorage) GetRecentAuditEntries(limit, offset int) ([]LifecycleAuditEntry, error) {
	// Apply reasonable limits
	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	if offset < 0 {
		offset = 0
	}

	query := `
		SELECT id, rule_id, old_status, new_status, reason, changed_by, changed_at, additional_data
		FROM lifecycle_audit
		ORDER BY changed_at DESC
		LIMIT ? OFFSET ?
	`

	rows, err := s.sqlite.ReadDB.Query(query, limit, offset)
	if err != nil {
		return nil, fmt.Errorf("failed to query recent audit entries: %w", err)
	}
	defer rows.Close()

	return s.scanAuditEntries(rows)
}

// scanAuditEntries scans rows into LifecycleAuditEntry slice
func (s *SQLiteLifecycleAuditStorage) scanAuditEntries(rows *sql.Rows) ([]LifecycleAuditEntry, error) {
	var entries []LifecycleAuditEntry

	for rows.Next() {
		var entry LifecycleAuditEntry
		var changedAtStr string
		var additionalDataJSON sql.NullString

		err := rows.Scan(
			&entry.ID,
			&entry.RuleID,
			&entry.OldStatus,
			&entry.NewStatus,
			&entry.Reason,
			&entry.ChangedBy,
			&changedAtStr,
			&additionalDataJSON,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan audit entry: %w", err)
		}

		// Parse timestamp
		changedAt, err := time.Parse(time.RFC3339, changedAtStr)
		if err != nil {
			s.logger.Warnf("Failed to parse changed_at timestamp: %v", err)
			changedAt = time.Now().UTC()
		}
		entry.ChangedAt = changedAt

		// Parse additional data
		if additionalDataJSON.Valid {
			var data map[string]interface{}
			if err := json.Unmarshal([]byte(additionalDataJSON.String), &data); err != nil {
				s.logger.Warnf("Failed to parse additional data for audit entry %d: %v", entry.ID, err)
			} else {
				entry.AdditionalData = data
			}
		}

		entries = append(entries, entry)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating audit entries: %w", err)
	}

	return entries, nil
}

// DeleteAuditEntriesForRule deletes all audit entries for a rule
// This is called when a rule is permanently deleted
func (s *SQLiteLifecycleAuditStorage) DeleteAuditEntriesForRule(ruleID string) error {
	if ruleID == "" {
		return fmt.Errorf("rule_id is required")
	}

	query := "DELETE FROM lifecycle_audit WHERE rule_id = ?"
	result, err := s.sqlite.WriteDB.Exec(query, ruleID)
	if err != nil {
		return fmt.Errorf("failed to delete audit entries: %w", err)
	}

	rows, err := result.RowsAffected()
	if err == nil && rows > 0 {
		s.logger.Infow("Deleted lifecycle audit entries", "rule_id", ruleID, "count", rows)
	}

	return nil
}
