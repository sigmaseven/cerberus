package storage

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"go.uber.org/zap"
)

// FieldMappingAuditEntry represents an audit entry for field mapping lifecycle changes
type FieldMappingAuditEntry struct {
	ID             int64                  `json:"id"`
	MappingID      string                 `json:"mapping_id"`
	OldStatus      string                 `json:"old_status"`
	NewStatus      string                 `json:"new_status"`
	Reason         string                 `json:"reason"`
	ChangedBy      string                 `json:"changed_by"`
	ChangedAt      time.Time              `json:"changed_at"`
	AdditionalData map[string]interface{} `json:"additional_data,omitempty"`
}

// FieldMappingAuditStorage interface for field mapping audit operations
type FieldMappingAuditStorage interface {
	CreateAuditEntry(entry *FieldMappingAuditEntry) error
	GetAuditHistory(mappingID string, limit, offset int) ([]FieldMappingAuditEntry, error)
	GetAuditHistoryCount(mappingID string) (int64, error)
	DeleteAuditEntriesForMapping(mappingID string) error
}

// SQLiteFieldMappingAuditStorage handles field mapping lifecycle audit persistence
type SQLiteFieldMappingAuditStorage struct {
	sqlite *SQLite
	logger *zap.SugaredLogger
}

// NewSQLiteFieldMappingAuditStorage creates field mapping audit storage
func NewSQLiteFieldMappingAuditStorage(sqlite *SQLite, logger *zap.SugaredLogger) *SQLiteFieldMappingAuditStorage {
	return &SQLiteFieldMappingAuditStorage{
		sqlite: sqlite,
		logger: logger,
	}
}

// CreateAuditEntry creates a new field mapping lifecycle audit entry
// SECURITY: Uses parameterized queries to prevent SQL injection
func (s *SQLiteFieldMappingAuditStorage) CreateAuditEntry(entry *FieldMappingAuditEntry) error {
	if entry == nil {
		return fmt.Errorf("audit entry cannot be nil")
	}

	// Validate required fields
	if entry.MappingID == "" {
		return fmt.Errorf("mapping_id is required")
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
		INSERT INTO field_mapping_audit (
			mapping_id, old_status, new_status, reason, changed_by, changed_at, additional_data
		) VALUES (?, ?, ?, ?, ?, ?, ?)
	`

	result, err := s.sqlite.WriteDB.Exec(
		query,
		entry.MappingID,
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

	s.logger.Infow("Field mapping lifecycle audit entry created",
		"mapping_id", entry.MappingID,
		"old_status", entry.OldStatus,
		"new_status", entry.NewStatus,
		"changed_by", entry.ChangedBy,
	)

	return nil
}

// GetAuditHistory retrieves lifecycle audit history for a field mapping
// Returns entries in reverse chronological order (newest first)
func (s *SQLiteFieldMappingAuditStorage) GetAuditHistory(mappingID string, limit, offset int) ([]FieldMappingAuditEntry, error) {
	if mappingID == "" {
		return nil, fmt.Errorf("mapping_id is required")
	}

	// Apply reasonable limits
	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	if offset < 0 {
		offset = 0
	}

	query := `
		SELECT id, mapping_id, old_status, new_status, reason, changed_by, changed_at, additional_data
		FROM field_mapping_audit
		WHERE mapping_id = ?
		ORDER BY changed_at DESC
		LIMIT ? OFFSET ?
	`

	rows, err := s.sqlite.ReadDB.Query(query, mappingID, limit, offset)
	if err != nil {
		return nil, fmt.Errorf("failed to query audit history: %w", err)
	}
	defer rows.Close()

	return s.scanAuditEntries(rows)
}

// GetAuditHistoryCount returns total count of audit entries for a field mapping
func (s *SQLiteFieldMappingAuditStorage) GetAuditHistoryCount(mappingID string) (int64, error) {
	if mappingID == "" {
		return 0, fmt.Errorf("mapping_id is required")
	}

	var count int64
	query := "SELECT COUNT(*) FROM field_mapping_audit WHERE mapping_id = ?"
	err := s.sqlite.ReadDB.QueryRow(query, mappingID).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("failed to count audit entries: %w", err)
	}

	return count, nil
}

// scanAuditEntries scans rows into FieldMappingAuditEntry slice
func (s *SQLiteFieldMappingAuditStorage) scanAuditEntries(rows *sql.Rows) ([]FieldMappingAuditEntry, error) {
	var entries []FieldMappingAuditEntry

	for rows.Next() {
		var entry FieldMappingAuditEntry
		var changedAtStr string
		var additionalDataJSON sql.NullString

		err := rows.Scan(
			&entry.ID,
			&entry.MappingID,
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

// DeleteAuditEntriesForMapping deletes all audit entries for a field mapping
// This is called when a field mapping is permanently deleted
func (s *SQLiteFieldMappingAuditStorage) DeleteAuditEntriesForMapping(mappingID string) error {
	if mappingID == "" {
		return fmt.Errorf("mapping_id is required")
	}

	query := "DELETE FROM field_mapping_audit WHERE mapping_id = ?"
	result, err := s.sqlite.WriteDB.Exec(query, mappingID)
	if err != nil {
		return fmt.Errorf("failed to delete audit entries: %w", err)
	}

	rows, err := result.RowsAffected()
	if err == nil && rows > 0 {
		s.logger.Infow("Deleted field mapping audit entries", "mapping_id", mappingID, "count", rows)
	}

	return nil
}
