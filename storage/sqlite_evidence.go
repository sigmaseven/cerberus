package storage

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"cerberus/core"

	"go.uber.org/zap"
)

// EvidenceStorage handles evidence persistence in SQLite
type SQLiteEvidenceStorage struct {
	sqlite *SQLite
	logger *zap.SugaredLogger
}

// NewSQLiteEvidenceStorage creates a new evidence storage
func NewSQLiteEvidenceStorage(sqlite *SQLite, logger *zap.SugaredLogger) (*SQLiteEvidenceStorage, error) {
	storage := &SQLiteEvidenceStorage{
		sqlite: sqlite,
		logger: logger,
	}

	if err := storage.ensureTable(); err != nil {
		return nil, fmt.Errorf("failed to ensure evidence table: %w", err)
	}

	return storage, nil
}

// ensureTable creates the evidence table if it doesn't exist
func (s *SQLiteEvidenceStorage) ensureTable() error {
	// Check if table exists with old schema (has 'original_name' column instead of 'name')
	// Use DB for schema checks since we're about to modify the schema
	var hasOldSchema bool
	row := s.sqlite.DB.QueryRow("SELECT COUNT(*) FROM pragma_table_info('evidence') WHERE name='original_name'")
	var count int
	if err := row.Scan(&count); err == nil && count > 0 {
		hasOldSchema = true
	}

	// Drop old table if schema is outdated
	if hasOldSchema {
		s.logger.Info("Dropping old evidence table with outdated schema")
		if _, err := s.sqlite.DB.Exec("DROP TABLE IF EXISTS evidence"); err != nil {
			return fmt.Errorf("failed to drop old evidence table: %w", err)
		}
	}

	schema := `
	CREATE TABLE IF NOT EXISTS evidence (
		id TEXT PRIMARY KEY,
		alert_id TEXT,
		investigation_id TEXT,
		type TEXT NOT NULL DEFAULT 'file',
		filename TEXT NOT NULL,
		name TEXT NOT NULL,
		mime_type TEXT NOT NULL,
		size INTEGER NOT NULL,
		description TEXT DEFAULT '',
		uploaded_by_id TEXT NOT NULL,
		uploaded_at DATETIME NOT NULL,
		hash TEXT DEFAULT '',
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);
	CREATE INDEX IF NOT EXISTS idx_evidence_alert_id ON evidence(alert_id);
	CREATE INDEX IF NOT EXISTS idx_evidence_investigation_id ON evidence(investigation_id);
	CREATE INDEX IF NOT EXISTS idx_evidence_uploaded_at ON evidence(uploaded_at);
	`

	_, err := s.sqlite.DB.Exec(schema)
	if err != nil {
		return fmt.Errorf("failed to create evidence table: %w", err)
	}

	s.logger.Info("Evidence table ensured in SQLite")
	return nil
}

// CreateEvidence stores evidence metadata
func (s *SQLiteEvidenceStorage) CreateEvidence(ctx context.Context, evidence *core.Evidence) error {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	query := `
		INSERT INTO evidence (id, alert_id, investigation_id, type, filename, name, mime_type, size, description, uploaded_by_id, uploaded_at, hash)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`

	_, err := s.sqlite.DB.ExecContext(ctx, query,
		evidence.ID,
		evidence.AlertID,
		evidence.InvestigationID,
		string(evidence.Type),
		evidence.Filename,
		evidence.Name,
		evidence.MimeType,
		evidence.Size,
		evidence.Description,
		evidence.UploadedByID,
		evidence.UploadedAt,
		evidence.Hash,
	)

	if err != nil {
		return fmt.Errorf("failed to insert evidence: %w", err)
	}

	s.logger.Infow("Evidence created",
		"id", evidence.ID,
		"alert_id", evidence.AlertID,
		"filename", evidence.Name,
		"size", evidence.Size,
	)

	return nil
}

// GetEvidence retrieves evidence by ID
// NOTE: Uses WriteDB (DB) for strong consistency - ensures we see recently committed writes
func (s *SQLiteEvidenceStorage) GetEvidence(ctx context.Context, id string) (*core.Evidence, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	query := `
		SELECT id, alert_id, investigation_id, type, filename, name, mime_type, size, description, uploaded_by_id, uploaded_at, hash
		FROM evidence
		WHERE id = ?
	`

	var evidence core.Evidence
	var alertID, investigationID sql.NullString
	var evidenceType string

	// Use DB (write pool) for strong consistency
	err := s.sqlite.DB.QueryRowContext(ctx, query, id).Scan(
		&evidence.ID,
		&alertID,
		&investigationID,
		&evidenceType,
		&evidence.Filename,
		&evidence.Name,
		&evidence.MimeType,
		&evidence.Size,
		&evidence.Description,
		&evidence.UploadedByID,
		&evidence.UploadedAt,
		&evidence.Hash,
	)

	if err == sql.ErrNoRows {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get evidence: %w", err)
	}

	evidence.Type = core.EvidenceType(evidenceType)
	if alertID.Valid {
		evidence.AlertID = alertID.String
	}
	if investigationID.Valid {
		evidence.InvestigationID = investigationID.String
	}

	return &evidence, nil
}

// ListEvidenceByAlert lists all evidence for an alert
// NOTE: Uses WriteDB (DB) for strong consistency - ensures we see recently committed writes
func (s *SQLiteEvidenceStorage) ListEvidenceByAlert(ctx context.Context, alertID string) ([]*core.Evidence, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	query := `
		SELECT id, alert_id, investigation_id, type, filename, name, mime_type, size, description, uploaded_by_id, uploaded_at, hash
		FROM evidence
		WHERE alert_id = ?
		ORDER BY uploaded_at DESC
	`

	// Use DB (write pool) for strong consistency
	rows, err := s.sqlite.DB.QueryContext(ctx, query, alertID)
	if err != nil {
		return nil, fmt.Errorf("failed to list evidence: %w", err)
	}
	defer rows.Close()

	return s.scanEvidenceRows(rows)
}

// ListEvidenceByInvestigation lists all evidence for an investigation
// NOTE: Uses WriteDB (DB) for strong consistency - ensures we see recently committed writes
func (s *SQLiteEvidenceStorage) ListEvidenceByInvestigation(ctx context.Context, investigationID string) ([]*core.Evidence, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	query := `
		SELECT id, alert_id, investigation_id, type, filename, name, mime_type, size, description, uploaded_by_id, uploaded_at, hash
		FROM evidence
		WHERE investigation_id = ?
		ORDER BY uploaded_at DESC
	`

	// Use DB (write pool) for strong consistency
	rows, err := s.sqlite.DB.QueryContext(ctx, query, investigationID)
	if err != nil {
		return nil, fmt.Errorf("failed to list evidence: %w", err)
	}
	defer rows.Close()

	return s.scanEvidenceRows(rows)
}

// DeleteEvidence removes evidence metadata
func (s *SQLiteEvidenceStorage) DeleteEvidence(ctx context.Context, id string) error {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	result, err := s.sqlite.DB.ExecContext(ctx, "DELETE FROM evidence WHERE id = ?", id)
	if err != nil {
		return fmt.Errorf("failed to delete evidence: %w", err)
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return ErrNotFound
	}

	s.logger.Infow("Evidence deleted", "id", id)
	return nil
}

// scanEvidenceRows scans multiple evidence rows
func (s *SQLiteEvidenceStorage) scanEvidenceRows(rows *sql.Rows) ([]*core.Evidence, error) {
	var evidenceList []*core.Evidence

	for rows.Next() {
		var evidence core.Evidence
		var alertID, investigationID sql.NullString
		var evidenceType string

		err := rows.Scan(
			&evidence.ID,
			&alertID,
			&investigationID,
			&evidenceType,
			&evidence.Filename,
			&evidence.Name,
			&evidence.MimeType,
			&evidence.Size,
			&evidence.Description,
			&evidence.UploadedByID,
			&evidence.UploadedAt,
			&evidence.Hash,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan evidence row: %w", err)
		}

		evidence.Type = core.EvidenceType(evidenceType)
		if alertID.Valid {
			evidence.AlertID = alertID.String
		}
		if investigationID.Valid {
			evidence.InvestigationID = investigationID.String
		}

		evidenceList = append(evidenceList, &evidence)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating evidence rows: %w", err)
	}

	return evidenceList, nil
}
