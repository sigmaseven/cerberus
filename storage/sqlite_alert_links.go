package storage

import (
	"context"
	"fmt"
	"time"

	"cerberus/core"

	"go.uber.org/zap"
)

// SQLiteAlertLinkStorage handles alert link persistence in SQLite
type SQLiteAlertLinkStorage struct {
	sqlite *SQLite
	logger *zap.SugaredLogger
}

// NewSQLiteAlertLinkStorage creates a new alert link storage
func NewSQLiteAlertLinkStorage(sqlite *SQLite, logger *zap.SugaredLogger) (*SQLiteAlertLinkStorage, error) {
	storage := &SQLiteAlertLinkStorage{
		sqlite: sqlite,
		logger: logger,
	}

	if err := storage.ensureTable(); err != nil {
		return nil, fmt.Errorf("failed to ensure alert_links table: %w", err)
	}

	return storage, nil
}

// ensureTable creates the alert_links table if it doesn't exist
func (s *SQLiteAlertLinkStorage) ensureTable() error {
	schema := `
	CREATE TABLE IF NOT EXISTS alert_links (
		id TEXT PRIMARY KEY,
		alert_id TEXT NOT NULL,
		linked_alert_id TEXT NOT NULL,
		link_type TEXT NOT NULL DEFAULT 'related',
		description TEXT DEFAULT '',
		created_by TEXT NOT NULL,
		created_at DATETIME NOT NULL,
		UNIQUE(alert_id, linked_alert_id)
	);
	CREATE INDEX IF NOT EXISTS idx_alert_links_alert_id ON alert_links(alert_id);
	CREATE INDEX IF NOT EXISTS idx_alert_links_linked_alert_id ON alert_links(linked_alert_id);
	`

	_, err := s.sqlite.DB.Exec(schema)
	if err != nil {
		return fmt.Errorf("failed to create alert_links table: %w", err)
	}

	s.logger.Info("Alert links table ensured in SQLite")
	return nil
}

// CreateLink creates a bi-directional link between two alerts
func (s *SQLiteAlertLinkStorage) CreateLink(ctx context.Context, link *core.AlertLink) error {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	// Use transaction to ensure both directions are created atomically
	tx, err := s.sqlite.DB.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback()

	query := `
		INSERT INTO alert_links (id, alert_id, linked_alert_id, link_type, description, created_by, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(alert_id, linked_alert_id) DO NOTHING
	`

	// Insert forward link (A -> B)
	_, err = tx.ExecContext(ctx, query,
		link.ID,
		link.AlertID,
		link.LinkedID,
		link.LinkType,
		link.Description,
		link.CreatedBy,
		link.CreatedAt,
	)
	if err != nil {
		return fmt.Errorf("failed to insert forward link: %w", err)
	}

	// Insert reverse link (B -> A) with a new ID
	reverseID := link.ID + "-rev"
	_, err = tx.ExecContext(ctx, query,
		reverseID,
		link.LinkedID,
		link.AlertID,
		link.LinkType,
		link.Description,
		link.CreatedBy,
		link.CreatedAt,
	)
	if err != nil {
		return fmt.Errorf("failed to insert reverse link: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	s.logger.Infow("Alert link created (bi-directional)",
		"alert_id", link.AlertID,
		"linked_alert_id", link.LinkedID,
		"link_type", link.LinkType,
		"created_by", link.CreatedBy,
	)

	return nil
}

// GetLinkedAlerts returns all alerts linked to the given alert ID
// NOTE: Uses WriteDB (DB) instead of ReadDB to ensure immediate consistency after writes.
// In SQLite WAL mode with separate read/write connection pools, the read pool may not
// immediately see commits from the write pool due to snapshot isolation.
// Since alert links are often queried immediately after creation, we need strong consistency.
func (s *SQLiteAlertLinkStorage) GetLinkedAlerts(ctx context.Context, alertID string) ([]*core.AlertLink, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	query := `
		SELECT id, alert_id, linked_alert_id, link_type, description, created_by, created_at
		FROM alert_links
		WHERE alert_id = ?
		ORDER BY created_at DESC
	`

	// Use DB (write pool) for strong consistency - ensures we see recently committed writes
	rows, err := s.sqlite.DB.QueryContext(ctx, query, alertID)
	if err != nil {
		return nil, fmt.Errorf("failed to query linked alerts: %w", err)
	}
	defer rows.Close()

	var links []*core.AlertLink
	for rows.Next() {
		var link core.AlertLink
		err := rows.Scan(
			&link.ID,
			&link.AlertID,
			&link.LinkedID,
			&link.LinkType,
			&link.Description,
			&link.CreatedBy,
			&link.CreatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan alert link: %w", err)
		}
		links = append(links, &link)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating alert links: %w", err)
	}

	return links, nil
}

// DeleteLink removes a bi-directional link between two alerts
func (s *SQLiteAlertLinkStorage) DeleteLink(ctx context.Context, alertID, linkedAlertID string) error {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	// Delete both directions in a transaction
	tx, err := s.sqlite.DB.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback()

	query := `DELETE FROM alert_links WHERE alert_id = ? AND linked_alert_id = ?`

	// Delete forward link
	result, err := tx.ExecContext(ctx, query, alertID, linkedAlertID)
	if err != nil {
		return fmt.Errorf("failed to delete forward link: %w", err)
	}

	forwardRows, _ := result.RowsAffected()

	// Delete reverse link
	result, err = tx.ExecContext(ctx, query, linkedAlertID, alertID)
	if err != nil {
		return fmt.Errorf("failed to delete reverse link: %w", err)
	}

	reverseRows, _ := result.RowsAffected()

	if forwardRows == 0 && reverseRows == 0 {
		return ErrNotFound
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	s.logger.Infow("Alert link deleted (bi-directional)",
		"alert_id", alertID,
		"linked_alert_id", linkedAlertID,
	)

	return nil
}

// LinkExists checks if a link already exists between two alerts (in either direction)
// NOTE: Uses WriteDB (DB) for strong consistency - ensures we see recently committed writes
func (s *SQLiteAlertLinkStorage) LinkExists(ctx context.Context, alertID, linkedAlertID string) (bool, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	query := `
		SELECT COUNT(*) FROM alert_links
		WHERE (alert_id = ? AND linked_alert_id = ?)
		   OR (alert_id = ? AND linked_alert_id = ?)
	`

	var count int
	// Use DB (write pool) for strong consistency
	err := s.sqlite.DB.QueryRowContext(ctx, query, alertID, linkedAlertID, linkedAlertID, alertID).Scan(&count)
	if err != nil {
		return false, fmt.Errorf("failed to check link existence: %w", err)
	}

	return count > 0, nil
}
