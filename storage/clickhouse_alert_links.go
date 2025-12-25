package storage

import (
	"context"
	"fmt"
	"time"

	"cerberus/core"

	"github.com/ClickHouse/clickhouse-go/v2/lib/driver"
	"go.uber.org/zap"
)

// ClickHouseAlertLinkStorage handles alert link persistence in ClickHouse
type ClickHouseAlertLinkStorage struct {
	conn   driver.Conn
	logger *zap.SugaredLogger
}

// NewClickHouseAlertLinkStorage creates a new ClickHouse alert link storage
func NewClickHouseAlertLinkStorage(conn driver.Conn, logger *zap.SugaredLogger) *ClickHouseAlertLinkStorage {
	return &ClickHouseAlertLinkStorage{
		conn:   conn,
		logger: logger,
	}
}

// CreateLink creates a bi-directional link between two alerts
func (s *ClickHouseAlertLinkStorage) CreateLink(ctx context.Context, link *core.AlertLink) error {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	// Insert both directions in a single batch for efficiency
	batch, err := s.conn.PrepareBatch(ctx, `
		INSERT INTO alert_links (id, alert_id, linked_alert_id, link_type, description, created_by, created_at)
	`)
	if err != nil {
		return fmt.Errorf("failed to prepare batch: %w", err)
	}

	// Forward link (A -> B)
	if err := batch.Append(
		link.ID,
		link.AlertID,
		link.LinkedID,
		link.LinkType,
		link.Description,
		link.CreatedBy,
		link.CreatedAt,
	); err != nil {
		return fmt.Errorf("failed to append forward link: %w", err)
	}

	// Reverse link (B -> A) with a new ID
	reverseID := link.ID + "-rev"
	if err := batch.Append(
		reverseID,
		link.LinkedID,
		link.AlertID,
		link.LinkType,
		link.Description,
		link.CreatedBy,
		link.CreatedAt,
	); err != nil {
		return fmt.Errorf("failed to append reverse link: %w", err)
	}

	if err := batch.Send(); err != nil {
		return fmt.Errorf("failed to send batch: %w", err)
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
func (s *ClickHouseAlertLinkStorage) GetLinkedAlerts(ctx context.Context, alertID string) ([]*core.AlertLink, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	query := `
		SELECT id, alert_id, linked_alert_id, link_type, description, created_by, created_at
		FROM alert_links
		WHERE alert_id = ?
		ORDER BY created_at DESC
	`

	rows, err := s.conn.Query(ctx, query, alertID)
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
			s.logger.Errorf("Failed to scan alert link: %v", err)
			continue
		}
		links = append(links, &link)
	}

	return links, nil
}

// DeleteLink removes a bi-directional link between two alerts
func (s *ClickHouseAlertLinkStorage) DeleteLink(ctx context.Context, alertID, linkedAlertID string) error {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	// Check if link exists first
	exists, err := s.LinkExists(ctx, alertID, linkedAlertID)
	if err != nil {
		return fmt.Errorf("failed to check link existence: %w", err)
	}
	if !exists {
		return ErrNotFound
	}

	// Delete both directions using ALTER TABLE DELETE
	// Note: This is a mutation operation in ClickHouse
	query := `
		ALTER TABLE alert_links DELETE
		WHERE (alert_id = ? AND linked_alert_id = ?)
		   OR (alert_id = ? AND linked_alert_id = ?)
	`

	err = s.conn.Exec(ctx, query, alertID, linkedAlertID, linkedAlertID, alertID)
	if err != nil {
		return fmt.Errorf("failed to delete link: %w", err)
	}

	s.logger.Infow("Alert link deleted (bi-directional)",
		"alert_id", alertID,
		"linked_alert_id", linkedAlertID,
	)

	return nil
}

// LinkExists checks if a link already exists between two alerts (in either direction)
func (s *ClickHouseAlertLinkStorage) LinkExists(ctx context.Context, alertID, linkedAlertID string) (bool, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	query := `
		SELECT count() FROM alert_links
		WHERE (alert_id = ? AND linked_alert_id = ?)
		   OR (alert_id = ? AND linked_alert_id = ?)
	`

	var count uint64
	err := s.conn.QueryRow(ctx, query, alertID, linkedAlertID, linkedAlertID, alertID).Scan(&count)
	if err != nil {
		return false, fmt.Errorf("failed to check link existence: %w", err)
	}

	return count > 0, nil
}
