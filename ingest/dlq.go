package ingest

import (
	"database/sql"
	"fmt"
	"time"

	"cerberus/metrics"

	"go.uber.org/zap"
)

// FailedEvent represents a malformed event that failed ingestion
// TASK 7.2: FailedEvent struct for DLQ storage
type FailedEvent struct {
	ListenerID   string // Optional listener ID for per-listener DLQ filtering
	Protocol     string // 'syslog', 'cef', 'json', 'fluentd'
	RawEvent     string // Original raw event data
	ErrorReason  string // Error category (e.g., 'parse_failure', 'validation_error')
	ErrorDetails string // Detailed error message
	SourceIP     string // Source IP address if available
}

// DLQ handles dead-letter queue operations for malformed events
// TASK 7.2: DLQ writer implementation with metrics integration
// REQUIREMENT: docs/requirements/data-ingestion-requirements.md FR-ING-012
type DLQ struct {
	db     *sql.DB
	logger *zap.SugaredLogger
	// TASK 7.4: Metrics are accessed directly through metrics package
}

// NewDLQ creates a new DLQ instance
func NewDLQ(db *sql.DB, logger *zap.SugaredLogger) *DLQ {
	return &DLQ{
		db:     db,
		logger: logger,
	}
}

// Add writes a failed event to the DLQ
// TASK 7.2: DLQ.Add() method with metrics tracking
func (d *DLQ) Add(event *FailedEvent) error {
	query := `
		INSERT INTO dead_letter_queue
		(listener_id, protocol, raw_event, error_reason, error_details, source_ip, status)
		VALUES (?, ?, ?, ?, ?, ?, 'pending')
	`

	_, err := d.db.Exec(query,
		event.ListenerID,
		event.Protocol,
		event.RawEvent,
		event.ErrorReason,
		event.ErrorDetails,
		event.SourceIP,
	)

	if err != nil {
		d.logger.Errorf("Failed to write event to DLQ: %v (protocol: %s, reason: %s)", err, event.Protocol, event.ErrorReason)
		return fmt.Errorf("failed to write event to DLQ: %w", err)
	}

	// Increment metrics on successful write
	metrics.DLQEventsTotal.Inc()
	metrics.DLQEventsByReason.WithLabelValues(event.ErrorReason).Inc()
	metrics.DLQEventsByProtocol.WithLabelValues(event.Protocol).Inc()

	d.logger.Debugf("Event written to DLQ: protocol=%s, reason=%s, source_ip=%s", event.Protocol, event.ErrorReason, event.SourceIP)
	return nil
}

// Get retrieves a DLQ event by ID
func (d *DLQ) Get(id int64) (*DLQEvent, error) {
	query := `
		SELECT id, timestamp, COALESCE(listener_id, '') as listener_id, protocol, raw_event, error_reason, error_details,
		       source_ip, retries, status, created_at
		FROM dead_letter_queue
		WHERE id = ?
	`

	var event DLQEvent
	err := d.db.QueryRow(query, id).Scan(
		&event.ID,
		&event.Timestamp,
		&event.ListenerID,
		&event.Protocol,
		&event.RawEvent,
		&event.ErrorReason,
		&event.ErrorDetails,
		&event.SourceIP,
		&event.Retries,
		&event.Status,
		&event.CreatedAt,
	)

	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("DLQ event not found: id=%d", id)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get DLQ event: %w", err)
	}

	return &event, nil
}

// DLQEvent represents a DLQ event record
type DLQEvent struct {
	ID           int64
	Timestamp    time.Time
	ListenerID   string
	Protocol     string
	RawEvent     string
	ErrorReason  string
	ErrorDetails string
	SourceIP     string
	Retries      int
	Status       string // 'pending', 'replayed', 'discarded'
	CreatedAt    time.Time
}

// List retrieves DLQ events with pagination and optional filtering
func (d *DLQ) List(page, limit int, filters map[string]interface{}) ([]*DLQEvent, int, error) {
	whereClauses := []string{}
	args := []interface{}{}

	if status, ok := filters["status"]; ok && status != nil {
		if statusStr, ok := status.(string); ok && statusStr != "" {
			whereClauses = append(whereClauses, "status = ?")
			args = append(args, statusStr)
		}
	}
	if protocol, ok := filters["protocol"]; ok && protocol != nil {
		if protocolStr, ok := protocol.(string); ok && protocolStr != "" {
			whereClauses = append(whereClauses, "protocol = ?")
			args = append(args, protocolStr)
		}
	}
	if listenerID, ok := filters["listener_id"]; ok && listenerID != nil {
		if listenerIDStr, ok := listenerID.(string); ok && listenerIDStr != "" {
			whereClauses = append(whereClauses, "listener_id = ?")
			args = append(args, listenerIDStr)
		}
	}

	whereClause := ""
	if len(whereClauses) > 0 {
		whereClause = "WHERE "
		for i, clause := range whereClauses {
			whereClause += clause
			if i < len(whereClauses)-1 {
				whereClause += " AND "
			}
		}
	}

	// Get total count
	countQuery := fmt.Sprintf("SELECT COUNT(*) FROM dead_letter_queue %s", whereClause)
	var total int
	err := d.db.QueryRow(countQuery, args...).Scan(&total)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to count DLQ events: %w", err)
	}

	// Get paginated results
	query := fmt.Sprintf(`
		SELECT id, timestamp, COALESCE(listener_id, '') as listener_id, protocol, raw_event, error_reason, error_details,
		       source_ip, retries, status, created_at
		FROM dead_letter_queue
		%s
		ORDER BY timestamp DESC
		LIMIT ? OFFSET ?
	`, whereClause)

	offset := (page - 1) * limit
	args = append(args, limit, offset)

	rows, err := d.db.Query(query, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to query DLQ events: %w", err)
	}
	defer rows.Close()

	events := []*DLQEvent{}
	for rows.Next() {
		var event DLQEvent
		err := rows.Scan(
			&event.ID,
			&event.Timestamp,
			&event.ListenerID,
			&event.Protocol,
			&event.RawEvent,
			&event.ErrorReason,
			&event.ErrorDetails,
			&event.SourceIP,
			&event.Retries,
			&event.Status,
			&event.CreatedAt,
		)
		if err != nil {
			return nil, 0, fmt.Errorf("failed to scan DLQ event: %w", err)
		}
		events = append(events, &event)
	}

	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("error iterating DLQ events: %w", err)
	}

	return events, total, nil
}

// UpdateStatus updates the status of a DLQ event
func (d *DLQ) UpdateStatus(id int64, status string) error {
	query := `UPDATE dead_letter_queue SET status = ? WHERE id = ?`
	_, err := d.db.Exec(query, status, id)
	if err != nil {
		return fmt.Errorf("failed to update DLQ event status: %w", err)
	}
	return nil
}

// IncrementRetries increments the retry counter for a DLQ event
func (d *DLQ) IncrementRetries(id int64) error {
	query := `UPDATE dead_letter_queue SET retries = retries + 1 WHERE id = ?`
	_, err := d.db.Exec(query, id)
	if err != nil {
		return fmt.Errorf("failed to increment DLQ event retries: %w", err)
	}
	return nil
}
