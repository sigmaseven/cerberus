package storage

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"cerberus/soar"

	"go.uber.org/zap"
)

// ClickHouseSOARAuditLogger implements SOAR audit logging using ClickHouse
// TASK 36: Audit log storage for SOAR playbook executions
// Implements soar.AuditLogger interface
type ClickHouseSOARAuditLogger struct {
	clickhouse *ClickHouse
	logger     *zap.SugaredLogger
}

// NewClickHouseSOARAuditLogger creates a new ClickHouse audit logger
// TASK 36.1: Initialize audit logger with ClickHouse connection
func NewClickHouseSOARAuditLogger(clickhouse *ClickHouse, logger *zap.SugaredLogger) (*ClickHouseSOARAuditLogger, error) {
	auditLogger := &ClickHouseSOARAuditLogger{
		clickhouse: clickhouse,
		logger:     logger,
	}

	if err := auditLogger.ensureTable(); err != nil {
		return nil, fmt.Errorf("failed to ensure audit log table: %w", err)
	}

	return auditLogger, nil
}

// ensureTable creates the soar_audit_log table if it doesn't exist
// TASK 36.1: Create ClickHouse audit log schema with proper indexing
func (l *ClickHouseSOARAuditLogger) ensureTable() error {
	query := `
	CREATE TABLE IF NOT EXISTS soar_audit_log (
		id UUID DEFAULT generateUUIDv4(),
		timestamp DateTime64(3) DEFAULT now64(),
		event_type String,
		playbook_id String,
		playbook_execution_id String,
		step_name String,
		action_type String,
		user_id String,
		user_email String,
		alert_id String,
		parameters String,  -- JSON, secrets redacted
		result String,
		error_message String,
		duration_ms UInt32,
		source_ip String,
		user_agent String
	) ENGINE = MergeTree()
	ORDER BY (timestamp, event_type)
	PARTITION BY toYYYYMM(timestamp)
	TTL timestamp + INTERVAL 90 DAY
	SETTINGS index_granularity = 8192;
	`

	// Execute via ClickHouse client
	if l.clickhouse.Conn == nil {
		return fmt.Errorf("ClickHouse connection not available")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	err := l.clickhouse.Conn.Exec(ctx, query)
	if err != nil {
		return fmt.Errorf("failed to create soar_audit_log table: %w", err)
	}

	l.logger.Info("SOAR audit log table ensured in ClickHouse")
	return nil
}

// Log logs an audit event to ClickHouse
// TASK 36.2: Log audit event with secrets redaction
// Implements soar.AuditLogger interface
func (l *ClickHouseSOARAuditLogger) Log(ctx context.Context, event *soar.AuditEvent) error {
	if event == nil {
		return fmt.Errorf("audit event cannot be nil")
	}

	// Redact secrets from parameters
	redactedParams := redactSecrets(event.Parameters)
	paramsJSON, err := json.Marshal(redactedParams)
	if err != nil {
		return fmt.Errorf("failed to marshal redacted parameters: %w", err)
	}

	query := `
		INSERT INTO soar_audit_log (
			event_type, playbook_id, playbook_execution_id, step_name,
			action_type, user_id, user_email, alert_id,
			parameters, result, error_message, duration_ms,
			source_ip, user_agent
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`

	if l.clickhouse.Conn == nil {
		return fmt.Errorf("ClickHouse connection not available")
	}

	// Use ClickHouse native client (batch insert for performance)
	err = l.clickhouse.Conn.Exec(ctx, query,
		event.EventType,
		event.PlaybookID,
		event.PlaybookExecutionID,
		event.StepName,
		event.ActionType,
		event.UserID,
		event.UserEmail,
		event.AlertID,
		string(paramsJSON),
		event.Result,
		event.ErrorMessage,
		event.DurationMs,
		event.SourceIP,
		event.UserAgent,
	)

	if err != nil {
		l.logger.Errorw("Failed to log audit event", "error", err, "event_type", event.EventType)
		return fmt.Errorf("failed to log audit event: %w", err)
	}

	return nil
}

// QueryAuditLogs queries audit logs with filters
// TASK 36.3: Query audit logs with filtering and pagination
// Implements soar.AuditLogger interface
func (l *ClickHouseSOARAuditLogger) QueryAuditLogs(ctx context.Context, filters soar.AuditLogFilters) ([]*soar.AuditEvent, int64, error) {
	whereClauses := []string{}
	params := []interface{}{}

	if filters.PlaybookID != "" {
		whereClauses = append(whereClauses, "playbook_id = ?")
		params = append(params, filters.PlaybookID)
	}

	if filters.UserID != "" {
		whereClauses = append(whereClauses, "user_id = ?")
		params = append(params, filters.UserID)
	}

	if filters.EventType != "" {
		whereClauses = append(whereClauses, "event_type = ?")
		params = append(params, filters.EventType)
	}

	if !filters.StartTime.IsZero() {
		whereClauses = append(whereClauses, "timestamp >= ?")
		params = append(params, filters.StartTime)
	}

	if !filters.EndTime.IsZero() {
		whereClauses = append(whereClauses, "timestamp <= ?")
		params = append(params, filters.EndTime)
	}

	whereClause := ""
	if len(whereClauses) > 0 {
		whereClause = "WHERE " + strings.Join(whereClauses, " AND ")
	}

	// Count query
	countQuery := fmt.Sprintf("SELECT count() FROM soar_audit_log %s", whereClause)

	if l.clickhouse.Conn == nil {
		return nil, 0, fmt.Errorf("ClickHouse connection not available")
	}

	var totalCount uint64
	err := l.clickhouse.Conn.QueryRow(ctx, countQuery, params...).Scan(&totalCount)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to count audit logs: %w", err)
	}

	// Data query with pagination
	limit := filters.Limit
	if limit <= 0 {
		limit = 100 // Default
	}
	if limit > 1000 {
		limit = 1000 // Max
	}

	offset := filters.Offset
	if offset < 0 {
		offset = 0
	}

	dataQuery := fmt.Sprintf(`
		SELECT 
			event_type, playbook_id, playbook_execution_id, step_name,
			action_type, user_id, user_email, alert_id,
			parameters, result, error_message, duration_ms,
			source_ip, user_agent, timestamp
		FROM soar_audit_log
		%s
		ORDER BY timestamp DESC
		LIMIT ? OFFSET ?
	`, whereClause)

	params = append(params, limit, offset)

	rows, err := l.clickhouse.Conn.Query(ctx, dataQuery, params...)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to query audit logs: %w", err)
	}
	defer rows.Close()

	var events []*soar.AuditEvent
	for rows.Next() {
		var event soar.AuditEvent
		var paramsJSON string
		var timestamp time.Time

		err := rows.Scan(
			&event.EventType,
			&event.PlaybookID,
			&event.PlaybookExecutionID,
			&event.StepName,
			&event.ActionType,
			&event.UserID,
			&event.UserEmail,
			&event.AlertID,
			&paramsJSON,
			&event.Result,
			&event.ErrorMessage,
			&event.DurationMs,
			&event.SourceIP,
			&event.UserAgent,
			&timestamp,
		)
		if err != nil {
			l.logger.Errorw("Failed to scan audit log row", "error", err)
			continue
		}

		// Unmarshal parameters JSON
		if paramsJSON != "" {
			var params map[string]interface{}
			if err := json.Unmarshal([]byte(paramsJSON), &params); err != nil {
				l.logger.Warnw("Failed to unmarshal parameters", "error", err)
			} else {
				event.Parameters = params
			}
		}

		eventPtr := event
		events = append(events, &eventPtr)
	}

	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("error iterating audit log rows: %w", err)
	}

	return events, int64(totalCount), nil
}

// redactSecrets redacts sensitive fields from parameters
// TASK 36.2: Secrets redaction before logging
func redactSecrets(params map[string]interface{}) map[string]interface{} {
	if params == nil {
		return nil
	}

	redacted := make(map[string]interface{})
	sensitiveKeys := []string{"password", "api_key", "token", "secret", "auth", "credentials", "apikey", "access_token", "refresh_token"}

	for k, v := range params {
		// Case-insensitive check
		keyLower := strings.ToLower(k)
		isSensitive := false
		for _, sensitive := range sensitiveKeys {
			if strings.Contains(keyLower, strings.ToLower(sensitive)) {
				isSensitive = true
				break
			}
		}

		if isSensitive {
			redacted[k] = "[REDACTED]"
		} else {
			// Recursively check nested maps
			if nestedMap, ok := v.(map[string]interface{}); ok {
				redacted[k] = redactSecrets(nestedMap)
			} else {
				redacted[k] = v
			}
		}
	}

	return redacted
}
