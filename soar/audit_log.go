package soar

import (
	"context"
	"time"
)

// AuditLogger interface for SOAR audit logging
// TASK 36: Audit logger interface for playbook and action execution logging
type AuditLogger interface {
	// Log logs an audit event
	Log(ctx context.Context, event *AuditEvent) error

	// QueryAuditLogs queries audit logs with filters
	QueryAuditLogs(ctx context.Context, filters AuditLogFilters) ([]*AuditEvent, int64, error)
}

// AuditEvent represents an audit log entry for SOAR operations
// TASK 36: Audit event structure matching ClickHouse schema
type AuditEvent struct {
	EventType           string                 `json:"event_type"` // playbook_started, step_executed, etc.
	PlaybookID          string                 `json:"playbook_id"`
	PlaybookExecutionID string                 `json:"playbook_execution_id"`
	StepName            string                 `json:"step_name"`
	ActionType          string                 `json:"action_type"` // webhook, email, script, etc.
	UserID              string                 `json:"user_id"`
	UserEmail           string                 `json:"user_email"`
	AlertID             string                 `json:"alert_id"`
	Parameters          map[string]interface{} `json:"parameters"` // Redacted before logging
	Result              string                 `json:"result"`     // success, failure, timeout, skipped
	ErrorMessage        string                 `json:"error_message"`
	DurationMs          uint32                 `json:"duration_ms"`
	SourceIP            string                 `json:"source_ip"`
	UserAgent           string                 `json:"user_agent"`
}

// AuditLogFilters represents filters for querying audit logs
// TASK 36: Filter structure for audit log queries
type AuditLogFilters struct {
	PlaybookID string
	UserID     string
	EventType  string
	StartTime  time.Time
	EndTime    time.Time
	Limit      int
	Offset     int
}

// NoOpAuditLogger is a no-op implementation that discards all audit events
// TASK 36: Fallback logger when ClickHouse is not available
type NoOpAuditLogger struct{}

// Log discards the audit event
func (n *NoOpAuditLogger) Log(ctx context.Context, event *AuditEvent) error {
	return nil
}

// QueryAuditLogs returns empty results
func (n *NoOpAuditLogger) QueryAuditLogs(ctx context.Context, filters AuditLogFilters) ([]*AuditEvent, int64, error) {
	return []*AuditEvent{}, 0, nil
}
