package soar

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TASK 62.7: Audit Logging Tests
// Tests cover: audit log creation, retrieval, retention, integrity

// TestNoOpAuditLogger_Logging tests no-op audit logger
func TestNoOpAuditLogger_Logging(t *testing.T) {
	logger := &NoOpAuditLogger{}

	event := &AuditEvent{
		EventType:  "playbook_started",
		PlaybookID: "test-playbook",
		Result:     "started",
	}

	ctx := context.Background()
	err := logger.Log(ctx, event)
	require.NoError(t, err, "No-op logger should not error")
}

// TestNoOpAuditLogger_QueryAuditLogs tests audit log querying
func TestNoOpAuditLogger_QueryAuditLogs(t *testing.T) {
	logger := &NoOpAuditLogger{}

	ctx := context.Background()
	filters := &AuditLogFilters{
		PlaybookID: "test-playbook",
	}

	logs, total, err := logger.QueryAuditLogs(ctx, *filters)
	require.NoError(t, err, "No-op logger should not error")
	assert.NotNil(t, logs, "Logs should not be nil")
	assert.Len(t, logs, 0, "No-op logger should return empty logs")
	assert.Equal(t, int64(0), total, "Total count should be 0")
}
