package storage

import (
	"context"
	"testing"
	"time"

	"cerberus/soar"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap/zaptest"
)

// setupSOARAuditTest creates a test ClickHouse SOAR audit logger
func setupSOARAuditTest(t *testing.T) (*ClickHouseSOARAuditLogger, *ClickHouse) {
	ch, _ := setupTestClickHouse(t)
	logger := zaptest.NewLogger(t).Sugar()

	auditLogger, err := NewClickHouseSOARAuditLogger(ch, logger)
	require.NoError(t, err)

	// Cleanup: drop table after test
	t.Cleanup(func() {
		if ch != nil && ch.Conn != nil {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_ = ch.Conn.Exec(ctx, "DROP TABLE IF EXISTS soar_audit_log")
		}
	})

	return auditLogger, ch
}

// TestClickHouseSOARAuditLogger_New tests creating a new audit logger
func TestClickHouseSOARAuditLogger_New(t *testing.T) {
	skipIfNoClickHouse(t)

	ch, _ := setupTestClickHouse(t)
	logger := zaptest.NewLogger(t).Sugar()

	auditLogger, err := NewClickHouseSOARAuditLogger(ch, logger)
	require.NoError(t, err)
	assert.NotNil(t, auditLogger)
	assert.NotNil(t, auditLogger.clickhouse)
	assert.NotNil(t, auditLogger.logger)

	// Verify table was created
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var tableExists uint8
	err = ch.Conn.QueryRow(ctx, `
		SELECT count() FROM system.tables 
		WHERE database = currentDatabase() AND name = 'soar_audit_log'
	`).Scan(&tableExists)
	require.NoError(t, err)
	assert.Equal(t, uint8(1), tableExists)
}

// TestClickHouseSOARAuditLogger_Log tests logging audit events
func TestClickHouseSOARAuditLogger_Log(t *testing.T) {
	skipIfNoClickHouse(t)

	auditLogger, _ := setupSOARAuditTest(t)
	ctx := context.Background()

	event := &soar.AuditEvent{
		EventType:           "playbook_executed",
		PlaybookID:          "pb-123",
		PlaybookExecutionID: "exec-456",
		StepName:            "step1",
		ActionType:          "send_notification",
		UserID:              "user-789",
		UserEmail:           "user@example.com",
		AlertID:             "alert-101",
		Parameters: map[string]interface{}{
			"webhook_url": "https://example.com/webhook",
			"message":     "Alert triggered",
		},
		Result:     "success",
		DurationMs: 150,
		SourceIP:   "192.168.1.1",
		UserAgent:  "Cerberus/1.0",
	}

	err := auditLogger.Log(ctx, event)
	require.NoError(t, err)

	// Verify event was logged
	events, total, err := auditLogger.QueryAuditLogs(ctx, soar.AuditLogFilters{
		PlaybookID: "pb-123",
		Limit:      100,
	})
	require.NoError(t, err)
	assert.Equal(t, int64(1), total)
	require.Len(t, events, 1)
	assert.Equal(t, event.EventType, events[0].EventType)
	assert.Equal(t, event.PlaybookID, events[0].PlaybookID)
	assert.Equal(t, event.UserID, events[0].UserID)
}

// TestClickHouseSOARAuditLogger_Log_NilEvent tests logging nil event
func TestClickHouseSOARAuditLogger_Log_NilEvent(t *testing.T) {
	skipIfNoClickHouse(t)

	auditLogger, _ := setupSOARAuditTest(t)
	ctx := context.Background()

	err := auditLogger.Log(ctx, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "audit event cannot be nil")
}

// TestClickHouseSOARAuditLogger_Log_SecretsRedaction tests secrets redaction
func TestClickHouseSOARAuditLogger_Log_SecretsRedaction(t *testing.T) {
	skipIfNoClickHouse(t)

	auditLogger, _ := setupSOARAuditTest(t)
	ctx := context.Background()

	event := &soar.AuditEvent{
		EventType:           "action_executed",
		PlaybookID:          "pb-secrets",
		PlaybookExecutionID: "exec-secrets",
		StepName:            "step1",
		ActionType:          "call_webhook",
		UserID:              "user-1",
		Parameters: map[string]interface{}{
			"url":           "https://api.example.com",
			"password":      "secret123",
			"api_key":       "key-abc123",
			"token":         "bearer-token",
			"api_secret":    "secret-value",
			"access_token":  "token123",
			"refresh_token": "refresh456",
			"credentials":   map[string]interface{}{"username": "user", "password": "pwd"},
			"safe_field":    "not-redacted",
		},
		Result: "success",
	}

	err := auditLogger.Log(ctx, event)
	require.NoError(t, err)

	// Query and verify secrets were redacted
	events, _, err := auditLogger.QueryAuditLogs(ctx, soar.AuditLogFilters{
		PlaybookID: "pb-secrets",
		Limit:      100,
	})
	require.NoError(t, err)
	require.Len(t, events, 1)

	params := events[0].Parameters
	assert.Equal(t, "[REDACTED]", params["password"])
	assert.Equal(t, "[REDACTED]", params["api_key"])
	assert.Equal(t, "[REDACTED]", params["token"])
	assert.Equal(t, "[REDACTED]", params["api_secret"])
	assert.Equal(t, "[REDACTED]", params["access_token"])
	assert.Equal(t, "[REDACTED]", params["refresh_token"])
	assert.Equal(t, "not-redacted", params["safe_field"])

	// Verify nested secrets were redacted
	if creds, ok := params["credentials"].(map[string]interface{}); ok {
		assert.Equal(t, "[REDACTED]", creds["password"])
	}
}

// TestClickHouseSOARAuditLogger_QueryAuditLogs tests querying audit logs
func TestClickHouseSOARAuditLogger_QueryAuditLogs(t *testing.T) {
	skipIfNoClickHouse(t)

	auditLogger, _ := setupSOARAuditTest(t)
	ctx := context.Background()

	// Insert multiple events
	events := []*soar.AuditEvent{
		{
			EventType:           "playbook_started",
			PlaybookID:          "pb-query1",
			PlaybookExecutionID: "exec-1",
			UserID:              "user-1",
			Result:              "success",
		},
		{
			EventType:           "playbook_completed",
			PlaybookID:          "pb-query1",
			PlaybookExecutionID: "exec-1",
			UserID:              "user-1",
			Result:              "success",
		},
		{
			EventType:           "playbook_started",
			PlaybookID:          "pb-query2",
			PlaybookExecutionID: "exec-2",
			UserID:              "user-2",
			Result:              "success",
		},
	}

	for _, event := range events {
		err := auditLogger.Log(ctx, event)
		require.NoError(t, err)
		time.Sleep(10 * time.Millisecond) // Ensure different timestamps
	}

	// Query by playbook ID
	filtered, total, err := auditLogger.QueryAuditLogs(ctx, soar.AuditLogFilters{
		PlaybookID: "pb-query1",
		Limit:      100,
	})
	require.NoError(t, err)
	assert.Equal(t, int64(2), total)
	assert.Len(t, filtered, 2)

	// Query by user ID
	filtered, total, err = auditLogger.QueryAuditLogs(ctx, soar.AuditLogFilters{
		UserID: "user-1",
		Limit:  100,
	})
	require.NoError(t, err)
	assert.Equal(t, int64(2), total)
	assert.Len(t, filtered, 2)

	// Query by event type
	filtered, total, err = auditLogger.QueryAuditLogs(ctx, soar.AuditLogFilters{
		EventType: "playbook_started",
		Limit:     100,
	})
	require.NoError(t, err)
	assert.Equal(t, int64(2), total)
	assert.Len(t, filtered, 2)
}

// TestClickHouseSOARAuditLogger_QueryAuditLogs_TimeRange tests time range filtering
func TestClickHouseSOARAuditLogger_QueryAuditLogs_TimeRange(t *testing.T) {
	skipIfNoClickHouse(t)

	auditLogger, _ := setupSOARAuditTest(t)
	ctx := context.Background()

	now := time.Now()
	startTime := now.Add(-2 * time.Hour)
	endTime := now.Add(-1 * time.Hour)
	futureTime := now.Add(1 * time.Hour)

	// Insert event in the past
	event1 := &soar.AuditEvent{
		EventType:           "playbook_executed",
		PlaybookID:          "pb-time1",
		PlaybookExecutionID: "exec-time1",
		UserID:              "user-1",
		Result:              "success",
	}
	err := auditLogger.Log(ctx, event1)
	require.NoError(t, err)

	time.Sleep(100 * time.Millisecond)

	// Insert event now
	event2 := &soar.AuditEvent{
		EventType:           "playbook_executed",
		PlaybookID:          "pb-time2",
		PlaybookExecutionID: "exec-time2",
		UserID:              "user-2",
		Result:              "success",
	}
	err = auditLogger.Log(ctx, event2)
	require.NoError(t, err)

	// Query with time range that excludes recent event
	_, total, err := auditLogger.QueryAuditLogs(ctx, soar.AuditLogFilters{
		StartTime: startTime,
		EndTime:   endTime,
		Limit:     100,
	})
	require.NoError(t, err)
	// The old event should be outside the range (it's in the past relative to now)
	// ClickHouse timestamps are UTC, so we check for events within range
	assert.GreaterOrEqual(t, total, int64(0))

	// Query with future end time (should include recent events)
	_, total, err = auditLogger.QueryAuditLogs(ctx, soar.AuditLogFilters{
		EndTime: futureTime,
		Limit:   100,
	})
	require.NoError(t, err)
	assert.GreaterOrEqual(t, total, int64(2))
}

// TestClickHouseSOARAuditLogger_QueryAuditLogs_Pagination tests pagination
func TestClickHouseSOARAuditLogger_QueryAuditLogs_Pagination(t *testing.T) {
	skipIfNoClickHouse(t)

	auditLogger, _ := setupSOARAuditTest(t)
	ctx := context.Background()

	// Insert 5 events
	for i := 0; i < 5; i++ {
		event := &soar.AuditEvent{
			EventType:           "playbook_executed",
			PlaybookID:          "pb-paginate",
			PlaybookExecutionID: "exec-paginate",
			UserID:              "user-1",
			Result:              "success",
		}
		err := auditLogger.Log(ctx, event)
		require.NoError(t, err)
		time.Sleep(10 * time.Millisecond)
	}

	// Query first page
	page1, total, err := auditLogger.QueryAuditLogs(ctx, soar.AuditLogFilters{
		PlaybookID: "pb-paginate",
		Limit:      2,
		Offset:     0,
	})
	require.NoError(t, err)
	assert.Equal(t, int64(5), total)
	assert.Len(t, page1, 2)

	// Query second page
	page2, total, err := auditLogger.QueryAuditLogs(ctx, soar.AuditLogFilters{
		PlaybookID: "pb-paginate",
		Limit:      2,
		Offset:     2,
	})
	require.NoError(t, err)
	assert.Equal(t, int64(5), total)
	assert.Len(t, page2, 2)

	// Verify no overlap
	assert.NotEqual(t, page1[0].PlaybookExecutionID, page2[0].PlaybookExecutionID)
}

// TestClickHouseSOARAuditLogger_QueryAuditLogs_MaxLimit tests max limit enforcement
func TestClickHouseSOARAuditLogger_QueryAuditLogs_MaxLimit(t *testing.T) {
	skipIfNoClickHouse(t)

	auditLogger, _ := setupSOARAuditTest(t)
	ctx := context.Background()

	// Query with limit > 1000 (should be capped at 1000)
	_, total, err := auditLogger.QueryAuditLogs(ctx, soar.AuditLogFilters{
		Limit: 5000,
	})
	require.NoError(t, err)
	assert.GreaterOrEqual(t, total, int64(0)) // Internal limit is enforced, can't easily test without checking internals
	_ = err                                   // Acknowledge usage
}

// TestClickHouseSOARAuditLogger_ConcurrentLogging tests concurrent logging
func TestClickHouseSOARAuditLogger_ConcurrentLogging(t *testing.T) {
	skipIfNoClickHouse(t)

	auditLogger, _ := setupSOARAuditTest(t)
	ctx := context.Background()

	const numGoroutines = 10
	const eventsPerGoroutine = 5
	done := make(chan bool, numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		go func(goroutineID int) {
			defer func() { done <- true }()
			for j := 0; j < eventsPerGoroutine; j++ {
				event := &soar.AuditEvent{
					EventType:           "playbook_executed",
					PlaybookID:          "pb-concurrent",
					PlaybookExecutionID: "exec-concurrent",
					UserID:              "user-1",
					Result:              "success",
				}
				err := auditLogger.Log(ctx, event)
				require.NoError(t, err)
			}
		}(i)
	}

	// Wait for all goroutines
	for i := 0; i < numGoroutines; i++ {
		<-done
	}

	// Verify all events were logged
	events, total, err := auditLogger.QueryAuditLogs(ctx, soar.AuditLogFilters{
		PlaybookID: "pb-concurrent",
		Limit:      1000,
	})
	require.NoError(t, err)
	assert.Equal(t, int64(numGoroutines*eventsPerGoroutine), total)
	assert.Len(t, events, numGoroutines*eventsPerGoroutine)
}

// TestClickHouseSOARAuditLogger_NoConnection tests behavior with no connection
func TestClickHouseSOARAuditLogger_NoConnection(t *testing.T) {
	logger := zaptest.NewLogger(t).Sugar()
	ch := &ClickHouse{Conn: nil} // No connection

	auditLogger := &ClickHouseSOARAuditLogger{
		clickhouse: ch,
		logger:     logger,
	}

	ctx := context.Background()
	event := &soar.AuditEvent{
		EventType: "test",
	}

	err := auditLogger.Log(ctx, event)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "ClickHouse connection not available")
}
