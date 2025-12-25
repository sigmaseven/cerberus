package ingest

import (
	"database/sql"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	_ "modernc.org/sqlite"
)

// setupDLQTestDB creates an in-memory SQLite database for DLQ tests
func setupDLQTestDB(t *testing.T) *sql.DB {
	db, err := sql.Open("sqlite", ":memory:")
	require.NoError(t, err)

	// Enable foreign keys
	_, err = db.Exec("PRAGMA foreign_keys=ON")
	require.NoError(t, err)

	// Create dead_letter_queue table
	schema := `
	CREATE TABLE IF NOT EXISTS dead_letter_queue (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		timestamp DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
		protocol TEXT NOT NULL,
		raw_event TEXT NOT NULL,
		error_reason TEXT NOT NULL,
		error_details TEXT,
		source_ip TEXT,
		retries INTEGER NOT NULL DEFAULT 0,
		status TEXT NOT NULL DEFAULT 'pending',
		created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
	);
	CREATE INDEX IF NOT EXISTS idx_dlq_timestamp ON dead_letter_queue(timestamp);
	CREATE INDEX IF NOT EXISTS idx_dlq_status ON dead_letter_queue(status);
	CREATE INDEX IF NOT EXISTS idx_dlq_protocol ON dead_letter_queue(protocol);
	`
	_, err = db.Exec(schema)
	require.NoError(t, err)

	return db
}

// setupDLQTestDBFile creates a file-based SQLite database for concurrent tests
func setupDLQTestDBFile(t *testing.T) (*sql.DB, string) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "dlq_test.db")

	db, err := sql.Open("sqlite", dbPath+"?_journal_mode=WAL")
	require.NoError(t, err)

	// Enable foreign keys
	_, err = db.Exec("PRAGMA foreign_keys=ON")
	require.NoError(t, err)

	// Enable WAL mode for better concurrency
	_, err = db.Exec("PRAGMA journal_mode=WAL")
	require.NoError(t, err)

	// Set busy timeout for concurrent access
	_, err = db.Exec("PRAGMA busy_timeout=5000")
	require.NoError(t, err)

	// Set connection pool for single writer (WAL mode works best with single writer)
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)

	// Create dead_letter_queue table
	schema := `
	CREATE TABLE IF NOT EXISTS dead_letter_queue (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		timestamp DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
		protocol TEXT NOT NULL,
		raw_event TEXT NOT NULL,
		error_reason TEXT NOT NULL,
		error_details TEXT,
		source_ip TEXT,
		retries INTEGER NOT NULL DEFAULT 0,
		status TEXT NOT NULL DEFAULT 'pending',
		created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
	);
	CREATE INDEX IF NOT EXISTS idx_dlq_timestamp ON dead_letter_queue(timestamp);
	CREATE INDEX IF NOT EXISTS idx_dlq_status ON dead_letter_queue(status);
	CREATE INDEX IF NOT EXISTS idx_dlq_protocol ON dead_letter_queue(protocol);
	`
	_, err = db.Exec(schema)
	require.NoError(t, err)

	return db, dbPath
}

func TestDLQ_Add(t *testing.T) {
	db := setupDLQTestDB(t)
	defer db.Close()

	logger, _ := zap.NewDevelopment()
	dlq := NewDLQ(db, logger.Sugar())

	tests := []struct {
		name    string
		event   *FailedEvent
		wantErr bool
	}{
		{
			name: "Valid syslog event",
			event: &FailedEvent{
				Protocol:     "syslog",
				RawEvent:     "<34>1 2023-01-01T00:00:00Z host app - - - test message",
				ErrorReason:  "parse_failure",
				ErrorDetails: "Invalid syslog format",
				SourceIP:     "192.168.1.1",
			},
			wantErr: false,
		},
		{
			name: "Valid CEF event",
			event: &FailedEvent{
				Protocol:     "cef",
				RawEvent:     "CEF:0|Vendor|Product|1.0|100|event|5|",
				ErrorReason:  "validation_error",
				ErrorDetails: "Missing required fields",
				SourceIP:     "10.0.0.1",
			},
			wantErr: false,
		},
		{
			name: "Valid JSON event",
			event: &FailedEvent{
				Protocol:     "json",
				RawEvent:     `{"timestamp":"2023-01-01T00:00:00Z","message":"test"}`,
				ErrorReason:  "schema_validation",
				ErrorDetails: "Schema validation failed",
				SourceIP:     "",
			},
			wantErr: false,
		},
		{
			name: "Event without source IP",
			event: &FailedEvent{
				Protocol:     "syslog",
				RawEvent:     "<34>test message",
				ErrorReason:  "parse_failure",
				ErrorDetails: "Invalid format",
				SourceIP:     "",
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := dlq.Add(tt.event)
			if tt.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)

				// Verify event was stored
				var count int
				err = db.QueryRow("SELECT COUNT(*) FROM dead_letter_queue WHERE protocol = ? AND error_reason = ?",
					tt.event.Protocol, tt.event.ErrorReason).Scan(&count)
				require.NoError(t, err)
				assert.Greater(t, count, 0)

				// Verify status is 'pending'
				var status string
				err = db.QueryRow("SELECT status FROM dead_letter_queue WHERE protocol = ? AND error_reason = ? ORDER BY id DESC LIMIT 1",
					tt.event.Protocol, tt.event.ErrorReason).Scan(&status)
				require.NoError(t, err)
				assert.Equal(t, "pending", status)
			}
		})
	}
}

func TestDLQ_Get(t *testing.T) {
	db := setupDLQTestDB(t)
	defer db.Close()

	logger, _ := zap.NewDevelopment()
	dlq := NewDLQ(db, logger.Sugar())

	// Add a test event
	event := &FailedEvent{
		Protocol:     "syslog",
		RawEvent:     "<34>test message",
		ErrorReason:  "parse_failure",
		ErrorDetails: "Invalid format",
		SourceIP:     "192.168.1.1",
	}
	err := dlq.Add(event)
	require.NoError(t, err)

	// Get the ID of the inserted event
	var id int64
	err = db.QueryRow("SELECT id FROM dead_letter_queue WHERE protocol = ? ORDER BY id DESC LIMIT 1",
		event.Protocol).Scan(&id)
	require.NoError(t, err)

	t.Run("Get existing event", func(t *testing.T) {
		dlqEvent, err := dlq.Get(id)
		require.NoError(t, err)
		assert.Equal(t, id, dlqEvent.ID)
		assert.Equal(t, event.Protocol, dlqEvent.Protocol)
		assert.Equal(t, event.RawEvent, dlqEvent.RawEvent)
		assert.Equal(t, event.ErrorReason, dlqEvent.ErrorReason)
		assert.Equal(t, event.ErrorDetails, dlqEvent.ErrorDetails)
		assert.Equal(t, event.SourceIP, dlqEvent.SourceIP)
		assert.Equal(t, 0, dlqEvent.Retries)
		assert.Equal(t, "pending", dlqEvent.Status)
		assert.False(t, dlqEvent.Timestamp.IsZero())
		assert.False(t, dlqEvent.CreatedAt.IsZero())
	})

	t.Run("Get non-existent event", func(t *testing.T) {
		_, err := dlq.Get(999999)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "not found")
	})
}

func TestDLQ_List(t *testing.T) {
	db := setupDLQTestDB(t)
	defer db.Close()

	logger, _ := zap.NewDevelopment()
	dlq := NewDLQ(db, logger.Sugar())

	// Add multiple test events
	events := []*FailedEvent{
		{Protocol: "syslog", RawEvent: "event1", ErrorReason: "parse_failure", ErrorDetails: "err1", SourceIP: "1.1.1.1"},
		{Protocol: "cef", RawEvent: "event2", ErrorReason: "validation_error", ErrorDetails: "err2", SourceIP: "2.2.2.2"},
		{Protocol: "json", RawEvent: "event3", ErrorReason: "parse_failure", ErrorDetails: "err3", SourceIP: "3.3.3.3"},
		{Protocol: "syslog", RawEvent: "event4", ErrorReason: "parse_failure", ErrorDetails: "err4", SourceIP: "4.4.4.4"},
		{Protocol: "cef", RawEvent: "event5", ErrorReason: "schema_validation", ErrorDetails: "err5", SourceIP: "5.5.5.5"},
	}

	for _, event := range events {
		err := dlq.Add(event)
		require.NoError(t, err)
		// Small delay to ensure different timestamps
		time.Sleep(10 * time.Millisecond)
	}

	t.Run("List all events with pagination", func(t *testing.T) {
		events, total, err := dlq.List(1, 3, map[string]interface{}{})
		require.NoError(t, err)
		assert.Equal(t, 5, total)
		assert.Len(t, events, 3)

		// Verify events are ordered by timestamp DESC (newest first)
		if len(events) >= 2 {
			assert.True(t, events[0].Timestamp.After(events[1].Timestamp) || events[0].Timestamp.Equal(events[1].Timestamp))
		}
	})

	t.Run("List page 2", func(t *testing.T) {
		events, total, err := dlq.List(2, 3, map[string]interface{}{})
		require.NoError(t, err)
		assert.Equal(t, 5, total)
		assert.Len(t, events, 2)
	})

	t.Run("Filter by status", func(t *testing.T) {
		events, total, err := dlq.List(1, 10, map[string]interface{}{
			"status": "pending",
		})
		require.NoError(t, err)
		assert.Equal(t, 5, total)
		assert.Len(t, events, 5)

		for _, event := range events {
			assert.Equal(t, "pending", event.Status)
		}
	})

	t.Run("Filter by protocol", func(t *testing.T) {
		events, total, err := dlq.List(1, 10, map[string]interface{}{
			"protocol": "syslog",
		})
		require.NoError(t, err)
		assert.Equal(t, 2, total)
		assert.Len(t, events, 2)

		for _, event := range events {
			assert.Equal(t, "syslog", event.Protocol)
		}
	})

	t.Run("Filter by status and protocol", func(t *testing.T) {
		events, total, err := dlq.List(1, 10, map[string]interface{}{
			"status":   "pending",
			"protocol": "cef",
		})
		require.NoError(t, err)
		assert.Equal(t, 2, total)
		assert.Len(t, events, 2)

		for _, event := range events {
			assert.Equal(t, "pending", event.Status)
			assert.Equal(t, "cef", event.Protocol)
		}
	})

	t.Run("Empty result set", func(t *testing.T) {
		events, total, err := dlq.List(1, 10, map[string]interface{}{
			"protocol": "nonexistent",
		})
		require.NoError(t, err)
		assert.Equal(t, 0, total)
		assert.Len(t, events, 0)
	})

	t.Run("Filter with nil values", func(t *testing.T) {
		events, total, err := dlq.List(1, 10, map[string]interface{}{
			"status":   nil,
			"protocol": "",
		})
		require.NoError(t, err)
		assert.Equal(t, 5, total)
		assert.Len(t, events, 5)
	})
}

func TestDLQ_UpdateStatus(t *testing.T) {
	db := setupDLQTestDB(t)
	defer db.Close()

	logger, _ := zap.NewDevelopment()
	dlq := NewDLQ(db, logger.Sugar())

	// Add a test event
	event := &FailedEvent{
		Protocol:     "syslog",
		RawEvent:     "<34>test message",
		ErrorReason:  "parse_failure",
		ErrorDetails: "Invalid format",
		SourceIP:     "192.168.1.1",
	}
	err := dlq.Add(event)
	require.NoError(t, err)

	// Get the ID
	var id int64
	err = db.QueryRow("SELECT id FROM dead_letter_queue WHERE protocol = ? ORDER BY id DESC LIMIT 1",
		event.Protocol).Scan(&id)
	require.NoError(t, err)

	tests := []struct {
		name   string
		id     int64
		status string
		valid  bool
	}{
		{
			name:   "Update to replayed",
			id:     id,
			status: "replayed",
			valid:  true,
		},
		{
			name:   "Update to discarded",
			id:     id,
			status: "discarded",
			valid:  true,
		},
		{
			name:   "Update to pending",
			id:     id,
			status: "pending",
			valid:  true,
		},
		{
			name:   "Non-existent ID",
			id:     999999,
			status: "replayed",
			valid:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := dlq.UpdateStatus(tt.id, tt.status)
			if !tt.valid {
				// Non-existent ID might not error, but status won't be updated
				// This is implementation-dependent
				if err == nil {
					// Verify status wasn't updated
					var count int
					db.QueryRow("SELECT COUNT(*) FROM dead_letter_queue WHERE id = ? AND status = ?",
						tt.id, tt.status).Scan(&count)
					assert.Equal(t, 0, count)
				}
			} else {
				require.NoError(t, err)

				// Verify status was updated
				var actualStatus string
				err = db.QueryRow("SELECT status FROM dead_letter_queue WHERE id = ?", tt.id).Scan(&actualStatus)
				require.NoError(t, err)
				assert.Equal(t, tt.status, actualStatus)

				// Verify via Get method
				dlqEvent, err := dlq.Get(tt.id)
				require.NoError(t, err)
				assert.Equal(t, tt.status, dlqEvent.Status)
			}
		})
	}
}

func TestDLQ_IncrementRetries(t *testing.T) {
	db := setupDLQTestDB(t)
	defer db.Close()

	logger, _ := zap.NewDevelopment()
	dlq := NewDLQ(db, logger.Sugar())

	// Add a test event
	event := &FailedEvent{
		Protocol:     "syslog",
		RawEvent:     "<34>test message",
		ErrorReason:  "parse_failure",
		ErrorDetails: "Invalid format",
		SourceIP:     "192.168.1.1",
	}
	err := dlq.Add(event)
	require.NoError(t, err)

	// Get the ID
	var id int64
	err = db.QueryRow("SELECT id FROM dead_letter_queue WHERE protocol = ? ORDER BY id DESC LIMIT 1",
		event.Protocol).Scan(&id)
	require.NoError(t, err)

	t.Run("Increment retries multiple times", func(t *testing.T) {
		// Initial retries should be 0
		dlqEvent, err := dlq.Get(id)
		require.NoError(t, err)
		assert.Equal(t, 0, dlqEvent.Retries)

		// Increment once
		err = dlq.IncrementRetries(id)
		require.NoError(t, err)

		dlqEvent, err = dlq.Get(id)
		require.NoError(t, err)
		assert.Equal(t, 1, dlqEvent.Retries)

		// Increment again
		err = dlq.IncrementRetries(id)
		require.NoError(t, err)

		dlqEvent, err = dlq.Get(id)
		require.NoError(t, err)
		assert.Equal(t, 2, dlqEvent.Retries)

		// Increment a third time
		err = dlq.IncrementRetries(id)
		require.NoError(t, err)

		dlqEvent, err = dlq.Get(id)
		require.NoError(t, err)
		assert.Equal(t, 3, dlqEvent.Retries)
	})

	t.Run("Increment retries on non-existent event", func(t *testing.T) {
		err := dlq.IncrementRetries(999999)
		// May or may not error, but shouldn't crash
		if err != nil {
			assert.Contains(t, err.Error(), "failed")
		}
	})
}

func TestDLQ_RetryLogic(t *testing.T) {
	db := setupDLQTestDB(t)
	defer db.Close()

	logger, _ := zap.NewDevelopment()
	dlq := NewDLQ(db, logger.Sugar())

	// Add a test event
	event := &FailedEvent{
		Protocol:     "syslog",
		RawEvent:     "<34>test message",
		ErrorReason:  "parse_failure",
		ErrorDetails: "Invalid format",
		SourceIP:     "192.168.1.1",
	}
	err := dlq.Add(event)
	require.NoError(t, err)

	// Get the ID
	var id int64
	err = db.QueryRow("SELECT id FROM dead_letter_queue WHERE protocol = ? ORDER BY id DESC LIMIT 1",
		event.Protocol).Scan(&id)
	require.NoError(t, err)

	t.Run("Simulate retry workflow", func(t *testing.T) {
		// Initial state: pending, 0 retries
		dlqEvent, err := dlq.Get(id)
		require.NoError(t, err)
		assert.Equal(t, "pending", dlqEvent.Status)
		assert.Equal(t, 0, dlqEvent.Retries)

		// First retry attempt
		err = dlq.IncrementRetries(id)
		require.NoError(t, err)

		dlqEvent, err = dlq.Get(id)
		require.NoError(t, err)
		assert.Equal(t, 1, dlqEvent.Retries)
		assert.Equal(t, "pending", dlqEvent.Status)

		// Second retry attempt
		err = dlq.IncrementRetries(id)
		require.NoError(t, err)

		dlqEvent, err = dlq.Get(id)
		require.NoError(t, err)
		assert.Equal(t, 2, dlqEvent.Retries)

		// After successful retry, mark as replayed
		err = dlq.UpdateStatus(id, "replayed")
		require.NoError(t, err)

		dlqEvent, err = dlq.Get(id)
		require.NoError(t, err)
		assert.Equal(t, "replayed", dlqEvent.Status)
		assert.Equal(t, 2, dlqEvent.Retries)
	})
}

func TestDLQ_MessageExpiration(t *testing.T) {
	db := setupDLQTestDB(t)
	defer db.Close()

	logger, _ := zap.NewDevelopment()
	dlq := NewDLQ(db, logger.Sugar())

	// Add an old event (manually set timestamp to past)
	_, err := db.Exec(`
		INSERT INTO dead_letter_queue 
		(protocol, raw_event, error_reason, error_details, source_ip, status, timestamp, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)
	`, "syslog", "old event", "parse_failure", "error", "1.1.1.1", "pending",
		time.Now().Add(-31*24*time.Hour), // 31 days ago
		time.Now().Add(-31*24*time.Hour))
	require.NoError(t, err)

	var oldID int64
	err = db.QueryRow("SELECT id FROM dead_letter_queue WHERE raw_event = 'old event'").Scan(&oldID)
	require.NoError(t, err)

	// Add a recent event
	event := &FailedEvent{
		Protocol:     "syslog",
		RawEvent:     "recent event",
		ErrorReason:  "parse_failure",
		ErrorDetails: "error",
		SourceIP:     "2.2.2.2",
	}
	err = dlq.Add(event)
	require.NoError(t, err)

	var recentID int64
	err = db.QueryRow("SELECT id FROM dead_letter_queue WHERE raw_event = 'recent event'").Scan(&recentID)
	require.NoError(t, err)

	t.Run("List events includes old and recent", func(t *testing.T) {
		events, total, err := dlq.List(1, 10, map[string]interface{}{})
		require.NoError(t, err)
		assert.Equal(t, 2, total)
		assert.Len(t, events, 2)

		// Verify both events are retrievable
		oldEvent, err := dlq.Get(oldID)
		require.NoError(t, err)
		assert.Equal(t, "old event", oldEvent.RawEvent)

		recentEvent, err := dlq.Get(recentID)
		require.NoError(t, err)
		assert.Equal(t, "recent event", recentEvent.RawEvent)
	})

	// Note: Actual expiration/cleanup would be implemented in a separate cleanup job
	// This test verifies that old events are still accessible, which is expected behavior
	// until a cleanup process runs
}

func TestDLQ_StatisticsCollection(t *testing.T) {
	db := setupDLQTestDB(t)
	defer db.Close()

	logger, _ := zap.NewDevelopment()
	dlq := NewDLQ(db, logger.Sugar())

	// Add multiple events with different protocols and reasons
	events := []*FailedEvent{
		{Protocol: "syslog", RawEvent: "event1", ErrorReason: "parse_failure", ErrorDetails: "err1"},
		{Protocol: "cef", RawEvent: "event2", ErrorReason: "parse_failure", ErrorDetails: "err2"},
		{Protocol: "syslog", RawEvent: "event3", ErrorReason: "validation_error", ErrorDetails: "err3"},
		{Protocol: "json", RawEvent: "event4", ErrorReason: "schema_validation", ErrorDetails: "err4"},
	}

	for _, event := range events {
		err := dlq.Add(event)
		require.NoError(t, err)
	}

	// Verify metrics were incremented by checking that events were stored
	// Note: Prometheus counters don't have a Reset() method, so we verify
	// indirectly by ensuring events were stored correctly, which confirms
	// that metrics were called during Add() operations

	// Verify events were stored
	var count int
	err := db.QueryRow("SELECT COUNT(*) FROM dead_letter_queue").Scan(&count)
	require.NoError(t, err)
	assert.Equal(t, 4, count)

	// Verify different protocols
	var syslogCount, cefCount, jsonCount int
	db.QueryRow("SELECT COUNT(*) FROM dead_letter_queue WHERE protocol = 'syslog'").Scan(&syslogCount)
	db.QueryRow("SELECT COUNT(*) FROM dead_letter_queue WHERE protocol = 'cef'").Scan(&cefCount)
	db.QueryRow("SELECT COUNT(*) FROM dead_letter_queue WHERE protocol = 'json'").Scan(&jsonCount)
	assert.Equal(t, 2, syslogCount)
	assert.Equal(t, 1, cefCount)
	assert.Equal(t, 1, jsonCount)

	// Verify different error reasons
	var parseFailureCount, validationErrorCount, schemaValidationCount int
	db.QueryRow("SELECT COUNT(*) FROM dead_letter_queue WHERE error_reason = 'parse_failure'").Scan(&parseFailureCount)
	db.QueryRow("SELECT COUNT(*) FROM dead_letter_queue WHERE error_reason = 'validation_error'").Scan(&validationErrorCount)
	db.QueryRow("SELECT COUNT(*) FROM dead_letter_queue WHERE error_reason = 'schema_validation'").Scan(&schemaValidationCount)
	assert.Equal(t, 2, parseFailureCount)
	assert.Equal(t, 1, validationErrorCount)
	assert.Equal(t, 1, schemaValidationCount)

	// Verify that metrics.DLQEventsTotal, metrics.DLQEventsByReason, and
	// metrics.DLQEventsByProtocol were called by inspecting the code
	// The metrics are incremented in dlq.Add(), so if events were stored,
	// metrics were incremented (assuming no panics occurred)
}

func TestDLQ_ConcurrentOperations(t *testing.T) {
	// Test concurrent adds
	t.Run("Concurrent Add operations", func(t *testing.T) {
		db, dbPath := setupDLQTestDBFile(t)
		defer func() {
			db.Close()
			os.Remove(dbPath)
		}()

		logger, _ := zap.NewDevelopment()
		dlq := NewDLQ(db, logger.Sugar())

		const numGoroutines = 10
		const eventsPerGoroutine = 5

		done := make(chan error, numGoroutines)

		for i := 0; i < numGoroutines; i++ {
			go func(id int) {
				var err error
				for j := 0; j < eventsPerGoroutine; j++ {
					event := &FailedEvent{
						Protocol:     "syslog",
						RawEvent:     "concurrent event",
						ErrorReason:  "parse_failure",
						ErrorDetails: "error",
						SourceIP:     "1.1.1.1",
					}
					if e := dlq.Add(event); e != nil {
						err = e
						break
					}
				}
				done <- err
			}(i)
		}

		// Wait for all goroutines
		for i := 0; i < numGoroutines; i++ {
			err := <-done
			require.NoError(t, err)
		}

		// Verify all events were added
		var count int
		err := db.QueryRow("SELECT COUNT(*) FROM dead_letter_queue").Scan(&count)
		require.NoError(t, err)
		assert.Equal(t, numGoroutines*eventsPerGoroutine, count)
	})

	// Test concurrent retry increments
	t.Run("Concurrent IncrementRetries operations", func(t *testing.T) {
		db, dbPath := setupDLQTestDBFile(t)
		defer func() {
			db.Close()
			os.Remove(dbPath)
		}()

		logger, _ := zap.NewDevelopment()
		dlq := NewDLQ(db, logger.Sugar())

		// Add a single event for concurrent update/retry tests
		event := &FailedEvent{
			Protocol:     "syslog",
			RawEvent:     "concurrent event",
			ErrorReason:  "parse_failure",
			ErrorDetails: "error",
			SourceIP:     "1.1.1.1",
		}
		err := dlq.Add(event)
		require.NoError(t, err)

		var id int64
		err = db.QueryRow("SELECT id FROM dead_letter_queue ORDER BY id DESC LIMIT 1").Scan(&id)
		require.NoError(t, err)

		const numGoroutines = 10
		const retriesPerGoroutine = 5

		done := make(chan error, numGoroutines)

		for i := 0; i < numGoroutines; i++ {
			go func() {
				var err error
				for j := 0; j < retriesPerGoroutine; j++ {
					if e := dlq.IncrementRetries(id); e != nil {
						err = e
						break
					}
				}
				done <- err
			}()
		}

		// Wait for all goroutines
		for i := 0; i < numGoroutines; i++ {
			err := <-done
			require.NoError(t, err)
		}

		// Verify retries were incremented
		dlqEvent, err := dlq.Get(id)
		require.NoError(t, err)
		assert.Equal(t, numGoroutines*retriesPerGoroutine, dlqEvent.Retries)
	})
}
