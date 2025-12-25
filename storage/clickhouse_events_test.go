package storage

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"testing"
	"time"

	"cerberus/config"
	"cerberus/core"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

// Test NewClickHouseEventStorage creation
func TestNewClickHouseEventStorage_Success(t *testing.T) {
	// Create mock ClickHouse (nil is ok for this test - just testing struct creation)
	ch := &ClickHouse{}
	cfg := &config.Config{}
	cfg.Storage.DedupCacheSize = 1000
	cfg.Storage.Deduplication = true
	cfg.ClickHouse.BatchSize = 1000
	cfg.ClickHouse.FlushInterval = 5
	eventCh := make(chan *core.Event, 100)
	logger := zap.NewNop().Sugar()

	ctx := context.Background()
	storage, err := NewClickHouseEventStorage(ctx, ch, cfg, eventCh, logger)
	require.NoError(t, err)
	require.NotNil(t, storage)

	assert.Equal(t, 1000, storage.batchSize)
	assert.Equal(t, 5*time.Second, storage.batchFlushInterval)
	assert.Equal(t, true, storage.enableDeduplication)
	assert.NotNil(t, storage.dedupCache)
}

func TestNewClickHouseEventStorage_DefaultBatchSize(t *testing.T) {
	ch := &ClickHouse{}
	cfg := &config.Config{}
	cfg.Storage.DedupCacheSize = 1000
	cfg.ClickHouse.BatchSize = 0     // Should default to 10000
	cfg.ClickHouse.FlushInterval = 0 // Should default to 5 seconds
	eventCh := make(chan *core.Event, 100)
	logger := zap.NewNop().Sugar()

	ctx := context.Background()
	storage, err := NewClickHouseEventStorage(ctx, ch, cfg, eventCh, logger)
	require.NoError(t, err)

	assert.Equal(t, 10000, storage.batchSize)
	assert.Equal(t, 5*time.Second, storage.batchFlushInterval)
}

func TestNewClickHouseEventStorage_InvalidCacheSize(t *testing.T) {
	ch := &ClickHouse{}
	cfg := &config.Config{}
	cfg.Storage.DedupCacheSize = -1 // Invalid cache size
	cfg.ClickHouse.BatchSize = 1000
	eventCh := make(chan *core.Event, 100)
	logger := zap.NewNop().Sugar()

	ctx := context.Background()
	storage, err := NewClickHouseEventStorage(ctx, ch, cfg, eventCh, logger)
	assert.Error(t, err)
	assert.Nil(t, storage)
	assert.Contains(t, err.Error(), "failed to create LRU cache")
}

func TestNewClickHouseEventStorage_NilChannel(t *testing.T) {
	ch := &ClickHouse{}
	cfg := &config.Config{}
	cfg.Storage.DedupCacheSize = 1000
	cfg.ClickHouse.BatchSize = 1000
	logger := zap.NewNop().Sugar()

	// Should not panic with nil channel (logs warning)
	ctx := context.Background()
	storage, err := NewClickHouseEventStorage(ctx, ch, cfg, nil, logger)
	require.NoError(t, err)
	assert.NotNil(t, storage)
}

// Test hashEvent function
func TestHashEvent(t *testing.T) {
	ch := &ClickHouse{}
	cfg := &config.Config{}
	cfg.Storage.DedupCacheSize = 1000
	cfg.ClickHouse.BatchSize = 1000
	eventCh := make(chan *core.Event, 100)
	logger := zap.NewNop().Sugar()

	ctx := context.Background()
	storage, err := NewClickHouseEventStorage(ctx, ch, cfg, eventCh, logger)
	require.NoError(t, err)

	timestamp := time.Now()

	tests := []struct {
		name    string
		event1  *core.Event
		event2  *core.Event
		samHash bool
	}{
		{
			name: "identical events produce same hash",
			event1: &core.Event{
				RawData:   "test log line",
				Timestamp: timestamp,
				Fields: map[string]interface{}{
					"source_ip":  "192.168.1.1",
					"event_type": "login",
				},
			},
			event2: &core.Event{
				RawData:   "test log line",
				Timestamp: timestamp,
				Fields: map[string]interface{}{
					"source_ip":  "192.168.1.1",
					"event_type": "login",
				},
			},
			samHash: true,
		},
		{
			name: "different raw data produces different hash",
			event1: &core.Event{
				RawData:   "test log line 1",
				Timestamp: timestamp,
				Fields: map[string]interface{}{
					"source_ip":  "192.168.1.1",
					"event_type": "login",
				},
			},
			event2: &core.Event{
				RawData:   "test log line 2",
				Timestamp: timestamp,
				Fields: map[string]interface{}{
					"source_ip":  "192.168.1.1",
					"event_type": "login",
				},
			},
			samHash: false,
		},
		{
			name: "different timestamp produces different hash",
			event1: &core.Event{
				RawData:   "test log line",
				Timestamp: timestamp,
				Fields: map[string]interface{}{
					"source_ip":  "192.168.1.1",
					"event_type": "login",
				},
			},
			event2: &core.Event{
				RawData:   "test log line",
				Timestamp: timestamp.Add(time.Second),
				Fields: map[string]interface{}{
					"source_ip":  "192.168.1.1",
					"event_type": "login",
				},
			},
			samHash: false,
		},
		{
			name: "different source_ip produces different hash",
			event1: &core.Event{
				RawData:   "test log line",
				Timestamp: timestamp,
				Fields: map[string]interface{}{
					"source_ip":  "192.168.1.1",
					"event_type": "login",
				},
			},
			event2: &core.Event{
				RawData:   "test log line",
				Timestamp: timestamp,
				Fields: map[string]interface{}{
					"source_ip":  "192.168.1.2",
					"event_type": "login",
				},
			},
			samHash: false,
		},
		{
			name: "missing fields uses defaults",
			event1: &core.Event{
				RawData:   "test log line",
				Timestamp: timestamp,
				Fields:    nil,
			},
			event2: &core.Event{
				RawData:   "test log line",
				Timestamp: timestamp,
				Fields:    map[string]interface{}{},
			},
			samHash: true, // Both use "unknown" defaults
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hash1 := storage.hashEvent(tt.event1)
			hash2 := storage.hashEvent(tt.event2)

			if tt.samHash {
				assert.Equal(t, hash1, hash2)
			} else {
				assert.NotEqual(t, hash1, hash2)
			}
		})
	}
}

// Test GetEvents requires real ClickHouse connection
// Skipped in unit tests - would be covered in integration tests
func TestGetEvents_RequiresConnection(t *testing.T) {
	t.Skip("GetEvents requires actual ClickHouse connection - skipping unit test")
}

// Test GetEventsWithCursor validation
func TestGetEventsWithCursor_LimitValidation(t *testing.T) {
	ch := &ClickHouse{
		Conn: nil,
	}
	cfg := &config.Config{}
	cfg.Storage.DedupCacheSize = 1000
	cfg.ClickHouse.BatchSize = 1000
	eventCh := make(chan *core.Event, 100)
	logger := zap.NewNop().Sugar()

	ctx := context.Background()
	storage, err := NewClickHouseEventStorage(ctx, ch, cfg, eventCh, logger)
	require.NoError(t, err)

	tests := []struct {
		name      string
		limit     int
		cursor    string
		expectErr bool
		errMsg    string
	}{
		{
			name:      "zero limit",
			limit:     0,
			cursor:    "",
			expectErr: true,
			errMsg:    "limit must be between 1 and 10000",
		},
		{
			name:      "negative limit",
			limit:     -10,
			cursor:    "",
			expectErr: true,
			errMsg:    "limit must be between 1 and 10000",
		},
		{
			name:      "limit too large",
			limit:     20000,
			cursor:    "",
			expectErr: true,
			errMsg:    "limit must be between 1 and 10000",
		},
		{
			name:      "invalid cursor format - no underscore",
			limit:     10,
			cursor:    "invalidcursor",
			expectErr: true,
			errMsg:    "invalid cursor format: expected 'timestamp_eventID'",
		},
		{
			name:      "invalid cursor format - bad timestamp",
			limit:     10,
			cursor:    "notanumber_eventid123",
			expectErr: true,
			errMsg:    "invalid cursor format: timestamp parsing failed",
		},
		{
			name:      "invalid cursor format - too many parts",
			limit:     10,
			cursor:    "123456_eventid_extra",
			expectErr: true,
			errMsg:    "invalid cursor format",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			page, err := storage.GetEventsWithCursor(ctx, tt.limit, tt.cursor)

			if tt.expectErr {
				assert.Error(t, err)
				assert.Nil(t, page)
				assert.Contains(t, err.Error(), tt.errMsg)
			}
		})
	}
}

// Test cursor parsing is tested via limit validation
// Actual query execution requires real ClickHouse connection
func TestGetEventsWithCursor_RequiresConnection(t *testing.T) {
	t.Skip("GetEventsWithCursor query requires actual ClickHouse connection - skipping unit test")
}

// Test GetEventCount requires actual connection
func TestGetEventCount_RequiresConnection(t *testing.T) {
	t.Skip("GetEventCount requires actual ClickHouse connection - skipping unit test")
}

// Test CleanupOldEvents requires actual connection
func TestCleanupOldEvents_RequiresConnection(t *testing.T) {
	t.Skip("CleanupOldEvents requires actual ClickHouse connection - skipping unit test")
}

// Test GetDatabaseInterface and related methods
func TestGetDatabaseInterface(t *testing.T) {
	ch := &ClickHouse{
		Conn: nil,
	}
	cfg := &config.Config{}
	cfg.Storage.DedupCacheSize = 1000
	cfg.ClickHouse.BatchSize = 1000
	eventCh := make(chan *core.Event, 100)
	logger := zap.NewNop().Sugar()

	ctx := context.Background()
	storage, err := NewClickHouseEventStorage(ctx, ch, cfg, eventCh, logger)
	require.NoError(t, err)

	// Test GetDatabaseInterface
	db := storage.GetDatabaseInterface()
	assert.Equal(t, ch.Conn, db)

	// Test GetDatabase (deprecated method)
	db2 := storage.GetDatabase()
	assert.Equal(t, ch.Conn, db2)

	// Test GetClickHouse
	clickhouse := storage.GetClickHouse()
	assert.Equal(t, ch, clickhouse)
}

// Test CreateEventIndexes requires actual connection
func TestCreateEventIndexes_RequiresConnection(t *testing.T) {
	t.Skip("CreateEventIndexes requires actual ClickHouse connection - skipping unit test")
}

// Test EventsPage structure
func TestEventsPage_Structure(t *testing.T) {
	page := &EventsPage{
		Events: []core.Event{
			{
				EventID:   "event1",
				Timestamp: time.Now(),
			},
		},
		NextCursor: "123456_event1",
		HasMore:    true,
	}

	assert.Len(t, page.Events, 1)
	assert.Equal(t, "123456_event1", page.NextCursor)
	assert.True(t, page.HasMore)

	// Test JSON serialization
	data, err := json.Marshal(page)
	assert.NoError(t, err)
	assert.Contains(t, string(data), "next_cursor")
	assert.Contains(t, string(data), "has_more")
}

// Test GetEventCountsByMonth requires actual connection
func TestGetEventCountsByMonth_RequiresConnection(t *testing.T) {
	t.Skip("GetEventCountsByMonth requires actual ClickHouse connection - skipping unit test")
}

// Test worker shutdown
func TestWorker_ChannelClose(t *testing.T) {
	ch := &ClickHouse{
		Conn: nil,
	}
	cfg := &config.Config{}
	cfg.Storage.DedupCacheSize = 1000
	cfg.ClickHouse.BatchSize = 10 // Small batch for testing
	cfg.ClickHouse.FlushInterval = 1
	eventCh := make(chan *core.Event, 100)
	logger := zap.NewNop().Sugar()

	ctx := context.Background()
	storage, err := NewClickHouseEventStorage(ctx, ch, cfg, eventCh, logger)
	require.NoError(t, err)

	// Start 1 worker
	storage.Start(1)

	// Close channel to trigger worker shutdown
	close(eventCh)

	// Wait for worker to finish
	err = storage.Stop()
	require.NoError(t, err)

	// Should complete without hanging
}

// BLOCKING-3 TEST: Test graceful shutdown with timeout
func TestEventStorage_GracefulShutdown_Timeout(t *testing.T) {
	ch := &ClickHouse{
		Conn: nil,
	}
	cfg := &config.Config{}
	cfg.Storage.DedupCacheSize = 1000
	cfg.ClickHouse.BatchSize = 10
	cfg.ClickHouse.FlushInterval = 1
	eventCh := make(chan *core.Event, 100)
	logger := zap.NewNop().Sugar()

	ctx := context.Background()
	storage, err := NewClickHouseEventStorage(ctx, ch, cfg, eventCh, logger)
	require.NoError(t, err)

	// Start worker
	storage.Start(1)

	// Trigger context cancellation to initiate shutdown
	storage.cancel()

	// Stop should complete successfully within timeout
	start := time.Now()
	err = storage.Stop()
	duration := time.Since(start)

	require.NoError(t, err)
	assert.Less(t, duration, 35*time.Second, "Stop should complete well within timeout")
}

// BLOCKING-3 TEST: Test shutdown completes quickly when workers are responsive
func TestEventStorage_GracefulShutdown_Fast(t *testing.T) {
	ch := &ClickHouse{
		Conn: nil,
	}
	cfg := &config.Config{}
	cfg.Storage.DedupCacheSize = 1000
	cfg.ClickHouse.BatchSize = 10
	cfg.ClickHouse.FlushInterval = 1
	eventCh := make(chan *core.Event, 100)
	logger := zap.NewNop().Sugar()

	ctx := context.Background()
	storage, err := NewClickHouseEventStorage(ctx, ch, cfg, eventCh, logger)
	require.NoError(t, err)

	// Start multiple workers
	storage.Start(3)

	// Close channel to signal workers to exit
	close(eventCh)

	// Stop should complete quickly since workers exit immediately on channel close
	start := time.Now()
	err = storage.Stop()
	duration := time.Since(start)

	require.NoError(t, err)
	assert.Less(t, duration, 1*time.Second, "Stop should complete quickly when workers exit cleanly")
}

// BLOCKING-2 TEST: Test parent context cancellation propagates to workers
func TestEventStorage_ParentContextCancellation(t *testing.T) {
	ch := &ClickHouse{
		Conn: nil,
	}
	cfg := &config.Config{}
	cfg.Storage.DedupCacheSize = 1000
	cfg.ClickHouse.BatchSize = 10
	cfg.ClickHouse.FlushInterval = 1
	eventCh := make(chan *core.Event, 100)
	logger := zap.NewNop().Sugar()

	// Create cancellable parent context
	parentCtx, cancelParent := context.WithCancel(context.Background())

	storage, err := NewClickHouseEventStorage(parentCtx, ch, cfg, eventCh, logger)
	require.NoError(t, err)

	// Start worker
	storage.Start(1)

	// Cancel parent context - this should propagate to storage workers
	cancelParent()

	// Give worker time to detect cancellation (should be very fast)
	time.Sleep(100 * time.Millisecond)

	// Stop should complete quickly since worker already exited
	start := time.Now()
	err = storage.Stop()
	duration := time.Since(start)

	require.NoError(t, err)
	assert.Less(t, duration, 1*time.Second, "Stop should complete quickly when parent context is cancelled")
}

// Test deduplication cache
func TestDeduplication(t *testing.T) {
	ch := &ClickHouse{
		Conn: nil,
	}
	cfg := &config.Config{}
	cfg.Storage.DedupCacheSize = 100
	cfg.Storage.Deduplication = true
	cfg.ClickHouse.BatchSize = 1000
	cfg.ClickHouse.FlushInterval = 5
	eventCh := make(chan *core.Event, 100)
	logger := zap.NewNop().Sugar()

	ctx := context.Background()
	storage, err := NewClickHouseEventStorage(ctx, ch, cfg, eventCh, logger)
	require.NoError(t, err)

	// Create two identical events
	event1 := &core.Event{
		EventID:   "event1",
		RawData:   "test log",
		Timestamp: time.Now(),
		Fields: map[string]interface{}{
			"source_ip":  "192.168.1.1",
			"event_type": "login",
		},
	}

	event2 := &core.Event{
		EventID:   "event2", // Different ID
		RawData:   "test log",
		Timestamp: event1.Timestamp, // Same timestamp
		Fields: map[string]interface{}{
			"source_ip":  "192.168.1.1",
			"event_type": "login",
		},
	}

	// Hash should be the same
	hash1 := storage.hashEvent(event1)
	hash2 := storage.hashEvent(event2)
	assert.Equal(t, hash1, hash2)

	// Add event1 to cache
	storage.dedupMutex.Lock()
	storage.dedupCache.Add(hash1, true)
	storage.dedupMutex.Unlock()

	// Check event2 should be in cache
	storage.dedupMutex.RLock()
	_, exists := storage.dedupCache.Get(hash2)
	storage.dedupMutex.RUnlock()
	assert.True(t, exists)
}

// Test deduplication disabled
func TestDeduplication_Disabled(t *testing.T) {
	ch := &ClickHouse{
		Conn: nil,
	}
	cfg := &config.Config{}
	cfg.Storage.DedupCacheSize = 100
	cfg.Storage.Deduplication = false // Disabled
	cfg.ClickHouse.BatchSize = 1000
	cfg.ClickHouse.FlushInterval = 5
	eventCh := make(chan *core.Event, 100)
	logger := zap.NewNop().Sugar()

	ctx := context.Background()
	storage, err := NewClickHouseEventStorage(ctx, ch, cfg, eventCh, logger)
	require.NoError(t, err)

	assert.False(t, storage.enableDeduplication)
}

// Skip tests that require actual ClickHouse connection
func TestGetEvents_Execution(t *testing.T) {
	t.Skip("GetEvents requires actual ClickHouse connection - covered by integration tests")
}

func TestGetEventCount_Execution(t *testing.T) {
	t.Skip("GetEventCount requires actual ClickHouse connection - covered by integration tests")
}

func TestGetEventCountsByMonth_Execution(t *testing.T) {
	t.Skip("GetEventCountsByMonth requires actual ClickHouse connection - covered by integration tests")
}

func TestCleanupOldEvents_Execution(t *testing.T) {
	t.Skip("CleanupOldEvents requires actual ClickHouse connection - covered by integration tests")
}

func TestCreateEventIndexes_Execution(t *testing.T) {
	t.Skip("CreateEventIndexes requires actual ClickHouse connection - covered by integration tests")
}

// TestEventsPage_CursorGeneration tests cursor generation logic
func TestEventsPage_CursorGeneration(t *testing.T) {
	event := core.Event{
		EventID:   "test-event-123",
		Timestamp: time.Date(2024, 1, 15, 10, 30, 0, 0, time.UTC),
	}

	cursor := fmt.Sprintf("%d_%s", event.Timestamp.UnixNano(), event.EventID)

	assert.Contains(t, cursor, "test-event-123")
	assert.Contains(t, cursor, "_")

	// Parse cursor back
	parts := strings.Split(cursor, "_")
	assert.Len(t, parts, 2)
	assert.Equal(t, "test-event-123", parts[1])

	// Verify timestamp part is numeric
	timestampNs, err := strconv.ParseInt(parts[0], 10, 64)
	assert.NoError(t, err)
	assert.Greater(t, timestampNs, int64(0))
}

// TestGetEventsWithCursor_ValidCursor tests cursor parsing and validation
func TestGetEventsWithCursor_ValidCursor(t *testing.T) {
	t.Skip("GetEventsWithCursor requires actual ClickHouse connection - covered by integration tests")
}

// TestHashEvent_EdgeCases tests event hashing edge cases
func TestHashEvent_EdgeCases(t *testing.T) {
	ch := &ClickHouse{}
	cfg := &config.Config{}
	cfg.Storage.DedupCacheSize = 1000
	cfg.ClickHouse.BatchSize = 1000
	eventCh := make(chan *core.Event, 100)
	logger := zap.NewNop().Sugar()

	ctx := context.Background()
	storage, err := NewClickHouseEventStorage(ctx, ch, cfg, eventCh, logger)
	require.NoError(t, err)

	timestamp := time.Now()

	tests := []struct {
		name  string
		event *core.Event
	}{
		{
			name: "nil fields",
			event: &core.Event{
				RawData:   "test",
				Timestamp: timestamp,
				Fields:    nil,
			},
		},
		{
			name: "empty fields",
			event: &core.Event{
				RawData:   "test",
				Timestamp: timestamp,
				Fields:    map[string]interface{}{},
			},
		},
		{
			name: "non-string source_ip",
			event: &core.Event{
				RawData:   "test",
				Timestamp: timestamp,
				Fields: map[string]interface{}{
					"source_ip": 12345,
				},
			},
		},
		{
			name: "non-string event_type",
			event: &core.Event{
				RawData:   "test",
				Timestamp: timestamp,
				Fields: map[string]interface{}{
					"event_type": true,
				},
			},
		},
		{
			name: "empty raw data",
			event: &core.Event{
				RawData:   "",
				Timestamp: timestamp,
				Fields:    nil,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hash := storage.hashEvent(tt.event)
			assert.NotEmpty(t, hash, "Hash should not be empty for %s", tt.name)
		})
	}
}
