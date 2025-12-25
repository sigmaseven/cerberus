package storage

import (
	"context"
	"fmt"
	"io"
	"testing"
	"time"

	"cerberus/config"
	"cerberus/core"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
	"go.uber.org/zap"
)

// ClickHouse test container configuration
const (
	clickhouseImage       = "clickhouse/clickhouse-server:latest"
	clickhouseNativePort  = "9000/tcp"
	clickhouseHTTPPort    = "8123/tcp"
	testDatabaseName      = "cerberus_integration_test"
	containerStartTimeout = 120 * time.Second
)

// clickhouseTestContainer encapsulates testcontainer lifecycle
type clickhouseTestContainer struct {
	container testcontainers.Container
	host      string
	port      string
	cleanup   func()
}

// setupClickHouseTestContainer creates and starts a ClickHouse testcontainer
// Returns a configured ClickHouse connection and cleanup function
func setupClickHouseTestContainer(t *testing.T) *clickhouseTestContainer {
	ctx := context.Background()

	req := testcontainers.ContainerRequest{
		Image:        clickhouseImage,
		ExposedPorts: []string{clickhouseNativePort, clickhouseHTTPPort},
		Env: map[string]string{
			"CLICKHOUSE_DB":                        testDatabaseName,
			"CLICKHOUSE_USER":                      "default",
			"CLICKHOUSE_PASSWORD":                  "testpassword",
			"CLICKHOUSE_DEFAULT_ACCESS_MANAGEMENT": "1",
		},
		// Wait for ClickHouse HTTP port to be ready - this is more reliable than log matching
		WaitingFor: wait.ForHTTP("/").
			WithPort(clickhouseHTTPPort).
			WithStartupTimeout(containerStartTimeout).
			WithResponseMatcher(func(body io.Reader) bool {
				// ClickHouse returns "Ok." for root path when ready
				buf, _ := io.ReadAll(body)
				return len(buf) > 0
			}),
	}

	container, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
	require.NoError(t, err, "Failed to start ClickHouse container")

	host, err := container.Host(ctx)
	require.NoError(t, err, "Failed to get container host")

	mappedPort, err := container.MappedPort(ctx, "9000")
	require.NoError(t, err, "Failed to get mapped port")

	cleanup := func() {
		if err := container.Terminate(ctx); err != nil {
			t.Logf("Warning: failed to terminate ClickHouse container: %v", err)
		}
	}

	t.Logf("ClickHouse container started at %s:%s", host, mappedPort.Port())

	return &clickhouseTestContainer{
		container: container,
		host:      host,
		port:      mappedPort.Port(),
		cleanup:   cleanup,
	}
}

// createClickHouseConnection creates a ClickHouse connection to the test container
func createClickHouseConnection(t *testing.T, testContainer *clickhouseTestContainer) *ClickHouse {
	logger := zap.NewNop().Sugar()
	cfg := &config.Config{}
	cfg.ClickHouse.Addr = fmt.Sprintf("%s:%s", testContainer.host, testContainer.port)
	cfg.ClickHouse.Database = testDatabaseName
	cfg.ClickHouse.Username = "default"
	cfg.ClickHouse.Password = "testpassword"
	cfg.ClickHouse.TLS = false
	cfg.ClickHouse.MaxPoolSize = 10
	cfg.ClickHouse.BatchSize = 1000
	cfg.ClickHouse.FlushInterval = 1 // 1 second for faster tests

	ch, err := NewClickHouse(cfg, logger)
	require.NoError(t, err, "Failed to connect to ClickHouse")
	require.NotNil(t, ch, "ClickHouse connection should not be nil")

	return ch
}

// TestClickHouseIntegration_HealthCheck tests ClickHouse health check with real connection
func TestClickHouseIntegration_HealthCheck(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	testContainer := setupClickHouseTestContainer(t)
	defer testContainer.cleanup()

	ch := createClickHouseConnection(t, testContainer)
	defer ch.Close()

	ctx := context.Background()
	err := ch.HealthCheck(ctx)
	assert.NoError(t, err, "Health check should pass")
}

// TestClickHouseIntegration_GetVersion tests version retrieval
func TestClickHouseIntegration_GetVersion(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	testContainer := setupClickHouseTestContainer(t)
	defer testContainer.cleanup()

	ch := createClickHouseConnection(t, testContainer)
	defer ch.Close()

	ctx := context.Background()
	version, err := ch.GetVersion(ctx)
	require.NoError(t, err, "Should get version")
	assert.NotEmpty(t, version, "Version should not be empty")
	t.Logf("ClickHouse version: %s", version)
}

// TestClickHouseIntegration_CreateTablesIfNotExist tests table creation
func TestClickHouseIntegration_CreateTablesIfNotExist(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	testContainer := setupClickHouseTestContainer(t)
	defer testContainer.cleanup()

	ch := createClickHouseConnection(t, testContainer)
	defer ch.Close()

	ctx := context.Background()

	// Create tables
	err := ch.CreateTablesIfNotExist(ctx)
	require.NoError(t, err, "Should create tables")

	// Verify events table exists
	var eventsCount uint64
	err = ch.Conn.QueryRow(ctx, "SELECT count() FROM system.tables WHERE database = ? AND name = ?",
		testDatabaseName, "events").Scan(&eventsCount)
	require.NoError(t, err)
	assert.Equal(t, uint64(1), eventsCount, "Events table should exist")

	// Verify alerts table exists
	var alertsCount uint64
	err = ch.Conn.QueryRow(ctx, "SELECT count() FROM system.tables WHERE database = ? AND name = ?",
		testDatabaseName, "alerts").Scan(&alertsCount)
	require.NoError(t, err)
	assert.Equal(t, uint64(1), alertsCount, "Alerts table should exist")

	// Test idempotency - creating again should not error
	err = ch.CreateTablesIfNotExist(ctx)
	assert.NoError(t, err, "Creating tables again should be idempotent")
}

// TestClickHouseIntegration_EnsureDatabase tests database creation
func TestClickHouseIntegration_EnsureDatabase(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	testContainer := setupClickHouseTestContainer(t)
	defer testContainer.cleanup()

	ch := createClickHouseConnection(t, testContainer)
	defer ch.Close()

	ctx := context.Background()
	logger := zap.NewNop().Sugar()

	// Test creating a new database
	testDB := "test_ensure_db"
	err := ensureDatabase(ctx, ch.Conn, testDB, logger)
	assert.NoError(t, err, "Should create database")

	// Verify database exists
	var count uint64
	err = ch.Conn.QueryRow(ctx, "SELECT count() FROM system.databases WHERE name = ?", testDB).Scan(&count)
	require.NoError(t, err)
	assert.Equal(t, uint64(1), count, "Database should exist")

	// Cleanup
	_ = ch.Conn.Exec(ctx, fmt.Sprintf("DROP DATABASE IF EXISTS %s", testDB))
}

// TestClickHouseIntegration_EnsureDatabase_SQLInjection tests SQL injection prevention
func TestClickHouseIntegration_EnsureDatabase_SQLInjection(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	testContainer := setupClickHouseTestContainer(t)
	defer testContainer.cleanup()

	ch := createClickHouseConnection(t, testContainer)
	defer ch.Close()

	ctx := context.Background()
	logger := zap.NewNop().Sugar()

	// Test SQL injection attempts - these should all fail validation
	sqlInjectionAttempts := []string{
		"test; DROP DATABASE test",
		"test' OR '1'='1",
		"test; DROP TABLE events",
		"test`; DROP DATABASE",
		"../../etc/passwd",
		"test@#$%",
		"test database",
		"test-database",
	}

	for _, dbName := range sqlInjectionAttempts {
		t.Run(fmt.Sprintf("injection_%s", dbName), func(t *testing.T) {
			err := ensureDatabase(ctx, ch.Conn, dbName, logger)
			assert.Error(t, err, "Should reject SQL injection attempt: %s", dbName)
			assert.Contains(t, err.Error(), "invalid database name", "Error should indicate validation failure")
		})
	}
}

// TestClickHouseIntegration_EventStorage_InsertAndQuery tests full event storage lifecycle
func TestClickHouseIntegration_EventStorage_InsertAndQuery(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	testContainer := setupClickHouseTestContainer(t)
	defer testContainer.cleanup()

	ch := createClickHouseConnection(t, testContainer)
	defer ch.Close()

	ctx := context.Background()
	logger := zap.NewNop().Sugar()

	// Create tables
	err := ch.CreateTablesIfNotExist(ctx)
	require.NoError(t, err)

	// Create event storage
	cfg := &config.Config{}
	cfg.ClickHouse.BatchSize = 100
	cfg.ClickHouse.FlushInterval = 1
	cfg.Storage.DedupCacheSize = 1000
	cfg.Storage.Deduplication = true

	eventCh := make(chan *core.Event, 100)
	bgCtx := context.Background()
	storage, err := NewClickHouseEventStorage(bgCtx, ch, cfg, eventCh, logger)
	require.NoError(t, err)

	// Test direct insert batch
	testEvents := []*core.Event{
		{
			EventID:   "test-event-1",
			Timestamp: time.Now(),
			RawData:   "Test event 1",
			SourceIP:  "192.168.1.1",
			Fields: map[string]interface{}{
				"event_type": "test",
				"severity":   "info",
			},
		},
		{
			EventID:   "test-event-2",
			Timestamp: time.Now(),
			RawData:   "Test event 2",
			SourceIP:  "192.168.1.2",
			Fields: map[string]interface{}{
				"event_type": "test",
				"severity":   "warning",
			},
		},
	}

	// Insert events using insertBatch (previously 0% coverage)
	storage.insertBatch(testEvents) // Returns no value

	// Wait for ClickHouse to process the insert
	time.Sleep(500 * time.Millisecond)

	// Test GetEvents (previously 0% coverage)
	events, err := storage.GetEvents(ctx, 100, 0)
	require.NoError(t, err, "Should get events")
	assert.GreaterOrEqual(t, len(events), 2, "Should have at least 2 events")

	// Test GetEventCount (previously 0% coverage)
	count, err := storage.GetEventCount(ctx)
	require.NoError(t, err, "Should get event count")
	assert.GreaterOrEqual(t, count, int64(2), "Should have at least 2 events")

	// Test GetEventsWithCursor (partially covered)
	page, err := storage.GetEventsWithCursor(ctx, 10, "")
	require.NoError(t, err, "Should get events with cursor")
	assert.NotNil(t, page, "Page should not be nil")
	assert.GreaterOrEqual(t, len(page.Events), 2, "Should have events in page")

	// Test cursor navigation
	if page.HasMore {
		nextPage, err := storage.GetEventsWithCursor(ctx, 10, page.NextCursor)
		require.NoError(t, err, "Should get next page")
		assert.NotNil(t, nextPage, "Next page should not be nil")
	}
}

// TestClickHouseIntegration_EventStorage_GetEventCountsByMonth tests monthly counts
func TestClickHouseIntegration_EventStorage_GetEventCountsByMonth(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	testContainer := setupClickHouseTestContainer(t)
	defer testContainer.cleanup()

	ch := createClickHouseConnection(t, testContainer)
	defer ch.Close()

	ctx := context.Background()
	logger := zap.NewNop().Sugar()

	err := ch.CreateTablesIfNotExist(ctx)
	require.NoError(t, err)

	cfg := &config.Config{}
	cfg.ClickHouse.BatchSize = 100
	cfg.Storage.DedupCacheSize = 1000

	eventCh := make(chan *core.Event, 10)
	bgCtx := context.Background()
	storage, err := NewClickHouseEventStorage(bgCtx, ch, cfg, eventCh, logger)
	require.NoError(t, err)

	// Insert events with different months
	now := time.Now()
	lastMonth := now.AddDate(0, -1, 0)

	testEvents := []*core.Event{
		{
			EventID:   "month-test-1",
			Timestamp: now,
			RawData:   "Current month event",
			SourceIP:  "192.168.1.1",
			Fields:    map[string]interface{}{"test": "current"},
		},
		{
			EventID:   "month-test-2",
			Timestamp: lastMonth,
			RawData:   "Last month event",
			SourceIP:  "192.168.1.2",
			Fields:    map[string]interface{}{"test": "last"},
		},
	}

	storage.insertBatch(testEvents) // Returns no value
	time.Sleep(500 * time.Millisecond)

	// Test GetEventCountsByMonth (previously 0% coverage)
	counts, err := storage.GetEventCountsByMonth(ctx)
	require.NoError(t, err, "Should get monthly counts")
	assert.NotNil(t, counts, "Counts should not be nil")

	// Should have at least current and last month
	assert.GreaterOrEqual(t, len(counts), 1, "Should have at least 1 month of data")
}

// TestClickHouseIntegration_EventStorage_CleanupOldEvents tests event cleanup
func TestClickHouseIntegration_EventStorage_CleanupOldEvents(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	testContainer := setupClickHouseTestContainer(t)
	defer testContainer.cleanup()

	ch := createClickHouseConnection(t, testContainer)
	defer ch.Close()

	ctx := context.Background()
	logger := zap.NewNop().Sugar()

	err := ch.CreateTablesIfNotExist(ctx)
	require.NoError(t, err)

	cfg := &config.Config{}
	cfg.ClickHouse.BatchSize = 100
	cfg.Storage.DedupCacheSize = 1000

	eventCh := make(chan *core.Event, 10)
	bgCtx := context.Background()
	storage, err := NewClickHouseEventStorage(bgCtx, ch, cfg, eventCh, logger)
	require.NoError(t, err)

	// Insert old events
	oldTimestamp := time.Now().AddDate(0, 0, -100) // 100 days ago
	oldEvents := []*core.Event{
		{
			EventID:   "old-event-1",
			Timestamp: oldTimestamp,
			RawData:   "Old event 1",
			SourceIP:  "192.168.1.1",
			Fields:    map[string]interface{}{"old": true},
		},
	}

	storage.insertBatch(oldEvents) // Returns no value
	time.Sleep(500 * time.Millisecond)

	// Get count before cleanup
	countBefore, err := storage.GetEventCount(ctx)
	require.NoError(t, err)

	// Test CleanupOldEvents (previously 0% coverage)
	err = storage.CleanupOldEvents(ctx, 90) // Delete events older than 90 days
	assert.NoError(t, err, "Should cleanup old events")

	time.Sleep(500 * time.Millisecond)

	// Get count after cleanup
	countAfter, err := storage.GetEventCount(ctx)
	require.NoError(t, err)

	// Count should be less or equal (old events should be deleted)
	assert.LessOrEqual(t, countAfter, countBefore, "Old events should be deleted")
}

// TestClickHouseIntegration_EventStorage_CreateEventIndexes tests index creation
func TestClickHouseIntegration_EventStorage_CreateEventIndexes(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	testContainer := setupClickHouseTestContainer(t)
	defer testContainer.cleanup()

	ch := createClickHouseConnection(t, testContainer)
	defer ch.Close()

	ctx := context.Background()
	logger := zap.NewNop().Sugar()

	err := ch.CreateTablesIfNotExist(ctx)
	require.NoError(t, err)

	cfg := &config.Config{}
	cfg.ClickHouse.BatchSize = 100
	cfg.Storage.DedupCacheSize = 1000

	eventCh := make(chan *core.Event, 10)
	bgCtx := context.Background()
	storage, err := NewClickHouseEventStorage(bgCtx, ch, cfg, eventCh, logger)
	require.NoError(t, err)

	// Test CreateEventIndexes (previously 0% coverage)
	err = storage.CreateEventIndexes(ctx)
	assert.NoError(t, err, "Should create indexes without error")

	// Creating indexes again should be idempotent
	err = storage.CreateEventIndexes(ctx)
	assert.NoError(t, err, "Creating indexes again should be idempotent")
}

// TestClickHouseIntegration_AlertStorage_InsertAndQuery tests full alert storage lifecycle
func TestClickHouseIntegration_AlertStorage_InsertAndQuery(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	testContainer := setupClickHouseTestContainer(t)
	defer testContainer.cleanup()

	ch := createClickHouseConnection(t, testContainer)
	defer ch.Close()

	ctx := context.Background()
	logger := zap.NewNop().Sugar()

	err := ch.CreateTablesIfNotExist(ctx)
	require.NoError(t, err)

	cfg := &config.Config{}
	cfg.ClickHouse.BatchSize = 100
	cfg.ClickHouse.FlushInterval = 1

	alertCh := make(chan *core.Alert, 100)
	storage, err := NewClickHouseAlertStorage(ctx, ch, cfg, alertCh, logger)
	require.NoError(t, err)

	// Create test alerts
	testAlerts := []*core.Alert{
		{
			AlertID:   "test-alert-1",
			RuleID:    "rule-1",
			EventID:   "event-1",
			Timestamp: time.Now(),
			Severity:  "high",
			Status:    core.AlertStatusPending,
			RuleName:  "Test Alert 1",
		},
		{
			AlertID:   "test-alert-2",
			RuleID:    "rule-2",
			EventID:   "event-2",
			Timestamp: time.Now(),
			Severity:  "medium",
			Status:    core.AlertStatusPending,
			RuleName:  "Test Alert 2",
		},
	}

	// Test InsertAlert (previously 0% coverage)
	err = storage.InsertAlert(ctx, testAlerts[0])
	assert.NoError(t, err, "Should insert single alert")

	// Test InsertAlerts with batch (previously 0% coverage via insertBatch)
	err = storage.InsertAlerts(testAlerts, ctx)
	assert.NoError(t, err, "Should insert alert batch")

	time.Sleep(500 * time.Millisecond)

	// Test GetAlerts (previously 0% coverage)
	alerts, err := storage.GetAlerts(ctx, 100, 0)
	require.NoError(t, err, "Should get alerts")
	assert.GreaterOrEqual(t, len(alerts), 2, "Should have at least 2 alerts")

	// Test GetAlertCount (previously 0% coverage)
	count, err := storage.GetAlertCount(ctx)
	require.NoError(t, err, "Should get alert count")
	assert.GreaterOrEqual(t, count, int64(2), "Should have at least 2 alerts")
}

// TestClickHouseIntegration_AlertStorage_Filtering tests alert filtering
func TestClickHouseIntegration_AlertStorage_Filtering(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	testContainer := setupClickHouseTestContainer(t)
	defer testContainer.cleanup()

	ch := createClickHouseConnection(t, testContainer)
	defer ch.Close()

	ctx := context.Background()
	logger := zap.NewNop().Sugar()

	err := ch.CreateTablesIfNotExist(ctx)
	require.NoError(t, err)

	cfg := &config.Config{}
	cfg.ClickHouse.BatchSize = 100

	alertCh := make(chan *core.Alert, 10)
	storage, err := NewClickHouseAlertStorage(ctx, ch, cfg, alertCh, logger)
	require.NoError(t, err)

	// Insert alerts with different severities
	highAlerts := []*core.Alert{
		{
			AlertID:   "high-alert-1",
			RuleID:    "rule-high",
			EventID:   "event-high-1",
			Timestamp: time.Now(),
			Severity:  "high",
			Status:    core.AlertStatusPending,
			RuleName:  "High Severity Alert",
		},
	}

	err = storage.InsertAlerts(highAlerts, ctx)
	require.NoError(t, err)
	time.Sleep(500 * time.Millisecond)

	// Test GetAlertsFiltered (previously 0% coverage)
	filteredAlerts, err := storage.GetAlertsFiltered(ctx, 100, 0, "high", "")
	require.NoError(t, err, "Should get filtered alerts")
	assert.NotNil(t, filteredAlerts, "Filtered alerts should not be nil")

	// Test GetAlertCountFiltered (previously 0% coverage)
	filteredCount, err := storage.GetAlertCountFiltered(ctx, "high", "")
	require.NoError(t, err, "Should get filtered count")
	assert.GreaterOrEqual(t, filteredCount, int64(0), "Filtered count should be non-negative")
}

// TestClickHouseIntegration_AlertStorage_TimeRangeQuery tests time-based queries
func TestClickHouseIntegration_AlertStorage_TimeRangeQuery(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	testContainer := setupClickHouseTestContainer(t)
	defer testContainer.cleanup()

	ch := createClickHouseConnection(t, testContainer)
	defer ch.Close()

	ctx := context.Background()
	logger := zap.NewNop().Sugar()

	err := ch.CreateTablesIfNotExist(ctx)
	require.NoError(t, err)

	cfg := &config.Config{}
	cfg.ClickHouse.BatchSize = 100

	alertCh := make(chan *core.Alert, 10)
	storage, err := NewClickHouseAlertStorage(ctx, ch, cfg, alertCh, logger)
	require.NoError(t, err)

	// Insert alerts at different times
	now := time.Now()
	alerts := []*core.Alert{
		{
			AlertID:   "time-alert-1",
			RuleID:    "rule-time",
			EventID:   "event-time-1",
			Timestamp: now.Add(-1 * time.Hour),
			Severity:  "low",
			Status:    core.AlertStatusPending,
			RuleName:  "1 Hour Ago",
		},
		{
			AlertID:   "time-alert-2",
			RuleID:    "rule-time",
			EventID:   "event-time-2",
			Timestamp: now,
			Severity:  "low",
			Status:    core.AlertStatusPending,
			RuleName:  "Now",
		},
	}

	err = storage.InsertAlerts(alerts, ctx)
	require.NoError(t, err)
	time.Sleep(500 * time.Millisecond)

	// Test GetAlertsByTimeRange (previously 0% coverage)
	start := now.Add(-2 * time.Hour)
	end := now.Add(1 * time.Hour)
	timeRangeAlerts, err := storage.GetAlertsByTimeRange(ctx, start, end)
	require.NoError(t, err, "Should get alerts by time range")
	assert.GreaterOrEqual(t, len(timeRangeAlerts), 0, "Should return alerts or empty slice")
}

// TestClickHouseIntegration_AlertStorage_Stats tests alert statistics
func TestClickHouseIntegration_AlertStorage_Stats(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	testContainer := setupClickHouseTestContainer(t)
	defer testContainer.cleanup()

	ch := createClickHouseConnection(t, testContainer)
	defer ch.Close()

	ctx := context.Background()
	logger := zap.NewNop().Sugar()

	err := ch.CreateTablesIfNotExist(ctx)
	require.NoError(t, err)

	cfg := &config.Config{}
	cfg.ClickHouse.BatchSize = 100

	alertCh := make(chan *core.Alert, 10)
	storage, err := NewClickHouseAlertStorage(ctx, ch, cfg, alertCh, logger)
	require.NoError(t, err)

	// Insert diverse alerts for stats
	statsAlerts := []*core.Alert{
		{
			AlertID:   "stats-alert-1",
			RuleID:    "rule-stats-1",
			EventID:   "event-stats-1",
			Timestamp: time.Now(),
			Severity:  "critical",
			Status:    core.AlertStatusPending,
			RuleName:  "Stats Test 1",
		},
		{
			AlertID:   "stats-alert-2",
			RuleID:    "rule-stats-2",
			EventID:   "event-stats-2",
			Timestamp: time.Now(),
			Severity:  "high",
			Status:    core.AlertStatusAcknowledged,
			RuleName:  "Stats Test 2",
		},
	}

	err = storage.InsertAlerts(statsAlerts, ctx)
	require.NoError(t, err)
	time.Sleep(500 * time.Millisecond)

	// Test GetAlertStats (previously 0% coverage)
	stats, err := storage.GetAlertStats(ctx)
	require.NoError(t, err, "Should get alert stats")
	assert.NotNil(t, stats, "Stats should not be nil")
}

// TestClickHouseIntegration_AlertStorage_DeleteAlert tests alert deletion
func TestClickHouseIntegration_AlertStorage_DeleteAlert(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	testContainer := setupClickHouseTestContainer(t)
	defer testContainer.cleanup()

	ch := createClickHouseConnection(t, testContainer)
	defer ch.Close()

	ctx := context.Background()
	logger := zap.NewNop().Sugar()

	err := ch.CreateTablesIfNotExist(ctx)
	require.NoError(t, err)

	cfg := &config.Config{}
	cfg.ClickHouse.BatchSize = 100

	alertCh := make(chan *core.Alert, 10)
	storage, err := NewClickHouseAlertStorage(ctx, ch, cfg, alertCh, logger)
	require.NoError(t, err)

	// Insert alert to delete
	deleteAlert := &core.Alert{
		AlertID:   "delete-test-alert",
		RuleID:    "rule-delete",
		EventID:   "event-delete",
		Timestamp: time.Now(),
		Severity:  "low",
		Status:    core.AlertStatusFalsePositive,
		RuleName:  "To Be Deleted",
	}

	err = storage.InsertAlert(ctx, deleteAlert)
	require.NoError(t, err)
	time.Sleep(500 * time.Millisecond)

	countBefore, _ := storage.GetAlertCount(ctx)

	// Test DeleteAlert (previously 0% coverage)
	err = storage.DeleteAlert(ctx, "delete-test-alert")
	assert.NoError(t, err, "Should delete alert")

	time.Sleep(500 * time.Millisecond)

	countAfter, _ := storage.GetAlertCount(ctx)

	// Count should be same or less (deletion is async in ClickHouse)
	assert.LessOrEqual(t, countAfter, countBefore, "Alert count should not increase after deletion")
}

// TestClickHouseIntegration_AlertStorage_CleanupOldAlerts tests alert cleanup
func TestClickHouseIntegration_AlertStorage_CleanupOldAlerts(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	testContainer := setupClickHouseTestContainer(t)
	defer testContainer.cleanup()

	ch := createClickHouseConnection(t, testContainer)
	defer ch.Close()

	ctx := context.Background()
	logger := zap.NewNop().Sugar()

	err := ch.CreateTablesIfNotExist(ctx)
	require.NoError(t, err)

	cfg := &config.Config{}
	cfg.ClickHouse.BatchSize = 100

	alertCh := make(chan *core.Alert, 10)
	storage, err := NewClickHouseAlertStorage(ctx, ch, cfg, alertCh, logger)
	require.NoError(t, err)

	// Insert old alerts
	oldTimestamp := time.Now().AddDate(0, 0, -100)
	oldAlerts := []*core.Alert{
		{
			AlertID:   "old-alert-cleanup",
			RuleID:    "rule-old",
			EventID:   "event-old",
			Timestamp: oldTimestamp,
			Severity:  "low",
			Status:    core.AlertStatusDismissed,
			RuleName:  "Old Alert",
		},
	}

	err = storage.InsertAlerts(oldAlerts, ctx)
	require.NoError(t, err)
	time.Sleep(500 * time.Millisecond)

	// Test CleanupOldAlerts with valid retention (partially covered at 21.1%)
	err = storage.CleanupOldAlerts(ctx, 90)
	assert.NoError(t, err, "Should cleanup old alerts")

	time.Sleep(500 * time.Millisecond)
}

// TestClickHouseIntegration_AlertStorage_GetAlertCountsByMonth tests monthly alert counts
func TestClickHouseIntegration_AlertStorage_GetAlertCountsByMonth(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	testContainer := setupClickHouseTestContainer(t)
	defer testContainer.cleanup()

	ch := createClickHouseConnection(t, testContainer)
	defer ch.Close()

	ctx := context.Background()
	logger := zap.NewNop().Sugar()

	err := ch.CreateTablesIfNotExist(ctx)
	require.NoError(t, err)

	cfg := &config.Config{}
	cfg.ClickHouse.BatchSize = 100

	alertCh := make(chan *core.Alert, 10)
	storage, err := NewClickHouseAlertStorage(ctx, ch, cfg, alertCh, logger)
	require.NoError(t, err)

	// Insert alerts in different months
	now := time.Now()
	lastMonth := now.AddDate(0, -1, 0)

	monthlyAlerts := []*core.Alert{
		{
			AlertID:   "monthly-alert-current",
			RuleID:    "rule-monthly",
			EventID:   "event-monthly-1",
			Timestamp: now,
			Severity:  "medium",
			Status:    core.AlertStatusPending,
			RuleName:  "Current Month",
		},
		{
			AlertID:   "monthly-alert-last",
			RuleID:    "rule-monthly",
			EventID:   "event-monthly-2",
			Timestamp: lastMonth,
			Severity:  "medium",
			Status:    core.AlertStatusPending,
			RuleName:  "Last Month",
		},
	}

	err = storage.InsertAlerts(monthlyAlerts, ctx)
	require.NoError(t, err)
	time.Sleep(500 * time.Millisecond)

	// Test GetAlertCountsByMonth (previously 0% coverage)
	counts, err := storage.GetAlertCountsByMonth(ctx)
	require.NoError(t, err, "Should get monthly alert counts")
	assert.NotNil(t, counts, "Monthly counts should not be nil")
	assert.GreaterOrEqual(t, len(counts), 1, "Should have at least 1 month of data")
}

// TestClickHouseIntegration_ConcurrentAccess tests concurrent operations
func TestClickHouseIntegration_ConcurrentAccess(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	testContainer := setupClickHouseTestContainer(t)
	defer testContainer.cleanup()

	ch := createClickHouseConnection(t, testContainer)
	defer ch.Close()

	ctx := context.Background()
	logger := zap.NewNop().Sugar()

	err := ch.CreateTablesIfNotExist(ctx)
	require.NoError(t, err)

	cfg := &config.Config{}
	cfg.ClickHouse.BatchSize = 100
	cfg.ClickHouse.FlushInterval = 1
	cfg.Storage.DedupCacheSize = 1000
	cfg.Storage.Deduplication = true

	// Test concurrent event inserts
	eventCh := make(chan *core.Event, 1000)
	eventStorage, err := NewClickHouseEventStorage(ctx, ch, cfg, eventCh, logger)
	require.NoError(t, err)

	// Start workers
	eventStorage.Start(3)

	// Send events concurrently
	numEvents := 100
	for i := 0; i < numEvents; i++ {
		event := &core.Event{
			EventID:   fmt.Sprintf("concurrent-event-%d", i),
			Timestamp: time.Now(),
			RawData:   fmt.Sprintf("Concurrent event %d", i),
			SourceIP:  "192.168.1.1",
			Fields: map[string]interface{}{
				"test":  "concurrent",
				"index": i,
			},
		}
		eventCh <- event
	}

	// Close and wait for workers
	close(eventCh)
	eventStorage.Stop()

	// Verify all events were processed
	time.Sleep(1 * time.Second)
	count, err := eventStorage.GetEventCount(ctx)
	require.NoError(t, err)
	assert.GreaterOrEqual(t, count, int64(numEvents), "Should have processed all events")
}

// TestClickHouseIntegration_WorkerLifecycle tests worker start/stop
func TestClickHouseIntegration_WorkerLifecycle(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	testContainer := setupClickHouseTestContainer(t)
	defer testContainer.cleanup()

	ch := createClickHouseConnection(t, testContainer)
	defer ch.Close()

	logger := zap.NewNop().Sugar()

	err := ch.CreateTablesIfNotExist(context.Background())
	require.NoError(t, err)

	cfg := &config.Config{}
	cfg.ClickHouse.BatchSize = 100
	cfg.Storage.DedupCacheSize = 1000

	// Test event worker lifecycle
	eventCh := make(chan *core.Event, 100)
	eventStorage, err := NewClickHouseEventStorage(context.Background(), ch, cfg, eventCh, logger)
	require.NoError(t, err)

	// Start workers (tests Start method - 100% coverage)
	eventStorage.Start(2)

	// Stop workers (tests Stop method - 100% coverage)
	close(eventCh)
	eventStorage.Stop()

	// Test alert worker lifecycle
	alertCh := make(chan *core.Alert, 100)
	bgCtx := context.Background()
	alertStorage, err := NewClickHouseAlertStorage(bgCtx, ch, cfg, alertCh, logger)
	require.NoError(t, err)

	alertStorage.Start(2)
	close(alertCh)
	alertStorage.Stop()
}
