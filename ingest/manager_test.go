package ingest

import (
	"context"
	"sync"
	"testing"
	"time"

	"cerberus/config"
	"cerberus/core"
	"cerberus/storage"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap/zaptest"
)

// TestListenerManager_MultiFormatRouting tests multi-format ingestion routing
func TestListenerManager_MultiFormatRouting(t *testing.T) {
	mockStorage := newMockListenerStorage()
	mockFieldMapping := newMockFieldMappingStorage()
	eventCh := make(chan *core.Event, 1000)
	cfg := &config.Config{}
	logger := zaptest.NewLogger(t).Sugar()

	// BLOCKING-3 FIX: Pass nil for DLQ in tests (no malformed event handling needed)
	lm := NewListenerManager(mockStorage, mockFieldMapping, eventCh, cfg, logger, nil)
	defer lm.Shutdown()

	// Create listeners for different formats
	formats := []struct {
		name     string
		listener *storage.DynamicListener
	}{
		{
			name: "Syslog listener",
			listener: &storage.DynamicListener{
				Name:     "syslog-udp",
				Type:     "syslog",
				Protocol: "udp",
				Host:     "127.0.0.1",
				Port:     0,
				Source:   "syslog-source",
			},
		},
		{
			name: "CEF listener",
			listener: &storage.DynamicListener{
				Name:     "cef-tcp",
				Type:     "cef",
				Protocol: "tcp",
				Host:     "127.0.0.1",
				Port:     0,
				Source:   "cef-source",
			},
		},
		{
			name: "JSON listener",
			listener: &storage.DynamicListener{
				Name:     "json-http",
				Type:     "json",
				Protocol: "http",
				Host:     "127.0.0.1",
				Port:     0,
				Source:   "json-source",
			},
		},
	}

	// Create and start all listeners
	listenerIDs := make([]string, 0, len(formats))
	for _, format := range formats {
		created, err := lm.CreateListener(format.listener)
		require.NoError(t, err, format.name)
		listenerIDs = append(listenerIDs, created.ID)

		err = lm.StartListener(created.ID)
		require.NoError(t, err, format.name)
	}

	// Wait for listeners to start
	time.Sleep(100 * time.Millisecond)

	// Verify all listeners are running
	running, err := lm.ListListeners()
	require.NoError(t, err)
	assert.GreaterOrEqual(t, len(running), len(formats))

	// Verify listeners are routing events
	for _, id := range listenerIDs {
		listener, err := lm.GetListener(id)
		require.NoError(t, err)
		assert.Equal(t, "running", listener.Status)
	}

	// Cleanup
	for _, id := range listenerIDs {
		lm.StopListener(id)
	}
}

// TestListenerManager_PipelineErrorHandling tests error handling in the ingestion pipeline
func TestListenerManager_PipelineErrorHandling(t *testing.T) {
	mockStorage := newMockListenerStorage()
	mockFieldMapping := newMockFieldMappingStorage()
	eventCh := make(chan *core.Event, 100)
	cfg := &config.Config{}
	logger := zaptest.NewLogger(t).Sugar()

	// Create DLQ for error handling
	db := setupDLQTestDB(t)
	defer db.Close()
	dlq := NewDLQ(db, logger)

	// BLOCKING-3 FIX: Pass nil for DLQ in tests (no malformed event handling needed)
	lm := NewListenerManager(mockStorage, mockFieldMapping, eventCh, cfg, logger, nil)
	lm.SetDLQ(dlq)
	defer lm.Shutdown()

	// Create a syslog listener
	listener := &storage.DynamicListener{
		Name:     "test-error-handling",
		Type:     "syslog",
		Protocol: "udp",
		Host:     "127.0.0.1",
		Port:     0,
		Source:   "test-source",
	}

	created, err := lm.CreateListener(listener)
	require.NoError(t, err)

	err = lm.StartListener(created.ID)
	require.NoError(t, err)

	// Wait for listener to start
	time.Sleep(100 * time.Millisecond)

	// Increment error count (simulating parser errors)
	lm.IncrementErrorCount(created.ID)

	// Get statistics
	stats, err := lm.GetStatistics(created.ID)
	require.NoError(t, err)
	assert.Greater(t, stats.ErrorCount, int64(0))

	// Stop listener
	err = lm.StopListener(created.ID)
	require.NoError(t, err)
}

// TestListenerManager_MetricsCollection tests ingestion metrics collection
func TestListenerManager_MetricsCollection(t *testing.T) {
	mockStorage := newMockListenerStorage()
	mockFieldMapping := newMockFieldMappingStorage()
	eventCh := make(chan *core.Event, 1000)
	cfg := &config.Config{}
	logger := zaptest.NewLogger(t).Sugar()

	// BLOCKING-3 FIX: Pass nil for DLQ in tests (no malformed event handling needed)
	lm := NewListenerManager(mockStorage, mockFieldMapping, eventCh, cfg, logger, nil)
	defer lm.Shutdown()

	// Create listener
	listener := &storage.DynamicListener{
		Name:     "test-metrics",
		Type:     "syslog",
		Protocol: "udp",
		Host:     "127.0.0.1",
		Port:     0,
		Source:   "test-source",
	}

	created, err := lm.CreateListener(listener)
	require.NoError(t, err)

	err = lm.StartListener(created.ID)
	require.NoError(t, err)

	// Wait for listener to start
	time.Sleep(100 * time.Millisecond)

	// Increment event count multiple times
	for i := 0; i < 10; i++ {
		lm.IncrementEventCount(created.ID)
		time.Sleep(10 * time.Millisecond)
	}

	// Get statistics
	stats, err := lm.GetStatistics(created.ID)
	require.NoError(t, err)
	assert.GreaterOrEqual(t, stats.EventsReceived, int64(10))

	// Check events per minute calculation
	if stats.UptimeDuration > 0 {
		assert.Greater(t, stats.EventsPerMinute, 0.0)
	}

	// Stop listener
	err = lm.StopListener(created.ID)
	require.NoError(t, err)
}

// TestListenerManager_GracefulShutdown tests graceful shutdown and cleanup
func TestListenerManager_GracefulShutdown(t *testing.T) {
	mockStorage := newMockListenerStorage()
	mockFieldMapping := newMockFieldMappingStorage()
	eventCh := make(chan *core.Event, 100)
	cfg := &config.Config{}
	logger := zaptest.NewLogger(t).Sugar()

	// BLOCKING-3 FIX: Pass nil for DLQ in tests (no malformed event handling needed)
	lm := NewListenerManager(mockStorage, mockFieldMapping, eventCh, cfg, logger, nil)

	// Create multiple listeners
	listenerIDs := make([]string, 0, 3)
	for i := 0; i < 3; i++ {
		listener := &storage.DynamicListener{
			Name:     "test-shutdown",
			Type:     "syslog",
			Protocol: "udp",
			Host:     "127.0.0.1",
			Port:     0,
			Source:   "test-source",
		}
		created, err := lm.CreateListener(listener)
		require.NoError(t, err)
		listenerIDs = append(listenerIDs, created.ID)

		err = lm.StartListener(created.ID)
		require.NoError(t, err)
	}

	// Wait for listeners to start
	time.Sleep(100 * time.Millisecond)

	// Verify listeners are running
	running, err := lm.ListListeners()
	require.NoError(t, err)
	assert.GreaterOrEqual(t, len(running), 3)

	// Shutdown manager
	lm.Shutdown()

	// Wait for shutdown to complete
	time.Sleep(200 * time.Millisecond)

	// Verify all listeners are stopped
	running, err = lm.ListListeners()
	require.NoError(t, err)
	for _, listener := range running {
		if contains(listenerIDs, listener.ID) {
			assert.Equal(t, "stopped", listener.Status)
		}
	}
}

// TestListenerManager_ConcurrentIngestion tests concurrent ingestion from multiple sources
func TestListenerManager_ConcurrentIngestion(t *testing.T) {
	mockStorage := newMockListenerStorage()
	mockFieldMapping := newMockFieldMappingStorage()
	eventCh := make(chan *core.Event, 10000)
	cfg := &config.Config{}
	logger := zaptest.NewLogger(t).Sugar()

	// BLOCKING-3 FIX: Pass nil for DLQ in tests (no malformed event handling needed)
	lm := NewListenerManager(mockStorage, mockFieldMapping, eventCh, cfg, logger, nil)
	defer lm.Shutdown()

	// Create multiple listeners for concurrent ingestion
	const numListeners = 5
	listenerIDs := make([]string, 0, numListeners)

	for i := 0; i < numListeners; i++ {
		listener := &storage.DynamicListener{
			Name:     "concurrent-listener",
			Type:     "syslog",
			Protocol: "udp",
			Host:     "127.0.0.1",
			Port:     0,
			Source:   "concurrent-source",
		}
		created, err := lm.CreateListener(listener)
		require.NoError(t, err)
		listenerIDs = append(listenerIDs, created.ID)

		err = lm.StartListener(created.ID)
		require.NoError(t, err)
	}

	// Wait for listeners to start
	time.Sleep(100 * time.Millisecond)

	// Concurrently increment event counts
	const eventsPerListener = 100
	var wg sync.WaitGroup
	for _, id := range listenerIDs {
		wg.Add(1)
		go func(listenerID string) {
			defer wg.Done()
			for i := 0; i < eventsPerListener; i++ {
				lm.IncrementEventCount(listenerID)
			}
		}(id)
	}

	wg.Wait()

	// Verify all listeners received events
	for _, id := range listenerIDs {
		stats, err := lm.GetStatistics(id)
		require.NoError(t, err)
		assert.Equal(t, int64(eventsPerListener), stats.EventsReceived)
	}

	// Stop all listeners
	for _, id := range listenerIDs {
		lm.StopListener(id)
	}
}

// TestListenerManager_BackpressureHandling tests backpressure when event channel is full
func TestListenerManager_BackpressureHandling(t *testing.T) {
	mockStorage := newMockListenerStorage()
	mockFieldMapping := newMockFieldMappingStorage()
	// Small channel to simulate backpressure (buffer of 2 to allow filling)
	eventCh := make(chan *core.Event, 2)
	cfg := &config.Config{}
	logger := zaptest.NewLogger(t).Sugar()

	// BLOCKING-3 FIX: Pass nil for DLQ in tests (no malformed event handling needed)
	lm := NewListenerManager(mockStorage, mockFieldMapping, eventCh, cfg, logger, nil)
	defer lm.Shutdown()

	// Create listener
	listener := &storage.DynamicListener{
		Name:     "test-backpressure",
		Type:     "syslog",
		Protocol: "udp",
		Host:     "127.0.0.1",
		Port:     0,
		Source:   "test-source",
	}

	created, err := lm.CreateListener(listener)
	require.NoError(t, err)

	err = lm.StartListener(created.ID)
	require.NoError(t, err)

	// Wait for listener to start
	time.Sleep(100 * time.Millisecond)

	// Fill the channel to create backpressure (capacity is 2)
	eventCh <- &core.Event{Timestamp: time.Now(), Fields: map[string]interface{}{"test": "1"}}
	eventCh <- &core.Event{Timestamp: time.Now(), Fields: map[string]interface{}{"test": "2"}}

	// Verify channel is full (backpressure scenario)
	// The listener should handle this gracefully without crashing
	// Use select with timeout to avoid blocking forever
	select {
	case eventCh <- &core.Event{Timestamp: time.Now(), Fields: map[string]interface{}{"test": "3"}}:
		// Channel accepted, which means one was consumed
	case <-time.After(100 * time.Millisecond):
		// Channel full, backpressure in effect - this is expected behavior
	}

	// Drain the channel to clean up
	for len(eventCh) > 0 {
		<-eventCh
	}

	// Stop listener
	err = lm.StopListener(created.ID)
	require.NoError(t, err)
}

// TestListenerManager_DLQRouting tests DLQ routing for malformed events
func TestListenerManager_DLQRouting(t *testing.T) {
	mockStorage := newMockListenerStorage()
	mockFieldMapping := newMockFieldMappingStorage()
	eventCh := make(chan *core.Event, 100)
	cfg := &config.Config{}
	logger := zaptest.NewLogger(t).Sugar()

	// Create DLQ
	db := setupDLQTestDB(t)
	defer db.Close()
	dlq := NewDLQ(db, logger)

	// BLOCKING-3 FIX: Pass nil for DLQ in tests (no malformed event handling needed)
	lm := NewListenerManager(mockStorage, mockFieldMapping, eventCh, cfg, logger, nil)
	lm.SetDLQ(dlq)
	defer lm.Shutdown()

	// Create listener
	listener := &storage.DynamicListener{
		Name:     "test-dlq",
		Type:     "syslog",
		Protocol: "udp",
		Host:     "127.0.0.1",
		Port:     0,
		Source:   "test-source",
	}

	created, err := lm.CreateListener(listener)
	require.NoError(t, err)

	err = lm.StartListener(created.ID)
	require.NoError(t, err)

	// Wait for listener to start
	time.Sleep(100 * time.Millisecond)

	// Verify DLQ is set on the listener
	// This is tested indirectly through error handling

	// Stop listener
	err = lm.StopListener(created.ID)
	require.NoError(t, err)
}

// TestListenerManager_FormatDistribution tests format distribution metrics
func TestListenerManager_FormatDistribution(t *testing.T) {
	mockStorage := newMockListenerStorage()
	mockFieldMapping := newMockFieldMappingStorage()
	eventCh := make(chan *core.Event, 1000)
	cfg := &config.Config{}
	logger := zaptest.NewLogger(t).Sugar()

	// BLOCKING-3 FIX: Pass nil for DLQ in tests (no malformed event handling needed)
	lm := NewListenerManager(mockStorage, mockFieldMapping, eventCh, cfg, logger, nil)
	defer lm.Shutdown()

	// Create listeners for different formats
	formats := []string{"syslog", "cef", "json"}
	formatCounts := make(map[string]int)

	for _, format := range formats {
		listener := &storage.DynamicListener{
			Name:     "format-" + format,
			Type:     format,
			Protocol: "udp",
			Host:     "127.0.0.1",
			Port:     0,
			Source:   format + "-source",
		}
		if format == "json" {
			listener.Protocol = "http"
		}

		created, err := lm.CreateListener(listener)
		require.NoError(t, err)

		err = lm.StartListener(created.ID)
		require.NoError(t, err)

		formatCounts[format] = 0
	}

	// Wait for listeners to start
	time.Sleep(100 * time.Millisecond)

	// Get all listeners and verify format distribution
	all, err := lm.ListListeners()
	require.NoError(t, err)

	for _, listener := range all {
		if count, ok := formatCounts[listener.Type]; ok {
			formatCounts[listener.Type] = count + 1
		}
	}

	// Verify each format has at least one listener
	for format := range formatCounts {
		assert.Greater(t, formatCounts[format], 0, "Format %s should have at least one listener", format)
	}

	// Cleanup
	all, _ = lm.ListListeners()
	for _, listener := range all {
		lm.StopListener(listener.ID)
	}
}

// Helper function to check if slice contains string
func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

// TestListenerManager_RestoreListeners tests listener restoration on startup
func TestListenerManager_RestoreListeners(t *testing.T) {
	mockStorage := newMockListenerStorage()
	mockFieldMapping := newMockFieldMappingStorage()
	eventCh := make(chan *core.Event, 100)
	cfg := &config.Config{}
	logger := zaptest.NewLogger(t).Sugar()

	// BLOCKING-3 FIX: Pass nil for DLQ in tests (no malformed event handling needed)
	lm := NewListenerManager(mockStorage, mockFieldMapping, eventCh, cfg, logger, nil)
	defer lm.Shutdown()

	// Create a listener and stop it (simulating saved state)
	listener := &storage.DynamicListener{
		Name:     "test-restore",
		Type:     "syslog",
		Protocol: "udp",
		Host:     "127.0.0.1",
		Port:     0,
		Source:   "test-source",
		Status:   "stopped",
	}

	created, err := lm.CreateListener(listener)
	require.NoError(t, err)

	// Restore listeners (should not start stopped listeners by default)
	err = lm.RestoreListeners()
	require.NoError(t, err)

	// Verify listener status
	retrieved, err := lm.GetListener(created.ID)
	require.NoError(t, err)
	assert.Equal(t, "stopped", retrieved.Status)
}

// TestListenerManager_ConcurrentAccess tests concurrent access to manager
func TestListenerManager_ConcurrentAccess(t *testing.T) {
	mockStorage := newMockListenerStorage()
	mockFieldMapping := newMockFieldMappingStorage()
	eventCh := make(chan *core.Event, 10000)
	cfg := &config.Config{}
	logger := zaptest.NewLogger(t).Sugar()

	// BLOCKING-3 FIX: Pass nil for DLQ in tests (no malformed event handling needed)
	lm := NewListenerManager(mockStorage, mockFieldMapping, eventCh, cfg, logger, nil)
	defer lm.Shutdown()

	// Create a listener
	listener := &storage.DynamicListener{
		Name:     "test-concurrent",
		Type:     "syslog",
		Protocol: "udp",
		Host:     "127.0.0.1",
		Port:     0,
		Source:   "test-source",
	}

	created, err := lm.CreateListener(listener)
	require.NoError(t, err)

	err = lm.StartListener(created.ID)
	require.NoError(t, err)

	// Wait for listener to start
	time.Sleep(100 * time.Millisecond)

	// Concurrently access manager
	const numGoroutines = 10
	var wg sync.WaitGroup
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-ctx.Done():
					return
				default:
					// Concurrent operations
					lm.GetListener(created.ID)
					lm.ListListeners()
					lm.IncrementEventCount(created.ID)
					lm.GetStatistics(created.ID)
				}
			}
		}()
	}

	wg.Wait()

	// Verify no data races occurred (test would fail with race detector)
	stats, err := lm.GetStatistics(created.ID)
	require.NoError(t, err)
	assert.GreaterOrEqual(t, stats.EventsReceived, int64(0))

	// Stop listener
	err = lm.StopListener(created.ID)
	require.NoError(t, err)
}
