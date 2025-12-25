package storage

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"cerberus/config"
	"cerberus/core"
	"cerberus/metrics"
	"cerberus/util/goroutine"

	lru "github.com/hashicorp/golang-lru/v2"
	"go.uber.org/zap"
)

// ClickHouseEventStorage handles event persistence in ClickHouse
type ClickHouseEventStorage struct {
	clickhouse          *ClickHouse
	batchSize           int
	batchFlushInterval  time.Duration
	eventCh             <-chan *core.Event
	wg                  sync.WaitGroup
	dedupCache          *lru.Cache[string, bool]
	dedupMutex          sync.RWMutex
	enableDeduplication bool
	logger              *zap.SugaredLogger
	// TASK 144: Context for graceful shutdown of worker goroutines
	ctx    context.Context
	cancel context.CancelFunc
}

// NewClickHouseEventStorage creates a new ClickHouse event storage handler
// TASK 144: Initializes context for graceful shutdown propagation
// BLOCKING-2 FIX: Accepts parent context parameter for proper context propagation
func NewClickHouseEventStorage(parentCtx context.Context, clickhouse *ClickHouse, cfg *config.Config, eventCh <-chan *core.Event, logger *zap.SugaredLogger) (*ClickHouseEventStorage, error) {
	lruCache, err := lru.New[string, bool](cfg.Storage.DedupCacheSize)
	if err != nil {
		return nil, fmt.Errorf("failed to create LRU cache: %w", err)
	}

	flushInterval := 5 * time.Second
	if cfg.ClickHouse.FlushInterval > 0 {
		flushInterval = time.Duration(cfg.ClickHouse.FlushInterval) * time.Second
	}

	batchSize := cfg.ClickHouse.BatchSize
	if batchSize == 0 {
		batchSize = 10000
	}

	// TASK 144: Create cancellable context for worker lifecycle management
	// BLOCKING-2 FIX: Derive worker context from parent context for proper cancellation propagation
	ctx, cancel := context.WithCancel(parentCtx)

	storage := &ClickHouseEventStorage{
		clickhouse:          clickhouse,
		batchSize:           batchSize,
		batchFlushInterval:  flushInterval,
		eventCh:             eventCh,
		dedupCache:          lruCache,
		enableDeduplication: cfg.Storage.Deduplication,
		logger:              logger,
		ctx:                 ctx,
		cancel:              cancel,
	}

	// DEBUG: Verify channel is not nil during initialization
	logger.Debugf("[CLICKHOUSE-INIT] ClickHouseEventStorage created with batchSize=%d, flushInterval=%v", batchSize, flushInterval)
	if eventCh == nil {
		logger.Errorf("[CLICKHOUSE-INIT] [CRITICAL] eventCh is NIL!")
	}

	return storage, nil
}

// Start starts the event storage workers
func (ces *ClickHouseEventStorage) Start(numWorkers int) {
	ces.logger.Infof("[CLICKHOUSE] Starting %d event storage workers", numWorkers)
	for i := 0; i < numWorkers; i++ {
		ces.wg.Add(1)
		workerID := i
		go ces.worker(workerID)
	}
}

// worker processes events from the channel
// TASK 144: Uses parent context for graceful shutdown support
// TASK 147: Added panic recovery to prevent worker crashes from affecting entire system
func (ces *ClickHouseEventStorage) worker(workerID int) {
	defer ces.wg.Done()
	defer goroutine.Recover("clickhouse-event-worker", ces.logger)
	ces.logger.Debugf("[CLICKHOUSE-WORKER-%d] Worker started, listening on channel", workerID)
	batch := make([]*core.Event, 0, ces.batchSize)

	flushTicker := time.NewTicker(ces.batchFlushInterval)
	defer flushTicker.Stop()

	eventCount := 0
	for {
		select {
		case event, ok := <-ces.eventCh:
			if !ok {
				// Channel closed, flush remaining batch with timeout
				ces.logger.Infof("[CLICKHOUSE-WORKER-%d] Channel closed, received %d total events, flushing %d remaining", workerID, eventCount, len(batch))
				if len(batch) > 0 {
					// TASK 144: Use timeout context for final flush, not parent context which may be cancelled
					// BLOCKING-1 FIX: Capture error and log with CRITICAL severity to prevent data loss
					flushCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
					if err := ces.insertBatchWithContext(flushCtx, batch); err != nil {
						ces.logger.Errorw("CRITICAL: Failed to flush events during channel close - data may be lost",
							"error", err,
							"event_count", len(batch),
							"worker_id", workerID)
					} else {
						ces.logger.Infof("[CLICKHOUSE-WORKER-%d] Final flush completed during channel close", workerID)
					}
					cancel()
				}
				return
			}

			eventCount++
			if eventCount == 1 || eventCount%1000 == 0 {
				// Extract event_type from Fields if present
				eventType := "unknown"
				if event.Fields != nil {
					if et, ok := event.Fields["event_type"].(string); ok {
						eventType = et
					}
				}
				ces.logger.Debugf("[CLICKHOUSE-WORKER-%d] Received event #%d from channel: ID=%s, Type=%s", workerID, eventCount, event.EventID, eventType)
			}

			// Deduplication
			if ces.enableDeduplication {
				hash := ces.hashEvent(event)
				ces.dedupMutex.Lock()

				if _, exists := ces.dedupCache.Get(hash); exists {
					ces.dedupMutex.Unlock()
					ces.logger.Debugf("[CLICKHOUSE] Event deduplicated: ID=%s", event.EventID)
					continue
				}

				ces.dedupCache.Add(hash, true)
				ces.dedupMutex.Unlock()
			}

			batch = append(batch, event)

			if len(batch) >= ces.batchSize {
				ces.logger.Debugf("[CLICKHOUSE] Batch full, inserting %d events", len(batch))
				// TASK 144: Use worker context for batch inserts to respect cancellation
				if err := ces.insertBatchWithContext(ces.ctx, batch); err != nil {
					ces.logger.Errorw("Failed to insert batch on size threshold",
						"error", err,
						"event_count", len(batch))
				}
				batch = batch[:0] // Reset batch
				flushTicker.Reset(ces.batchFlushInterval)
			}

		case <-flushTicker.C:
			if len(batch) > 0 {
				ces.logger.Debugf("[CLICKHOUSE-WORKER-%d] Flush interval reached, inserting %d events", workerID, len(batch))
				// TASK 144: Use worker context for periodic flushes
				if err := ces.insertBatchWithContext(ces.ctx, batch); err != nil {
					ces.logger.Errorw("Failed to insert batch on timer flush",
						"error", err,
						"event_count", len(batch),
						"worker_id", workerID)
				}
				batch = batch[:0]
			}

		case <-ces.ctx.Done():
			// TASK 144: Graceful shutdown requested - flush remaining batch and exit
			if len(batch) > 0 {
				ces.logger.Infof("[CLICKHOUSE-WORKER-%d] Shutdown requested, flushing %d events", workerID, len(batch))
				// Use timeout context for final flush, not cancelled parent context
				// BLOCKING-1 FIX: Capture error and log with CRITICAL severity to prevent data loss
				flushCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
				if err := ces.insertBatchWithContext(flushCtx, batch); err != nil {
					ces.logger.Errorw("CRITICAL: Failed to flush events during shutdown - data may be lost",
						"error", err,
						"event_count", len(batch),
						"worker_id", workerID)
				} else {
					ces.logger.Infof("[CLICKHOUSE-WORKER-%d] Final flush completed during shutdown", workerID)
				}
				cancel()
			}
			ces.logger.Infof("[CLICKHOUSE-WORKER-%d] Shutting down gracefully", workerID)
			return
		}
	}
}

// insertBatch inserts a batch of events using ClickHouse batch API
// TASK 144: Deprecated - use insertBatchWithContext instead
func (ces *ClickHouseEventStorage) insertBatch(batch []*core.Event) {
	// TASK 144: Create default timeout context for backward compatibility
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	ces.insertBatchWithContext(ctx, batch)
}

// insertBatchWithContext inserts a batch of events using ClickHouse batch API with context
// TASK 144: New method that accepts context for cancellation support
// BLOCKING-1 FIX: Returns error instead of void to enable proper error handling and logging
func (ces *ClickHouseEventStorage) insertBatchWithContext(ctx context.Context, batch []*core.Event) error {
	// SAFETY: Guard against nil ClickHouse connection (can occur in tests)
	if ces.clickhouse == nil || ces.clickhouse.Conn == nil {
		ces.logger.Warn("[CLICKHOUSE] Skipping event batch insert - ClickHouse connection not available")
		return nil
	}

	start := time.Now()

	// Prepare batch statement
	prepareBatch, err := ces.clickhouse.Conn.PrepareBatch(ctx, `
		INSERT INTO events (
			event_id, timestamp, ingested_at, listener_id, listener_name,
			source, source_format, raw_data, fields
		)
	`)
	if err != nil {
		ces.logger.Errorf("[CLICKHOUSE] Failed to prepare batch: %v", err)
		return fmt.Errorf("failed to prepare batch: %w", err)
	}

	// Append all events to batch
	for i, event := range batch {
		// Check context cancellation periodically (every 1000 events)
		if i > 0 && i%1000 == 0 {
			select {
			case <-ctx.Done():
				ces.logger.Debugw("Context cancelled during ClickHouse batch append",
					"processed_events", i,
					"total_events", len(batch))
				return ctx.Err()
			default:
			}
		}

		// Serialize Fields to JSON
		fieldsData := ""
		if event.Fields != nil && len(event.Fields) > 0 {
			if data, err := json.Marshal(event.Fields); err == nil {
				fieldsData = string(data)
			}
		}

		err := prepareBatch.Append(
			event.EventID,
			event.Timestamp,
			event.IngestedAt,
			event.ListenerID,
			event.ListenerName,
			event.Source,
			event.SourceFormat,
			string(event.RawData), // Convert json.RawMessage to string for ClickHouse String column
			fieldsData,
		)
		if err != nil {
			ces.logger.Errorf("[CLICKHOUSE] Failed to append event %s: %v", event.EventID, err)
		}
	}

	// Send batch
	if err := prepareBatch.Send(); err != nil {
		ces.logger.Errorf("[CLICKHOUSE] Failed to send batch: %v", err)
		return fmt.Errorf("failed to send batch: %w", err)
	}

	duration := time.Since(start)
	eps := float64(len(batch)) / duration.Seconds()
	ces.logger.Debugf("[CLICKHOUSE] Inserted %d events in %v (%.0f events/sec)", len(batch), duration, eps)

	// Update metrics
	for i, event := range batch {
		// Check context cancellation periodically (every 1000 events)
		if i > 0 && i%1000 == 0 {
			select {
			case <-ctx.Done():
				ces.logger.Debugw("Context cancelled during metrics update",
					"processed_events", i,
					"total_events", len(batch))
				return ctx.Err()
			default:
			}
		}
		metrics.EventsIngested.WithLabelValues(event.SourceFormat).Inc()
	}

	return nil
}

// hashEvent generates a hash for deduplication
func (ces *ClickHouseEventStorage) hashEvent(event *core.Event) string {
	// Extract source_ip from Fields if present
	sourceIP := "unknown"
	if event.Fields != nil {
		if ip, ok := event.Fields["source_ip"].(string); ok {
			sourceIP = ip
		}
	}

	// Extract event_type from Fields if present
	eventType := "unknown"
	if event.Fields != nil {
		if et, ok := event.Fields["event_type"].(string); ok {
			eventType = et
		}
	}

	return fmt.Sprintf("%s|%s|%s|%d", string(event.RawData), eventType, sourceIP, event.Timestamp.Unix())
}

// Stop gracefully shuts down all workers
// TASK 144: Triggers context cancellation to signal workers to stop
// BLOCKING-3 FIX: Implements timeout on WaitGroup.Wait() to prevent indefinite blocking
func (ces *ClickHouseEventStorage) Stop() error {
	// Cancel context to signal workers to stop
	if ces.cancel != nil {
		ces.cancel()
	}

	// BLOCKING-3 FIX: Wait for workers with timeout to prevent indefinite blocking
	// TASK 147: Added panic recovery to timeout helper goroutine
	done := make(chan struct{})
	go func() {
		defer goroutine.Recover("clickhouse-event-shutdown-helper", ces.logger)
		ces.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		ces.logger.Info("[CLICKHOUSE] All event workers stopped gracefully")
		return nil
	case <-time.After(30 * time.Second):
		ces.logger.Error("[CLICKHOUSE] CRITICAL: Event workers did not stop within 30s - possible hung worker")
		return fmt.Errorf("graceful shutdown timeout: event workers did not stop within 30s")
	}
}

// EventsPage represents a page of events with cursor for pagination
type EventsPage struct {
	Events     []core.Event `json:"events"`
	NextCursor string       `json:"next_cursor,omitempty"` // Cursor for next page (timestamp_eventID)
	HasMore    bool         `json:"has_more"`
}

// GetEvents retrieves recent events using offset-based pagination
// DEPRECATED: Use GetEventsWithCursor for better performance on large datasets
// This function uses OFFSET which is O(n) and slow for large offsets
func (ces *ClickHouseEventStorage) GetEvents(ctx context.Context, limit, offset int) ([]core.Event, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	query := `
		SELECT
			event_id, timestamp, ingested_at, listener_id, listener_name,
			source, source_format, raw_data, fields
		FROM events
		ORDER BY timestamp DESC, event_id DESC
		LIMIT ? OFFSET ?
	`

	rows, err := ces.clickhouse.Conn.Query(ctx, query, limit, offset)
	if err != nil {
		return nil, fmt.Errorf("failed to query events: %w", err)
	}
	defer rows.Close()

	events := make([]core.Event, 0)
	for rows.Next() {
		var event core.Event
		var fieldsData string
		var rawDataStr string // Scan into string, then convert to json.RawMessage

		err := rows.Scan(
			&event.EventID,
			&event.Timestamp,
			&event.IngestedAt,
			&event.ListenerID,
			&event.ListenerName,
			&event.Source,
			&event.SourceFormat,
			&rawDataStr,
			&fieldsData,
		)
		if err != nil {
			ces.logger.Errorf("Failed to scan event: %v", err)
			continue
		}

		// Convert raw_data string to json.RawMessage
		event.RawData = json.RawMessage(rawDataStr)

		// Deserialize Fields from JSON
		if fieldsData != "" {
			var fields map[string]interface{}
			if err := json.Unmarshal([]byte(fieldsData), &fields); err == nil {
				event.Fields = fields
			}
		}

		events = append(events, event)
	}

	return events, nil
}

// GetEventsWithCursor retrieves events using cursor-based pagination for better performance
// PERFORMANCE: O(1) pagination instead of O(n) offset-based pagination
// cursor format: "timestamp_eventID" or empty for first page
func (ces *ClickHouseEventStorage) GetEventsWithCursor(ctx context.Context, limit int, cursor string) (*EventsPage, error) {
	const maxLimit = 10000

	// Validate limit
	if limit <= 0 || limit > maxLimit {
		return nil, fmt.Errorf("limit must be between 1 and %d, got %d", maxLimit, limit)
	}

	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	var lastTimestamp time.Time
	var lastEventID string

	// Parse cursor if provided
	if cursor != "" {
		parts := strings.Split(cursor, "_")
		if len(parts) == 2 {
			timestampNs, err := strconv.ParseInt(parts[0], 10, 64)
			if err != nil {
				return nil, fmt.Errorf("invalid cursor format: timestamp parsing failed: %w", err)
			}
			lastTimestamp = time.Unix(0, timestampNs)
			lastEventID = parts[1]
		} else {
			return nil, fmt.Errorf("invalid cursor format: expected 'timestamp_eventID'")
		}
	}

	// Build query with cursor-based filtering
	var query string
	var args []interface{}

	if cursor == "" {
		// First page - no cursor filtering
		query = `
			SELECT
				event_id, timestamp, ingested_at, listener_id, listener_name,
				source, source_format, raw_data, fields
			FROM events
			ORDER BY timestamp DESC, event_id DESC
			LIMIT ?
		`
		args = []interface{}{limit + 1} // Fetch limit+1 to check if there are more results
	} else {
		// Subsequent pages - filter using cursor position
		// Find events older than the cursor position
		query = `
			SELECT
				event_id, timestamp, ingested_at, listener_id, listener_name,
				source, source_format, raw_data, fields
			FROM events
			WHERE (timestamp, event_id) < (?, ?)
			ORDER BY timestamp DESC, event_id DESC
			LIMIT ?
		`
		args = []interface{}{lastTimestamp, lastEventID, limit + 1}
	}

	rows, err := ces.clickhouse.Conn.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to query events: %w", err)
	}
	defer rows.Close()

	events := make([]core.Event, 0, limit)
	for rows.Next() {
		var event core.Event
		var fieldsData string
		var rawDataStr string // Scan into string, then convert to json.RawMessage

		err := rows.Scan(
			&event.EventID,
			&event.Timestamp,
			&event.IngestedAt,
			&event.ListenerID,
			&event.ListenerName,
			&event.Source,
			&event.SourceFormat,
			&rawDataStr,
			&fieldsData,
		)
		if err != nil {
			ces.logger.Errorf("Failed to scan event: %v", err)
			continue
		}

		// Convert raw_data string to json.RawMessage
		event.RawData = json.RawMessage(rawDataStr)

		// Deserialize Fields from JSON
		if fieldsData != "" {
			var fields map[string]interface{}
			if err := json.Unmarshal([]byte(fieldsData), &fields); err == nil {
				event.Fields = fields
			}
		}

		events = append(events, event)
	}

	// Check if there are more results
	hasMore := len(events) > limit
	if hasMore {
		events = events[:limit] // Trim to requested limit
	}

	// Generate next cursor if there are more results
	var nextCursor string
	if hasMore && len(events) > 0 {
		lastEvent := events[len(events)-1]
		// Format: timestamp_eventID (use Unix nanoseconds for precision)
		nextCursor = fmt.Sprintf("%d_%s", lastEvent.Timestamp.UnixNano(), lastEvent.EventID)
	}

	return &EventsPage{
		Events:     events,
		NextCursor: nextCursor,
		HasMore:    hasMore,
	}, nil
}

// GetEventCount returns total event count
func (ces *ClickHouseEventStorage) GetEventCount(ctx context.Context) (int64, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	var count uint64
	err := ces.clickhouse.Conn.QueryRow(ctx, "SELECT count() FROM events").Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("failed to count events: %w", err)
	}

	return int64(count), nil
}

// GetEventCountsByMonth returns event counts grouped by month
func (ces *ClickHouseEventStorage) GetEventCountsByMonth(ctx context.Context) ([]map[string]interface{}, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	// Get last 6 months
	months := core.DefaultChartMonths
	query := `
		SELECT
			toStartOfMonth(timestamp) as month,
			count() as count
		FROM events
		WHERE timestamp >= now() - INTERVAL ? MONTH
		GROUP BY month
		ORDER BY month ASC
	`

	rows, err := ces.clickhouse.Conn.Query(ctx, query, months)
	if err != nil {
		return nil, fmt.Errorf("failed to query event counts: %w", err)
	}
	defer rows.Close()

	// Create map of results
	results := make(map[string]int)
	for rows.Next() {
		var month time.Time
		var count uint64

		if err := rows.Scan(&month, &count); err != nil {
			return nil, err
		}

		monthStr := month.Format("2006-01")
		results[monthStr] = int(count)
	}

	// Build chart data for all months (fill in zeros for missing months)
	chartData := make([]map[string]interface{}, 0, months)
	now := time.Now()

	for i := 0; i < months; i++ {
		targetMonth := now.AddDate(0, -(months-1)+i, 0)
		monthStr := fmt.Sprintf("%d-%02d", targetMonth.Year(), targetMonth.Month())

		count := 0
		if c, exists := results[monthStr]; exists {
			count = c
		}

		chartData = append(chartData, map[string]interface{}{
			"name":   monthStr,
			"events": count,
		})
	}

	return chartData, nil
}

// CleanupOldEvents uses ClickHouse's efficient partition dropping
func (ces *ClickHouseEventStorage) CleanupOldEvents(ctx context.Context, retentionDays int) error {
	ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()

	// ClickHouse TTL handles this automatically, but we can also drop old partitions manually
	cutoffDate := time.Now().AddDate(0, 0, -retentionDays)
	partition := cutoffDate.Format("200601") // YYYYMM format

	// Validate partition format to prevent SQL injection (must be exactly 6 digits)
	if !regexp.MustCompile(`^\d{6}$`).MatchString(partition) {
		return fmt.Errorf("invalid partition format: %s (expected YYYYMM)", partition)
	}

	query := fmt.Sprintf("ALTER TABLE events DROP PARTITION '%s'", partition)

	err := ces.clickhouse.Conn.Exec(ctx, query)
	if err != nil {
		ces.logger.Warnf("Failed to drop partition %s: %v (may not exist)", partition, err)
	} else {
		ces.logger.Infof("Dropped events partition %s", partition)
	}

	return nil
}

// GetDatabaseInterface returns the ClickHouse connection for search operations
func (ces *ClickHouseEventStorage) GetDatabaseInterface() interface{} {
	return ces.clickhouse.Conn
}

// GetDatabase returns the ClickHouse connection (deprecated, use GetDatabaseInterface)
func (ces *ClickHouseEventStorage) GetDatabase() interface{} {
	return ces.clickhouse.Conn
}

// GetClickHouse returns the underlying ClickHouse connection (for search executor)
func (ces *ClickHouseEventStorage) GetClickHouse() *ClickHouse {
	return ces.clickhouse
}

// CreateEventIndexes creates indexes for efficient event queries
// PERFORMANCE: Indexes dramatically improve query performance for pagination and filtering
// These indexes are safe to call multiple times - ClickHouse will skip if they exist
func (ces *ClickHouseEventStorage) CreateEventIndexes(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()

	queries := []struct {
		name  string
		query string
	}{
		{
			name: "timestamp_eventid_minmax",
			query: `ALTER TABLE events
				ADD INDEX IF NOT EXISTS idx_timestamp_eventid (timestamp, event_id)
				TYPE minmax GRANULARITY 1`,
		},
		{
			name: "source_format_set",
			query: `ALTER TABLE events
				ADD INDEX IF NOT EXISTS idx_source_format (source_format)
				TYPE set(0) GRANULARITY 1`,
		},
		{
			name: "listener_name_set",
			query: `ALTER TABLE events
				ADD INDEX IF NOT EXISTS idx_listener_name (listener_name)
				TYPE set(0) GRANULARITY 1`,
		},
	}

	for _, q := range queries {
		if err := ces.clickhouse.Conn.Exec(ctx, q.query); err != nil {
			// Log but don't fail - index might already exist or table might not support it
			ces.logger.Warnf("Failed to create index %s: %v", q.name, err)
		} else {
			ces.logger.Infof("Created or verified index: %s", q.name)
		}
	}

	return nil
}
