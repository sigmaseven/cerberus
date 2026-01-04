package storage

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
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

// PERFORMANCE OPTIMIZATION: sync.Pool for JSON encoding buffers
// This reduces allocations by reusing byte buffers across batch inserts
// Expected impact: 15-40% throughput improvement in JSON-heavy workloads
var jsonBufferPool = sync.Pool{
	New: func() interface{} {
		return bytes.NewBuffer(make([]byte, 0, 4096)) // Pre-allocate 4KB
	},
}

// canonicalBufferPool provides reusable buffers for canonical JSON serialization
// Used by hashEvent when canonical deduplication is enabled
var canonicalBufferPool = sync.Pool{
	New: func() interface{} {
		return bytes.NewBuffer(make([]byte, 0, 4096)) // Pre-allocate 4KB
	},
}

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
	useCanonicalHash    bool // Use canonical JSON hashing for format-agnostic deduplication
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
		useCanonicalHash:    cfg.Storage.DedupCanonical,
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

			// NOTE: Deduplication now happens at ingestion time (dedup.Service)
			// before events reach the storage layer. This eliminates wasted CPU
			// on detection/correlation for duplicate events. The ContentHash
			// is computed and attached to events at ingestion time.
			//
			// The storage layer just persists events and their content_hash.
			// If ContentHash is not set (e.g., for events from older ingestion paths),
			// it will be computed during batch insert.

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

// Retry configuration for transient ClickHouse failures
const (
	maxRetryAttempts     = 3
	initialRetryDelay    = 100 * time.Millisecond
	maxRetryDelay        = 5 * time.Second
	retryBackoffMultiple = 2.0
)

// isRetryableError checks if an error is transient and worth retrying
func isRetryableError(err error) bool {
	if err == nil {
		return false
	}
	errStr := err.Error()
	// Transient errors that are worth retrying
	return strings.Contains(errStr, "connection refused") ||
		strings.Contains(errStr, "connection reset") ||
		strings.Contains(errStr, "timeout") ||
		strings.Contains(errStr, "temporary failure") ||
		strings.Contains(errStr, "too many connections") ||
		strings.Contains(errStr, "server is overloaded") ||
		strings.Contains(errStr, "i/o timeout") ||
		strings.Contains(errStr, "EOF")
}

// insertBatchWithContext inserts a batch of events using ClickHouse batch API with context
// TASK 144: New method that accepts context for cancellation support
// BLOCKING-1 FIX: Returns error instead of void to enable proper error handling and logging
// PIPELINE FIX: Added retry logic with exponential backoff for transient failures
func (ces *ClickHouseEventStorage) insertBatchWithContext(ctx context.Context, batch []*core.Event) error {
	// SAFETY: Guard against nil ClickHouse connection (can occur in tests)
	if ces.clickhouse == nil || ces.clickhouse.Conn == nil {
		ces.logger.Warn("[CLICKHOUSE] Skipping event batch insert - ClickHouse connection not available")
		return nil
	}

	start := time.Now()
	var lastErr error

	// Retry loop with exponential backoff
	for attempt := 0; attempt < maxRetryAttempts; attempt++ {
		if attempt > 0 {
			// Exponential backoff
			delay := initialRetryDelay * time.Duration(1<<uint(attempt-1))
			if delay > maxRetryDelay {
				delay = maxRetryDelay
			}
			ces.logger.Warnw("Retrying batch insert after transient failure",
				"attempt", attempt+1,
				"max_attempts", maxRetryAttempts,
				"delay", delay,
				"error", lastErr)
			metrics.StorageBatchInsertRetries.WithLabelValues("events").Inc()

			select {
			case <-ctx.Done():
				metrics.StorageEventsDropped.WithLabelValues("events", "context_cancelled").Add(float64(len(batch)))
				return ctx.Err()
			case <-time.After(delay):
			}
		}

		err := ces.doInsertBatch(ctx, batch)
		if err == nil {
			// Success - record duration and return
			duration := time.Since(start)
			metrics.StorageBatchInsertDuration.WithLabelValues("events").Observe(duration.Seconds())
			eps := float64(len(batch)) / duration.Seconds()
			ces.logger.Debugf("[CLICKHOUSE] Inserted %d events in %v (%.0f events/sec)", len(batch), duration, eps)

			// Update ingestion metrics
			for _, event := range batch {
				metrics.EventsIngested.WithLabelValues(event.SourceFormat).Inc()
			}
			return nil
		}

		lastErr = err
		if !isRetryableError(err) {
			// Non-retryable error - fail immediately
			ces.logger.Errorw("Non-retryable batch insert error",
				"error", err,
				"event_count", len(batch))
			metrics.StorageBatchInsertFailures.WithLabelValues("events", "send").Inc()
			metrics.StorageEventsDropped.WithLabelValues("events", "non_retryable").Add(float64(len(batch)))
			return err
		}
	}

	// All retries exhausted
	ces.logger.Errorw("CRITICAL: Batch insert failed after all retries - events will be lost",
		"error", lastErr,
		"event_count", len(batch),
		"attempts", maxRetryAttempts)
	metrics.StorageBatchInsertFailures.WithLabelValues("events", "retry_exhausted").Inc()
	metrics.StorageEventsDropped.WithLabelValues("events", "retry_exhausted").Add(float64(len(batch)))
	return fmt.Errorf("batch insert failed after %d attempts: %w", maxRetryAttempts, lastErr)
}

// doInsertBatch performs the actual batch insert without retry logic
func (ces *ClickHouseEventStorage) doInsertBatch(ctx context.Context, batch []*core.Event) error {
	// Prepare batch statement
	prepareBatch, err := ces.clickhouse.Conn.PrepareBatch(ctx, `
		INSERT INTO events (
			event_id, timestamp, ingested_at, listener_id, listener_name,
			source, source_format, raw_data, fields, content_hash
		)
	`)
	if err != nil {
		ces.logger.Errorf("[CLICKHOUSE] Failed to prepare batch: %v", err)
		metrics.StorageBatchInsertFailures.WithLabelValues("events", "prepare").Inc()
		return fmt.Errorf("failed to prepare batch: %w", err)
	}

	// PERFORMANCE OPTIMIZATION: Reuse encoder across events in batch
	buf := jsonBufferPool.Get().(*bytes.Buffer)
	defer jsonBufferPool.Put(buf)

	// Append all events to batch
	appendErrors := 0
	for i, event := range batch {
		// Check context cancellation periodically (every 1000 events)
		if i > 0 && i%1000 == 0 {
			select {
			case <-ctx.Done():
				ces.logger.Debugw("Context cancelled during ClickHouse batch append",
					"processed_events", i,
					"total_events", len(batch))
				metrics.StorageEventsDropped.WithLabelValues("events", "context_cancelled").Add(float64(len(batch) - i))
				return ctx.Err()
			default:
			}
		}

		// PERFORMANCE OPTIMIZATION: Use pooled buffer for JSON encoding
		// Reuse buffer for each event instead of getting new one from pool
		buf.Reset()
		fieldsData := ""
		if event.Fields != nil && len(event.Fields) > 0 {
			encoder := json.NewEncoder(buf)
			encoder.SetEscapeHTML(false) // Faster encoding, no HTML escaping needed
			if err := encoder.Encode(event.Fields); err == nil {
				// Remove trailing newline added by Encode
				data := buf.Bytes()
				if len(data) > 0 && data[len(data)-1] == '\n' {
					data = data[:len(data)-1]
				}
				fieldsData = string(data)
			}
		}

		// Compute content hash if not already set (e.g., by dedup service)
		// This enables retroactive duplicate detection via GROUP BY content_hash
		contentHash := event.ContentHash
		if contentHash == "" && ces.useCanonicalHash && event.Fields != nil {
			contentHash = ces.hashEventCanonical(event)
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
			contentHash, // Canonical hash for retroactive deduplication
		)
		if err != nil {
			// FIX: Track append failures instead of silently continuing
			appendErrors++
			ces.logger.Errorw("Failed to append event to batch",
				"event_id", event.EventID,
				"error", err,
				"append_errors", appendErrors)
			metrics.StorageBatchInsertFailures.WithLabelValues("events", "append").Inc()

			// If too many append errors, abort the batch
			if appendErrors > len(batch)/10 && appendErrors > 10 {
				ces.logger.Errorw("Too many append errors, aborting batch",
					"append_errors", appendErrors,
					"total_events", len(batch))
				metrics.StorageEventsDropped.WithLabelValues("events", "append_error").Add(float64(len(batch) - i))
				return fmt.Errorf("too many append errors: %d/%d", appendErrors, len(batch))
			}
		}
	}

	// Send batch
	if err := prepareBatch.Send(); err != nil {
		ces.logger.Errorf("[CLICKHOUSE] Failed to send batch: %v", err)
		return fmt.Errorf("failed to send batch: %w", err)
	}

	return nil
}

// hashEvent generates a hash for deduplication
// When useCanonicalHash is enabled, uses canonical JSON serialization of Fields
// for format-agnostic deduplication (handles JSON key reordering, whitespace changes)
func (ces *ClickHouseEventStorage) hashEvent(event *core.Event) string {
	if ces.useCanonicalHash && event.Fields != nil {
		return ces.hashEventCanonical(event)
	}
	return ces.hashEventLegacy(event)
}

// hashEventCanonical generates a hash using canonical JSON serialization
// This is format-agnostic: same logical JSON produces same hash regardless of formatting
func (ces *ClickHouseEventStorage) hashEventCanonical(event *core.Event) string {
	buf := canonicalBufferPool.Get().(*bytes.Buffer)
	defer func() {
		buf.Reset()
		canonicalBufferPool.Put(buf)
	}()

	// Write canonical JSON representation of Fields
	writeCanonicalJSON(buf, event.Fields)

	// Include timestamp for time-based uniqueness
	buf.WriteByte('|')
	buf.WriteString(strconv.FormatInt(event.Timestamp.Unix(), 10))

	h := sha256.Sum256(buf.Bytes())
	return hex.EncodeToString(h[:])
}

// hashEventLegacy generates a hash using raw data (legacy behavior)
// This is byte-exact: only identical raw JSON produces same hash
func (ces *ClickHouseEventStorage) hashEventLegacy(event *core.Event) string {
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

// writeCanonicalJSON writes a deterministic JSON representation to the buffer
// Keys are sorted alphabetically at each nesting level for consistent hashing
func writeCanonicalJSON(buf *bytes.Buffer, v interface{}) {
	switch val := v.(type) {
	case map[string]interface{}:
		keys := make([]string, 0, len(val))
		for k := range val {
			keys = append(keys, k)
		}
		sort.Strings(keys)

		buf.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				buf.WriteByte(',')
			}
			buf.WriteString(strconv.Quote(k))
			buf.WriteByte(':')
			writeCanonicalJSON(buf, val[k])
		}
		buf.WriteByte('}')

	case []interface{}:
		buf.WriteByte('[')
		for i, elem := range val {
			if i > 0 {
				buf.WriteByte(',')
			}
			writeCanonicalJSON(buf, elem)
		}
		buf.WriteByte(']')

	case string:
		buf.WriteString(strconv.Quote(val))
	case float64:
		buf.WriteString(strconv.FormatFloat(val, 'f', -1, 64))
	case int:
		buf.WriteString(strconv.Itoa(val))
	case int64:
		buf.WriteString(strconv.FormatInt(val, 10))
	case bool:
		buf.WriteString(strconv.FormatBool(val))
	case nil:
		buf.WriteString("null")
	default:
		// Fallback for other types
		fmt.Fprintf(buf, "%v", val)
	}
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

// DedupAnalyzeResult contains the results of a duplicate analysis.
type DedupAnalyzeResult struct {
	TotalEvents              int64            `json:"total_events"`
	UniqueEvents             int64            `json:"unique_events"`
	DuplicateEvents          int64            `json:"duplicate_events"`
	DuplicateGroups          int64            `json:"duplicate_groups"`
	EstimatedStorageSavingMB float64          `json:"estimated_storage_savings_mb"`
	SampleDuplicates         []DuplicateGroup `json:"sample_duplicates,omitempty"`
	AnalysisDurationMs       int64            `json:"analysis_duration_ms"`
	EventsWithoutHash        int64            `json:"events_without_hash"`
}

// DuplicateGroup represents a set of duplicate events sharing the same content hash.
type DuplicateGroup struct {
	ContentHash string    `json:"content_hash"`
	Count       int       `json:"count"`
	EventIDs    []string  `json:"event_ids"`
	KeepID      string    `json:"keep_id"`
	FirstSeen   time.Time `json:"first_seen"`
	LastSeen    time.Time `json:"last_seen"`
}

// AnalyzeDuplicates analyzes events in a time range to find duplicates by content_hash.
// Returns statistics and sample duplicate groups.
func (ces *ClickHouseEventStorage) AnalyzeDuplicates(ctx context.Context, startTime, endTime time.Time, limit int) (*DedupAnalyzeResult, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()

	result := &DedupAnalyzeResult{
		SampleDuplicates: make([]DuplicateGroup, 0),
	}

	// Get total event count
	totalQuery := `SELECT COUNT(*) FROM events WHERE timestamp BETWEEN ? AND ?`
	var total uint64
	if err := ces.clickhouse.Conn.QueryRow(ctx, totalQuery, startTime, endTime).Scan(&total); err != nil {
		return nil, fmt.Errorf("failed to count total events: %w", err)
	}
	result.TotalEvents = int64(total)

	// Count events without content_hash (need backfill)
	noHashQuery := `SELECT COUNT(*) FROM events WHERE timestamp BETWEEN ? AND ? AND content_hash = ''`
	var noHashCount uint64
	if err := ces.clickhouse.Conn.QueryRow(ctx, noHashQuery, startTime, endTime).Scan(&noHashCount); err != nil {
		ces.logger.Warnf("Failed to count events without hash: %v", err)
	}
	result.EventsWithoutHash = int64(noHashCount)

	// Count unique hashes (only events WITH hash)
	uniqueQuery := `SELECT COUNT(DISTINCT content_hash) FROM events WHERE timestamp BETWEEN ? AND ? AND content_hash != ''`
	var unique uint64
	if err := ces.clickhouse.Conn.QueryRow(ctx, uniqueQuery, startTime, endTime).Scan(&unique); err != nil {
		return nil, fmt.Errorf("failed to count unique hashes: %w", err)
	}

	// Count events with hash
	eventsWithHash := result.TotalEvents - result.EventsWithoutHash
	result.UniqueEvents = int64(unique) + result.EventsWithoutHash // Events without hash are considered unique
	result.DuplicateEvents = eventsWithHash - int64(unique)

	// Find duplicate groups (hashes with count > 1)
	dupGroupsQuery := `
		SELECT COUNT(*) FROM (
			SELECT content_hash
			FROM events
			WHERE timestamp BETWEEN ? AND ?
			  AND content_hash != ''
			GROUP BY content_hash
			HAVING COUNT(*) > 1
		)`
	var dupGroups uint64
	if err := ces.clickhouse.Conn.QueryRow(ctx, dupGroupsQuery, startTime, endTime).Scan(&dupGroups); err != nil {
		return nil, fmt.Errorf("failed to count duplicate groups: %w", err)
	}
	result.DuplicateGroups = int64(dupGroups)

	// Estimate storage savings (assuming ~1KB per event average)
	result.EstimatedStorageSavingMB = float64(result.DuplicateEvents) * 1.0 / 1024.0

	// Get sample duplicate groups
	sampleQuery := `
		SELECT
			content_hash,
			COUNT(*) as duplicate_count,
			groupArray(10)(event_id) as event_ids,
			MIN(timestamp) as first_seen,
			MAX(timestamp) as last_seen
		FROM events
		WHERE timestamp BETWEEN ? AND ?
		  AND content_hash != ''
		GROUP BY content_hash
		HAVING duplicate_count > 1
		ORDER BY duplicate_count DESC
		LIMIT ?`

	rows, err := ces.clickhouse.Conn.Query(ctx, sampleQuery, startTime, endTime, limit)
	if err != nil {
		ces.logger.Warnf("Failed to get sample duplicates: %v", err)
		return result, nil // Return partial result
	}
	defer rows.Close()

	for rows.Next() {
		var hash string
		var count uint64
		var eventIDs []string
		var firstSeen, lastSeen time.Time

		if err := rows.Scan(&hash, &count, &eventIDs, &firstSeen, &lastSeen); err != nil {
			ces.logger.Warnf("Failed to scan duplicate group: %v", err)
			continue
		}

		keepID := ""
		if len(eventIDs) > 0 {
			keepID = eventIDs[0] // Keep first by default
		}

		result.SampleDuplicates = append(result.SampleDuplicates, DuplicateGroup{
			ContentHash: hash,
			Count:       int(count),
			EventIDs:    eventIDs,
			KeepID:      keepID,
			FirstSeen:   firstSeen,
			LastSeen:    lastSeen,
		})
	}

	return result, nil
}

// DeleteDuplicates removes duplicate events in a time range, keeping the first or last occurrence.
// Returns the number of deleted events.
func (ces *ClickHouseEventStorage) DeleteDuplicates(ctx context.Context, startTime, endTime time.Time, strategy string, maxDelete int64) (int64, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()

	// Determine sort order based on strategy
	sortOrder := "ASC" // keep_first: keep MIN(timestamp), delete rest
	if strategy == "keep_last" {
		sortOrder = "DESC" // keep_last: keep MAX(timestamp), delete rest
	}

	// ClickHouse doesn't support DELETE with subquery directly in standard way
	// We need to use ALTER TABLE DELETE with a WHERE clause
	// Strategy: Find event_ids to delete (all but first/last per hash) and delete them

	// Step 1: Get event IDs to delete
	// This query gets all event IDs that are NOT the one to keep (first or last)
	selectQuery := fmt.Sprintf(`
		SELECT event_id FROM (
			SELECT
				event_id,
				content_hash,
				ROW_NUMBER() OVER (PARTITION BY content_hash ORDER BY timestamp %s) as rn
			FROM events
			WHERE timestamp BETWEEN ? AND ?
			  AND content_hash != ''
			  AND content_hash IN (
				  SELECT content_hash
				  FROM events
				  WHERE timestamp BETWEEN ? AND ?
					AND content_hash != ''
				  GROUP BY content_hash
				  HAVING COUNT(*) > 1
			  )
		)
		WHERE rn > 1
		LIMIT ?`, sortOrder)

	rows, err := ces.clickhouse.Conn.Query(ctx, selectQuery, startTime, endTime, startTime, endTime, maxDelete)
	if err != nil {
		return 0, fmt.Errorf("failed to find duplicates to delete: %w", err)
	}
	defer rows.Close()

	// Collect event IDs to delete
	var idsToDelete []string
	for rows.Next() {
		var eventID string
		if err := rows.Scan(&eventID); err != nil {
			ces.logger.Warnf("Failed to scan event ID for deletion: %v", err)
			continue
		}
		idsToDelete = append(idsToDelete, eventID)
	}

	if len(idsToDelete) == 0 {
		return 0, nil
	}

	ces.logger.Infof("Found %d duplicate events to delete", len(idsToDelete))

	// Step 2: Delete in batches
	batchSize := 1000
	var totalDeleted int64 = 0

	for i := 0; i < len(idsToDelete); i += batchSize {
		end := i + batchSize
		if end > len(idsToDelete) {
			end = len(idsToDelete)
		}
		batch := idsToDelete[i:end]

		// Build the IN clause
		deleteQuery := "ALTER TABLE events DELETE WHERE event_id IN (?)"
		if err := ces.clickhouse.Conn.Exec(ctx, deleteQuery, batch); err != nil {
			ces.logger.Errorw("Failed to delete batch of duplicates",
				"error", err,
				"batch_start", i,
				"batch_size", len(batch))
			// Continue with next batch
			continue
		}
		totalDeleted += int64(len(batch))
		ces.logger.Debugf("Deleted batch %d-%d (%d events)", i, end, len(batch))
	}

	ces.logger.Infof("Retroactive deduplication completed: deleted %d events", totalDeleted)

	// Record metric for monitoring
	if totalDeleted > 0 {
		metrics.EventsRetroactivelyDeduplicated.Add(float64(totalDeleted))
	}

	return totalDeleted, nil
}
