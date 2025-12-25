package service

import (
	"context"
	"fmt"
	"time"

	"cerberus/core"

	"github.com/google/uuid"
	"go.uber.org/zap"
)

// ============================================================================
// Constants
// ============================================================================

const (
	// Pagination limits
	defaultEventPageSize = 100   // Default limit when not specified
	maxEventPageSize     = 10000 // Maximum allowed page size

	// Batch processing limits
	maxBatchSize = 1000 // Maximum events per batch insert

	// Retention defaults
	minRetentionDays = 1   // Minimum retention period (1 day)
	maxRetentionDays = 365 // Maximum retention period (1 year)
)

// EventServiceImpl implements the EventService interface from core package.
// It provides business logic layer between HTTP handlers and storage layer.
//
// SECURITY CONSIDERATIONS:
// - All user inputs are validated before storage operations
// - Pagination limits prevent memory exhaustion attacks
// - Batch sizes are capped to prevent resource exhaustion
// - Retention operations use context for cancellation
//
// DESIGN PATTERNS:
// - Dependency injection via constructor
// - Context propagation for cancellation
// - Typed error returns with wrapping
// - Separation of concerns (business logic vs storage)
type EventServiceImpl struct {
	eventStorage EventStorage
	logger       *zap.SugaredLogger
}

// EventStorage defines event storage operations needed by service.
// Defined here (consumer package) following Interface Segregation Principle.
type EventStorage interface {
	GetEvents(ctx context.Context, limit, offset int) ([]core.Event, error)
	GetEventCount(ctx context.Context) (int64, error)
	// Note: Search is handled separately via search package
}

// NewEventService creates a new EventService instance.
//
// PARAMETERS:
//   - eventStorage: Event persistence layer (required, panics if nil)
//   - logger: Structured logger (required, panics if nil)
//
// DESIGN NOTE: Constructor validates required dependencies to fail fast.
func NewEventService(
	eventStorage EventStorage,
	logger *zap.SugaredLogger,
) *EventServiceImpl {
	if eventStorage == nil {
		panic("eventStorage is required")
	}
	if logger == nil {
		panic("logger is required")
	}

	return &EventServiceImpl{
		eventStorage: eventStorage,
		logger:       logger,
	}
}

// ============================================================================
// EventReader Implementation
// ============================================================================

// GetEventByID retrieves a single event by ID.
//
// BUSINESS LOGIC:
// 1. Validate event ID format
// 2. Retrieve event from storage
//
// ERRORS:
//   - fmt.Errorf: Event doesn't exist or invalid ID
//   - Wrapped storage errors with context
//
// NOTE: ClickHouse event storage doesn't have GetByID method.
// This implementation returns ErrNotImplemented for now.
// Events are typically retrieved via ListEvents or SearchEvents.
func (s *EventServiceImpl) GetEventByID(ctx context.Context, eventID string) (*core.Event, error) {
	// Validate input
	if eventID == "" {
		return nil, fmt.Errorf("eventID is required")
	}

	// Check context cancellation
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("context cancelled: %w", err)
	}

	// ClickHouse event storage doesn't support GetByID
	// Events are stored in time-series format optimized for batch queries
	return nil, fmt.Errorf("GetEventByID not supported - use SearchEvents with event_id filter")
}

// ListEvents retrieves paginated events.
//
// BUSINESS LOGIC:
// 1. Validate pagination parameters
// 2. Apply bounds checking
// 3. Retrieve events from storage
//
// PARAMETERS:
//   - limit: Page size (validated, capped at maxEventPageSize)
//   - offset: Offset for pagination
//
// RETURNS:
//   - events: Slice of events (empty if no matches)
//   - total: Total count for pagination
//   - error: Any errors encountered
//
// DEFENSIVE PROGRAMMING: Validates and sanitizes all input parameters.
func (s *EventServiceImpl) ListEvents(
	ctx context.Context,
	limit, offset int,
) ([]*core.Event, int64, error) {
	// Check context cancellation
	if err := ctx.Err(); err != nil {
		return nil, 0, fmt.Errorf("context cancelled: %w", err)
	}

	// Validate pagination bounds
	if limit < 1 {
		limit = defaultEventPageSize
	}
	if limit > maxEventPageSize {
		limit = maxEventPageSize
	}
	if offset < 0 {
		offset = 0
	}

	// Retrieve events
	events, err := s.eventStorage.GetEvents(ctx, limit, offset)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to retrieve events: %w", err)
	}

	// Get total count
	total, err := s.eventStorage.GetEventCount(ctx)
	if err != nil {
		// Log warning but return partial results
		s.logger.Warnw("Failed to get event count",
			"error", err)
		total = int64(len(events)) // Fallback to current page count
	}

	// Convert []Event to []*Event
	result := make([]*core.Event, len(events))
	for i := range events {
		result[i] = &events[i]
	}

	return result, total, nil
}

// SearchEvents performs CQL-based event search.
//
// NOTE: Search is delegated to the search package, not implemented here.
// This is a placeholder to satisfy the interface.
func (s *EventServiceImpl) SearchEvents(
	ctx context.Context,
	query string,
	limit, offset int,
) ([]*core.Event, int64, error) {
	return nil, 0, fmt.Errorf("SearchEvents should use search.Executor directly, not EventService")
}

// ============================================================================
// EventWriter Implementation
// ============================================================================

// StoreEvent stores a security event.
//
// BUSINESS LOGIC:
// 1. Validate event structure
// 2. Generate event ID if not provided
// 3. Set timestamp if not provided
// 4. Persist to storage
//
// RETURNS:
//   - Stored event with generated ID and timestamp
//   - Error if validation or storage fails
//
// NOTE: This is a placeholder. ClickHouse event storage uses channel-based ingestion.
// Events are stored via the ingest pipeline, not directly via this service.
func (s *EventServiceImpl) StoreEvent(ctx context.Context, event *core.Event) (*core.Event, error) {
	if event == nil {
		return nil, fmt.Errorf("event is required")
	}

	// Check context cancellation
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("context cancelled: %w", err)
	}

	// DEFENSIVE COPY: Prevent caller mutation
	eventCopy := deepCopyEvent(event)
	if eventCopy == nil {
		return nil, fmt.Errorf("failed to copy event")
	}

	// Generate ID if not provided
	if eventCopy.EventID == "" {
		eventCopy.EventID = generateEventID()
	}

	// Set timestamp if not provided
	if eventCopy.Timestamp.IsZero() {
		eventCopy.Timestamp = time.Now()
	}

	// Validate required fields
	if err := validateEventStructure(eventCopy); err != nil {
		return nil, fmt.Errorf("event validation failed: %w", err)
	}

	// NOTE: ClickHouse event storage uses channel-based ingestion
	// Direct insert not supported - events must go through ingest pipeline
	s.logger.Warnw("StoreEvent called - events should use ingest pipeline, not direct storage",
		"event_id", eventCopy.EventID)

	return nil, fmt.Errorf("direct event storage not supported - use ingest pipeline")
}

// BatchStoreEvents stores multiple events efficiently.
//
// NOTE: This is a placeholder. ClickHouse event storage uses channel-based ingestion.
func (s *EventServiceImpl) BatchStoreEvents(ctx context.Context, events []*core.Event) (int, error) {
	if len(events) == 0 {
		return 0, nil
	}

	// Check context cancellation
	if err := ctx.Err(); err != nil {
		return 0, fmt.Errorf("context cancelled: %w", err)
	}

	// Validate batch size
	if len(events) > maxBatchSize {
		return 0, fmt.Errorf("batch size %d exceeds maximum %d", len(events), maxBatchSize)
	}

	// NOTE: ClickHouse event storage uses channel-based ingestion
	s.logger.Warnw("BatchStoreEvents called - events should use ingest pipeline",
		"count", len(events))

	return 0, fmt.Errorf("batch event storage not supported - use ingest pipeline")
}

// ============================================================================
// EventRetentionManager Implementation
// ============================================================================

// CleanupExpiredEvents deletes events older than retention period.
//
// BUSINESS LOGIC:
// 1. Validate retention period bounds
// 2. Calculate cutoff timestamp
// 3. Delete events older than cutoff
// 4. Return count of deleted events
//
// PARAMETERS:
//   - retentionDays: Number of days to retain events (validated)
//
// RETURNS:
//   - count: Number of events deleted
//   - error: Any errors encountered
//
// SECURITY:
// - Validates retention period to prevent accidental data loss
// - Uses context for cancellation support
// - Logs retention operations for audit trail
//
// NOTE: This is a placeholder. Actual retention is handled by storage/retention.go.
func (s *EventServiceImpl) CleanupExpiredEvents(
	ctx context.Context,
	retentionDays int,
) (int64, error) {
	// Check context cancellation
	if err := ctx.Err(); err != nil {
		return 0, fmt.Errorf("context cancelled: %w", err)
	}

	// Validate retention period
	if retentionDays < minRetentionDays {
		return 0, fmt.Errorf("retention period too short: %d days (minimum %d)", retentionDays, minRetentionDays)
	}
	if retentionDays > maxRetentionDays {
		return 0, fmt.Errorf("retention period too long: %d days (maximum %d)", retentionDays, maxRetentionDays)
	}

	// Calculate cutoff timestamp
	cutoffTime := time.Now().AddDate(0, 0, -retentionDays)

	s.logger.Infow("Event retention cleanup initiated",
		"retention_days", retentionDays,
		"cutoff_time", cutoffTime)

	// NOTE: Actual retention is handled by storage/retention.go
	// This service method is a placeholder for API integration
	s.logger.Warnw("CleanupExpiredEvents called - retention is handled by storage/retention.go worker")

	return 0, fmt.Errorf("event retention is handled by background worker - use storage/retention.go")
}

// ============================================================================
// Helper Functions
// ============================================================================

// generateEventID generates a unique event ID using UUID v4.
//
// SECURITY: Uses cryptographically secure random number generation via uuid.New()
// COLLISION RESISTANCE: UUID v4 has ~2^122 unique values, collision probability negligible
func generateEventID() string {
	return uuid.New().String()
}

// validateEventStructure performs basic event validation.
//
// BUSINESS RULES:
// - EventID is required
// - Timestamp is required
// - Fields map should not be nil
func validateEventStructure(event *core.Event) error {
	if event == nil {
		return fmt.Errorf("event cannot be nil")
	}

	if event.EventID == "" {
		return fmt.Errorf("event.EventID is required")
	}

	if event.Timestamp.IsZero() {
		return fmt.Errorf("event.Timestamp is required")
	}

	// Fields can be empty map but not nil
	if event.Fields == nil {
		return fmt.Errorf("event.Fields cannot be nil (use empty map)")
	}

	return nil
}

// deepCopyEvent creates a defensive copy of an event.
//
// DEFENSIVE PROGRAMMING: Prevents caller from mutating service-managed state.
// PERFORMANCE: Only copies when necessary for mutation protection.
//
// BLOCKER-3 FIX: Uses shared deepCopyValue from helpers.go
func deepCopyEvent(event *core.Event) *core.Event {
	if event == nil {
		return nil
	}

	// Create shallow copy of event struct
	eventCopy := *event

	// Deep copy Fields map using shared helper
	if event.Fields != nil {
		eventCopy.Fields = make(map[string]interface{}, len(event.Fields))
		for k, v := range event.Fields {
			eventCopy.Fields[k] = deepCopyValue(v) // From helpers.go
		}
	}

	// Note: RawData is a string, so it's copied by value in the struct copy above
	// No need for additional deep copy

	return &eventCopy
}
