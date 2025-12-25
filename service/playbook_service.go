package service

import (
	"context"
	"fmt"
	"strings"
	"time"

	"cerberus/core"
	"cerberus/soar"
	"cerberus/storage"

	"github.com/google/uuid"
	"go.uber.org/zap"
)

// ============================================================================
// Constants
// ============================================================================

const (
	// ID generation
	uuidPrefixLength = 8 // Length of UUID prefix for playbook/step IDs

	// Pagination limits
	defaultPageSize = 50   // Default limit when not specified
	maxPageSize     = 1000 // Maximum allowed page size

	// Validation limits
	maxNameLength        = 200  // Maximum playbook name length
	maxDescriptionLength = 2000 // Maximum description length
	maxStepsPerPlaybook  = 50   // Maximum steps in a playbook
	maxTriggersPerBook   = 10   // Maximum triggers per playbook

	// Execution timeouts
	executionTimeout = 5 * time.Minute // Max playbook execution time
)

// PlaybookServiceImpl implements the PlaybookService interface from core package.
// It provides business logic layer between HTTP handlers and storage layer.
//
// SECURITY CONSIDERATIONS:
// - All user inputs are validated before storage operations
// - Playbook validation prevents invalid configurations
// - Name uniqueness enforced to prevent conflicts
// - Execution validation ensures only enabled playbooks run
// - User tracking for audit trail on all mutations
//
// DESIGN PATTERNS:
// - Dependency injection via constructor
// - Context propagation for cancellation
// - Typed error returns with wrapping
// - Separation of concerns (business logic vs storage)
type PlaybookServiceImpl struct {
	playbookStorage  PlaybookStorage
	executionStorage PlaybookExecutionStorage
	alertStorage     PlaybookAlertStorage
	executor         PlaybookEngineExecutor
	logger           *zap.SugaredLogger
}

// PlaybookStorage defines playbook storage operations needed by service.
// Defined here (consumer package) following Interface Segregation Principle.
type PlaybookStorage interface {
	CreatePlaybook(playbook *soar.Playbook) error
	GetPlaybook(id string) (*soar.Playbook, error)
	GetPlaybooks(limit, offset int) ([]soar.Playbook, error)
	GetPlaybooksByStatus(enabled bool) ([]soar.Playbook, error)
	GetPlaybooksByTag(tag string) ([]soar.Playbook, error)
	GetPlaybookCount() (int64, error)
	UpdatePlaybook(id string, playbook *soar.Playbook) error
	DeletePlaybook(id string) error
	EnablePlaybook(id string) error
	DisablePlaybook(id string) error
	PlaybookNameExists(name string, excludeID string) (bool, error)
	GetPlaybookStats() (*storage.PlaybookStats, error)
}

// PlaybookExecutionStorage defines execution storage operations.
type PlaybookExecutionStorage interface {
	CreatePlaybookExecution(ctx context.Context, executionID, playbookID, alertID string) error
	GetExecution(ctx context.Context, executionID string) (*soar.PlaybookExecution, error)
	CompleteExecution(ctx context.Context, executionID string, status soar.ActionStatus, errorMsg string, stepResults map[string]*soar.ActionResult) error
}

// PlaybookAlertStorage defines alert storage operations for playbook execution.
type PlaybookAlertStorage interface {
	GetAlert(ctx context.Context, alertID string) (*core.Alert, error)
}

// PlaybookEngineExecutor defines playbook execution operations.
type PlaybookEngineExecutor interface {
	ExecutePlaybook(ctx context.Context, playbook *soar.Playbook, alert *core.Alert) (*soar.PlaybookExecution, error)
}

// NewPlaybookService creates a new PlaybookService instance.
//
// PARAMETERS:
//   - playbookStorage: Playbook persistence layer (required, panics if nil)
//   - executionStorage: Execution storage for tracking (can be nil, execution features disabled)
//   - alertStorage: Alert storage for execution (can be nil, execution features disabled)
//   - executor: Playbook execution engine (can be nil, execution features disabled)
//   - logger: Structured logger (required, panics if nil)
//
// DESIGN NOTE: Constructor validates required dependencies to fail fast.
func NewPlaybookService(
	playbookStorage PlaybookStorage,
	executionStorage PlaybookExecutionStorage,
	alertStorage PlaybookAlertStorage,
	executor PlaybookEngineExecutor,
	logger *zap.SugaredLogger,
) *PlaybookServiceImpl {
	if playbookStorage == nil {
		panic("playbookStorage is required")
	}
	if logger == nil {
		panic("logger is required")
	}

	return &PlaybookServiceImpl{
		playbookStorage:  playbookStorage,
		executionStorage: executionStorage,
		alertStorage:     alertStorage,
		executor:         executor,
		logger:           logger,
	}
}

// ============================================================================
// PlaybookReader Implementation
// ============================================================================

// GetPlaybookByID retrieves a single playbook by ID.
//
// BUSINESS LOGIC:
// 1. Validate playbook ID format
// 2. Retrieve playbook from storage
//
// ERRORS:
//   - storage.ErrPlaybookNotFound: Playbook doesn't exist
//   - Wrapped storage errors with context
//
// NOTE: Returns soar.Playbook converted to core.Playbook interface.
// core.Playbook is currently interface{}, so we cast *soar.Playbook to it.
func (s *PlaybookServiceImpl) GetPlaybookByID(ctx context.Context, playbookID string) (*core.Playbook, error) {
	// Validate input
	if playbookID == "" {
		return nil, fmt.Errorf("playbookID is required")
	}

	// Check context cancellation
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("context cancelled before retrieval: %w", err)
	}

	// Retrieve playbook
	playbook, err := s.playbookStorage.GetPlaybook(playbookID)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve playbook %s: %w", playbookID, err)
	}

	if playbook == nil {
		return nil, storage.ErrPlaybookNotFound
	}

	// Convert *soar.Playbook to core.Playbook (which is interface{})
	// This is safe because core.Playbook is defined as interface{}
	var result core.Playbook = playbook
	return &result, nil
}

// ListPlaybooks retrieves paginated playbooks with filtering.
//
// BUSINESS LOGIC:
// 1. Validate pagination parameters
// 2. Apply filters (enabled status or tag) if provided
// 3. Return paginated results
//
// PARAMETERS:
//   - enabled: Filter by enabled status (nil = no filter)
//   - tag: Filter by tag (empty = no filter)
//   - limit: Page size (validated, capped at 1000)
//   - offset: Offset for pagination
//
// RETURNS:
//   - playbooks: Slice of playbooks (empty if no matches)
//   - total: Total count matching filters
//   - error: Any errors encountered
func (s *PlaybookServiceImpl) ListPlaybooks(
	ctx context.Context,
	enabled *bool,
	tag string,
	limit, offset int,
) ([]*core.Playbook, int64, error) {
	// Check context cancellation
	if err := ctx.Err(); err != nil {
		return nil, 0, fmt.Errorf("context cancelled: %w", err)
	}

	// Validate pagination bounds
	if limit < 1 {
		limit = defaultPageSize
	}
	if limit > maxPageSize {
		limit = maxPageSize
	}
	if offset < 0 {
		offset = 0
	}

	var playbooks []soar.Playbook
	var total int64
	var err error

	// Apply filters if specified
	if enabled != nil {
		playbooks, err = s.playbookStorage.GetPlaybooksByStatus(*enabled)
		if err != nil {
			return nil, 0, fmt.Errorf("failed to get playbooks by status: %w", err)
		}
		// Manual pagination for filtered results
		total = int64(len(playbooks))
		playbooks = paginatePlaybooks(playbooks, limit, offset)
	} else if tag != "" {
		playbooks, err = s.playbookStorage.GetPlaybooksByTag(tag)
		if err != nil {
			return nil, 0, fmt.Errorf("failed to get playbooks by tag: %w", err)
		}
		// Manual pagination for filtered results
		total = int64(len(playbooks))
		playbooks = paginatePlaybooks(playbooks, limit, offset)
	} else {
		// Simple paginated query
		playbooks, err = s.playbookStorage.GetPlaybooks(limit, offset)
		if err != nil {
			return nil, 0, fmt.Errorf("failed to get playbooks: %w", err)
		}
		total, err = s.playbookStorage.GetPlaybookCount()
		if err != nil {
			return nil, 0, fmt.Errorf("failed to get playbook count: %w", err)
		}
	}

	// Convert []soar.Playbook to []*core.Playbook
	// core.Playbook is interface{}, so we can assign *soar.Playbook to it
	result := make([]*core.Playbook, len(playbooks))
	for i := range playbooks {
		var pb core.Playbook = &playbooks[i]
		result[i] = &pb
	}

	return result, total, nil
}

// paginatePlaybooks applies manual pagination to a slice of playbooks.
func paginatePlaybooks(playbooks []soar.Playbook, limit, offset int) []soar.Playbook {
	if offset >= len(playbooks) {
		return []soar.Playbook{}
	}
	end := offset + limit
	if end > len(playbooks) {
		end = len(playbooks)
	}
	return playbooks[offset:end]
}

// GetPlaybookStats returns aggregated playbook statistics.
//
// BUSINESS LOGIC:
// 1. Retrieve stats from storage
// 2. Convert storage type to core type
func (s *PlaybookServiceImpl) GetPlaybookStats(ctx context.Context) (*core.PlaybookStats, error) {
	// Check context cancellation
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("context cancelled: %w", err)
	}

	stats, err := s.playbookStorage.GetPlaybookStats()
	if err != nil {
		return nil, fmt.Errorf("failed to get playbook stats: %w", err)
	}

	// Convert storage.PlaybookStats to core.PlaybookStats
	return &core.PlaybookStats{
		TotalPlaybooks:    stats.TotalPlaybooks,
		EnabledPlaybooks:  stats.EnabledPlaybooks,
		DisabledPlaybooks: stats.DisabledPlaybooks,
	}, nil
}

// ============================================================================
// PlaybookWriter Implementation
// ============================================================================

// CreatePlaybook creates a new playbook with validation.
//
// BUSINESS LOGIC:
// 1. Validate playbook structure
// 2. Generate ID if not provided
// 3. Check name uniqueness
// 4. Set audit fields (created_by, timestamps)
// 5. Initialize empty slices to prevent nil
// 6. Persist to storage
//
// RETURNS:
//   - Created playbook with generated ID
//   - Error if validation or storage fails
func (s *PlaybookServiceImpl) CreatePlaybook(
	ctx context.Context,
	playbook *core.Playbook,
) (*core.Playbook, error) {
	if playbook == nil {
		return nil, fmt.Errorf("playbook is required")
	}

	// Check context cancellation
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("context cancelled: %w", err)
	}

	// Extract soar.Playbook from core.Playbook interface
	pb, ok := (*playbook).(*soar.Playbook)
	if !ok {
		return nil, fmt.Errorf("invalid playbook type")
	}

	// BLOCKER-3 FIX: Create defensive copy to prevent caller mutation
	pbCopy := deepCopyPlaybookInternal(pb)
	if pbCopy == nil {
		return nil, fmt.Errorf("failed to copy playbook")
	}

	// Generate ID if not provided
	if pbCopy.ID == "" {
		pbCopy.ID = generatePlaybookID()
	}

	// Validate playbook structure
	if errors := validatePlaybookStructure(pbCopy); len(errors) > 0 {
		return nil, fmt.Errorf("playbook validation failed: %s", strings.Join(errors, "; "))
	}

	// Check name uniqueness
	exists, err := s.playbookStorage.PlaybookNameExists(pbCopy.Name, "")
	if err != nil {
		return nil, fmt.Errorf("failed to check playbook name uniqueness: %w", err)
	}
	if exists {
		return nil, storage.ErrPlaybookNameExists
	}

	// Initialize empty slices to prevent nil (for proper JSON serialization)
	if pbCopy.Triggers == nil {
		pbCopy.Triggers = make([]soar.PlaybookTrigger, 0)
	}
	if pbCopy.Steps == nil {
		pbCopy.Steps = make([]soar.PlaybookStep, 0)
	}
	if pbCopy.Tags == nil {
		pbCopy.Tags = make([]string, 0)
	}

	// Audit fields are set by caller (handler extracts from context)
	// This service is pure business logic

	// Persist to storage
	if err := s.playbookStorage.CreatePlaybook(pbCopy); err != nil {
		return nil, fmt.Errorf("failed to create playbook: %w", err)
	}

	s.logger.Infow("Playbook created",
		"playbook_id", pbCopy.ID,
		"name", pbCopy.Name,
		"enabled", pbCopy.Enabled,
		"step_count", len(pbCopy.Steps))

	// Return the copied playbook wrapped in core.Playbook
	var result core.Playbook = pbCopy
	return &result, nil
}

// UpdatePlaybook updates an existing playbook with validation.
//
// BUSINESS LOGIC:
// 1. Validate playbook ID
// 2. Check playbook exists
// 3. Validate playbook structure
// 4. Check name uniqueness (excluding current playbook)
// 5. Preserve immutable fields (created_by, created_at)
// 6. Update in storage
func (s *PlaybookServiceImpl) UpdatePlaybook(
	ctx context.Context,
	playbookID string,
	playbook *core.Playbook,
) error {
	if playbookID == "" {
		return fmt.Errorf("playbookID is required")
	}
	if playbook == nil {
		return fmt.Errorf("playbook is required")
	}

	// Check context cancellation
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("context cancelled: %w", err)
	}

	// Extract soar.Playbook from core.Playbook interface
	pb, ok := (*playbook).(*soar.Playbook)
	if !ok {
		return fmt.Errorf("invalid playbook type")
	}

	// BLOCKER-3 FIX: Create defensive copy to prevent caller mutation
	pbCopy := deepCopyPlaybookInternal(pb)
	if pbCopy == nil {
		return fmt.Errorf("failed to copy playbook")
	}

	// Ensure ID matches path parameter
	pbCopy.ID = playbookID

	// Validate playbook exists
	existing, err := s.playbookStorage.GetPlaybook(playbookID)
	if err != nil {
		return fmt.Errorf("failed to retrieve existing playbook: %w", err)
	}
	if existing == nil {
		return storage.ErrPlaybookNotFound
	}

	// Validate playbook structure
	if errors := validatePlaybookStructure(pbCopy); len(errors) > 0 {
		return fmt.Errorf("playbook validation failed: %s", strings.Join(errors, "; "))
	}

	// Check name uniqueness (exclude current playbook)
	if pbCopy.Name != existing.Name {
		exists, err := s.playbookStorage.PlaybookNameExists(pbCopy.Name, playbookID)
		if err != nil {
			return fmt.Errorf("failed to check playbook name uniqueness: %w", err)
		}
		if exists {
			return storage.ErrPlaybookNameExists
		}
	}

	// Preserve immutable audit fields
	pbCopy.CreatedBy = existing.CreatedBy
	pbCopy.CreatedAt = existing.CreatedAt
	// UpdatedAt is set by caller

	// Initialize empty slices to prevent nil
	if pbCopy.Triggers == nil {
		pbCopy.Triggers = make([]soar.PlaybookTrigger, 0)
	}
	if pbCopy.Steps == nil {
		pbCopy.Steps = make([]soar.PlaybookStep, 0)
	}
	if pbCopy.Tags == nil {
		pbCopy.Tags = make([]string, 0)
	}

	// Update in storage
	if err := s.playbookStorage.UpdatePlaybook(playbookID, pbCopy); err != nil {
		return fmt.Errorf("failed to update playbook: %w", err)
	}

	s.logger.Infow("Playbook updated",
		"playbook_id", playbookID,
		"name", pbCopy.Name,
		"enabled", pbCopy.Enabled)

	return nil
}

// DeletePlaybook permanently deletes a playbook.
//
// ERRORS:
//   - storage.ErrPlaybookNotFound: Playbook doesn't exist
func (s *PlaybookServiceImpl) DeletePlaybook(ctx context.Context, playbookID string) error {
	if playbookID == "" {
		return fmt.Errorf("playbookID is required")
	}

	// Check context cancellation
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("context cancelled: %w", err)
	}

	// Verify exists before delete (for better error messages)
	existing, err := s.playbookStorage.GetPlaybook(playbookID)
	if err != nil {
		return fmt.Errorf("failed to retrieve playbook: %w", err)
	}
	if existing == nil {
		return storage.ErrPlaybookNotFound
	}

	// Delete from storage
	if err := s.playbookStorage.DeletePlaybook(playbookID); err != nil {
		return fmt.Errorf("failed to delete playbook %s: %w", playbookID, err)
	}

	s.logger.Infow("Playbook deleted",
		"playbook_id", playbookID,
		"name", existing.Name)

	return nil
}

// DuplicatePlaybook creates a copy of an existing playbook.
//
// BUSINESS LOGIC:
// 1. Retrieve original playbook
// 2. Create deep copy
// 3. Generate new ID and modify name
// 4. Set new playbook as disabled by default
// 5. Set audit fields
// 6. Persist copy
//
// RETURNS:
//   - New playbook with unique ID
//   - Error if original not found or creation fails
func (s *PlaybookServiceImpl) DuplicatePlaybook(
	ctx context.Context,
	playbookID, userID string,
) (*core.Playbook, error) {
	if playbookID == "" {
		return nil, fmt.Errorf("playbookID is required")
	}
	if userID == "" {
		return nil, fmt.Errorf("userID is required for audit trail")
	}

	// Check context cancellation
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("context cancelled: %w", err)
	}

	// Get original playbook
	original, err := s.playbookStorage.GetPlaybook(playbookID)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve playbook: %w", err)
	}
	if original == nil {
		return nil, storage.ErrPlaybookNotFound
	}

	// Create deep copy with context cancellation support
	duplicate, err := deepCopyPlaybookWithContext(ctx, original)
	if err != nil {
		return nil, fmt.Errorf("failed to copy playbook: %w", err)
	}

	// Set new ID and metadata
	duplicate.ID = generatePlaybookID()
	duplicate.Name = original.Name + " (Copy)"
	duplicate.Enabled = false // Disabled by default for safety
	duplicate.CreatedBy = userID
	duplicate.CreatedAt = time.Now()
	duplicate.UpdatedAt = time.Now()

	// Persist duplicate
	if err := s.playbookStorage.CreatePlaybook(duplicate); err != nil {
		return nil, fmt.Errorf("failed to create duplicate playbook: %w", err)
	}

	s.logger.Infow("Playbook duplicated",
		"original_id", playbookID,
		"duplicate_id", duplicate.ID,
		"duplicated_by", userID)

	// Convert *soar.Playbook to core.Playbook interface
	var result core.Playbook = duplicate
	return &result, nil
}

// ============================================================================
// PlaybookStateManager Implementation
// ============================================================================

// EnablePlaybook enables a playbook for automatic execution.
func (s *PlaybookServiceImpl) EnablePlaybook(ctx context.Context, playbookID string) error {
	if playbookID == "" {
		return fmt.Errorf("playbookID is required")
	}

	// Check context cancellation
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("context cancelled: %w", err)
	}

	// Enable in storage
	if err := s.playbookStorage.EnablePlaybook(playbookID); err != nil {
		return fmt.Errorf("failed to enable playbook %s: %w", playbookID, err)
	}

	s.logger.Infow("Playbook enabled", "playbook_id", playbookID)

	return nil
}

// DisablePlaybook disables a playbook.
func (s *PlaybookServiceImpl) DisablePlaybook(ctx context.Context, playbookID string) error {
	if playbookID == "" {
		return fmt.Errorf("playbookID is required")
	}

	// Check context cancellation
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("context cancelled: %w", err)
	}

	// Disable in storage
	if err := s.playbookStorage.DisablePlaybook(playbookID); err != nil {
		return fmt.Errorf("failed to disable playbook %s: %w", playbookID, err)
	}

	s.logger.Infow("Playbook disabled", "playbook_id", playbookID)

	return nil
}

// ============================================================================
// PlaybookExecutor Implementation
// ============================================================================

// ExecutePlaybook executes a playbook for an alert asynchronously.
//
// BUSINESS LOGIC:
// 1. Validate playbook exists and is enabled
// 2. Validate alert exists
// 3. Create execution record
// 4. Execute playbook asynchronously
// 5. Return execution ID immediately
//
// RETURNS:
//   - executionID: Unique ID for tracking execution
//   - error: Validation errors or storage failures
//
// SECURITY:
// - Only enabled playbooks can execute
// - Validates all inputs before execution
func (s *PlaybookServiceImpl) ExecutePlaybook(
	ctx context.Context,
	playbookID, alertID, userID string,
) (executionID string, err error) {
	// Validate inputs
	if playbookID == "" {
		return "", fmt.Errorf("playbookID is required")
	}
	if alertID == "" {
		return "", fmt.Errorf("alertID is required")
	}
	if userID == "" {
		return "", fmt.Errorf("userID is required for audit trail")
	}

	// Check context cancellation
	if err := ctx.Err(); err != nil {
		return "", fmt.Errorf("context cancelled: %w", err)
	}

	// Check dependencies are available
	if s.executor == nil {
		return "", fmt.Errorf("playbook executor not available")
	}
	if s.alertStorage == nil {
		return "", fmt.Errorf("alert storage not available")
	}
	if s.executionStorage == nil {
		return "", fmt.Errorf("execution storage not available")
	}

	// Load playbook from storage
	playbook, err := s.playbookStorage.GetPlaybook(playbookID)
	if err != nil {
		return "", fmt.Errorf("failed to retrieve playbook: %w", err)
	}
	if playbook == nil {
		return "", storage.ErrPlaybookNotFound
	}

	// Validate playbook is enabled
	if !playbook.Enabled {
		return "", fmt.Errorf("playbook %s is disabled and cannot be executed", playbookID)
	}

	// Validate alert exists
	alert, err := s.alertStorage.GetAlert(ctx, alertID)
	if err != nil {
		return "", fmt.Errorf("failed to retrieve alert: %w", err)
	}
	if alert == nil {
		return "", storage.ErrAlertNotFound
	}

	// Generate execution ID
	executionID = generateExecutionID()

	// Create execution record
	if err := s.executionStorage.CreatePlaybookExecution(ctx, executionID, playbookID, alertID); err != nil {
		return "", fmt.Errorf("failed to create execution record: %w", err)
	}

	// Execute playbook asynchronously
	go s.executeAsync(playbook, alert, executionID)

	s.logger.Infow("Playbook execution initiated",
		"playbook_id", playbookID,
		"alert_id", alertID,
		"execution_id", executionID,
		"user_id", userID)

	return executionID, nil
}

// executeAsync runs playbook execution in background.
// Uses background context since HTTP request context will be cancelled.
func (s *PlaybookServiceImpl) executeAsync(
	playbook *soar.Playbook,
	alert *core.Alert,
	executionID string,
) {
	// Create background context with timeout
	ctx, cancel := context.WithTimeout(context.Background(), executionTimeout)
	defer cancel()

	execution, err := s.executor.ExecutePlaybook(ctx, playbook, alert)
	if err != nil {
		s.logger.Errorw("Playbook execution failed",
			"playbook_id", playbook.ID,
			"alert_id", alert.AlertID,
			"execution_id", executionID,
			"error", err)

		// Persist failure
		if persistErr := s.executionStorage.CompleteExecution(
			ctx, executionID, soar.ActionStatusFailed, err.Error(), nil,
		); persistErr != nil {
			s.logger.Errorw("Failed to persist execution failure",
				"execution_id", executionID,
				"error", persistErr)
		}
		return
	}

	// Update execution ID if executor returned one
	if execution.ID != "" {
		executionID = execution.ID
	}

	s.logger.Infow("Playbook execution completed",
		"playbook_id", playbook.ID,
		"alert_id", alert.AlertID,
		"execution_id", executionID,
		"status", execution.Status)

	// Persist completion state
	if execution.Status == soar.ActionStatusCompleted || execution.Status == soar.ActionStatusFailed {
		if err := s.executionStorage.CompleteExecution(
			ctx, executionID, execution.Status, execution.Error, execution.StepResults,
		); err != nil {
			s.logger.Errorw("Failed to persist execution completion",
				"execution_id", executionID,
				"error", err)
		}
	}
}

// GetExecutionStatus retrieves status of a playbook execution.
func (s *PlaybookServiceImpl) GetExecutionStatus(
	ctx context.Context,
	executionID string,
) (*core.PlaybookExecutionStatus, error) {
	if executionID == "" {
		return nil, fmt.Errorf("executionID is required")
	}

	// Check context cancellation
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("context cancelled: %w", err)
	}

	if s.executionStorage == nil {
		return nil, fmt.Errorf("execution storage not available")
	}

	execution, err := s.executionStorage.GetExecution(ctx, executionID)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve execution: %w", err)
	}
	if execution == nil {
		return nil, fmt.Errorf("execution %s not found", executionID)
	}

	// Convert to core type
	status := &core.PlaybookExecutionStatus{
		ExecutionID: execution.ID,
		PlaybookID:  execution.PlaybookID,
		AlertID:     execution.AlertID,
		Status:      string(execution.Status),
		StartedAt:   execution.StartedAt,
		Error:       execution.Error,
		StepResults: convertActionResults(execution.StepResults),
	}

	if !execution.CompletedAt.IsZero() {
		status.CompletedAt = &execution.CompletedAt
	}

	return status, nil
}

// ============================================================================
// PlaybookValidator Implementation
// ============================================================================

// ValidatePlaybook validates playbook structure without creating it.
//
// BUSINESS LOGIC:
// 1. Validate playbook structure
// 2. Check name uniqueness (as warning, not error)
// 3. Return errors and warnings separately
func (s *PlaybookServiceImpl) ValidatePlaybook(
	ctx context.Context,
	playbook *core.Playbook,
) (errors []string, warnings []string, err error) {
	if playbook == nil {
		return []string{"playbook is required"}, nil, nil
	}

	// Check context cancellation
	if err := ctx.Err(); err != nil {
		return nil, nil, fmt.Errorf("context cancelled: %w", err)
	}

	// Extract soar.Playbook from core.Playbook interface
	pb, ok := (*playbook).(*soar.Playbook)
	if !ok {
		return []string{"invalid playbook type"}, nil, nil
	}

	// Validate structure
	errors = validatePlaybookStructure(pb)

	// Check name uniqueness as warning (not error)
	if pb.Name != "" {
		exists, checkErr := s.playbookStorage.PlaybookNameExists(pb.Name, pb.ID)
		if checkErr == nil && exists {
			warnings = append(warnings, "A playbook with this name already exists")
		}
	}

	return errors, warnings, nil
}

// ============================================================================
// Helper Functions
// ============================================================================

// generatePlaybookID generates a unique playbook ID.
//
// SECURITY: Uses cryptographically secure random via uuid.New()
func generatePlaybookID() string {
	return fmt.Sprintf("pb-%s", uuid.New().String()[:uuidPrefixLength])
}

// generateExecutionID generates a unique execution ID.
func generateExecutionID() string {
	return fmt.Sprintf("exec-%d", time.Now().UnixNano())
}

// validatePlaybookStructure performs comprehensive validation.
// Returns slice of validation error messages.
func validatePlaybookStructure(p *soar.Playbook) []string {
	var errs []string

	if p == nil {
		return []string{"playbook cannot be nil"}
	}

	// Validate name
	name := strings.TrimSpace(p.Name)
	if name == "" {
		errs = append(errs, "name is required")
	} else if len(name) > maxNameLength {
		errs = append(errs, fmt.Sprintf("name too long: %d characters (max %d)", len(name), maxNameLength))
	}

	// Validate description length
	if len(p.Description) > maxDescriptionLength {
		errs = append(errs, fmt.Sprintf("description too long: %d characters (max %d)", len(p.Description), maxDescriptionLength))
	}

	// Validate steps
	if len(p.Steps) == 0 {
		errs = append(errs, "at least one step is required")
	} else if len(p.Steps) > maxStepsPerPlaybook {
		errs = append(errs, fmt.Sprintf("too many steps: %d (max %d)", len(p.Steps), maxStepsPerPlaybook))
	}

	// Validate triggers
	if len(p.Triggers) > maxTriggersPerBook {
		errs = append(errs, fmt.Sprintf("too many triggers: %d (max %d)", len(p.Triggers), maxTriggersPerBook))
	}

	// Validate priority
	if p.Priority < 0 {
		errs = append(errs, fmt.Sprintf("priority cannot be negative: %d", p.Priority))
	}

	return errs
}

// deepCopyPlaybookWithContext creates a deep copy of a playbook with context cancellation support.
// BLOCKER-2 FIX: Checks context cancellation in loops to prevent unbounded execution.
func deepCopyPlaybookWithContext(ctx context.Context, original *soar.Playbook) (*soar.Playbook, error) {
	if original == nil {
		return nil, nil
	}

	// Check context before starting
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("deep copy cancelled before start: %w", err)
	}

	duplicate := &soar.Playbook{
		Name:        original.Name,
		Description: original.Description,
		Enabled:     original.Enabled,
		Priority:    original.Priority,
	}

	// Deep copy Tags
	if original.Tags != nil {
		duplicate.Tags = make([]string, len(original.Tags))
		copy(duplicate.Tags, original.Tags)
	} else {
		duplicate.Tags = make([]string, 0)
	}

	// Deep copy Triggers with context cancellation checks
	if original.Triggers != nil {
		duplicate.Triggers = make([]soar.PlaybookTrigger, len(original.Triggers))
		for i, trigger := range original.Triggers {
			// Check context cancellation in loop
			if err := ctx.Err(); err != nil {
				return nil, fmt.Errorf("deep copy cancelled during triggers: %w", err)
			}
			duplicate.Triggers[i] = deepCopyTriggerWithContext(ctx, trigger)
		}
	} else {
		duplicate.Triggers = make([]soar.PlaybookTrigger, 0)
	}

	// Deep copy Steps with new step IDs and context cancellation checks
	if original.Steps != nil {
		duplicate.Steps = make([]soar.PlaybookStep, len(original.Steps))
		for i, step := range original.Steps {
			// Check context cancellation in loop
			if err := ctx.Err(); err != nil {
				return nil, fmt.Errorf("deep copy cancelled during steps: %w", err)
			}
			duplicate.Steps[i] = deepCopyStepWithContext(ctx, step)
			// Generate new step ID for duplicate
			duplicate.Steps[i].ID = fmt.Sprintf("step-%s", uuid.New().String()[:uuidPrefixLength])
		}
	} else {
		duplicate.Steps = make([]soar.PlaybookStep, 0)
	}

	return duplicate, nil
}

// deepCopyPlaybookInternal creates a deep copy of a playbook without context.
// Uses background context internally for legacy compatibility.
func deepCopyPlaybookInternal(original *soar.Playbook) *soar.Playbook {
	// Use background context for internal calls (CreatePlaybook, UpdatePlaybook)
	// These already have their own context checks at the service level
	duplicate, _ := deepCopyPlaybookWithContext(context.Background(), original)
	return duplicate
}

// deepCopyTriggerWithContext creates a deep copy of a trigger with context support.
func deepCopyTriggerWithContext(ctx context.Context, original soar.PlaybookTrigger) soar.PlaybookTrigger {
	trigger := soar.PlaybookTrigger{
		Type: original.Type,
	}

	if original.Conditions != nil {
		trigger.Conditions = make([]soar.PlaybookCondition, len(original.Conditions))
		for i, cond := range original.Conditions {
			// Check context in loop
			if ctx.Err() != nil {
				// Return partially copied trigger (will fail at upper level)
				return trigger
			}
			trigger.Conditions[i] = deepCopyCondition(cond)
		}
	} else {
		trigger.Conditions = make([]soar.PlaybookCondition, 0)
	}

	return trigger
}

// deepCopyStepWithContext creates a deep copy of a step with context support.
func deepCopyStepWithContext(ctx context.Context, original soar.PlaybookStep) soar.PlaybookStep {
	step := soar.PlaybookStep{
		ID:              original.ID,
		Name:            original.Name,
		ActionType:      original.ActionType,
		ContinueOnError: original.ContinueOnError,
		Timeout:         original.Timeout,
	}

	// Deep copy Parameters map
	if original.Parameters != nil {
		step.Parameters = make(map[string]interface{}, len(original.Parameters))
		for k, v := range original.Parameters {
			// Check context in loop
			if ctx.Err() != nil {
				// Return partially copied step
				return step
			}
			step.Parameters[k] = deepCopyValue(v)
		}
	} else {
		step.Parameters = make(map[string]interface{})
	}

	// Deep copy Conditions
	if original.Conditions != nil {
		step.Conditions = make([]soar.PlaybookCondition, len(original.Conditions))
		for i, cond := range original.Conditions {
			// Check context in loop
			if ctx.Err() != nil {
				// Return partially copied step
				return step
			}
			step.Conditions[i] = deepCopyCondition(cond)
		}
	} else {
		step.Conditions = make([]soar.PlaybookCondition, 0)
	}

	return step
}

// deepCopyCondition creates a deep copy of a condition.
func deepCopyCondition(original soar.PlaybookCondition) soar.PlaybookCondition {
	return soar.PlaybookCondition{
		Field:    original.Field,
		Operator: original.Operator,
		Value:    deepCopyValue(original.Value),
	}
}

// BLOCKER-3 FIX: deepCopyValue moved to helpers.go for shared use across services
// (Previously defined here, now imported from helpers.go)

// convertActionResults converts map of soar.ActionResult to core.ActionResult.
func convertActionResults(results map[string]*soar.ActionResult) map[string]*core.ActionResult {
	if results == nil {
		return nil
	}

	converted := make(map[string]*core.ActionResult, len(results))
	for k, v := range results {
		if v != nil {
			converted[k] = &core.ActionResult{
				Success: v.Status == soar.ActionStatusCompleted,
				Message: v.Message,
				Data:    v.Output,
			}
		}
	}
	return converted
}
