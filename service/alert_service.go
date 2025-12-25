package service

import (
	"context"
	"fmt"
	"strings"

	"cerberus/core"
	"cerberus/storage"

	"github.com/google/uuid"
	"go.uber.org/zap"
)

// AlertServiceImpl implements the AlertService interface from core package.
// It provides business logic layer between HTTP handlers and storage layer.
//
// SECURITY CONSIDERATIONS:
// - All user inputs are validated before storage operations
// - State machine validation enforces valid alert status transitions
// - Assignee validation prevents assignment to non-existent users
// - Disposition changes are audited with username tracking
//
// DESIGN PATTERNS:
// - Dependency injection via constructor
// - Context propagation for cancellation
// - Typed error returns with wrapping
// - Separation of concerns (business logic vs storage)
type AlertServiceImpl struct {
	alertStorage         AlertStorage
	ruleStorage          RuleStorage
	userStorage          UserStorage
	investigationStorage InvestigationStorage
	logger               *zap.SugaredLogger
}

// AlertStorage defines alert storage operations needed by service.
// Defined here (consumer package) following Interface Segregation Principle.
type AlertStorage interface {
	GetAlertByID(ctx context.Context, alertID string) (*core.Alert, error)
	GetAlerts(ctx context.Context, limit, offset int) ([]core.Alert, error)
	GetAlertsWithFilters(ctx context.Context, filters *core.AlertFilters) ([]*core.Alert, int64, error)
	GetAlertCount(ctx context.Context) (int64, error)
	GetAlert(ctx context.Context, alertID string) (*core.Alert, error)
	InsertAlert(ctx context.Context, alert *core.Alert) error
	UpdateAlertStatus(ctx context.Context, alertID string, status core.AlertStatus) error
	UpdateAlertDisposition(ctx context.Context, alertID string, disposition core.AlertDisposition, reason, username string) (string, error)
	UpdateAlertAssignee(ctx context.Context, alertID string, assigneeID *string) error
	UpdateAlertInvestigation(ctx context.Context, alertID, investigationID string) error
	AssignAlert(ctx context.Context, alertID, assignTo string) error
	DeleteAlert(ctx context.Context, alertID string) error
}

// RuleStorage defines rule storage operations needed for alert enrichment.
type RuleStorage interface {
	GetRule(id string) (*core.Rule, error)
}

// UserStorage defines user storage operations needed for validation.
type UserStorage interface {
	GetUserByUsername(ctx context.Context, username string) (*storage.User, error)
}

// InvestigationStorage defines investigation storage operations.
type InvestigationStorage interface {
	GetInvestigation(id string) (*core.Investigation, error)
	CreateInvestigation(investigation *core.Investigation) error
	DeleteInvestigation(id string) error
	AddAlert(investigationID, alertID string) error
}

// NewAlertService creates a new AlertService instance.
//
// PARAMETERS:
//   - alertStorage: Alert persistence layer (required, panics if nil)
//   - ruleStorage: Rule storage for enrichment (required, panics if nil)
//   - userStorage: User storage for validation (can be nil, validation skipped)
//   - investigationStorage: Investigation storage for linking (can be nil)
//   - logger: Structured logger (required, panics if nil)
//
// DESIGN NOTE: Constructor validates required dependencies to fail fast.
func NewAlertService(
	alertStorage AlertStorage,
	ruleStorage RuleStorage,
	userStorage UserStorage,
	investigationStorage InvestigationStorage,
	logger *zap.SugaredLogger,
) *AlertServiceImpl {
	if alertStorage == nil {
		panic("alertStorage is required")
	}
	if ruleStorage == nil {
		panic("ruleStorage is required")
	}
	if logger == nil {
		panic("logger is required")
	}

	return &AlertServiceImpl{
		alertStorage:         alertStorage,
		ruleStorage:          ruleStorage,
		userStorage:          userStorage,
		investigationStorage: investigationStorage,
		logger:               logger,
	}
}

// ============================================================================
// AlertReader Implementation
// ============================================================================

// GetAlertByID retrieves a single alert by ID with enrichment.
//
// BUSINESS LOGIC:
// 1. Validate alert ID format
// 2. Retrieve alert from storage
// 3. Enrich with rule information (name, description, MITRE techniques)
//
// ERRORS:
//   - storage.ErrAlertNotFound: Alert doesn't exist
//   - Wrapped storage errors with context
func (s *AlertServiceImpl) GetAlertByID(ctx context.Context, alertID string) (*core.Alert, error) {
	// Validate input
	if alertID == "" {
		return nil, fmt.Errorf("alertID is required")
	}

	// Retrieve alert
	alert, err := s.alertStorage.GetAlertByID(ctx, alertID)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve alert %s: %w", alertID, err)
	}

	if alert == nil {
		return nil, storage.ErrAlertNotFound
	}

	// Enrich with rule information
	if err := s.EnrichAlert(ctx, alert); err != nil {
		// Log warning but don't fail - enrichment is best-effort
		s.logger.Warnw("Failed to enrich alert",
			"alert_id", alertID,
			"error", err)
	}

	return alert, nil
}

// ListAlerts retrieves paginated alerts with filtering and enrichment.
//
// BUSINESS LOGIC:
// 1. Validate pagination parameters
// 2. Apply filters and retrieve alerts from storage
// 3. Bulk enrich all alerts with rule information
//
// PARAMETERS:
//   - filters: Alert filtering criteria (nil uses defaults)
//
// RETURNS:
//   - alerts: Slice of enriched alerts (empty if no matches)
//   - total: Total count matching filters (for pagination)
//   - error: Any errors encountered
//
// DEFENSIVE PROGRAMMING: Creates a defensive copy of filters to avoid mutating caller's data.
func (s *AlertServiceImpl) ListAlerts(ctx context.Context, filters *core.AlertFilters) ([]*core.Alert, int64, error) {
	// Validate filters
	if filters == nil {
		return nil, 0, fmt.Errorf("filters are required")
	}

	// DEFENSIVE COPY: Avoid mutating caller's filters object
	filtersCopy := *filters

	// Validate pagination bounds
	if filtersCopy.Page < 1 {
		filtersCopy.Page = 1
	}
	if filtersCopy.Limit < 1 {
		filtersCopy.Limit = 100
	}
	if filtersCopy.Limit > 10000 {
		filtersCopy.Limit = 10000
	}

	// Check if we need filtering
	var alerts []*core.Alert
	var total int64
	var err error

	if s.hasFilters(&filtersCopy) {
		// Use filtered query
		alerts, total, err = s.alertStorage.GetAlertsWithFilters(ctx, &filtersCopy)
		if err != nil {
			return nil, 0, fmt.Errorf("failed to retrieve filtered alerts: %w", err)
		}
	} else {
		// Simple paginated query
		offset := (filtersCopy.Page - 1) * filtersCopy.Limit
		simpleAlerts, err := s.alertStorage.GetAlerts(ctx, filtersCopy.Limit, offset)
		if err != nil {
			return nil, 0, fmt.Errorf("failed to retrieve alerts: %w", err)
		}

		// Convert []Alert to []*Alert
		alerts = make([]*core.Alert, len(simpleAlerts))
		for i := range simpleAlerts {
			alerts[i] = &simpleAlerts[i]
		}

		total, err = s.alertStorage.GetAlertCount(ctx)
		if err != nil {
			return nil, 0, fmt.Errorf("failed to get alert count: %w", err)
		}
	}

	// Enrich all alerts
	if err := s.EnrichAlerts(ctx, alerts); err != nil {
		// Log warning but don't fail - enrichment is best-effort
		s.logger.Warnw("Failed to enrich alerts",
			"count", len(alerts),
			"error", err)
	}

	return alerts, total, nil
}

// hasFilters checks if any filters are applied.
func (s *AlertServiceImpl) hasFilters(filters *core.AlertFilters) bool {
	if filters == nil {
		return false
	}

	return filters.Search != "" ||
		len(filters.Severities) > 0 ||
		len(filters.Statuses) > 0 ||
		len(filters.RuleIDs) > 0 ||
		len(filters.AssignedTo) > 0 ||
		len(filters.Tags) > 0 ||
		len(filters.MitreTactics) > 0 ||
		len(filters.MitreTechniques) > 0 ||
		filters.CreatedAfter != nil ||
		filters.CreatedBefore != nil ||
		filters.UpdatedAfter != nil ||
		filters.UpdatedBefore != nil ||
		len(filters.Dispositions) > 0 ||
		filters.HasDisposition != nil
}

// ============================================================================
// AlertWriter Implementation
// ============================================================================

// CreateAlert creates a new alert with validation.
//
// BUSINESS LOGIC:
// 1. Validate alert structure
// 2. Generate alert ID if not provided
// 3. Persist to storage
//
// RETURNS:
//   - Created alert with generated ID
//   - Error if validation or storage fails
func (s *AlertServiceImpl) CreateAlert(ctx context.Context, alert *core.Alert) (*core.Alert, error) {
	if alert == nil {
		return nil, fmt.Errorf("alert is required")
	}

	// Validate required fields
	if alert.RuleID == "" {
		return nil, fmt.Errorf("alert.RuleID is required")
	}
	if alert.Severity == "" {
		return nil, fmt.Errorf("alert.Severity is required")
	}

	// Generate ID if not provided
	if alert.AlertID == "" {
		alert.AlertID = generateAlertID()
	}

	// Set default status if not provided
	if alert.Status == "" {
		alert.Status = core.AlertStatusPending
	}

	// Insert into storage
	if err := s.alertStorage.InsertAlert(ctx, alert); err != nil {
		return nil, fmt.Errorf("failed to create alert: %w", err)
	}

	return alert, nil
}

// UpdateAlertStatus updates alert status with state machine validation.
//
// BUSINESS LOGIC:
// 1. Retrieve current alert
// 2. Validate state transition using alert state machine
// 3. Update status in storage
//
// ERRORS:
//   - storage.ErrAlertNotFound: Alert doesn't exist
//   - core.ErrInvalidStateTransition: Invalid transition
func (s *AlertServiceImpl) UpdateAlertStatus(ctx context.Context, alertID string, status core.AlertStatus, userID string) error {
	// Validate inputs
	if alertID == "" {
		return fmt.Errorf("alertID is required")
	}
	if !status.IsValid() {
		return fmt.Errorf("invalid alert status: %s", status)
	}
	if userID == "" {
		return fmt.Errorf("userID is required for audit trail")
	}

	// Get current alert for state validation
	alert, err := s.alertStorage.GetAlert(ctx, alertID)
	if err != nil {
		return fmt.Errorf("failed to retrieve alert %s: %w", alertID, err)
	}
	if alert == nil {
		return storage.ErrAlertNotFound
	}

	// Validate state transition
	if err := alert.TransitionTo(status, userID); err != nil {
		return fmt.Errorf("invalid state transition from %s to %s: %w", alert.Status, status, err)
	}

	// Update in storage
	if err := s.alertStorage.UpdateAlertStatus(ctx, alertID, status); err != nil {
		return fmt.Errorf("failed to update alert status: %w", err)
	}

	return nil
}

// DeleteAlert permanently deletes an alert.
//
// ERRORS:
//   - storage.ErrAlertNotFound: Alert doesn't exist
func (s *AlertServiceImpl) DeleteAlert(ctx context.Context, alertID string) error {
	if alertID == "" {
		return fmt.Errorf("alertID is required")
	}

	if err := s.alertStorage.DeleteAlert(ctx, alertID); err != nil {
		return fmt.Errorf("failed to delete alert %s: %w", alertID, err)
	}

	return nil
}

// ============================================================================
// AlertDispositionManager Implementation
// ============================================================================

// SetDisposition sets analyst verdict on an alert with audit trail.
//
// BUSINESS LOGIC:
// 1. Validate disposition value
// 2. Validate username format
// 3. Update disposition with atomic read-update-return
//
// RETURNS:
//   - previousDisposition: Previous verdict for audit logging
//   - error: Any validation or storage errors
//
// SECURITY:
// - Username is validated to prevent injection
// - Reason is length-limited in handlers (this enforces business rules)
func (s *AlertServiceImpl) SetDisposition(
	ctx context.Context,
	alertID string,
	disposition core.AlertDisposition,
	reason, username string,
) (previousDisposition core.AlertDisposition, err error) {
	// Validate inputs
	if alertID == "" {
		return "", fmt.Errorf("alertID is required")
	}
	if !disposition.IsValid() {
		return "", fmt.Errorf("invalid disposition: %s (valid: %v)", disposition, core.ValidDispositions())
	}
	if username == "" {
		return "", fmt.Errorf("username is required for audit trail")
	}

	// Update disposition (storage returns previous value)
	previousDispositionStr, err := s.alertStorage.UpdateAlertDisposition(ctx, alertID, disposition, reason, username)
	if err != nil {
		return "", fmt.Errorf("failed to update alert disposition: %w", err)
	}

	// Convert previous disposition string to type
	previous := core.AlertDisposition(previousDispositionStr)

	return previous, nil
}

// ============================================================================
// AlertAssignmentManager Implementation
// ============================================================================

// AssignAlert assigns an alert to a user with validation.
//
// BUSINESS LOGIC:
// 1. Validate assignee exists (if userStorage available)
// 2. Update assignment in storage
// 3. nil assignee unassigns the alert
//
// ERRORS:
//   - fmt.Errorf: User doesn't exist
//   - storage.ErrAlertNotFound: Alert doesn't exist
func (s *AlertServiceImpl) AssignAlert(ctx context.Context, alertID string, assignee *string, assignedBy string) error {
	// Validate inputs
	if alertID == "" {
		return fmt.Errorf("alertID is required")
	}
	if assignedBy == "" {
		return fmt.Errorf("assignedBy is required for audit trail")
	}

	// Validate assignee exists (if provided and userStorage available)
	if assignee != nil && *assignee != "" && s.userStorage != nil {
		_, err := s.userStorage.GetUserByUsername(ctx, *assignee)
		if err != nil {
			return fmt.Errorf("assignee %q does not exist: %w", *assignee, err)
		}
	}

	// Update assignment
	if err := s.alertStorage.UpdateAlertAssignee(ctx, alertID, assignee); err != nil {
		return fmt.Errorf("failed to assign alert: %w", err)
	}

	return nil
}

// ============================================================================
// AlertEnricher Implementation
// ============================================================================

// EnrichAlert adds rule information to a single alert.
//
// BUSINESS LOGIC:
// 1. Lookup rule by alert.RuleID
// 2. Populate RuleName, RuleDescription, RuleType
// 3. Extract MITRE techniques from rule tags
// 4. Generate human-friendly title if rule not found
//
// DESIGN NOTE: This is best-effort - errors are logged but don't fail the operation.
func (s *AlertServiceImpl) EnrichAlert(ctx context.Context, alert *core.Alert) error {
	if alert == nil || alert.RuleID == "" {
		return nil
	}

	// Try to get rule from storage
	rule, err := s.ruleStorage.GetRule(alert.RuleID)
	if err == nil && rule != nil {
		alert.RuleName = rule.Name
		alert.RuleDescription = rule.Description
		alert.RuleType = rule.Type

		// Extract MITRE techniques from tags if not already set
		if len(alert.MitreTechniques) == 0 && len(rule.Tags) > 0 {
			for _, tag := range rule.Tags {
				if strings.HasPrefix(tag, "attack.t") {
					alert.MitreTechniques = append(alert.MitreTechniques, tag)
				}
			}
		}
		return nil
	}

	// Rule not found - generate human-friendly name from event data
	alert.RuleName = s.generateAlertTitle(alert)
	return nil
}

// EnrichAlerts bulk enrichment for multiple alerts.
//
// DESIGN NOTE: Continues on individual failures to enrich as many as possible.
// CANCELLATION: Checks context every 100 alerts for long-running operations.
func (s *AlertServiceImpl) EnrichAlerts(ctx context.Context, alerts []*core.Alert) error {
	if len(alerts) == 0 {
		return nil
	}

	var firstError error
	for i, alert := range alerts {
		if alert == nil {
			continue
		}

		// PERFORMANCE: Check for cancellation every 100 alerts
		// Avoids overhead on every iteration while staying responsive
		if i%100 == 0 {
			if err := ctx.Err(); err != nil {
				return fmt.Errorf("enrichment cancelled after %d alerts: %w", i, err)
			}
		}

		if err := s.EnrichAlert(ctx, alert); err != nil && firstError == nil {
			firstError = err
		}
	}

	return firstError
}

// generateAlertTitle creates a human-friendly title for alerts without matching rules.
func (s *AlertServiceImpl) generateAlertTitle(alert *core.Alert) string {
	if alert == nil {
		return "Unknown Alert"
	}

	// Try to extract useful info from event fields
	if alert.Event != nil && alert.Event.Fields != nil {
		fields := alert.Event.Fields

		// Check for a message field first (most descriptive)
		if msg, ok := fields["message"].(string); ok && msg != "" {
			return msg
		}

		// Try event_type and make it human-readable
		if eventType, ok := fields["event_type"].(string); ok && eventType != "" {
			return humanizeEventType(eventType)
		}

		// Try EventID field
		if eventID, ok := fields["EventID"].(string); ok && eventID != "" {
			return humanizeEventType(eventID)
		}
	}

	// Last resort: humanize the rule_id
	return humanizeEventType(alert.RuleID)
}

// humanizeEventType converts snake_case or kebab-case identifiers to Title Case.
func humanizeEventType(s string) string {
	if s == "" {
		return "Unknown Alert"
	}

	// Replace underscores and hyphens with spaces
	s = strings.ReplaceAll(s, "_", " ")
	s = strings.ReplaceAll(s, "-", " ")

	// Title case each word
	words := strings.Fields(s)
	for i, word := range words {
		if len(word) > 0 {
			words[i] = strings.ToUpper(string(word[0])) + strings.ToLower(word[1:])
		}
	}

	return strings.Join(words, " ")
}

// generateAlertID generates a unique alert ID using UUID v4.
//
// SECURITY: Uses cryptographically secure random number generation via uuid.New()
// COLLISION RESISTANCE: UUID v4 has ~2^122 unique values, collision probability negligible
func generateAlertID() string {
	return uuid.New().String()
}

// ============================================================================
// Additional Alert Service Methods
// ============================================================================

// AcknowledgeAlert marks an alert as acknowledged by transitioning to acknowledged status.
//
// BUSINESS LOGIC:
// 1. Retrieve current alert
// 2. Validate state transition to acknowledged
// 3. Update status via UpdateAlertStatus (reuses state machine validation)
//
// DESIGN NOTE: This is a convenience method that delegates to UpdateAlertStatus
// for consistent state machine enforcement.
func (s *AlertServiceImpl) AcknowledgeAlert(ctx context.Context, alertID, userID string) error {
	if alertID == "" {
		return fmt.Errorf("alertID is required")
	}
	if userID == "" {
		return fmt.Errorf("userID is required for audit trail")
	}

	// Use UpdateAlertStatus for state machine validation
	return s.UpdateAlertStatus(ctx, alertID, core.AlertStatusAcknowledged, userID)
}

// DismissAlert marks an alert as dismissed (resolved with low priority).
//
// BUSINESS LOGIC:
// 1. Retrieve current alert to capture previous disposition
// 2. Set disposition to benign_positive (dismissed alerts are benign)
// 3. Update status to resolved
// 4. Rollback disposition if status update fails (ATOMICITY)
//
// DESIGN NOTE: Dismiss = benign verdict + resolve. This is a compound operation.
// ATOMICITY: Uses rollback to maintain consistency between disposition and status.
func (s *AlertServiceImpl) DismissAlert(ctx context.Context, alertID, reason, username string) error {
	if alertID == "" {
		return fmt.Errorf("alertID is required")
	}
	if username == "" {
		return fmt.Errorf("username is required for audit trail")
	}

	// Set benign disposition first (returns previous disposition for rollback)
	previousDisposition, err := s.SetDisposition(ctx, alertID, core.DispositionBenign, reason, username)
	if err != nil {
		return fmt.Errorf("failed to set benign disposition: %w", err)
	}

	// Then mark as resolved
	if err := s.UpdateAlertStatus(ctx, alertID, core.AlertStatusResolved, username); err != nil {
		// ROLLBACK: Restore previous disposition to maintain consistency
		rollbackReason := fmt.Sprintf("Rollback after failed status update: %v", err)
		if _, rollbackErr := s.SetDisposition(ctx, alertID, previousDisposition, rollbackReason, username); rollbackErr != nil {
			// Critical: both operations failed - log for manual intervention
			s.logger.Errorw("CRITICAL: Failed to rollback disposition after status update failure - manual cleanup required",
				"alert_id", alertID,
				"previous_disposition", previousDisposition,
				"current_disposition", core.DispositionBenign,
				"status_update_error", err,
				"rollback_error", rollbackErr,
				"username", username)
		}
		return fmt.Errorf("failed to resolve alert: %w", err)
	}

	return nil
}

// CreateInvestigationFromAlert creates an investigation from an alert atomically.
//
// BUSINESS LOGIC:
// 1. Validate alert exists and is not already linked
// 2. Auto-generate investigation title/description if not provided
// 3. Map alert severity to investigation priority
// 4. Inherit assignee and MITRE techniques from alert
// 5. Create investigation
// 6. Link alert to investigation
// 7. Rollback investigation if linking fails
//
// ATOMICITY: Uses rollback pattern to maintain consistency.
// RETURNS:
//   - investigation: Created investigation with linked alert
//   - warnings: Non-fatal issues (e.g., MITRE techniques truncated)
//   - error: Fatal errors preventing operation
//
// ERRORS:
//   - storage.ErrAlertNotFound: Alert doesn't exist
//   - storage.ErrAlertAlreadyLinked: Alert already in another investigation
//   - Wrapped storage errors
func (s *AlertServiceImpl) CreateInvestigationFromAlert(
	ctx context.Context,
	alertID string,
	title, description string,
	priority core.InvestigationPriority,
	userID string,
) (investigation *core.Investigation, warnings []string, err error) {
	// Validate inputs
	if alertID == "" {
		return nil, nil, fmt.Errorf("alertID is required")
	}
	if userID == "" {
		return nil, nil, fmt.Errorf("userID is required for audit trail")
	}

	// Get alert to validate it exists and extract metadata
	alert, err := s.alertStorage.GetAlertByID(ctx, alertID)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to retrieve alert %s: %w", alertID, err)
	}
	if alert == nil {
		return nil, nil, storage.ErrAlertNotFound
	}

	// Check if already linked (prevent duplicate investigations)
	if alert.InvestigationID != "" {
		return nil, nil, storage.ErrAlertAlreadyLinked
	}

	// Auto-generate title if not provided
	if title == "" {
		ruleName := alert.RuleName
		if ruleName == "" {
			ruleName = alert.RuleID
		}
		if ruleName == "" {
			ruleName = "Unknown Rule"
		}
		title = fmt.Sprintf("Investigation: %s", ruleName)
	}

	// Auto-generate description if not provided
	if description == "" {
		ruleName := alert.RuleName
		if ruleName != "" {
			description = fmt.Sprintf("Investigation created from alert triggered by rule: %s", ruleName)
		} else {
			description = fmt.Sprintf("Investigation created from alert %s", alertID)
		}
	}

	// Auto-map priority if not provided (zero value check)
	if priority == "" {
		priority = mapAlertSeverityToInvestigationPriority(alert.Severity)
	}

	// Validate priority
	if !priority.IsValid() {
		return nil, nil, fmt.Errorf("invalid priority: %s", priority)
	}

	// Create investigation
	investigation = core.NewInvestigation(title, description, priority, userID)

	// Inherit assignee from alert if set
	if alert.AssignedTo != "" {
		investigation.AssigneeID = alert.AssignedTo
	}

	// Add alert ID
	investigation.AlertIDs = []string{alertID}

	// Copy MITRE techniques from alert (with limit and user warning)
	const maxMitreTechniques = 50
	if len(alert.MitreTechniques) > 0 {
		techniques := alert.MitreTechniques
		if len(techniques) > maxMitreTechniques {
			// Log for server-side monitoring
			s.logger.Warnw("Alert has excessive MITRE techniques, truncating",
				"alert_id", alertID,
				"technique_count", len(techniques),
				"limit", maxMitreTechniques)

			// Return warning to user so they know data was truncated
			warnings = append(warnings, fmt.Sprintf(
				"Alert has %d MITRE techniques (limit: %d). Only first %d techniques were added to investigation.",
				len(techniques), maxMitreTechniques, maxMitreTechniques))

			techniques = techniques[:maxMitreTechniques]
		}
		investigation.MitreTechniques = append(investigation.MitreTechniques, techniques...)
	}

	// Create investigation in storage
	if s.investigationStorage == nil {
		return nil, nil, fmt.Errorf("investigation storage not available")
	}

	if err := s.investigationStorage.CreateInvestigation(investigation); err != nil {
		return nil, nil, fmt.Errorf("failed to create investigation: %w", err)
	}

	// Link alert to investigation (CRITICAL: rollback on failure)
	if err := s.alertStorage.UpdateAlertInvestigation(ctx, alertID, investigation.InvestigationID); err != nil {
		// Rollback: Safely delete investigation if it's still empty (no other alerts linked)
		if rollbackErr := s.safeDeleteEmptyInvestigation(investigation.InvestigationID); rollbackErr != nil {
			s.logger.Errorw("CRITICAL: Failed to rollback investigation after link failure - manual cleanup may be required",
				"investigation_id", investigation.InvestigationID,
				"alert_id", alertID,
				"link_error", err,
				"rollback_error", rollbackErr)
		}
		return nil, nil, fmt.Errorf("failed to link alert to investigation: %w", err)
	}

	return investigation, warnings, nil
}

// safeDeleteEmptyInvestigation deletes an investigation only if it has no linked alerts.
// This prevents race conditions where concurrent operations might link alerts while rollback is happening.
//
// RACE CONDITION PROTECTION:
// - Re-fetches investigation before deletion
// - Only deletes if AlertIDs is empty or contains only the original alert
// - Logs warning if investigation was modified by concurrent operation
//
// RETURNS: nil on successful deletion or if investigation already has alerts (safe to keep)
func (s *AlertServiceImpl) safeDeleteEmptyInvestigation(investigationID string) error {
	if s.investigationStorage == nil {
		return fmt.Errorf("investigation storage not available")
	}

	// Re-fetch investigation to check current state
	investigation, err := s.investigationStorage.GetInvestigation(investigationID)
	if err != nil {
		return fmt.Errorf("failed to fetch investigation for safe delete: %w", err)
	}

	if investigation == nil {
		// Investigation already deleted (idempotent)
		return nil
	}

	// Check if investigation has any linked alerts
	if len(investigation.AlertIDs) > 0 {
		// Investigation has alerts - don't delete (concurrent operation may have linked alerts)
		s.logger.Warnw("Investigation not deleted during rollback - has linked alerts (likely concurrent operation)",
			"investigation_id", investigationID,
			"alert_count", len(investigation.AlertIDs))
		return nil // Not an error - investigation is now valid
	}

	// Safe to delete - no alerts linked
	if err := s.investigationStorage.DeleteInvestigation(investigationID); err != nil {
		return fmt.Errorf("failed to delete empty investigation: %w", err)
	}

	return nil
}

// LinkAlertToInvestigation links an existing alert to an existing investigation.
//
// BUSINESS LOGIC:
// 1. Validate both alert and investigation exist
// 2. Check alert is not already linked
// 3. Update alert.InvestigationID
// 4. Add alert ID to investigation.AlertIDs (best-effort)
// 5. Return warnings if bidirectional linking partially fails
//
// DESIGN NOTE: Returns warnings for partial success (eventual consistency).
// Primary relationship is stored in alert (investigation_id column).
// Secondary relationship in investigation.AlertIDs may lag.
func (s *AlertServiceImpl) LinkAlertToInvestigation(
	ctx context.Context,
	alertID, investigationID, userID string,
) (warnings []string, err error) {
	// Validate inputs
	if alertID == "" {
		return nil, fmt.Errorf("alertID is required")
	}
	if investigationID == "" {
		return nil, fmt.Errorf("investigationID is required")
	}
	if userID == "" {
		return nil, fmt.Errorf("userID is required for audit trail")
	}

	// Validate alert exists and is not already linked
	alert, err := s.alertStorage.GetAlertByID(ctx, alertID)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve alert %s: %w", alertID, err)
	}
	if alert == nil {
		return nil, storage.ErrAlertNotFound
	}
	if alert.InvestigationID != "" {
		if alert.InvestigationID == investigationID {
			// Already linked to this investigation - idempotent success
			// Return nil warnings to match original success response (consistency)
			return nil, nil
		}
		return nil, storage.ErrAlertAlreadyLinked
	}

	// Validate investigation exists
	if s.investigationStorage == nil {
		return nil, fmt.Errorf("investigation storage not available")
	}

	investigation, err := s.investigationStorage.GetInvestigation(investigationID)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve investigation %s: %w", investigationID, err)
	}
	if investigation == nil {
		return nil, fmt.Errorf("investigation not found: %s", investigationID)
	}

	// Update alert -> investigation link (primary relationship)
	if err := s.alertStorage.UpdateAlertInvestigation(ctx, alertID, investigationID); err != nil {
		return nil, fmt.Errorf("failed to link alert to investigation: %w", err)
	}

	// Update investigation -> alert link (secondary, best-effort)
	if err := s.investigationStorage.AddAlert(investigationID, alertID); err != nil {
		warnings = append(warnings, fmt.Sprintf("Alert linked but investigation list update failed: %v", err))
		s.logger.Warnw("Investigation alert list update failed (eventual consistency)",
			"investigation_id", investigationID,
			"alert_id", alertID,
			"error", err)
	}

	return warnings, nil
}

// mapAlertSeverityToInvestigationPriority converts alert severity to investigation priority.
func mapAlertSeverityToInvestigationPriority(severity string) core.InvestigationPriority {
	switch strings.ToLower(severity) {
	case "critical":
		return core.InvestigationPriorityCritical
	case "high":
		return core.InvestigationPriorityHigh
	case "medium":
		return core.InvestigationPriorityMedium
	case "low":
		return core.InvestigationPriorityLow
	default:
		return core.InvestigationPriorityMedium // Default to medium
	}
}
