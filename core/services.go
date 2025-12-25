package core

import (
	"context"
	"time"
)

// ============================================================================
// Service Layer Architecture - Task 145.1
// ============================================================================
//
// DESIGN PRINCIPLES:
// 1. Interfaces are defined WHERE THEY ARE USED (consumer package), not where implemented
// 2. Small interfaces (1-3 methods ideal, following Interface Segregation Principle)
// 3. Accept interfaces, return concrete types
// 4. context.Context as first parameter for cancellation support
// 5. Typed errors (sentinel errors in storage package, wrapped with context in services)
//
// SERVICE LAYER PURPOSE:
// - Extract business logic from HTTP handlers
// - Provide transaction boundaries and consistency guarantees
// - Orchestrate multiple storage operations atomically
// - Enforce business rules and validation
// - Enable easier testing with interface mocks
// - Decouple HTTP concerns from domain logic
//
// IMPLEMENTATION STRATEGY:
// - Phase 1: Define service interfaces (this file)
// - Phase 2: Implement concrete services in service/ package
// - Phase 3: Refactor handlers to use services instead of direct storage calls
// - Phase 4: Add comprehensive service-layer tests

// ============================================================================
// Alert Service Interfaces
// ============================================================================

// AlertReader provides read operations for alerts.
// Consumers: API handlers (getAlerts, getAlertByID)
type AlertReader interface {
	// GetAlertByID retrieves a single alert by ID with optional enrichment.
	// Returns ErrAlertNotFound if alert doesn't exist.
	GetAlertByID(ctx context.Context, alertID string) (*Alert, error)

	// ListAlerts retrieves paginated alerts with filtering.
	// Returns empty slice if no alerts match filters.
	ListAlerts(ctx context.Context, filters *AlertFilters) ([]*Alert, int64, error)
}

// AlertWriter provides write operations for alerts.
// Consumers: Detection engine, API handlers
type AlertWriter interface {
	// CreateAlert creates a new alert with validation.
	// Returns the created alert with generated ID.
	CreateAlert(ctx context.Context, alert *Alert) (*Alert, error)

	// UpdateAlertStatus updates alert status with state machine validation.
	// Returns ErrInvalidStateTransition if transition not allowed.
	UpdateAlertStatus(ctx context.Context, alertID string, status AlertStatus, userID string) error

	// DeleteAlert permanently deletes an alert.
	// Returns ErrAlertNotFound if alert doesn't exist.
	DeleteAlert(ctx context.Context, alertID string) error
}

// AlertDispositionManager handles analyst verdict operations.
// Consumers: API handlers (updateAlertDisposition)
// Design: Separated from AlertWriter to follow Interface Segregation Principle
type AlertDispositionManager interface {
	// SetDisposition sets the analyst's verdict on an alert with audit trail.
	// Validates disposition value and records username, timestamp, reason.
	// Returns previous disposition for audit logging.
	SetDisposition(ctx context.Context, alertID string, disposition AlertDisposition, reason, username string) (previousDisposition AlertDisposition, err error)
}

// AlertAssignmentManager handles alert assignment operations.
// Consumers: API handlers (assignAlert, updateAlertAssignee)
type AlertAssignmentManager interface {
	// AssignAlert assigns an alert to a user with validation.
	// Validates assignee exists before assignment.
	// nil assignee unassigns the alert.
	AssignAlert(ctx context.Context, alertID string, assignee *string, assignedBy string) error
}

// AlertEnricher adds contextual information to alerts.
// Consumers: API handlers (enrichAlertsWithRuleInfo)
type AlertEnricher interface {
	// EnrichAlert adds rule name, description, type, and MITRE techniques.
	// Handles missing rules gracefully with auto-generated titles.
	EnrichAlert(ctx context.Context, alert *Alert) error

	// EnrichAlerts bulk enrichment for list operations.
	EnrichAlerts(ctx context.Context, alerts []*Alert) error
}

// AlertLifecycleManager handles alert lifecycle transitions.
// Consumers: API handlers (acknowledgeAlert, dismissAlert)
type AlertLifecycleManager interface {
	// AcknowledgeAlert marks an alert as acknowledged.
	// Validates state transition via alert state machine.
	AcknowledgeAlert(ctx context.Context, alertID, userID string) error

	// DismissAlert marks an alert as dismissed (benign + resolved).
	// Compound operation: sets benign disposition and resolves.
	DismissAlert(ctx context.Context, alertID, reason, username string) error
}

// AlertInvestigationLinker manages alert-investigation relationships.
// Consumers: API handlers (createInvestigationFromAlert, linkAlertToInvestigation)
// Design: Separated to follow Interface Segregation Principle
type AlertInvestigationLinker interface {
	// CreateInvestigationFromAlert creates investigation and links alert atomically.
	// Auto-generates title/description, maps severity to priority, inherits assignee.
	// Returns ErrAlertAlreadyLinked if alert is already linked.
	// Returns warnings for non-fatal issues (e.g., MITRE technique truncation).
	CreateInvestigationFromAlert(ctx context.Context, alertID string, title, description string, priority InvestigationPriority, userID string) (*Investigation, []string, error)

	// LinkAlertToInvestigation links existing alert to existing investigation bidirectionally.
	// Validates both exist. Returns warnings for partial success (eventual consistency).
	LinkAlertToInvestigation(ctx context.Context, alertID, investigationID, userID string) (warnings []string, err error)
}

// AlertService is the complete alert service interface.
// Most consumers should use smaller, focused interfaces above.
// Use this only when you need all alert operations in one place.
type AlertService interface {
	AlertReader
	AlertWriter
	AlertDispositionManager
	AlertAssignmentManager
	AlertEnricher
	AlertLifecycleManager
	AlertInvestigationLinker
}

// ============================================================================
// Investigation Service Interfaces
// ============================================================================

// InvestigationReader provides read operations for investigations.
// Consumers: API handlers (getInvestigation, listInvestigations)
type InvestigationReader interface {
	// GetInvestigationByID retrieves a single investigation with full details.
	// Returns ErrInvestigationNotFound if not found.
	GetInvestigationByID(ctx context.Context, investigationID string) (*Investigation, error)

	// ListInvestigations retrieves paginated investigations with filtering.
	ListInvestigations(ctx context.Context, filters map[string]interface{}, limit, offset int) ([]*Investigation, int64, error)
}

// InvestigationWriter provides write operations for investigations.
// Consumers: API handlers (createInvestigation, updateInvestigation)
type InvestigationWriter interface {
	// CreateInvestigation creates a new investigation with validation.
	// Generates UUID and sets created timestamp.
	CreateInvestigation(ctx context.Context, investigation *Investigation) (*Investigation, error)

	// UpdateInvestigation updates investigation details.
	// Returns ErrInvestigationNotFound if not found.
	UpdateInvestigation(ctx context.Context, investigationID string, investigation *Investigation) error

	// DeleteInvestigation permanently deletes an investigation.
	DeleteInvestigation(ctx context.Context, investigationID string) error
}

// InvestigationAlertLinker manages alert-investigation relationships.
// Consumers: API handlers (createInvestigationFromAlert, linkAlertToInvestigation)
type InvestigationAlertLinker interface {
	// CreateInvestigationFromAlert creates investigation and links alert atomically.
	// Performs rollback on failure to maintain consistency.
	// Returns ErrAlertAlreadyLinked if alert is already linked.
	// Returns warnings for non-fatal issues (e.g., MITRE technique truncation).
	CreateInvestigationFromAlert(ctx context.Context, alertID string, title, description string, priority InvestigationPriority, userID string) (*Investigation, []string, error)

	// LinkAlertToInvestigation links existing alert to existing investigation bidirectionally.
	// Validates both alert and investigation exist.
	// Returns warnings for partial success (eventual consistency).
	LinkAlertToInvestigation(ctx context.Context, alertID, investigationID, userID string) (warnings []string, err error)

	// UnlinkAlertFromInvestigation removes alert-investigation link.
	UnlinkAlertFromInvestigation(ctx context.Context, alertID, investigationID string) error
}

// InvestigationLifecycleManager handles investigation state transitions.
// Consumers: API handlers (closeInvestigation, reopenInvestigation)
type InvestigationLifecycleManager interface {
	// CloseInvestigation transitions investigation to closed state with verdict.
	// Validates all required fields and closure requirements.
	CloseInvestigation(ctx context.Context, investigationID string, verdict InvestigationVerdict, resolutionCategory, summary string, affectedAssets []string, userID string) error

	// ReopenInvestigation transitions closed investigation back to open.
	// Only allowed from specific statuses.
	ReopenInvestigation(ctx context.Context, investigationID, reason, userID string) error
}

// InvestigationService is the complete investigation service interface.
// Most consumers should use smaller, focused interfaces above.
type InvestigationService interface {
	InvestigationReader
	InvestigationWriter
	InvestigationAlertLinker
	InvestigationLifecycleManager
}

// ============================================================================
// Rule Service Interfaces
// ============================================================================

// RuleReader provides read operations for detection rules.
// Consumers: API handlers, detection engine
type RuleReader interface {
	// GetRuleByID retrieves a single rule by ID.
	// Returns ErrRuleNotFound if not found.
	GetRuleByID(ctx context.Context, ruleID string) (*Rule, error)

	// ListRules retrieves paginated rules with optional filtering.
	ListRules(ctx context.Context, filters *RuleFilters, limit, offset int) ([]*Rule, int64, error)

	// GetEnabledRules retrieves all enabled rules for detection engine.
	GetEnabledRules(ctx context.Context) ([]*Rule, error)
}

// RuleWriter provides write operations for detection rules.
// Consumers: API handlers
type RuleWriter interface {
	// CreateRule creates a new rule with validation and hot-reload.
	// Performs atomic operation: persist + reload, with rollback on failure.
	// Returns the created rule with generated ID.
	CreateRule(ctx context.Context, rule *Rule) (*Rule, error)

	// UpdateRule updates an existing rule with validation and hot-reload.
	// Performs atomic operation: persist + reload, with rollback on failure.
	UpdateRule(ctx context.Context, ruleID string, rule *Rule) error

	// DeleteRule deletes a rule and hot-reloads detection engine.
	// Performs atomic operation: delete + reload, with rollback on failure.
	DeleteRule(ctx context.Context, ruleID string) error
}

// RuleStateManager manages rule enable/disable state.
// Consumers: API handlers
type RuleStateManager interface {
	// EnableRule enables a rule and reloads detection engine.
	EnableRule(ctx context.Context, ruleID string) error

	// DisableRule disables a rule and reloads detection engine.
	DisableRule(ctx context.Context, ruleID string) error
}

// RuleValidator validates rule configuration.
// Consumers: API handlers (validatePlaybookHandler equivalent for rules)
type RuleValidator interface {
	// ValidateRule validates rule structure without creating it.
	// Returns validation errors and warnings.
	ValidateRule(ctx context.Context, rule *Rule) (errors []string, warnings []string, err error)
}

// RuleService is the complete rule service interface.
type RuleService interface {
	RuleReader
	RuleWriter
	RuleStateManager
	RuleValidator
}

// ============================================================================
// Playbook Service Interfaces
// ============================================================================

// PlaybookReader provides read operations for playbooks.
// Consumers: API handlers, playbook executor
type PlaybookReader interface {
	// GetPlaybookByID retrieves a single playbook by ID.
	// Returns ErrPlaybookNotFound if not found.
	GetPlaybookByID(ctx context.Context, playbookID string) (*Playbook, error)

	// ListPlaybooks retrieves paginated playbooks with optional filtering.
	ListPlaybooks(ctx context.Context, enabled *bool, tag string, limit, offset int) ([]*Playbook, int64, error)

	// GetPlaybookStats returns aggregated playbook statistics.
	GetPlaybookStats(ctx context.Context) (*PlaybookStats, error)
}

// PlaybookWriter provides write operations for playbooks.
// Consumers: API handlers
type PlaybookWriter interface {
	// CreatePlaybook creates a new playbook with validation.
	// Generates ID if not provided, validates uniqueness of name.
	CreatePlaybook(ctx context.Context, playbook *Playbook) (*Playbook, error)

	// UpdatePlaybook updates an existing playbook with validation.
	// Validates name uniqueness (excluding current playbook).
	UpdatePlaybook(ctx context.Context, playbookID string, playbook *Playbook) error

	// DeletePlaybook permanently deletes a playbook.
	DeletePlaybook(ctx context.Context, playbookID string) error

	// DuplicatePlaybook creates a copy of an existing playbook.
	// New playbook is disabled by default with " (Copy)" suffix.
	DuplicatePlaybook(ctx context.Context, playbookID, userID string) (*Playbook, error)
}

// PlaybookStateManager manages playbook enable/disable state.
// Consumers: API handlers
type PlaybookStateManager interface {
	// EnablePlaybook enables a playbook for automatic execution.
	EnablePlaybook(ctx context.Context, playbookID string) error

	// DisablePlaybook disables a playbook.
	DisablePlaybook(ctx context.Context, playbookID string) error
}

// PlaybookExecutor executes playbooks.
// Consumers: API handlers, alert handlers
type PlaybookExecutor interface {
	// ExecutePlaybook executes a playbook for an alert asynchronously.
	// Returns execution ID immediately, actual execution happens in background.
	// Validates playbook is enabled before execution.
	ExecutePlaybook(ctx context.Context, playbookID, alertID, userID string) (executionID string, err error)

	// GetExecutionStatus retrieves status of a playbook execution.
	GetExecutionStatus(ctx context.Context, executionID string) (*PlaybookExecutionStatus, error)
}

// PlaybookValidator validates playbook configuration.
// Consumers: API handlers (validatePlaybookHandler)
type PlaybookValidator interface {
	// ValidatePlaybook validates playbook structure without creating it.
	// Returns validation errors and warnings.
	ValidatePlaybook(ctx context.Context, playbook *Playbook) (errors []string, warnings []string, err error)
}

// PlaybookService is the complete playbook service interface.
type PlaybookService interface {
	PlaybookReader
	PlaybookWriter
	PlaybookStateManager
	PlaybookExecutor
	PlaybookValidator
}

// ============================================================================
// Event Service Interfaces
// ============================================================================

// EventReader provides read operations for security events.
// Consumers: API handlers
type EventReader interface {
	// GetEventByID retrieves a single event by ID.
	// Returns ErrEventNotFound if not found.
	GetEventByID(ctx context.Context, eventID string) (*Event, error)

	// ListEvents retrieves paginated events with optional filtering.
	ListEvents(ctx context.Context, limit, offset int) ([]*Event, int64, error)

	// SearchEvents performs CQL-based event search.
	SearchEvents(ctx context.Context, query string, limit, offset int) ([]*Event, int64, error)
}

// EventWriter provides write operations for security events.
// Consumers: Ingest pipeline
type EventWriter interface {
	// StoreEvent stores a security event.
	// Returns the event with generated ID and timestamp.
	StoreEvent(ctx context.Context, event *Event) (*Event, error)

	// BatchStoreEvents stores multiple events efficiently.
	// Returns count of successfully stored events.
	BatchStoreEvents(ctx context.Context, events []*Event) (int, error)
}

// EventRetentionManager manages event lifecycle and cleanup.
// Consumers: Retention worker, admin API
type EventRetentionManager interface {
	// CleanupExpiredEvents deletes events older than retention period.
	// Returns count of deleted events.
	CleanupExpiredEvents(ctx context.Context, retentionDays int) (int64, error)
}

// EventService is the complete event service interface.
type EventService interface {
	EventReader
	EventWriter
	EventRetentionManager
}

// ============================================================================
// Supporting Types (referenced by service interfaces)
// ============================================================================

// PlaybookStats represents aggregated statistics for playbooks.
// Temporary definition - will be moved to soar package in Phase 2.
type PlaybookStats struct {
	TotalPlaybooks    int64 `json:"total_playbooks"`
	EnabledPlaybooks  int64 `json:"enabled_playbooks"`
	DisabledPlaybooks int64 `json:"disabled_playbooks"`
}

// PlaybookExecutionStatus represents the status of a playbook execution.
// Temporary definition - will be moved to soar package in Phase 2.
type PlaybookExecutionStatus struct {
	ExecutionID string                   `json:"execution_id"`
	PlaybookID  string                   `json:"playbook_id"`
	AlertID     string                   `json:"alert_id"`
	Status      string                   `json:"status"` // running, completed, failed
	StartedAt   time.Time                `json:"started_at"`
	CompletedAt *time.Time               `json:"completed_at,omitempty"`
	Error       string                   `json:"error,omitempty"`
	StepResults map[string]*ActionResult `json:"step_results,omitempty"`
}

// ActionResult represents the result of executing a playbook action.
// Temporary definition - will be moved to soar package in Phase 2.
type ActionResult struct {
	Success bool        `json:"success"`
	Message string      `json:"message"`
	Data    interface{} `json:"data,omitempty"`
}

// Playbook is a placeholder - actual type is in soar package.
// This placeholder allows service interface to compile independently.
type Playbook interface{}

// ============================================================================
// Implementation Notes for Service Package (Phase 2)
// ============================================================================
//
// SERVICE IMPLEMENTATION STRUCTURE:
//
// service/
//   ├── alert_service.go          - Implements AlertService
//   ├── alert_service_test.go     - Unit tests with mocked storage
//   ├── investigation_service.go  - Implements InvestigationService
//   ├── investigation_service_test.go
//   ├── rule_service.go           - Implements RuleService
//   ├── rule_service_test.go
//   ├── playbook_service.go       - Implements PlaybookService
//   ├── playbook_service_test.go
//   ├── event_service.go          - Implements EventService
//   ├── event_service_test.go
//   └── errors.go                 - Service-layer error types
//
// SERVICE IMPLEMENTATION PATTERNS:
//
// 1. Constructor Pattern:
//    func NewAlertService(
//        alertStorage storage.AlertStorage,
//        ruleStorage storage.RuleStorage,
//        logger *zap.SugaredLogger,
//    ) *AlertServiceImpl {
//        return &AlertServiceImpl{...}
//    }
//
// 2. Transaction Boundaries:
//    - Services orchestrate multiple storage calls
//    - Implement rollback on failure (see createRule example in handlers.go)
//    - Use context for cancellation propagation
//
// 3. Error Handling:
//    - Wrap storage errors with context: fmt.Errorf("failed to create alert: %w", err)
//    - Return sentinel errors from service layer when appropriate
//    - Log errors at service layer, don't expose internal details to API
//
// 4. Validation:
//    - Perform business validation in service layer
//    - Don't rely solely on storage-layer constraints
//    - Return structured validation errors
//
// 5. Audit Logging:
//    - Services log business operations with context
//    - Include user ID, resource ID, operation, outcome
//    - Use structured logging (logger.Infow/Errorw)
//
// HANDLER REFACTORING PATTERN (Phase 3):
//
// Before (direct storage access):
//   func (a *API) getAlerts(w http.ResponseWriter, r *http.Request) {
//       alerts, err := a.alertStorage.GetAlerts(r.Context(), limit, offset)
//       if err != nil { ... }
//       a.enrichAlertsWithRuleInfo(alerts)
//       ...
//   }
//
// After (service layer):
//   func (a *API) getAlerts(w http.ResponseWriter, r *http.Request) {
//       alerts, total, err := a.alertService.ListAlerts(r.Context(), filters)
//       if err != nil { ... }
//       // Enrichment happens inside service
//       ...
//   }
//
// BENEFITS:
// - Handlers become thin HTTP adapters (parse request, call service, format response)
// - Business logic consolidated in testable service layer
// - Easier to add new transport layers (gRPC, message queue consumers, etc.)
// - Clear separation of concerns: HTTP vs business logic
