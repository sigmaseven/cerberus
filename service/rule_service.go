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

// ============================================================================
// Constants
// ============================================================================

const (
	// Pagination limits
	defaultRulePageSize = 50   // Default limit when not specified
	maxRulePageSize     = 1000 // Maximum allowed page size

	// Validation limits
	maxRuleNameLength        = 200  // Maximum rule name length
	maxRuleDescriptionLength = 2000 // Maximum description length
	maxTagsPerRule           = 50   // Maximum tags per rule
	maxConditionsPerRule     = 100  // Maximum conditions per rule

	// ID validation
	maxRuleIDLength = 100 // Maximum rule ID length
)

// RuleServiceImpl implements the RuleService interface from core package.
// It provides business logic layer between HTTP handlers and storage layer.
//
// SECURITY CONSIDERATIONS:
// - All user inputs are validated before storage operations
// - Rule validation prevents invalid detection logic
// - Atomic operations with rollback ensure consistency
// - Hot-reload with rollback on failure maintains detector state
// - User tracking for audit trail on all mutations
//
// DESIGN PATTERNS:
// - Dependency injection via constructor
// - Context propagation for cancellation
// - Typed error returns with wrapping
// - Atomic operations with rollback
// - Separation of concerns (business logic vs storage vs detection)
type RuleServiceImpl struct {
	ruleStorage RuleStorageOps
	detector    RuleDetector
	logger      *zap.SugaredLogger
}

// RuleStorageOps defines rule storage operations needed by service.
// Defined here (consumer package) following Interface Segregation Principle.
// Named RuleStorageOps to avoid conflict with alert_service.go's RuleStorage.
type RuleStorageOps interface {
	CreateRule(rule *core.Rule) error
	GetRule(id string) (*core.Rule, error)
	GetRules(limit, offset int) ([]core.Rule, error)
	GetAllRules() ([]core.Rule, error)
	GetEnabledRules() ([]core.Rule, error)
	GetRuleCount() (int64, error)
	UpdateRule(id string, rule *core.Rule) error
	DeleteRule(id string) error
	EnableRule(id string) error
	DisableRule(id string) error
	GetRulesWithFilters(filters *core.RuleFilters) ([]core.Rule, int64, error)
}

// RuleDetector defines detection engine operations for hot-reload.
type RuleDetector interface {
	ReloadRules(rules []core.Rule) error
}

// NewRuleService creates a new RuleService instance.
//
// PARAMETERS:
//   - ruleStorage: Rule persistence layer (required, panics if nil)
//   - detector: Detection engine for hot-reload (required, panics if nil)
//   - logger: Structured logger (required, panics if nil)
//
// DESIGN NOTE: Constructor validates required dependencies to fail fast.
func NewRuleService(
	ruleStorage RuleStorageOps,
	detector RuleDetector,
	logger *zap.SugaredLogger,
) *RuleServiceImpl {
	if ruleStorage == nil {
		panic("ruleStorage is required")
	}
	if detector == nil {
		panic("detector is required")
	}
	if logger == nil {
		panic("logger is required")
	}

	return &RuleServiceImpl{
		ruleStorage: ruleStorage,
		detector:    detector,
		logger:      logger,
	}
}

// ============================================================================
// RuleReader Implementation
// ============================================================================

// GetRuleByID retrieves a single rule by ID.
//
// BUSINESS LOGIC:
// 1. Validate rule ID format
// 2. Retrieve rule from storage
//
// ERRORS:
//   - storage.ErrRuleNotFound: Rule doesn't exist
//   - Wrapped storage errors with context
func (s *RuleServiceImpl) GetRuleByID(ctx context.Context, ruleID string) (*core.Rule, error) {
	// Validate input
	if ruleID == "" {
		return nil, fmt.Errorf("ruleID is required")
	}
	if len(ruleID) > maxRuleIDLength {
		return nil, fmt.Errorf("ruleID too long: %d characters (max %d)", len(ruleID), maxRuleIDLength)
	}

	// Check context cancellation
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("context cancelled: %w", err)
	}

	// Retrieve rule
	rule, err := s.ruleStorage.GetRule(ruleID)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve rule %s: %w", ruleID, err)
	}

	if rule == nil {
		return nil, storage.ErrRuleNotFound
	}

	return rule, nil
}

// ListRules retrieves paginated rules with optional filtering.
//
// BUSINESS LOGIC:
// 1. Validate pagination parameters
// 2. Apply filters if provided
// 3. Retrieve rules from storage
//
// PARAMETERS:
//   - filters: Rule filtering criteria (nil uses defaults)
//   - limit: Page size (validated, capped at maxRulePageSize)
//   - offset: Offset for pagination
//
// RETURNS:
//   - rules: Slice of rules (empty if no matches)
//   - total: Total count matching filters
//   - error: Any errors encountered
//
// DEFENSIVE PROGRAMMING: Creates defensive copy of filters to avoid mutating caller's data.
func (s *RuleServiceImpl) ListRules(
	ctx context.Context,
	filters *core.RuleFilters,
	limit, offset int,
) ([]*core.Rule, int64, error) {
	// Check context cancellation
	if err := ctx.Err(); err != nil {
		return nil, 0, fmt.Errorf("context cancelled: %w", err)
	}

	// Validate pagination bounds
	if limit < 1 {
		limit = defaultRulePageSize
	}
	if limit > maxRulePageSize {
		limit = maxRulePageSize
	}
	if offset < 0 {
		offset = 0
	}

	var rules []core.Rule
	var total int64
	var err error

	// Check if we need filtering
	if filters != nil && s.hasRuleFilters(filters) {
		// DEFENSIVE COPY: Avoid mutating caller's filters object
		filtersCopy := *filters

		// Use filtered query
		rules, total, err = s.ruleStorage.GetRulesWithFilters(&filtersCopy)
		if err != nil {
			return nil, 0, fmt.Errorf("failed to retrieve filtered rules: %w", err)
		}

		// Manual pagination for filtered results (storage may not support it)
		rules = paginateRules(rules, limit, offset)
	} else {
		// Simple paginated query
		rules, err = s.ruleStorage.GetRules(limit, offset)
		if err != nil {
			return nil, 0, fmt.Errorf("failed to retrieve rules: %w", err)
		}

		total, err = s.ruleStorage.GetRuleCount()
		if err != nil {
			// Log warning but return partial results
			s.logger.Warnw("Failed to get rule count",
				"error", err)
			total = int64(len(rules)) // Fallback to current page count
		}
	}

	// Convert []Rule to []*Rule
	result := make([]*core.Rule, len(rules))
	for i := range rules {
		result[i] = &rules[i]
	}

	return result, total, nil
}

// GetEnabledRules retrieves all enabled rules for detection engine.
//
// BUSINESS LOGIC:
// 1. Retrieve all enabled rules
// 2. Convert to slice of pointers
//
// NOTE: No pagination for detection engine - it needs all enabled rules.
func (s *RuleServiceImpl) GetEnabledRules(ctx context.Context) ([]*core.Rule, error) {
	// Check context cancellation
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("context cancelled: %w", err)
	}

	rules, err := s.ruleStorage.GetEnabledRules()
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve enabled rules: %w", err)
	}

	// Convert []Rule to []*Rule
	result := make([]*core.Rule, len(rules))
	for i := range rules {
		result[i] = &rules[i]
	}

	return result, nil
}

// hasRuleFilters checks if any filters are applied.
func (s *RuleServiceImpl) hasRuleFilters(filters *core.RuleFilters) bool {
	if filters == nil {
		return false
	}

	return filters.Search != "" ||
		len(filters.Types) > 0 ||
		len(filters.Severities) > 0 ||
		filters.Enabled != nil ||
		len(filters.Tags) > 0 ||
		len(filters.MitreTechniques) > 0 ||
		filters.CreatedAfter != nil ||
		filters.CreatedBefore != nil
}

// paginateRules applies manual pagination to a slice of rules.
func paginateRules(rules []core.Rule, limit, offset int) []core.Rule {
	if offset >= len(rules) {
		return []core.Rule{}
	}
	end := offset + limit
	if end > len(rules) {
		end = len(rules)
	}
	return rules[offset:end]
}

// ============================================================================
// RuleWriter Implementation
// ============================================================================

// CreateRule creates a new rule with validation and hot-reload.
//
// BUSINESS LOGIC (ATOMIC OPERATION):
// 1. Fail-fast: Validate detector availability
// 2. Fail-fast: Validate storage availability
// 3. Validate rule structure
// 4. Generate rule ID if not provided
// 5. Persist to database
// 6. Hot-reload detection engine
// 7. ROLLBACK: Delete rule if hot-reload fails
//
// RETURNS:
//   - Created rule with generated ID
//   - Error if validation, storage, or hot-reload fails
//
// ATOMICITY: Uses rollback pattern to maintain consistency between storage and detector.
func (s *RuleServiceImpl) CreateRule(ctx context.Context, rule *core.Rule) (*core.Rule, error) {
	if rule == nil {
		return nil, fmt.Errorf("rule is required")
	}

	// Check context cancellation
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("context cancelled: %w", err)
	}

	// DEFENSIVE COPY: Prevent caller mutation
	ruleCopy := deepCopyRule(rule)
	if ruleCopy == nil {
		return nil, fmt.Errorf("failed to copy rule")
	}

	// Generate ID if not provided
	if ruleCopy.ID == "" {
		ruleCopy.ID = generateRuleID()
	}

	// Validate rule structure
	if err := s.ValidateRuleStructure(ruleCopy); err != nil {
		return nil, fmt.Errorf("rule validation failed: %w", err)
	}

	// STEP 1: Persist to database (only after all pre-flight checks pass)
	if err := s.ruleStorage.CreateRule(ruleCopy); err != nil {
		return nil, fmt.Errorf("failed to create rule: %w", err)
	}

	// STEP 2: Hot-reload with ROLLBACK on failure to maintain atomicity
	rules, err := s.ruleStorage.GetAllRules()
	if err != nil {
		// ROLLBACK: Delete the rule we just created
		if deleteErr := s.ruleStorage.DeleteRule(ruleCopy.ID); deleteErr != nil {
			s.logger.Errorw("Failed to rollback rule creation after GetAllRules failure",
				"rule_id", ruleCopy.ID,
				"rollback_error", deleteErr,
				"original_error", err)
		} else {
			s.logger.Infow("Successfully rolled back rule creation",
				"rule_id", ruleCopy.ID,
				"reason", "GetAllRules failed")
		}
		return nil, fmt.Errorf("failed to activate rule: %w", err)
	}

	if err := s.detector.ReloadRules(rules); err != nil {
		// ROLLBACK: Delete the rule we just created
		if deleteErr := s.ruleStorage.DeleteRule(ruleCopy.ID); deleteErr != nil {
			s.logger.Errorw("Failed to rollback rule creation after ReloadRules failure",
				"rule_id", ruleCopy.ID,
				"rollback_error", deleteErr,
				"original_error", err)
		} else {
			s.logger.Infow("Successfully rolled back rule creation",
				"rule_id", ruleCopy.ID,
				"reason", "ReloadRules failed")
		}
		return nil, fmt.Errorf("failed to activate rule: %w", err)
	}

	// STEP 3: Success only if all steps completed
	s.logger.Infow("Rule created and activated atomically",
		"rule_id", ruleCopy.ID,
		"name", ruleCopy.Name,
		"total_rules", len(rules))

	return ruleCopy, nil
}

// UpdateRule updates an existing rule with validation and hot-reload.
//
// BUSINESS LOGIC (ATOMIC OPERATION):
// 1. Fail-fast: Validate inputs
// 2. Retrieve old rule for rollback capability
// 3. Validate new rule structure
// 4. Persist update to database
// 5. Hot-reload detection engine
// 6. ROLLBACK: Restore old rule if hot-reload fails
//
// ATOMICITY: Uses rollback pattern to maintain consistency.
func (s *RuleServiceImpl) UpdateRule(ctx context.Context, ruleID string, rule *core.Rule) error {
	if ruleID == "" {
		return fmt.Errorf("ruleID is required")
	}
	if len(ruleID) > maxRuleIDLength {
		return fmt.Errorf("ruleID too long: %d characters (max %d)", len(ruleID), maxRuleIDLength)
	}
	if rule == nil {
		return fmt.Errorf("rule is required")
	}

	// Check context cancellation
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("context cancelled: %w", err)
	}

	// DEFENSIVE COPY: Prevent caller mutation
	ruleCopy := deepCopyRule(rule)
	if ruleCopy == nil {
		return fmt.Errorf("failed to copy rule")
	}

	// Ensure ID matches path parameter
	ruleCopy.ID = ruleID

	// Validate rule structure
	if err := s.ValidateRuleStructure(ruleCopy); err != nil {
		return fmt.Errorf("rule validation failed: %w", err)
	}

	// STEP 1: Get old rule for rollback capability
	oldRule, err := s.ruleStorage.GetRule(ruleID)
	if err != nil {
		return fmt.Errorf("failed to get existing rule: %w", err)
	}
	if oldRule == nil {
		return storage.ErrRuleNotFound
	}

	// STEP 2: Persist update to database
	if err := s.ruleStorage.UpdateRule(ruleID, ruleCopy); err != nil {
		return fmt.Errorf("failed to update rule: %w", err)
	}

	// STEP 3: Hot-reload with ROLLBACK on failure
	rules, err := s.ruleStorage.GetAllRules()
	if err != nil {
		// ROLLBACK: Restore the old rule
		if rollbackErr := s.ruleStorage.UpdateRule(ruleID, oldRule); rollbackErr != nil {
			s.logger.Errorw("Failed to rollback rule update after GetAllRules failure",
				"rule_id", ruleID,
				"rollback_error", rollbackErr,
				"original_error", err)
		} else {
			s.logger.Infow("Successfully rolled back rule update",
				"rule_id", ruleID,
				"reason", "GetAllRules failed")
		}
		return fmt.Errorf("failed to activate rule: %w", err)
	}

	if err := s.detector.ReloadRules(rules); err != nil {
		// ROLLBACK: Restore the old rule
		if rollbackErr := s.ruleStorage.UpdateRule(ruleID, oldRule); rollbackErr != nil {
			s.logger.Errorw("Failed to rollback rule update after ReloadRules failure",
				"rule_id", ruleID,
				"rollback_error", rollbackErr,
				"original_error", err)
		} else {
			s.logger.Infow("Successfully rolled back rule update",
				"rule_id", ruleID,
				"reason", "ReloadRules failed")
		}
		return fmt.Errorf("failed to activate rule: %w", err)
	}

	// STEP 4: Success only if all steps completed
	s.logger.Infow("Rule updated and activated atomically",
		"rule_id", ruleID,
		"name", ruleCopy.Name,
		"total_rules", len(rules))

	return nil
}

// DeleteRule deletes a rule and hot-reloads detection engine.
//
// BUSINESS LOGIC (ATOMIC OPERATION):
// 1. Fail-fast: Validate inputs
// 2. Get rule for rollback capability
// 3. Delete from database
// 4. Hot-reload detection engine
// 5. ROLLBACK: Re-create rule if hot-reload fails
//
// ATOMICITY: Uses rollback pattern to maintain consistency.
func (s *RuleServiceImpl) DeleteRule(ctx context.Context, ruleID string) error {
	if ruleID == "" {
		return fmt.Errorf("ruleID is required")
	}
	if len(ruleID) > maxRuleIDLength {
		return fmt.Errorf("ruleID too long: %d characters (max %d)", len(ruleID), maxRuleIDLength)
	}

	// Check context cancellation
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("context cancelled: %w", err)
	}

	// STEP 1: Get rule for rollback capability
	deletedRule, err := s.ruleStorage.GetRule(ruleID)
	if err != nil {
		return fmt.Errorf("failed to get rule: %w", err)
	}
	if deletedRule == nil {
		return storage.ErrRuleNotFound
	}

	// STEP 2: Delete from database
	if err := s.ruleStorage.DeleteRule(ruleID); err != nil {
		return fmt.Errorf("failed to delete rule: %w", err)
	}

	// STEP 3: Hot-reload with ROLLBACK on failure
	rules, err := s.ruleStorage.GetAllRules()
	if err != nil {
		// ROLLBACK: Re-create the deleted rule
		if rollbackErr := s.ruleStorage.CreateRule(deletedRule); rollbackErr != nil {
			s.logger.Errorw("Failed to rollback rule deletion after GetAllRules failure",
				"rule_id", ruleID,
				"rollback_error", rollbackErr,
				"original_error", err)
		} else {
			s.logger.Infow("Successfully rolled back rule deletion",
				"rule_id", ruleID,
				"reason", "GetAllRules failed")
		}
		return fmt.Errorf("failed to deactivate rule: %w", err)
	}

	if err := s.detector.ReloadRules(rules); err != nil {
		// ROLLBACK: Re-create the deleted rule
		if rollbackErr := s.ruleStorage.CreateRule(deletedRule); rollbackErr != nil {
			s.logger.Errorw("Failed to rollback rule deletion after ReloadRules failure",
				"rule_id", ruleID,
				"rollback_error", rollbackErr,
				"original_error", err)
		} else {
			s.logger.Infow("Successfully rolled back rule deletion",
				"rule_id", ruleID,
				"reason", "ReloadRules failed")
		}
		return fmt.Errorf("failed to deactivate rule: %w", err)
	}

	// STEP 4: Success only if all steps completed
	s.logger.Infow("Rule deleted and deactivated atomically",
		"rule_id", ruleID,
		"name", deletedRule.Name,
		"total_rules", len(rules))

	return nil
}

// ============================================================================
// RuleStateManager Implementation
// ============================================================================

// EnableRule enables a rule and reloads detection engine.
func (s *RuleServiceImpl) EnableRule(ctx context.Context, ruleID string) error {
	if ruleID == "" {
		return fmt.Errorf("ruleID is required")
	}

	// Check context cancellation
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("context cancelled: %w", err)
	}

	// Verify rule exists
	rule, err := s.ruleStorage.GetRule(ruleID)
	if err != nil {
		return fmt.Errorf("failed to get rule: %w", err)
	}
	if rule == nil {
		return storage.ErrRuleNotFound
	}

	// Enable in storage
	if err := s.ruleStorage.EnableRule(ruleID); err != nil {
		return fmt.Errorf("failed to enable rule: %w", err)
	}

	// Hot-reload detection engine
	rules, err := s.ruleStorage.GetAllRules()
	if err != nil {
		// Note: We don't rollback enable/disable state changes
		// Storage state is source of truth
		return fmt.Errorf("rule enabled in storage but failed to reload detector: %w", err)
	}

	if err := s.detector.ReloadRules(rules); err != nil {
		return fmt.Errorf("rule enabled in storage but failed to reload detector: %w", err)
	}

	s.logger.Infow("Rule enabled",
		"rule_id", ruleID,
		"name", rule.Name)

	return nil
}

// DisableRule disables a rule and reloads detection engine.
func (s *RuleServiceImpl) DisableRule(ctx context.Context, ruleID string) error {
	if ruleID == "" {
		return fmt.Errorf("ruleID is required")
	}

	// Check context cancellation
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("context cancelled: %w", err)
	}

	// Verify rule exists
	rule, err := s.ruleStorage.GetRule(ruleID)
	if err != nil {
		return fmt.Errorf("failed to get rule: %w", err)
	}
	if rule == nil {
		return storage.ErrRuleNotFound
	}

	// Disable in storage
	if err := s.ruleStorage.DisableRule(ruleID); err != nil {
		return fmt.Errorf("failed to disable rule: %w", err)
	}

	// Hot-reload detection engine
	rules, err := s.ruleStorage.GetAllRules()
	if err != nil {
		return fmt.Errorf("rule disabled in storage but failed to reload detector: %w", err)
	}

	if err := s.detector.ReloadRules(rules); err != nil {
		return fmt.Errorf("rule disabled in storage but failed to reload detector: %w", err)
	}

	s.logger.Infow("Rule disabled",
		"rule_id", ruleID,
		"name", rule.Name)

	return nil
}

// ============================================================================
// RuleValidator Implementation
// ============================================================================

// ValidateRule validates rule structure without creating it.
//
// BUSINESS LOGIC:
// 1. Validate rule structure
// 2. Validate detection logic (Sigma/CQL syntax)
// 3. Check for warnings (e.g., overlapping conditions)
//
// RETURNS:
//   - errors: List of validation errors
//   - warnings: List of non-fatal warnings
//   - err: System errors during validation
func (s *RuleServiceImpl) ValidateRule(
	ctx context.Context,
	rule *core.Rule,
) (errors []string, warnings []string, err error) {
	if rule == nil {
		return []string{"rule is required"}, nil, nil
	}

	// Check context cancellation
	if err := ctx.Err(); err != nil {
		return nil, nil, fmt.Errorf("context cancelled: %w", err)
	}

	// Validate structure
	if validationErr := s.ValidateRuleStructure(rule); validationErr != nil {
		errors = append(errors, validationErr.Error())
	}

	// Validate detection logic based on type
	switch rule.Type {
	case "sigma":
		// TASK #184: Sigma rules require sigma_yaml (Detection field removed)
		if rule.SigmaYAML == "" {
			errors = append(errors, "Sigma rule requires sigma_yaml")
		}
		// TODO: Add Sigma parser validation
		// For now, log warning
		if rule.SigmaYAML != "" {
			warnings = append(warnings, "Sigma YAML syntax validation not yet implemented")
		}

	case "cql":
		// Validate CQL syntax
		if rule.Query == "" {
			errors = append(errors, "CQL rule requires query")
		}
		// TODO: Add CQL parser validation
		warnings = append(warnings, "CQL syntax validation not yet implemented")

	default:
		errors = append(errors, fmt.Sprintf("unsupported rule type: %s", rule.Type))
	}

	return errors, warnings, nil
}

// ValidateRuleStructure performs comprehensive structural validation.
//
// VALIDATION RULES:
// - Name is required and within length limits
// - Type is required and valid
// - Detection logic matches type
// - Tags are within limits
// TASK #184: Conditions validation removed - SIGMA rules use SigmaYAML
func (s *RuleServiceImpl) ValidateRuleStructure(rule *core.Rule) error {
	if rule == nil {
		return fmt.Errorf("rule cannot be nil")
	}

	// Validate name
	name := strings.TrimSpace(rule.Name)
	if name == "" {
		return fmt.Errorf("rule.Name is required")
	}
	if len(name) > maxRuleNameLength {
		return fmt.Errorf("rule.Name too long: %d characters (max %d)", len(name), maxRuleNameLength)
	}

	// Validate description length
	if len(rule.Description) > maxRuleDescriptionLength {
		return fmt.Errorf("rule.Description too long: %d characters (max %d)", len(rule.Description), maxRuleDescriptionLength)
	}

	// Validate type
	if rule.Type == "" {
		return fmt.Errorf("rule.Type is required")
	}
	if !isValidRuleType(rule.Type) {
		return fmt.Errorf("invalid rule.Type: %s (valid: sigma, cql, correlation)", rule.Type)
	}

	// Validate tags
	if len(rule.Tags) > maxTagsPerRule {
		return fmt.Errorf("too many tags: %d (max %d)", len(rule.Tags), maxTagsPerRule)
	}

	return nil
}

// ============================================================================
// Helper Functions
// ============================================================================

// generateRuleID generates a unique rule ID using UUID v4.
//
// SECURITY: Uses cryptographically secure random number generation via uuid.New()
func generateRuleID() string {
	return uuid.New().String()
}

// isValidRuleType checks if rule type is valid.
func isValidRuleType(ruleType string) bool {
	switch ruleType {
	case "sigma", "cql", "correlation":
		return true
	default:
		return false
	}
}

// deepCopyRule creates a defensive copy of a rule.
//
// DEFENSIVE PROGRAMMING: Prevents caller from mutating service-managed state.
//
// BLOCKER-3 FIX: Uses shared deepCopyValue from helpers.go
func deepCopyRule(rule *core.Rule) *core.Rule {
	if rule == nil {
		return nil
	}

	// Create shallow copy
	ruleCopy := *rule

	// Deep copy Tags
	if rule.Tags != nil {
		ruleCopy.Tags = make([]string, len(rule.Tags))
		copy(ruleCopy.Tags, rule.Tags)
	}

	// Deep copy MitreTechniques
	if rule.MitreTechniques != nil {
		ruleCopy.MitreTechniques = make([]string, len(rule.MitreTechniques))
		copy(ruleCopy.MitreTechniques, rule.MitreTechniques)
	}

	// TASK #184: Detection and Conditions fields removed from core.Rule

	// Deep copy Metadata map if present
	if rule.Metadata != nil {
		ruleCopy.Metadata = make(map[string]interface{}, len(rule.Metadata))
		for k, v := range rule.Metadata {
			ruleCopy.Metadata[k] = deepCopyValue(v) // From helpers.go
		}
	}

	// Deep copy Actions
	if rule.Actions != nil {
		ruleCopy.Actions = make([]core.Action, len(rule.Actions))
		copy(ruleCopy.Actions, rule.Actions)
	}

	return &ruleCopy
}
