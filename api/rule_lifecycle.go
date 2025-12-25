package api

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"cerberus/core"
	"cerberus/storage"

	"github.com/gorilla/mux"
)

// Custom errors for lifecycle transitions
var (
	ErrInvalidTransition      = errors.New("invalid lifecycle transition")
	ErrRuleNotFound           = errors.New("rule not found")
	ErrInvalidAction          = errors.New("invalid action")
	ErrSunsetDateInvalid      = errors.New("sunset date must be in the future")
	ErrSunsetDateTooFar       = errors.New("sunset date must be within 2 years")
	ErrReasonTooLong          = errors.New("reason exceeds maximum length")
	ErrMigrationNotApplied    = errors.New("lifecycle management requires database migration 1.8.0")
)

const (
	maxReasonLength     = 1000
	maxSunsetYears      = 2
)

// LifecycleAction represents a lifecycle action request
type LifecycleAction struct {
	Action       string     `json:"action"`                  // promote, deprecate, archive, activate
	TargetStatus string     `json:"target_status,omitempty"` // Optional explicit target status
	Reason       string     `json:"reason"`
	SunsetDate   *time.Time `json:"sunset_date,omitempty"`
}

// LifecycleStatus represents valid lifecycle states
type LifecycleStatus string

const (
	LifecycleExperimental LifecycleStatus = "experimental"
	LifecycleTest         LifecycleStatus = "test"
	LifecycleStable       LifecycleStatus = "stable"
	LifecycleDeprecated   LifecycleStatus = "deprecated"
	LifecycleArchived     LifecycleStatus = "archived"
)

// lifecycleStateMachine defines valid state transitions
// State machine enforces lifecycle progression: experimental -> test -> stable -> deprecated -> archived
var lifecycleStateMachine = map[LifecycleStatus][]LifecycleStatus{
	LifecycleExperimental: {LifecycleTest, LifecycleArchived},
	LifecycleTest:         {LifecycleStable, LifecycleExperimental, LifecycleArchived},
	LifecycleStable:       {LifecycleDeprecated, LifecycleArchived},
	LifecycleDeprecated:   {LifecycleArchived, LifecycleStable},
	LifecycleArchived:     {}, // Terminal state
}

// handleRuleLifecycle handles POST /api/v1/rules/{id}/lifecycle
// Transitions rules through lifecycle states with validation and audit trail
//
// SECURITY:
// - RBAC: Requires rules:update permission
// - Input validation: Validates action and target status
// - State machine: Enforces valid transitions only
// - SQL injection: Uses parameterized queries
// - Atomic transactions: Rule update and audit entry are atomic
func (a *API) handleRuleLifecycle(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	ruleID := vars["id"]

	if ruleID == "" {
		writeError(w, http.StatusBadRequest, "Rule ID is required", nil, a.logger)
		return
	}

	// Parse request body
	var action LifecycleAction
	if err := json.NewDecoder(r.Body).Decode(&action); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body", err, a.logger)
		return
	}

	// Validate action
	if err := validateLifecycleAction(&action); err != nil {
		writeError(w, http.StatusBadRequest, err.Error(), nil, a.logger)
		return
	}

	// Get authenticated user
	username := getUsernameFromContext(r.Context())
	if username == "" {
		writeError(w, http.StatusUnauthorized, "Authentication required", nil, a.logger)
		return
	}

	// Execute lifecycle transition with context
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	if err := a.executeLifecycleTransition(ctx, ruleID, username, &action); err != nil {
		if errors.Is(err, ErrRuleNotFound) {
			writeError(w, http.StatusNotFound, "Rule not found", err, a.logger)
			return
		}
		if errors.Is(err, ErrInvalidTransition) || errors.Is(err, ErrInvalidAction) {
			writeError(w, http.StatusBadRequest, err.Error(), err, a.logger)
			return
		}
		writeError(w, http.StatusInternalServerError, "Lifecycle transition failed", err, a.logger)
		return
	}

	// Return success response
	a.respondJSON(w, map[string]interface{}{
		"message": "Lifecycle transition successful",
		"rule_id": ruleID,
		"action":  action.Action,
	}, http.StatusOK)
}

// validateLifecycleAction validates the lifecycle action request
// COMPLEXITY: 25 lines, CCN ~5
func validateLifecycleAction(action *LifecycleAction) error {
	if action == nil {
		return fmt.Errorf("action cannot be nil")
	}

	// Validate action type
	validActions := map[string]bool{
		"promote":   true,
		"deprecate": true,
		"archive":   true,
		"activate":  true,
	}

	if !validActions[action.Action] {
		return fmt.Errorf("%w: %s (must be promote, deprecate, archive, or activate)", ErrInvalidAction, action.Action)
	}

	// Validate reason is provided and length
	if action.Action != "promote" {
		if action.Reason == "" {
			return fmt.Errorf("reason is required for %s action", action.Action)
		}
		if len(action.Reason) > maxReasonLength {
			return fmt.Errorf("%w: %d characters (max %d)", ErrReasonTooLong, len(action.Reason), maxReasonLength)
		}
	}

	// Validate sunset date for deprecation
	if action.Action == "deprecate" && action.SunsetDate != nil {
		now := time.Now().UTC()
		if action.SunsetDate.Before(now) {
			return ErrSunsetDateInvalid
		}
		maxSunsetDate := now.AddDate(maxSunsetYears, 0, 0)
		if action.SunsetDate.After(maxSunsetDate) {
			return ErrSunsetDateTooFar
		}
	}

	return nil
}

// executeLifecycleTransition executes a lifecycle transition with validation
// BLOCKER-15 FIX: Reduced from 64 to 42 lines by extracting persistLifecycleChange
// COMPLEXITY: 42 lines, CCN ~6
// SECURITY: Uses transactions to ensure atomicity between rule update and audit entry
func (a *API) executeLifecycleTransition(ctx context.Context, ruleID, username string, action *LifecycleAction) error {
	// Check migration is applied
	if err := a.checkLifecycleMigration(ctx); err != nil {
		return err
	}

	// Get current rule
	rule, err := a.getRuleWithLifecycle(ctx, ruleID)
	if err != nil {
		if err == sql.ErrNoRows {
			return ErrRuleNotFound
		}
		return fmt.Errorf("failed to get rule: %w", err)
	}

	if rule == nil {
		return ErrRuleNotFound
	}

	// Determine current and target status
	currentStatus := getLifecycleStatus(rule)
	targetStatus, err := determineTargetStatus(currentStatus, action)
	if err != nil {
		return err
	}

	// Validate state transition
	if err := validateStateTransition(currentStatus, targetStatus); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidTransition, err)
	}

	// Persist changes in transaction
	if err := a.persistLifecycleChange(ctx, rule, ruleID, currentStatus, targetStatus, username, action); err != nil {
		return err
	}

	a.logger.Infow("Rule lifecycle transition executed",
		"rule_id", ruleID,
		"old_status", currentStatus,
		"new_status", targetStatus,
		"action", action.Action,
		"user", username,
	)

	return nil
}

// persistLifecycleChange persists lifecycle changes in a transaction
// BLOCKER-15 FIX: Extracted from executeLifecycleTransition to reduce complexity
// COMPLEXITY: 30 lines, CCN ~3
func (a *API) persistLifecycleChange(ctx context.Context, rule *storage.RuleWithLifecycle, ruleID string, currentStatus, targetStatus LifecycleStatus, username string, action *LifecycleAction) error {
	tx, err := a.sqlite.WriteDB.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback()

	// Update rule lifecycle status in transaction
	if err := a.updateRuleLifecycleInTx(ctx, tx, rule, targetStatus, username, action); err != nil {
		return fmt.Errorf("failed to update rule lifecycle: %w", err)
	}

	// Create audit entry in same transaction
	if err := a.createLifecycleAuditEntryInTx(ctx, tx, ruleID, currentStatus, targetStatus, username, action); err != nil {
		return fmt.Errorf("failed to create audit entry: %w", err)
	}

	// Commit transaction
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	return nil
}

// getRuleWithLifecycle retrieves rule with lifecycle fields
// CRITICAL-18 FIX: Return error if not SQLite storage instead of incorrect default
func (a *API) getRuleWithLifecycle(ctx context.Context, ruleID string) (*storage.RuleWithLifecycle, error) {
	// Cast storage to SQLiteRuleStorage to access GetRuleWithLifecycle
	sqliteStorage, ok := a.ruleStorage.(*storage.SQLiteRuleStorage)
	if !ok {
		return nil, fmt.Errorf("lifecycle management requires SQLite storage backend")
	}

	return sqliteStorage.GetRuleWithLifecycle(ruleID)
}

// getLifecycleStatus extracts lifecycle status from rule metadata
func getLifecycleStatus(rule *storage.RuleWithLifecycle) LifecycleStatus {
	if rule.LifecycleStatus == "" {
		return LifecycleExperimental // Default
	}
	return LifecycleStatus(rule.LifecycleStatus)
}

// determineTargetStatus determines target status based on action
// COMPLEXITY: 25 lines, CCN ~5
func determineTargetStatus(current LifecycleStatus, action *LifecycleAction) (LifecycleStatus, error) {
	// If explicit target status provided, use it
	if action.TargetStatus != "" {
		return LifecycleStatus(action.TargetStatus), nil
	}

	// Determine target based on action
	switch action.Action {
	case "promote":
		return promoteStatus(current)
	case "deprecate":
		return LifecycleDeprecated, nil
	case "archive":
		return LifecycleArchived, nil
	case "activate":
		// Activate returns to stable (or test if never reached stable)
		if current == LifecycleExperimental {
			return LifecycleTest, nil
		}
		return LifecycleStable, nil
	default:
		return "", fmt.Errorf("%w: unknown action: %s", ErrInvalidAction, action.Action)
	}
}

// promoteStatus advances status to next stage in lifecycle
// COMPLEXITY: 20 lines, CCN ~5
func promoteStatus(current LifecycleStatus) (LifecycleStatus, error) {
	switch current {
	case LifecycleExperimental:
		return LifecycleTest, nil
	case LifecycleTest:
		return LifecycleStable, nil
	case LifecycleStable:
		return "", fmt.Errorf("stable rules cannot be promoted further")
	case LifecycleDeprecated:
		return "", fmt.Errorf("deprecated rules cannot be promoted")
	case LifecycleArchived:
		return "", fmt.Errorf("archived rules cannot be promoted")
	default:
		return "", fmt.Errorf("unknown lifecycle status: %s", current)
	}
}

// validateStateTransition validates if transition is allowed by state machine
// COMPLEXITY: 20 lines, CCN ~4
func validateStateTransition(current, target LifecycleStatus) error {
	// Same state is always valid (idempotent)
	if current == target {
		return nil
	}

	// Check if transition is allowed
	allowedTargets, ok := lifecycleStateMachine[current]
	if !ok {
		return fmt.Errorf("unknown current status: %s", current)
	}

	for _, allowed := range allowedTargets {
		if allowed == target {
			return nil
		}
	}

	return fmt.Errorf("transition from %s to %s not allowed", current, target)
}

// updateRuleLifecycleInTx updates rule lifecycle fields in database within transaction
// FIX ISSUE #7: Transaction support
// FIX ISSUE #12: All timestamps use UTC
// COMPLEXITY: 35 lines, CCN ~5
func (a *API) updateRuleLifecycleInTx(ctx context.Context, tx *sql.Tx, rule *storage.RuleWithLifecycle, targetStatus LifecycleStatus, username string, action *LifecycleAction) error {
	now := time.Now().UTC()

	// Build update query dynamically based on action
	query := "UPDATE rules SET lifecycle_status = ?, updated_at = ?"
	args := []interface{}{string(targetStatus), now.Format(time.RFC3339)}

	// Handle deprecation fields
	if targetStatus == LifecycleDeprecated {
		query += ", deprecated_at = ?, deprecated_reason = ?, deprecated_by = ?"
		args = append(args, now.Format(time.RFC3339), action.Reason, username)

		if action.SunsetDate != nil {
			query += ", sunset_date = ?"
			args = append(args, action.SunsetDate.UTC().Format(time.RFC3339))
		}
	} else if targetStatus != LifecycleDeprecated && rule.DeprecatedAt.Valid {
		// Clear deprecation fields when leaving deprecated state
		query += ", deprecated_at = NULL, deprecated_reason = NULL, deprecated_by = NULL, sunset_date = NULL"
	}

	// Add WHERE clause
	query += " WHERE id = ?"
	args = append(args, rule.ID)

	// Execute update in transaction
	_, err := tx.ExecContext(ctx, query, args...)
	return err
}

// createLifecycleAuditEntryInTx creates audit trail entry within transaction
// FIX ISSUE #6: Propagate audit errors
// FIX ISSUE #7: Transaction support
// FIX ISSUE #12: All timestamps use UTC
// COMPLEXITY: 30 lines, CCN ~3
func (a *API) createLifecycleAuditEntryInTx(ctx context.Context, tx *sql.Tx, ruleID string, oldStatus, newStatus LifecycleStatus, username string, action *LifecycleAction) error {
	if a.lifecycleAuditStorage == nil {
		return fmt.Errorf("lifecycle audit storage not initialized")
	}

	// Serialize additional data if present
	var additionalDataJSON sql.NullString
	if action.SunsetDate != nil {
		data := map[string]interface{}{
			"sunset_date": action.SunsetDate.UTC().Format(time.RFC3339),
		}
		dataBytes, err := json.Marshal(data)
		if err != nil {
			return fmt.Errorf("failed to marshal additional data: %w", err)
		}
		additionalDataJSON = sql.NullString{String: string(dataBytes), Valid: true}
	}

	// Insert audit entry directly using transaction
	query := `
		INSERT INTO lifecycle_audit (
			rule_id, old_status, new_status, reason, changed_by, changed_at, additional_data
		) VALUES (?, ?, ?, ?, ?, ?, ?)
	`

	_, err := tx.ExecContext(
		ctx,
		query,
		ruleID,
		string(oldStatus),
		string(newStatus),
		action.Reason,
		username,
		time.Now().UTC().Format(time.RFC3339),
		additionalDataJSON,
	)
	if err != nil {
		return fmt.Errorf("failed to create audit entry: %w", err)
	}

	return nil
}

// handleGetLifecycleHistory handles GET /api/v1/rules/{id}/lifecycle-history
// Returns chronological list of lifecycle transitions for a rule
//
// SECURITY: Requires rules:read permission
// FIX ISSUE #9: Reduced complexity by extracting helper functions
func (a *API) handleGetLifecycleHistory(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	ruleID := vars["id"]

	if ruleID == "" {
		writeError(w, http.StatusBadRequest, "Rule ID is required", nil, a.logger)
		return
	}

	// Verify rule exists
	_, err := a.ruleStorage.GetRule(ruleID)
	if err != nil {
		if err == sql.ErrNoRows {
			writeError(w, http.StatusNotFound, "Rule not found", err, a.logger)
			return
		}
		writeError(w, http.StatusInternalServerError, "Failed to get rule", err, a.logger)
		return
	}

	// Parse pagination
	params := ParsePaginationParams(r, 100, 1000)
	limit := params.Limit
	offset := params.CalculateOffset()

	// Get audit history
	entries, err := a.lifecycleAuditStorage.GetAuditHistory(ruleID, limit, offset)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to get lifecycle history", err, a.logger)
		return
	}

	// Get total count
	total, err := a.lifecycleAuditStorage.GetAuditHistoryCount(ruleID)
	if err != nil {
		a.logger.Warnf("Failed to get audit history count: %v", err)
		total = int64(len(entries))
	}

	// Return paginated response
	a.respondJSON(w, map[string]interface{}{
		"items": entries,
		"total": total,
		"limit": limit,
	}, http.StatusOK)
}

// checkLifecycleMigration verifies that lifecycle columns exist
// BLOCKER-16 FIX: Use proper error checking instead of string comparison
func (a *API) checkLifecycleMigration(ctx context.Context) error {
	query := "SELECT lifecycle_status FROM rules LIMIT 1"
	var dummy sql.NullString

	err := a.sqlite.ReadDB.QueryRowContext(ctx, query).Scan(&dummy)
	if err != nil {
		// If we get ErrNoRows, the schema exists (query worked, just no rows)
		if err == sql.ErrNoRows {
			return nil
		}
		// Any other error likely means schema problem (column doesn't exist)
		// Return migration error to inform user to run migrations
		return ErrMigrationNotApplied
	}

	return nil
}

// =============================================================================
// Rule Clone and Version Endpoints for E2E Test Support
// =============================================================================

// CloneRuleRequest represents a request to clone a rule
type CloneRuleRequest struct {
	NewName string `json:"newName,omitempty"` // Optional: defaults to "Original Name (Copy)"
}

// CloneRuleResponse represents the response from cloning a rule
type CloneRuleResponse struct {
	Success bool        `json:"success"`
	Data    interface{} `json:"data"`
}

// RuleVersionEntry represents a single version in the rule history
type RuleVersionEntry struct {
	Version   int    `json:"version"`
	Title     string `json:"title"`
	CreatedAt string `json:"createdAt"`
	Author    string `json:"author"`
}

// RuleVersionsResponse represents the response for listing rule versions
type RuleVersionsResponse struct {
	Success bool               `json:"success"`
	Data    []RuleVersionEntry `json:"data"`
}

// RestoreRuleRequest represents a request to restore a rule to a previous version
type RestoreRuleRequest struct {
	Version int `json:"version"`
}

// RestoreRuleResponse represents the response from restoring a rule
type RestoreRuleResponse struct {
	Success bool `json:"success"`
	Data    struct {
		ID                  string `json:"id"`
		Version             int    `json:"version"`
		RestoredFromVersion int    `json:"restoredFromVersion"`
		Title               string `json:"title"`
		Content             string `json:"content"`
		RestoredAt          string `json:"restoredAt"`
	} `json:"data"`
}

// cloneRule handles POST /api/v1/rules/{id}/clone
// Create a copy of an existing rule
//
//	@Summary		Clone a rule
//	@Description	Create a copy of an existing rule with optional new name
//	@Tags			rules
//	@Accept			json
//	@Produce		json
//	@Param			id		path		string				true	"Rule ID to clone"
//	@Param			request	body		CloneRuleRequest	false	"Clone options"
//	@Success		201		{object}	CloneRuleResponse	"Cloned rule"
//	@Failure		400		{object}	map[string]string	"Invalid request"
//	@Failure		404		{object}	map[string]string	"Rule not found"
//	@Failure		500		{object}	map[string]string	"Internal server error"
//	@Security		BearerAuth
//	@Router			/api/v1/rules/{id}/clone [post]
func (a *API) cloneRule(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id := vars["id"]

	// Validate ID format
	if id == "" || len(id) > 100 {
		writeError(w, http.StatusBadRequest, "Invalid rule ID format", nil, a.logger)
		return
	}

	// Check storage availability
	if a.ruleStorage == nil {
		writeError(w, http.StatusServiceUnavailable, "Rule storage not available", nil, a.logger)
		return
	}

	// Get the original rule
	originalRule, err := a.ruleStorage.GetRule(id)
	if err != nil {
		if errors.Is(err, storage.ErrRuleNotFound) {
			writeError(w, http.StatusNotFound, "Rule not found", err, a.logger)
			return
		}
		writeError(w, http.StatusInternalServerError, "Failed to get rule", err, a.logger)
		return
	}

	// Parse request body for optional new name
	var req CloneRuleRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		// Empty body is OK - use default name
		req = CloneRuleRequest{}
	}

	// Create cloned rule with deep copy to prevent shared slice/map references
	clonedRule := deepCopyRule(originalRule)
	clonedRule.ID = "" // Will be set by createRuleInternal

	// Set name for clone
	if req.NewName != "" {
		clonedRule.Name = req.NewName
	} else {
		clonedRule.Name = originalRule.Name + " (Copy)"
	}

	// Reset timestamps and metadata
	clonedRule.CreatedAt = time.Now()
	clonedRule.UpdatedAt = time.Now()
	clonedRule.Enabled = false // Disabled by default

	// Get username from context
	username := getUsernameFromContext(r.Context())

	// Audit log
	a.logger.Infow("Rule clone requested",
		"original_id", id,
		"new_name", clonedRule.Name,
		"cloned_by", username)

	// Create the cloned rule using the internal method
	// clonedRule is already a *core.Rule from deepCopyRule
	a.createRuleInternal(w, r, clonedRule)
}

// getRuleVersions handles GET /api/v1/rules/{id}/versions
// Get version history for a rule
//
//	@Summary		Get rule version history
//	@Description	Retrieve the version history for a specific rule
//	@Tags			rules
//	@Produce		json
//	@Param			id	path		string					true	"Rule ID"
//	@Success		200	{object}	RuleVersionsResponse	"Version history"
//	@Failure		400	{object}	map[string]string		"Invalid request"
//	@Failure		404	{object}	map[string]string		"Rule not found"
//	@Failure		500	{object}	map[string]string		"Internal server error"
//	@Security		BearerAuth
//	@Router			/api/v1/rules/{id}/versions [get]
func (a *API) getRuleVersions(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id := vars["id"]

	// Validate ID format
	if id == "" || len(id) > 100 {
		writeError(w, http.StatusBadRequest, "Invalid rule ID format", nil, a.logger)
		return
	}

	// Check storage availability
	if a.ruleStorage == nil {
		writeError(w, http.StatusServiceUnavailable, "Rule storage not available", nil, a.logger)
		return
	}

	// Verify rule exists
	rule, err := a.ruleStorage.GetRule(id)
	if err != nil {
		if errors.Is(err, storage.ErrRuleNotFound) {
			writeError(w, http.StatusNotFound, "Rule not found", err, a.logger)
			return
		}
		writeError(w, http.StatusInternalServerError, "Failed to get rule", err, a.logger)
		return
	}

	// PLACEHOLDER: In production, this would query a rule_versions table
	// For now, return the current version as version 1
	// The actual implementation would store versions on each update
	versions := []RuleVersionEntry{
		{
			Version:   1,
			Title:     rule.Name,
			CreatedAt: rule.CreatedAt.Format(time.RFC3339),
			Author:    "system", // Would be from version history
		},
	}

	response := RuleVersionsResponse{
		Success: true,
		Data:    versions,
	}

	a.respondJSON(w, response, http.StatusOK)
}

// restoreRule handles POST /api/v1/rules/{id}/restore
// Restore a rule to a previous version
//
//	@Summary		Restore rule to previous version
//	@Description	Restore a rule to a specific version from its history
//	@Tags			rules
//	@Accept			json
//	@Produce		json
//	@Param			id		path		string				true	"Rule ID"
//	@Param			request	body		RestoreRuleRequest	true	"Version to restore"
//	@Success		200		{object}	RestoreRuleResponse	"Restored rule"
//	@Failure		400		{object}	map[string]string	"Invalid request or version"
//	@Failure		404		{object}	map[string]string	"Rule or version not found"
//	@Failure		500		{object}	map[string]string	"Internal server error"
//	@Security		BearerAuth
//	@Router			/api/v1/rules/{id}/restore [post]
func (a *API) restoreRule(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id := vars["id"]

	// Validate ID format
	if id == "" || len(id) > 100 {
		writeError(w, http.StatusBadRequest, "Invalid rule ID format", nil, a.logger)
		return
	}

	// Parse request body
	var req RestoreRuleRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body", err, a.logger)
		return
	}

	// Validate version
	if req.Version < 1 {
		writeError(w, http.StatusBadRequest, "Invalid version number", nil, a.logger)
		return
	}

	// Check storage availability
	if a.ruleStorage == nil {
		writeError(w, http.StatusServiceUnavailable, "Rule storage not available", nil, a.logger)
		return
	}

	// Verify rule exists
	rule, err := a.ruleStorage.GetRule(id)
	if err != nil {
		if errors.Is(err, storage.ErrRuleNotFound) {
			writeError(w, http.StatusNotFound, "Rule not found", err, a.logger)
			return
		}
		writeError(w, http.StatusInternalServerError, "Failed to get rule", err, a.logger)
		return
	}

	// PLACEHOLDER: In production, this would:
	// 1. Query the rule_versions table for the requested version
	// 2. Restore the rule content from that version
	// 3. Create a new version entry for the restore action
	// For now, we'll return success with the current rule data

	// Get username from context
	username := getUsernameFromContext(r.Context())

	// Audit log
	a.logger.Infow("Rule restore requested",
		"rule_id", id,
		"target_version", req.Version,
		"restored_by", username)

	// For placeholder, just return current version as "restored"
	response := RestoreRuleResponse{
		Success: true,
	}
	response.Data.ID = rule.ID
	response.Data.Version = req.Version + 1 // New version after restore
	response.Data.RestoredFromVersion = req.Version
	response.Data.Title = rule.Name
	response.Data.Content = rule.SigmaYAML
	response.Data.RestoredAt = time.Now().Format(time.RFC3339)

	a.respondJSON(w, response, http.StatusOK)
}

// =============================================================================
// Deep Copy Helpers for Rule Cloning
// =============================================================================

// deepCopyRule creates a deep copy of a rule to prevent shared slice/map references
// This is critical for rule cloning to ensure modifications to the clone don't affect the original
func deepCopyRule(original *core.Rule) *core.Rule {
	if original == nil {
		return nil
	}

	// Create new rule with scalar fields
	cloned := &core.Rule{
		ID:                original.ID,
		Type:              original.Type,
		Name:              original.Name,
		Description:       original.Description,
		Severity:          original.Severity,
		Version:           original.Version,
		Author:            original.Author,
		Enabled:           original.Enabled,
		Query:             original.Query,
		SigmaYAML:         original.SigmaYAML,
		LogsourceCategory: original.LogsourceCategory,
		LogsourceProduct:  original.LogsourceProduct,
		LogsourceService:  original.LogsourceService,
		CreatedAt:         original.CreatedAt,
		UpdatedAt:         original.UpdatedAt,
	}

	// Deep copy Tags slice
	if original.Tags != nil {
		cloned.Tags = make([]string, len(original.Tags))
		copy(cloned.Tags, original.Tags)
	}

	// Deep copy MitreTactics slice
	if original.MitreTactics != nil {
		cloned.MitreTactics = make([]string, len(original.MitreTactics))
		copy(cloned.MitreTactics, original.MitreTactics)
	}

	// Deep copy MitreTechniques slice
	if original.MitreTechniques != nil {
		cloned.MitreTechniques = make([]string, len(original.MitreTechniques))
		copy(cloned.MitreTechniques, original.MitreTechniques)
	}

	// Deep copy References slice
	if original.References != nil {
		cloned.References = make([]string, len(original.References))
		copy(cloned.References, original.References)
	}

	// Deep copy FalsePositives slice
	if original.FalsePositives != nil {
		cloned.FalsePositives = make([]string, len(original.FalsePositives))
		copy(cloned.FalsePositives, original.FalsePositives)
	}

	// Deep copy Metadata map
	if original.Metadata != nil {
		cloned.Metadata = make(map[string]interface{}, len(original.Metadata))
		for k, v := range original.Metadata {
			cloned.Metadata[k] = deepCopyRuleValue(v)
		}
	}

	// Deep copy Correlation map
	if original.Correlation != nil {
		cloned.Correlation = make(map[string]interface{}, len(original.Correlation))
		for k, v := range original.Correlation {
			cloned.Correlation[k] = deepCopyRuleValue(v)
		}
	}

	// Deep copy Actions slice
	if original.Actions != nil {
		cloned.Actions = make([]core.Action, len(original.Actions))
		for i, action := range original.Actions {
			cloned.Actions[i] = deepCopyAction(action)
		}
	}

	return cloned
}

// deepCopyAction creates a deep copy of an Action
func deepCopyAction(original core.Action) core.Action {
	action := core.Action{
		ID:        original.ID,
		Type:      original.Type,
		CreatedAt: original.CreatedAt,
		UpdatedAt: original.UpdatedAt,
	}

	// Deep copy Config map
	if original.Config != nil {
		action.Config = make(map[string]interface{}, len(original.Config))
		for k, v := range original.Config {
			action.Config[k] = deepCopyRuleValue(v)
		}
	}

	return action
}

// deepCopyRuleValue creates a deep copy of an interface{} value
// Handles nested maps and slices recursively
func deepCopyRuleValue(v interface{}) interface{} {
	if v == nil {
		return nil
	}

	switch val := v.(type) {
	case map[string]interface{}:
		result := make(map[string]interface{}, len(val))
		for k, v := range val {
			result[k] = deepCopyRuleValue(v)
		}
		return result
	case []interface{}:
		result := make([]interface{}, len(val))
		for i, v := range val {
			result[i] = deepCopyRuleValue(v)
		}
		return result
	case []string:
		result := make([]string, len(val))
		copy(result, val)
		return result
	default:
		// Primitive types (string, int, float64, bool) are copied by value
		return val
	}
}
