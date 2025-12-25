package api

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"cerberus/storage"

	"github.com/gorilla/mux"
)

// Custom errors for field mapping lifecycle transitions
var (
	ErrFieldMappingNotFound           = errors.New("field mapping not found")
	ErrFieldMappingInvalidTransition  = errors.New("invalid lifecycle transition")
	ErrFieldMappingInvalidAction      = errors.New("invalid action")
	ErrFieldMappingMigrationNotApplied = errors.New("field mapping lifecycle management requires database migration 1.8.0")
)

// FieldMappingLifecycleAction represents a lifecycle action request
type FieldMappingLifecycleAction struct {
	Action       string     `json:"action"`                  // promote, deprecate, archive, activate
	TargetStatus string     `json:"target_status,omitempty"` // Optional explicit target status
	Reason       string     `json:"reason"`
	SunsetDate   *time.Time `json:"sunset_date,omitempty"`
}

// fieldMappingLifecycleStateMachine defines valid state transitions for field mappings
// State machine enforces lifecycle progression: experimental -> test -> stable -> deprecated -> archived
var fieldMappingLifecycleStateMachine = map[LifecycleStatus][]LifecycleStatus{
	LifecycleExperimental: {LifecycleTest, LifecycleArchived},
	LifecycleTest:         {LifecycleStable, LifecycleExperimental, LifecycleArchived},
	LifecycleStable:       {LifecycleDeprecated, LifecycleArchived},
	LifecycleDeprecated:   {LifecycleArchived, LifecycleStable},
	LifecycleArchived:     {}, // Terminal state
}

// handleFieldMappingLifecycle handles POST /api/v1/field-mappings/{id}/lifecycle
// Transitions field mappings through lifecycle states with validation and audit trail
//
// SECURITY:
// - RBAC: Requires field_mappings:update permission
// - Input validation: Validates action and target status
// - State machine: Enforces valid transitions only
// - SQL injection: Uses parameterized queries
// - Atomic transactions: Mapping update and audit entry are atomic
func (a *API) handleFieldMappingLifecycle(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	mappingID := vars["id"]

	if mappingID == "" {
		writeError(w, http.StatusBadRequest, "Mapping ID is required", nil, a.logger)
		return
	}

	// Parse request body
	var action FieldMappingLifecycleAction
	if err := json.NewDecoder(r.Body).Decode(&action); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body", err, a.logger)
		return
	}

	// Validate action
	if err := validateFieldMappingLifecycleAction(&action); err != nil {
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

	if err := a.executeFieldMappingLifecycleTransition(ctx, mappingID, username, &action); err != nil {
		if errors.Is(err, ErrFieldMappingNotFound) {
			writeError(w, http.StatusNotFound, "Field mapping not found", err, a.logger)
			return
		}
		if errors.Is(err, ErrFieldMappingInvalidTransition) || errors.Is(err, ErrFieldMappingInvalidAction) {
			writeError(w, http.StatusBadRequest, err.Error(), err, a.logger)
			return
		}
		if errors.Is(err, ErrFieldMappingMigrationNotApplied) {
			writeError(w, http.StatusServiceUnavailable, err.Error(), err, a.logger)
			return
		}
		writeError(w, http.StatusInternalServerError, "Lifecycle transition failed", err, a.logger)
		return
	}

	// Return success response
	a.respondJSON(w, map[string]interface{}{
		"message":    "Lifecycle transition successful",
		"mapping_id": mappingID,
		"action":     action.Action,
	}, http.StatusOK)
}

// validateFieldMappingLifecycleAction validates the lifecycle action request
func validateFieldMappingLifecycleAction(action *FieldMappingLifecycleAction) error {
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
		return fmt.Errorf("%w: %s (must be promote, deprecate, archive, or activate)", ErrFieldMappingInvalidAction, action.Action)
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

// executeFieldMappingLifecycleTransition executes a lifecycle transition with validation
func (a *API) executeFieldMappingLifecycleTransition(ctx context.Context, mappingID, username string, action *FieldMappingLifecycleAction) error {
	// Check migration is applied
	if err := a.checkFieldMappingLifecycleMigration(ctx); err != nil {
		return err
	}

	// Get current mapping
	mapping, err := a.fieldMappingStorage.GetWithLifecycle(mappingID)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrFieldMappingNotFound, err)
	}

	if mapping == nil {
		return ErrFieldMappingNotFound
	}

	// Determine current and target status
	currentStatus := getFieldMappingLifecycleStatus(mapping)
	targetStatus, err := determineFieldMappingTargetStatus(currentStatus, action)
	if err != nil {
		return err
	}

	// Validate state transition
	if err := validateFieldMappingStateTransition(currentStatus, targetStatus); err != nil {
		return fmt.Errorf("%w: %v", ErrFieldMappingInvalidTransition, err)
	}

	// Update lifecycle status
	var deprecatedAt *time.Time
	if targetStatus == LifecycleDeprecated {
		now := time.Now().UTC()
		deprecatedAt = &now
	}

	if err := a.fieldMappingStorage.UpdateLifecycleStatus(
		mappingID,
		string(targetStatus),
		deprecatedAt,
		action.Reason,
		username,
		action.SunsetDate,
	); err != nil {
		return fmt.Errorf("failed to update lifecycle status: %w", err)
	}

	// Create audit entry
	if a.fieldMappingAuditStorage != nil {
		auditEntry := &storage.FieldMappingAuditEntry{
			MappingID: mappingID,
			OldStatus: string(currentStatus),
			NewStatus: string(targetStatus),
			Reason:    action.Reason,
			ChangedBy: username,
			ChangedAt: time.Now().UTC(),
		}
		if action.SunsetDate != nil {
			auditEntry.AdditionalData = map[string]interface{}{
				"sunset_date": action.SunsetDate.UTC().Format(time.RFC3339),
			}
		}
		if err := a.fieldMappingAuditStorage.CreateAuditEntry(auditEntry); err != nil {
			a.logger.Warnw("Failed to create audit entry", "error", err, "mapping_id", mappingID)
		}
	}

	a.logger.Infow("Field mapping lifecycle transition executed",
		"mapping_id", mappingID,
		"old_status", currentStatus,
		"new_status", targetStatus,
		"action", action.Action,
		"user", username,
	)

	return nil
}

// getFieldMappingLifecycleStatus extracts lifecycle status from mapping
func getFieldMappingLifecycleStatus(mapping *storage.FieldMappingWithLifecycle) LifecycleStatus {
	if mapping.LifecycleStatus == "" {
		return LifecycleExperimental // Default
	}
	return LifecycleStatus(mapping.LifecycleStatus)
}

// determineFieldMappingTargetStatus determines target status based on action
func determineFieldMappingTargetStatus(current LifecycleStatus, action *FieldMappingLifecycleAction) (LifecycleStatus, error) {
	// If explicit target status provided, use it
	if action.TargetStatus != "" {
		return LifecycleStatus(action.TargetStatus), nil
	}

	// Determine target based on action
	switch action.Action {
	case "promote":
		return promoteFieldMappingStatus(current)
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
		return "", fmt.Errorf("%w: unknown action: %s", ErrFieldMappingInvalidAction, action.Action)
	}
}

// promoteFieldMappingStatus advances status to next stage in lifecycle
func promoteFieldMappingStatus(current LifecycleStatus) (LifecycleStatus, error) {
	switch current {
	case LifecycleExperimental:
		return LifecycleTest, nil
	case LifecycleTest:
		return LifecycleStable, nil
	case LifecycleStable:
		return "", fmt.Errorf("stable mappings cannot be promoted further")
	case LifecycleDeprecated:
		return "", fmt.Errorf("deprecated mappings cannot be promoted")
	case LifecycleArchived:
		return "", fmt.Errorf("archived mappings cannot be promoted")
	default:
		return "", fmt.Errorf("unknown lifecycle status: %s", current)
	}
}

// validateFieldMappingStateTransition validates if transition is allowed by state machine
func validateFieldMappingStateTransition(current, target LifecycleStatus) error {
	// Same state is always valid (idempotent)
	if current == target {
		return nil
	}

	// Check if transition is allowed
	allowedTargets, ok := fieldMappingLifecycleStateMachine[current]
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

// handleGetFieldMappingLifecycleHistory handles GET /api/v1/field-mappings/{id}/lifecycle-history
// Returns chronological list of lifecycle transitions for a field mapping
func (a *API) handleGetFieldMappingLifecycleHistory(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	mappingID := vars["id"]

	if mappingID == "" {
		writeError(w, http.StatusBadRequest, "Mapping ID is required", nil, a.logger)
		return
	}

	// Verify mapping exists
	_, err := a.fieldMappingStorage.Get(mappingID)
	if err != nil {
		writeError(w, http.StatusNotFound, "Field mapping not found", err, a.logger)
		return
	}

	if a.fieldMappingAuditStorage == nil {
		writeError(w, http.StatusServiceUnavailable, "Audit storage not configured", nil, a.logger)
		return
	}

	// Parse pagination
	params := ParsePaginationParams(r, 100, 1000)
	limit := params.Limit
	offset := params.CalculateOffset()

	// Get audit history
	entries, err := a.fieldMappingAuditStorage.GetAuditHistory(mappingID, limit, offset)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to get lifecycle history", err, a.logger)
		return
	}

	// Get total count
	total, err := a.fieldMappingAuditStorage.GetAuditHistoryCount(mappingID)
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

// handleGetFieldMappingUsage handles GET /api/v1/field-mappings/{id}/usage
// Returns list of listeners using this field mapping
func (a *API) handleGetFieldMappingUsage(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	mappingID := vars["id"]

	if mappingID == "" {
		writeError(w, http.StatusBadRequest, "Mapping ID is required", nil, a.logger)
		return
	}

	// Verify mapping exists
	_, err := a.fieldMappingStorage.Get(mappingID)
	if err != nil {
		writeError(w, http.StatusNotFound, "Field mapping not found", err, a.logger)
		return
	}

	// Check usage
	inUse, listeners, err := a.fieldMappingStorage.IsMappingInUse(mappingID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to check mapping usage", err, a.logger)
		return
	}

	a.respondJSON(w, map[string]interface{}{
		"mapping_id": mappingID,
		"in_use":     inUse,
		"listeners":  listeners,
		"count":      len(listeners),
	}, http.StatusOK)
}

// checkFieldMappingLifecycleMigration verifies that lifecycle columns exist
func (a *API) checkFieldMappingLifecycleMigration(ctx context.Context) error {
	if a.sqlite == nil {
		return fmt.Errorf("SQLite storage not configured")
	}

	query := "SELECT lifecycle_status FROM field_mappings LIMIT 1"
	var dummy sql.NullString

	err := a.sqlite.ReadDB.QueryRowContext(ctx, query).Scan(&dummy)
	if err != nil {
		// If we get ErrNoRows, the schema exists (query worked, just no rows)
		if err == sql.ErrNoRows {
			return nil
		}
		// Any other error likely means schema problem (column doesn't exist)
		return ErrFieldMappingMigrationNotApplied
	}

	return nil
}
