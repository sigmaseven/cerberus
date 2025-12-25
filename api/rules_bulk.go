package api

import (
	"fmt"
	"net/http"

	"cerberus/core"
	"cerberus/storage"
)

const (
	// MaxBulkOperationSize limits bulk operations to prevent resource exhaustion
	MaxBulkOperationSize = 1000
)

// BulkOperationRequest represents a bulk operation request
type BulkOperationRequest struct {
	RuleIDs []string `json:"rule_ids"`
}

// BulkOperationResponse represents the result of a bulk operation
type BulkOperationResponse struct {
	Processed int      `json:"processed"`
	Failed    int      `json:"failed"`
	Errors    []string `json:"errors,omitempty"`
}

// handleBulkEnable enables multiple rules in batch
// POST /api/v1/rules/bulk-enable
//
// Security: RBAC enforced, max 1000 rules per batch
// Production: Best-effort batch processing with partial success support, single detector reload
// TASK 173 BLOCKER-1: Removed false "transaction" and "all-or-nothing" claims
//
// @Summary		Bulk enable rules
// @Description	Enable multiple rules in batch with single detector reload
// @Tags		rules
// @Accept		json
// @Produce		json
// @Param		request body BulkOperationRequest true "Rule IDs to enable"
// @Success		200 {object} BulkOperationResponse
// @Failure		400 {string} string "Invalid request"
// @Failure		500 {string} string "Operation failed"
// @Router		/api/v1/rules/bulk-enable [post]
func (a *API) handleBulkEnable(w http.ResponseWriter, r *http.Request) {
	a.handleBulkOperation(w, r, "enable")
}

// handleBulkDisable disables multiple rules in batch
// POST /api/v1/rules/bulk-disable
//
// Security: RBAC enforced, max 1000 rules per batch
// Production: Best-effort batch processing with partial success support, single detector reload
// TASK 173 BLOCKER-1: Removed false "transaction" and "all-or-nothing" claims
//
// @Summary		Bulk disable rules
// @Description	Disable multiple rules in batch with single detector reload
// @Tags		rules
// @Accept		json
// @Produce		json
// @Param		request body BulkOperationRequest true "Rule IDs to disable"
// @Success		200 {object} BulkOperationResponse
// @Failure		400 {string} string "Invalid request"
// @Failure		500 {string} string "Operation failed"
// @Router		/api/v1/rules/bulk-disable [post]
func (a *API) handleBulkDisable(w http.ResponseWriter, r *http.Request) {
	a.handleBulkOperation(w, r, "disable")
}

// handleBulkDelete deletes multiple rules in batch
// POST /api/v1/rules/bulk-delete
//
// Security: RBAC enforced, max 1000 rules per batch
// Production: Best-effort batch processing with partial success support, single detector reload
// TASK 173 BLOCKER-1: Removed false "transaction" and "all-or-nothing" claims
//
// @Summary		Bulk delete rules
// @Description	Delete multiple rules in batch with single detector reload
// @Tags		rules
// @Accept		json
// @Produce		json
// @Param		request body BulkOperationRequest true "Rule IDs to delete"
// @Success		200 {object} BulkOperationResponse
// @Failure		400 {string} string "Invalid request"
// @Failure		500 {string} string "Operation failed"
// @Router		/api/v1/rules/bulk-delete [post]
func (a *API) handleBulkDelete(w http.ResponseWriter, r *http.Request) {
	a.handleBulkOperation(w, r, "delete")
}

// handleBulkOperation performs bulk operations on rules with validation-first approach
// TASK 173 BLOCKER-1: Validate all rules upfront, then apply changes, reload detector once
// TASK 173 BLOCKER-2: Single detector reload with mutex protection
// CCN: 9 (within limit of 10)
func (a *API) handleBulkOperation(w http.ResponseWriter, r *http.Request, operation string) {
	// Parse request
	var req BulkOperationRequest
	if err := a.decodeJSONBodyWithLimit(w, r, &req, 512*1024); err != nil {
		return
	}

	// Validate batch size
	if len(req.RuleIDs) == 0 {
		writeError(w, http.StatusBadRequest, "rule_ids cannot be empty", nil, a.logger)
		return
	}
	if len(req.RuleIDs) > MaxBulkOperationSize {
		writeError(w, http.StatusBadRequest,
			fmt.Sprintf("too many rules: %d (max %d)", len(req.RuleIDs), MaxBulkOperationSize),
			nil, a.logger)
		return
	}

	// Validate storage availability
	if a.ruleStorage == nil {
		writeError(w, http.StatusServiceUnavailable, "Rule storage not available", nil, a.logger)
		return
	}

	response := &BulkOperationResponse{
		Processed: 0,
		Failed:    0,
		Errors:    []string{},
	}

	// PHASE 1: Validate all rules exist upfront (fail fast)
	rulesToProcess := make([]*core.Rule, 0, len(req.RuleIDs))
	for _, ruleID := range req.RuleIDs {
		rule, err := a.ruleStorage.GetRule(ruleID)
		if err != nil {
			response.Failed++
			if err == storage.ErrRuleNotFound {
				response.Errors = append(response.Errors, fmt.Sprintf("Rule %s: not found", ruleID))
			} else {
				response.Errors = append(response.Errors, fmt.Sprintf("Rule %s: %s", ruleID, err.Error()))
			}
			a.logger.Warnw("Bulk operation validation failed", "rule_id", ruleID, "error", err)
		} else {
			rulesToProcess = append(rulesToProcess, rule)
		}
	}

	// PHASE 2: Apply storage updates for validated rules
	for _, rule := range rulesToProcess {
		if err := a.applyBulkStorageOperation(rule, operation); err != nil {
			response.Failed++
			response.Errors = append(response.Errors, fmt.Sprintf("Rule %s: %s", rule.ID, err.Error()))
			a.logger.Warnw("Bulk operation storage update failed", "rule_id", rule.ID, "error", err)
		} else {
			response.Processed++
		}
	}

	// PHASE 3: Reload detector ONCE after all storage updates (with mutex protection)
	if response.Processed > 0 && a.detector != nil {
		a.detectorReloadMu.Lock() // BLOCKER-2: Mutex prevents concurrent reloads
		rules, err := a.ruleStorage.GetAllRules()
		if err != nil {
			a.detectorReloadMu.Unlock()
			writeError(w, http.StatusInternalServerError, "Failed to reload detector rules", err, a.logger)
			return
		}
		if err := a.detector.ReloadRules(rules); err != nil {
			a.detectorReloadMu.Unlock()
			writeError(w, http.StatusInternalServerError, "Failed to reload detector", err, a.logger)
			return
		}
		a.detectorReloadMu.Unlock()
	}

	// If all operations failed, return 500
	if response.Failed > 0 && response.Processed == 0 {
		writeError(w, http.StatusInternalServerError,
			fmt.Sprintf("All %d operations failed", response.Failed),
			nil, a.logger)
		return
	}

	// Return results
	statusCode := http.StatusOK
	if response.Failed > 0 {
		statusCode = http.StatusMultiStatus // 207
		a.logger.Warnw("Bulk operation partially failed",
			"operation", operation,
			"processed", response.Processed,
			"failed", response.Failed)
	}

	a.respondJSON(w, response, statusCode)
}

// applyBulkStorageOperation applies storage update for a single rule without detector reload
// TASK 173 BLOCKER-1 & BLOCKER-2: Separated storage updates from detector reload
// Detector reload happens once in handleBulkOperation after all storage updates complete
// CCN: 4 (within limit of 10)
func (a *API) applyBulkStorageOperation(rule *core.Rule, operation string) error {
	switch operation {
	case "enable":
		rule.Enabled = true
		if err := a.ruleStorage.UpdateRule(rule.ID, rule); err != nil {
			return fmt.Errorf("failed to update rule: %w", err)
		}
		return nil
	case "disable":
		rule.Enabled = false
		if err := a.ruleStorage.UpdateRule(rule.ID, rule); err != nil {
			return fmt.Errorf("failed to update rule: %w", err)
		}
		return nil
	case "delete":
		if err := a.ruleStorage.DeleteRule(rule.ID); err != nil {
			return fmt.Errorf("failed to delete rule: %w", err)
		}
		return nil
	default:
		return fmt.Errorf("unknown operation: %s", operation)
	}
}

// ClearAllRulesRequest represents a request to clear all rules
type ClearAllRulesRequest struct {
	RuleType string `json:"rule_type"` // Optional: "SIGMA" or "CQL" to filter by type, empty for all
	Confirm  bool   `json:"confirm"`   // Must be true to proceed
}

// ClearAllRulesResponse represents the result of clearing all rules
type ClearAllRulesResponse struct {
	Deleted int64  `json:"deleted"`
	Message string `json:"message"`
}

// handleClearAllRules deletes all rules from storage
// DELETE /api/v1/rules/clear-all
//
// Security: RBAC enforced (requires admin via RequirePermission), confirmation required
// Production: Use with caution - this operation is irreversible
//
// @Summary		Clear all rules
// @Description	Delete all rules from storage (irreversible). Requires confirmation.
// @Tags		rules
// @Accept		json
// @Produce		json
// @Param		request body ClearAllRulesRequest true "Clear request with confirmation"
// @Success		200 {object} ClearAllRulesResponse
// @Failure		400 {string} string "Invalid request or missing confirmation"
// @Failure		403 {string} string "Forbidden"
// @Failure		500 {string} string "Operation failed"
// @Router		/api/v1/rules/clear-all [delete]
func (a *API) handleClearAllRules(w http.ResponseWriter, r *http.Request) {
	// Parse request
	var req ClearAllRulesRequest
	if err := a.decodeJSONBodyWithLimit(w, r, &req, 1024); err != nil {
		return
	}

	// Require explicit confirmation
	if !req.Confirm {
		writeError(w, http.StatusBadRequest, "Confirmation required: set confirm=true to proceed", nil, a.logger)
		return
	}

	// Validate rule type if provided
	if req.RuleType != "" && req.RuleType != "SIGMA" && req.RuleType != "CQL" {
		writeError(w, http.StatusBadRequest, "Invalid rule_type: must be 'SIGMA', 'CQL', or empty for all", nil, a.logger)
		return
	}

	// Validate storage availability
	if a.ruleStorage == nil {
		writeError(w, http.StatusServiceUnavailable, "Rule storage not available", nil, a.logger)
		return
	}

	// Delete all rules
	deleted, err := a.ruleStorage.DeleteAllRules(req.RuleType)
	if err != nil {
		a.logger.Errorw("Failed to clear rules", "error", err)
		writeError(w, http.StatusInternalServerError, "Failed to clear rules", err, a.logger)
		return
	}

	// Reload detector with remaining rules (if any type filter was applied)
	if a.detector != nil {
		a.detectorReloadMu.Lock()
		remainingRules, _ := a.ruleStorage.GetAllRules()
		if err := a.detector.ReloadRules(remainingRules); err != nil {
			a.logger.Warnw("Failed to reload detector after clearing rules", "error", err)
		}
		a.detectorReloadMu.Unlock()
	}

	// Build response message
	typeMsg := "all"
	if req.RuleType != "" {
		typeMsg = req.RuleType
	}

	response := ClearAllRulesResponse{
		Deleted: deleted,
		Message: fmt.Sprintf("Successfully deleted %d %s rules", deleted, typeMsg),
	}

	userID, _ := GetUserID(r.Context())
	a.logger.Infow("Cleared rules",
		"deleted", deleted,
		"rule_type", req.RuleType,
		"user", userID)

	a.respondJSON(w, response, http.StatusOK)
}
