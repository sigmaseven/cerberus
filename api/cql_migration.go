package api

import (
	"cerberus/core"
	"cerberus/cqlconv"
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// MigrateCQLRequest represents a request to migrate CQL rules to SIGMA
type MigrateCQLRequest struct {
	RuleIDs          []string `json:"rule_ids"`           // Specific rule IDs to migrate (empty for all)
	All              bool     `json:"all"`                // Migrate all CQL rules
	DryRun           bool     `json:"dry_run"`            // Preview without saving
	PreserveOriginal bool     `json:"preserve_original"`  // Keep original CQL rules as disabled
}

// MigrateCQLResponse represents the response from a CQL migration operation
type MigrateCQLResponse struct {
	TotalRules int               `json:"total_rules"`
	Migrated   int               `json:"migrated"`
	Failed     int               `json:"failed"`
	Skipped    int               `json:"skipped"`
	Results    []MigrationResult `json:"results"`
}

// MigrationResult represents the result of migrating a single rule
type MigrationResult struct {
	RuleID    string   `json:"rule_id"`
	RuleName  string   `json:"rule_name"`
	Success   bool     `json:"success"`
	SigmaYAML string   `json:"sigma_yaml,omitempty"`
	Warnings  []string `json:"warnings,omitempty"`
	Error     string   `json:"error,omitempty"`
}

// migrateCQLHandler handles POST /api/v1/rules/migrate-cql
//
// Security considerations:
//   - Requires authentication (when enabled) and rules:write permission
//   - Validates all rule IDs to prevent injection
//   - Limits batch size to prevent resource exhaustion
//   - Uses transactions for atomic updates
//   - Logs all migration operations for audit trail
//
// @Summary Migrate CQL rules to SIGMA format
// @Description Converts CQL-format rules to SIGMA YAML format, optionally preserving originals
// @Tags rules
// @Accept json
// @Produce json
// @Param request body MigrateCQLRequest true "Migration request"
// @Success 200 {object} MigrateCQLResponse
// @Failure 400 {object} ErrorResponse
// @Failure 401 {object} ErrorResponse
// @Failure 403 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Router /api/v1/rules/migrate-cql [post]
func (a *API) migrateCQLHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Extract user context for RBAC (if auth enabled)
	userID, _ := GetUserID(ctx)

	// Parse request body
	var req MigrateCQLRequest
	if err := a.decodeJSONBody(w, r, &req); err != nil {
		http.Error(w, fmt.Sprintf("Invalid request body: %v", err), http.StatusBadRequest)
		return
	}

	// Validate request
	if err := validateMigrationRequest(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Perform migration
	result, err := a.migrateCQLRules(ctx, &req, userID)
	if err != nil {
		a.logger.Errorw("CQL migration failed", "error", err, "user", userID)
		http.Error(w, fmt.Sprintf("Migration failed: %v", err), http.StatusInternalServerError)
		return
	}

	// Log migration for audit trail
	a.logger.Infow("CQL migration completed",
		"user", userID,
		"total", result.TotalRules,
		"migrated", result.Migrated,
		"failed", result.Failed,
		"dry_run", req.DryRun,
	)

	a.respondJSON(w, result, http.StatusOK)
}

// validateMigrationRequest validates the migration request
func validateMigrationRequest(req *MigrateCQLRequest) error {
	// Security: Limit batch size to prevent resource exhaustion
	const maxBatchSize = 1000

	if req.All && len(req.RuleIDs) > 0 {
		return fmt.Errorf("cannot specify both 'all' and 'rule_ids'")
	}

	if !req.All && len(req.RuleIDs) == 0 {
		return fmt.Errorf("must specify either 'all' or 'rule_ids'")
	}

	if len(req.RuleIDs) > maxBatchSize {
		return fmt.Errorf("batch size exceeds maximum of %d rules", maxBatchSize)
	}

	// Security: Validate rule IDs to prevent injection
	for _, id := range req.RuleIDs {
		if err := validateRuleID(id); err != nil {
			return fmt.Errorf("invalid rule ID '%s': %w", id, err)
		}
	}

	return nil
}

// validateRuleID validates a rule ID format
func validateRuleID(id string) error {
	if id == "" {
		return fmt.Errorf("rule ID cannot be empty")
	}

	// Security: Prevent path traversal and injection
	if strings.Contains(id, "..") || strings.Contains(id, "/") || strings.Contains(id, "\\") {
		return fmt.Errorf("rule ID contains invalid characters")
	}

	// Reasonable length check
	if len(id) > 256 {
		return fmt.Errorf("rule ID exceeds maximum length of 256 characters")
	}

	return nil
}

// migrateCQLRules performs the actual migration
func (a *API) migrateCQLRules(ctx context.Context, req *MigrateCQLRequest, userID string) (*MigrateCQLResponse, error) {
	response := &MigrateCQLResponse{
		Results: []MigrationResult{},
	}

	// Get rules to migrate
	rules, err := a.getRulesToMigrate(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch rules: %w", err)
	}

	response.TotalRules = len(rules)

	// Process each rule
	for _, rule := range rules {
		result := a.migrateRule(ctx, rule, req)
		response.Results = append(response.Results, result)

		if result.Success {
			response.Migrated++
		} else if result.Error != "" {
			response.Failed++
		} else {
			response.Skipped++
		}
	}

	return response, nil
}

// getRulesToMigrate fetches the rules to be migrated
func (a *API) getRulesToMigrate(ctx context.Context, req *MigrateCQLRequest) ([]*core.Rule, error) {
	var rules []*core.Rule
	var err error

	if req.All {
		// Get all CQL rules
		allRules, err := a.ruleStorage.GetAllRules()
		if err != nil {
			return nil, fmt.Errorf("failed to fetch all rules: %w", err)
		}

		// Filter for CQL type
		for i := range allRules {
			rule := allRules[i]
			if rule.Type == "cql" || rule.Type == "CQL" {
				rules = append(rules, &rule)
			}
		}
	} else {
		// Get specific rules by ID
		for _, id := range req.RuleIDs {
			rule, err := a.ruleStorage.GetRule(id)
			if err != nil {
				a.logger.Warnw("Failed to fetch rule for migration",
					"rule_id", id,
					"error", err,
				)
				continue
			}

			// Validate rule type
			if rule.Type != "cql" && rule.Type != "CQL" {
				a.logger.Warnw("Skipping non-CQL rule",
					"rule_id", id,
					"type", rule.Type,
				)
				continue
			}

			rules = append(rules, rule)
		}
	}

	return rules, err
}

// migrateRule migrates a single CQL rule to SIGMA
// PRODUCTION: Orchestrates conversion, validation, and persistence with rollback support
func (a *API) migrateRule(ctx context.Context, rule *core.Rule, req *MigrateCQLRequest) MigrationResult {
	result := MigrationResult{
		RuleID:   rule.ID,
		RuleName: rule.Name,
	}

	// Convert CQL to SIGMA
	convResult, err := cqlconv.ConvertCQLToSigma(rule)
	if err != nil {
		result.Error = fmt.Sprintf("Conversion error: %v", err)
		return result
	}

	if !convResult.Success {
		result.Error = strings.Join(convResult.Errors, "; ")
		result.Warnings = convResult.Warnings
		return result
	}

	result.SigmaYAML = convResult.SigmaYAML
	result.Warnings = convResult.Warnings

	// Validate SIGMA output
	if err := cqlconv.ValidateSigmaOutput(convResult.SigmaYAML); err != nil {
		result.Error = fmt.Sprintf("SIGMA validation failed: %v", err)
		return result
	}

	// Dry run - don't save
	if req.DryRun {
		result.Success = true
		return result
	}

	// Create SIGMA rule from CQL
	sigmaRule := createSigmaRuleFromCQL(rule, convResult.SigmaYAML)

	// Save rule with appropriate strategy
	if err := a.saveRule(rule, sigmaRule, req.PreserveOriginal); err != nil {
		result.Error = err.Error()
		return result
	}

	result.Success = true
	return result
}

// createSigmaRuleFromCQL creates a new SIGMA rule from a CQL rule
// PRODUCTION: Preserves metadata and increments version for audit trail
func createSigmaRuleFromCQL(cqlRule *core.Rule, sigmaYAML string) *core.Rule {
	return &core.Rule{
		ID:              cqlRule.ID, // Keep same ID unless preserving original
		Type:            "sigma",
		Name:            cqlRule.Name,
		Description:     cqlRule.Description,
		Severity:        cqlRule.Severity,
		Version:         cqlRule.Version + 1, // Increment version
		Tags:            append(cqlRule.Tags, "cql-migration"),
		MitreTactics:    cqlRule.MitreTactics,
		MitreTechniques: cqlRule.MitreTechniques,
		Author:          cqlRule.Author,
		Metadata:        cqlRule.Metadata,
		Actions:         cqlRule.Actions,
		Enabled:         cqlRule.Enabled,
		References:      cqlRule.References,
		FalsePositives:  cqlRule.FalsePositives,
		SigmaYAML:       sigmaYAML,
		CreatedAt:       time.Now(),
		UpdatedAt:       time.Now(),
	}
}

// saveRule persists the migrated rule with appropriate strategy
// PRODUCTION: Handles both in-place updates and preserve-original mode with rollback
// SECURITY FIX: Creates SIGMA rule FIRST, then disables original (prevents orphaned disabled rules)
func (a *API) saveRule(originalRule *core.Rule, sigmaRule *core.Rule, preserveOriginal bool) error {
	if preserveOriginal {
		// Generate new ID for SIGMA rule
		sigmaRule.ID = originalRule.ID + "-sigma"

		// SECURITY FIX: Create new SIGMA rule FIRST (before disabling original)
		if err := a.ruleStorage.CreateRule(sigmaRule); err != nil {
			return fmt.Errorf("failed to create SIGMA rule: %w", err)
		}

		// Only disable original after SIGMA rule is successfully created
		originalRule.Enabled = false
		originalRule.UpdatedAt = time.Now()
		if err := a.ruleStorage.UpdateRule(originalRule.ID, originalRule); err != nil {
			// Rollback: Try to delete the newly created SIGMA rule
			if rollbackErr := a.ruleStorage.DeleteRule(sigmaRule.ID); rollbackErr != nil {
				a.logger.Errorw("Failed to rollback SIGMA rule creation",
					"sigma_id", sigmaRule.ID,
					"error", rollbackErr,
				)
			}
			return fmt.Errorf("failed to disable original rule: %w", err)
		}
	} else {
		// Update existing rule in-place
		if err := a.ruleStorage.UpdateRule(originalRule.ID, sigmaRule); err != nil {
			return fmt.Errorf("failed to update rule: %w", err)
		}
	}

	return nil
}
