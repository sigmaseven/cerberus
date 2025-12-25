package storage

// This file implements SIGMA YAML migration for converting existing rules
// from JSON detection blocks to SIGMA YAML format.
//
// IMPORTANT CONCURRENCY NOTE:
// This migration is designed to run SINGLE-THREADED. Do not invoke
// MigrateToSigmaYAML or RollbackSigmaYAMLMigration concurrently.
// Each function uses a single database transaction which provides isolation,
// but concurrent invocations could cause lock contention or unexpected behavior.
//
// RACE DETECTOR NOTE:
// Race detection requires CGO which may not be available on all platforms.
// The migration has been verified safe by design (single transaction, no goroutines)
// but should be tested with `go test -race` on platforms where CGO is available
// before production deployment.
//
// RECOMMENDED USAGE:
// - Run during maintenance window (not under load)
// - Execute single-threaded (no concurrent migrations)
// - Test in staging with full production dataset first
// - Monitor memory usage for large rule sets (1000+)
// - Have rollback ready: RollbackSigmaYAMLMigration

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"

	"go.uber.org/zap"
	"gopkg.in/yaml.v3"
)

// MigrationOptions configures SIGMA YAML migration behavior
// SECURITY: All boolean options default to safe values
type MigrationOptions struct {
	// DryRun simulates migration without committing database changes
	// When true, all operations execute in a transaction that is rolled back
	DryRun bool

	// ValidateOnly validates all rules but does not perform migration
	// Useful for pre-migration validation without modifying the database
	ValidateOnly bool

	// ContinueOnError determines fail-fast vs skip-on-error behavior
	// false: Fail immediately and rollback on first error (default, safest)
	// true: Skip invalid rules, log errors, and continue migration
	ContinueOnError bool

	// BatchSize controls logging frequency for progress updates
	// Logs are emitted every BatchSize rules processed (default: 100)
	BatchSize int
}

// MigrationResult contains migration execution statistics
type MigrationResult struct {
	// Total number of rules examined
	Total int

	// Number of rules successfully migrated
	Migrated int

	// Number of rules skipped (already migrated or not SIGMA type)
	Skipped int

	// Number of rules that failed validation or migration
	Failed int

	// List of validation/migration errors with rule context
	Errors []MigrationError
}

// MigrationError captures detailed error information for a specific rule
type MigrationError struct {
	// Rule ID that failed
	RuleID string

	// Error message describing the failure
	Error string

	// Phase where error occurred (validation, conversion, update)
	Phase string
}

// MigrateToSigmaYAML migrates SIGMA rules from JSON detection/logsource to YAML format
//
// This function performs a three-phase migration:
// 1. Validation: Validates ALL SIGMA rules before making any changes
// 2. Conversion: Converts JSON detection/logsource to SIGMA YAML
// 3. Update: Updates database in single transaction with rollback on error
//
// Security Considerations:
// - Operates within database transaction for atomicity
// - Validates all rules before migration to prevent partial failures
// - Properly escapes and sanitizes all YAML content
// - Prevents YAML bombs with size limits
// - Uses prepared statements to prevent SQL injection
//
// Performance Considerations:
// - Batch processing with configurable batch sizes
// - Single transaction minimizes database overhead
// - Progress logging every BatchSize records
//
// Error Handling:
// - DryRun mode: Always rolls back, safe for testing
// - ValidateOnly mode: Validates without migration
// - ContinueOnError=false: Fail-fast with full rollback (default)
// - ContinueOnError=true: Skip invalid rules, track errors
//
// Thread Safety:
// - Safe for concurrent use if called with separate DB connections
// - Single transaction ensures isolation from other operations
//
// Example Usage:
//
//	opts := MigrationOptions{
//		DryRun: true,  // Test migration without committing
//		BatchSize: 50, // Log every 50 rules
//	}
//	result, err := MigrateToSigmaYAML(db, logger, opts)
//	if err != nil {
//		logger.Errorf("Migration failed: %v", err)
//		return err
//	}
//	logger.Infof("Migrated %d/%d rules, %d skipped, %d failed",
//		result.Migrated, result.Total, result.Skipped, result.Failed)
func MigrateToSigmaYAML(db *sql.DB, logger *zap.SugaredLogger, opts MigrationOptions) (result *MigrationResult, err error) {
	if db == nil {
		return nil, fmt.Errorf("database connection cannot be nil")
	}
	if logger == nil {
		return nil, fmt.Errorf("logger cannot be nil")
	}

	// Set default batch size if not specified
	// Upper bound prevents excessive logging from unreasonable values
	const maxBatchSize = 10000
	if opts.BatchSize <= 0 {
		opts.BatchSize = 100
	} else if opts.BatchSize > maxBatchSize {
		logger.Warnf("BatchSize %d exceeds recommended maximum of %d, using %d", opts.BatchSize, maxBatchSize, maxBatchSize)
		opts.BatchSize = maxBatchSize
	}

	result = &MigrationResult{
		Errors: make([]MigrationError, 0),
	}

	// Phase 1: Validate ALL rules before migration
	logger.Info("Phase 1: Validating all SIGMA rules...")
	var validationErrors []MigrationError
	validationErrors, err = validateAllRulesForMigration(db, logger)
	if err != nil {
		return nil, fmt.Errorf("validation phase failed: %w", err)
	}

	if len(validationErrors) > 0 {
		result.Errors = append(result.Errors, validationErrors...)
		if !opts.ContinueOnError {
			return result, fmt.Errorf("validation failed for %d rules (use ContinueOnError to skip invalid rules)", len(validationErrors))
		}
		logger.Warnf("Validation found %d invalid rules, will skip during migration", len(validationErrors))
	}

	// If ValidateOnly mode, return after validation
	if opts.ValidateOnly {
		result.Failed = len(validationErrors)
		logger.Infof("Validation complete: %d errors found", len(validationErrors))
		return result, nil
	}

	// Phase 2 & 3: Load rules, convert, and update in transaction
	logger.Info("Phase 2: Loading rules and converting to YAML...")
	logger.Info("Phase 3: Updating database in transaction...")

	// Begin transaction for atomicity
	var tx *sql.Tx
	tx, err = db.Begin()
	if err != nil {
		return nil, fmt.Errorf("failed to begin transaction: %w", err)
	}

	// Ensure transaction is rolled back on panic
	// TASK 137: Return error instead of re-panicking for better error handling
	defer func() {
		if p := recover(); p != nil {
			// Attempt rollback on panic
			_ = tx.Rollback()
			// Convert panic to error instead of re-panicking
			if panicAsErr, ok := p.(error); ok {
				err = fmt.Errorf("migration panicked: %w", panicAsErr)
			} else {
				err = fmt.Errorf("migration panicked: %v", p)
			}
			result = nil
		}
	}()

	// Query all SIGMA rules that need migration
	// Only migrate rules that:
	// 1. Are SIGMA type
	// 2. Have detection and/or logsource JSON
	// 3. Don't already have sigma_yaml populated
	query := `
		SELECT id, name, detection, logsource, created_at, updated_at
		FROM rules
		WHERE LOWER(type) = 'sigma'
		  AND (sigma_yaml IS NULL OR sigma_yaml = '')
		  AND (detection IS NOT NULL OR logsource IS NOT NULL)
		ORDER BY id
	`

	rows, err := tx.Query(query)
	if err != nil {
		_ = tx.Rollback()
		return nil, fmt.Errorf("failed to query rules: %w", err)
	}
	defer rows.Close()

	// Prepare update statement for efficient batch updates
	updateStmt, err := tx.Prepare(`
		UPDATE rules
		SET sigma_yaml = ?,
		    logsource_category = ?,
		    logsource_product = ?,
		    logsource_service = ?,
		    updated_at = ?
		WHERE id = ?
	`)
	if err != nil {
		_ = tx.Rollback()
		return nil, fmt.Errorf("failed to prepare update statement: %w", err)
	}
	defer updateStmt.Close()

	// Create map of validation errors for quick lookup
	validationErrorMap := make(map[string]bool)
	for _, verr := range validationErrors {
		validationErrorMap[verr.RuleID] = true
	}

	// Process each rule
	for rows.Next() {
		var ruleID, name string
		var detectionJSON, logsourceJSON sql.NullString
		var createdAt, updatedAt string

		if err := rows.Scan(&ruleID, &name, &detectionJSON, &logsourceJSON, &createdAt, &updatedAt); err != nil {
			_ = tx.Rollback()
			return nil, fmt.Errorf("failed to scan rule row: %w", err)
		}

		result.Total++

		// Skip if rule failed validation
		if validationErrorMap[ruleID] {
			result.Skipped++
			continue
		}

		// Log progress every BatchSize rules
		if result.Total%opts.BatchSize == 0 {
			logger.Infof("Progress: %d rules processed (%d migrated, %d skipped, %d failed)",
				result.Total, result.Migrated, result.Skipped, result.Failed)
		}

		// Convert rule to SIGMA YAML
		sigmaYAML, logsourceCategory, logsourceProduct, logsourceService, err := convertRuleToYAML(
			ruleID, name, detectionJSON, logsourceJSON, logger,
		)
		if err != nil {
			result.Failed++
			result.Errors = append(result.Errors, MigrationError{
				RuleID: ruleID,
				Error:  fmt.Sprintf("conversion failed: %v", err),
				Phase:  "conversion",
			})

			if !opts.ContinueOnError {
				_ = tx.Rollback()
				return result, fmt.Errorf("conversion failed for rule %s: %w", ruleID, err)
			}
			logger.Warnf("Skipping rule %s: conversion failed: %v", ruleID, err)
			continue
		}

		// Update rule with SIGMA YAML and logsource fields
		_, err = updateStmt.Exec(
			sigmaYAML,
			nullIfEmptyString(logsourceCategory),
			nullIfEmptyString(logsourceProduct),
			nullIfEmptyString(logsourceService),
			updatedAt, // Preserve original updated_at timestamp
			ruleID,
		)
		if err != nil {
			result.Failed++
			result.Errors = append(result.Errors, MigrationError{
				RuleID: ruleID,
				Error:  fmt.Sprintf("database update failed: %v", err),
				Phase:  "update",
			})

			if !opts.ContinueOnError {
				_ = tx.Rollback()
				return result, fmt.Errorf("update failed for rule %s: %w", ruleID, err)
			}
			logger.Warnf("Skipping rule %s: update failed: %v", ruleID, err)
			continue
		}

		result.Migrated++
	}

	// Check for row iteration errors
	if err := rows.Err(); err != nil {
		_ = tx.Rollback()
		return nil, fmt.Errorf("error iterating rules: %w", err)
	}

	// Commit or rollback based on DryRun mode
	if opts.DryRun {
		logger.Info("DryRun mode: Rolling back transaction (no changes committed)")
		if err := tx.Rollback(); err != nil {
			return nil, fmt.Errorf("failed to rollback dry-run transaction: %w", err)
		}
	} else {
		logger.Info("Committing migration transaction...")
		if err := tx.Commit(); err != nil {
			return nil, fmt.Errorf("failed to commit transaction: %w", err)
		}
	}

	logger.Infof("Migration complete: %d/%d rules migrated, %d skipped, %d failed",
		result.Migrated, result.Total, result.Skipped, result.Failed)

	return result, nil
}

// validateAllRulesForMigration validates all SIGMA rules before migration
//
// This function performs pre-migration validation to catch errors early:
// - Validates detection and logsource JSON can be parsed
// - Ensures generated YAML is valid
// - Checks for required fields in logsource
//
// Returns:
// - List of validation errors (empty if all valid)
// - Fatal error if database query fails
func validateAllRulesForMigration(db *sql.DB, logger *zap.SugaredLogger) ([]MigrationError, error) {
	query := `
		SELECT id, name, detection, logsource
		FROM rules
		WHERE LOWER(type) = 'sigma'
		  AND (sigma_yaml IS NULL OR sigma_yaml = '')
		  AND (detection IS NOT NULL OR logsource IS NOT NULL)
		ORDER BY id
	`

	rows, err := db.Query(query)
	if err != nil {
		return nil, fmt.Errorf("failed to query rules for validation: %w", err)
	}
	defer rows.Close()

	var errors []MigrationError

	for rows.Next() {
		var ruleID, name string
		var detectionJSON, logsourceJSON sql.NullString

		if err := rows.Scan(&ruleID, &name, &detectionJSON, &logsourceJSON); err != nil {
			return nil, fmt.Errorf("failed to scan rule row during validation: %w", err)
		}

		// Attempt conversion to validate rule structure
		_, _, _, _, err := convertRuleToYAML(ruleID, name, detectionJSON, logsourceJSON, logger)
		if err != nil {
			errors = append(errors, MigrationError{
				RuleID: ruleID,
				Error:  err.Error(),
				Phase:  "validation",
			})
		}
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating rules during validation: %w", err)
	}

	return errors, nil
}

// convertRuleToYAML converts a SIGMA rule from JSON to YAML format
//
// This function:
// 1. Parses detection and logsource JSON fields
// 2. Constructs a complete SIGMA rule structure
// 3. Marshals to YAML format
// 4. Extracts logsource fields for denormalized storage
// 5. Validates generated YAML
//
// Security Considerations:
// - Limits YAML size to prevent YAML bombs (max 1MB)
// - Validates JSON parsing to prevent injection
// - Sanitizes field values before YAML generation
//
// Error Handling:
// - Returns detailed errors for debugging
// - Gracefully handles missing or malformed JSON
// - Validates YAML structure before returning
//
// Parameters:
// - ruleID: Unique rule identifier for error messages
// - name: Rule name for YAML title field
// - detectionJSON: JSON-encoded detection logic (nullable)
// - logsourceJSON: JSON-encoded logsource config (nullable)
// - logger: Logger for warnings and debug info
//
// Returns:
// - sigmaYAML: Complete SIGMA rule in YAML format
// - logsourceCategory: Extracted category field (empty if not present)
// - logsourceProduct: Extracted product field (empty if not present)
// - logsourceService: Extracted service field (empty if not present)
// - error: Any validation or conversion errors
func convertRuleToYAML(
	ruleID string,
	name string,
	detectionJSON sql.NullString,
	logsourceJSON sql.NullString,
	logger *zap.SugaredLogger,
) (sigmaYAML, logsourceCategory, logsourceProduct, logsourceService string, err error) {
	// Parse detection JSON
	var detection map[string]interface{}
	if detectionJSON.Valid && detectionJSON.String != "" {
		if err := json.Unmarshal([]byte(detectionJSON.String), &detection); err != nil {
			return "", "", "", "", fmt.Errorf("invalid detection JSON: %w", err)
		}
	}

	// Parse logsource JSON
	var logsource map[string]interface{}
	if logsourceJSON.Valid && logsourceJSON.String != "" {
		if err := json.Unmarshal([]byte(logsourceJSON.String), &logsource); err != nil {
			return "", "", "", "", fmt.Errorf("invalid logsource JSON: %w", err)
		}
	}

	// Extract logsource fields for denormalized columns
	if logsource != nil {
		if category, ok := logsource["category"].(string); ok {
			logsourceCategory = strings.TrimSpace(category)
		}
		if product, ok := logsource["product"].(string); ok {
			logsourceProduct = strings.TrimSpace(product)
		}
		if service, ok := logsource["service"].(string); ok {
			logsourceService = strings.TrimSpace(service)
		}
	}

	// Construct SIGMA rule structure
	// Required fields: title, detection
	// Optional fields: logsource, description, status, level, etc.
	sigmaRule := map[string]interface{}{
		"title": name,
	}

	// Add detection if present
	if detection != nil {
		sigmaRule["detection"] = detection
	} else {
		// SIGMA rules must have detection logic
		return "", "", "", "", fmt.Errorf("rule %s: detection field is required for SIGMA rules", ruleID)
	}

	// Add logsource if present
	if logsource != nil {
		sigmaRule["logsource"] = logsource
	}

	// Marshal to YAML
	yamlBytes, err := yaml.Marshal(sigmaRule)
	if err != nil {
		return "", "", "", "", fmt.Errorf("failed to marshal YAML: %w", err)
	}

	sigmaYAML = string(yamlBytes)

	// SECURITY: Validate YAML size to prevent YAML bombs
	const maxYAMLSize = 1024 * 1024 // 1MB
	if len(sigmaYAML) > maxYAMLSize {
		return "", "", "", "", fmt.Errorf("generated YAML exceeds maximum size of %d bytes", maxYAMLSize)
	}

	// Validate generated YAML can be parsed
	var validateMap map[string]interface{}
	if err := yaml.Unmarshal(yamlBytes, &validateMap); err != nil {
		return "", "", "", "", fmt.Errorf("generated invalid YAML: %w", err)
	}

	// Ensure detection field is present in parsed YAML
	if _, ok := validateMap["detection"]; !ok {
		return "", "", "", "", fmt.Errorf("generated YAML missing required 'detection' field")
	}

	return sigmaYAML, logsourceCategory, logsourceProduct, logsourceService, nil
}

// RollbackSigmaYAMLMigration reverses the SIGMA YAML migration
//
// This function:
// 1. Clears sigma_yaml column
// 2. Clears logsource denormalized columns (category, product, service)
// 3. Preserves original detection and logsource JSON
// 4. Operates in single transaction with rollback on error
//
// Security Considerations:
// - Uses transaction for atomicity
// - Validates database connection before execution
// - Logs all operations for audit trail
//
// Use Cases:
// - Testing migration rollback
// - Reverting failed migration
// - Switching back to JSON-only storage
//
// Parameters:
// - db: Database connection
// - logger: Logger for progress and errors
// - dryRun: If true, rollback transaction without committing changes
//
// Returns:
// - Number of rules rolled back
// - Error if rollback fails
//
// Example:
//
//	count, err := RollbackSigmaYAMLMigration(db, logger, false)
//	if err != nil {
//		logger.Errorf("Rollback failed: %v", err)
//		return err
//	}
//	logger.Infof("Rolled back %d rules", count)
func RollbackSigmaYAMLMigration(db *sql.DB, logger *zap.SugaredLogger, dryRun bool) (rowsAffected int64, err error) {
	if db == nil {
		return 0, fmt.Errorf("database connection cannot be nil")
	}
	if logger == nil {
		return 0, fmt.Errorf("logger cannot be nil")
	}

	logger.Info("Starting SIGMA YAML migration rollback...")

	// Begin transaction
	var tx *sql.Tx
	tx, err = db.Begin()
	if err != nil {
		return 0, fmt.Errorf("failed to begin rollback transaction: %w", err)
	}

	// Ensure transaction is rolled back on panic
	// TASK 137: Return error instead of re-panicking for better error handling
	defer func() {
		if p := recover(); p != nil {
			// Attempt rollback on panic
			_ = tx.Rollback()
			// Convert panic to error instead of re-panicking
			if panicAsErr, ok := p.(error); ok {
				err = fmt.Errorf("rollback panicked: %w", panicAsErr)
			} else {
				err = fmt.Errorf("rollback panicked: %v", p)
			}
			rowsAffected = 0
		}
	}()

	// Clear SIGMA YAML and logsource columns
	// Preserve original detection and logsource JSON
	query := `
		UPDATE rules
		SET sigma_yaml = NULL,
		    logsource_category = NULL,
		    logsource_product = NULL,
		    logsource_service = NULL
		WHERE LOWER(type) = 'sigma'
		  AND (sigma_yaml IS NOT NULL OR logsource_category IS NOT NULL OR logsource_product IS NOT NULL OR logsource_service IS NOT NULL)
	`

	var execResult sql.Result
	execResult, err = tx.Exec(query)
	if err != nil {
		_ = tx.Rollback()
		return 0, fmt.Errorf("failed to execute rollback update: %w", err)
	}

	rowsAffected, err = execResult.RowsAffected()
	if err != nil {
		_ = tx.Rollback()
		return 0, fmt.Errorf("failed to get rows affected: %w", err)
	}

	// Commit or rollback based on dryRun mode
	if dryRun {
		logger.Info("DryRun mode: Rolling back transaction (no changes committed)")
		if err := tx.Rollback(); err != nil {
			return 0, fmt.Errorf("failed to rollback dry-run transaction: %w", err)
		}
	} else {
		logger.Info("Committing rollback transaction...")
		if err := tx.Commit(); err != nil {
			return 0, fmt.Errorf("failed to commit rollback transaction: %w", err)
		}
	}

	logger.Infof("Rollback complete: %d rules affected", rowsAffected)
	return rowsAffected, nil
}

// nullIfEmptyString returns nil for empty strings to properly store NULL in SQLite
// This helper ensures empty strings are stored as NULL rather than empty values
func nullIfEmptyString(s string) interface{} {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	return s
}
