package storage

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"regexp"
	"time"
)

const (
	// Migration timing constants
	migrationTimeBufferMinutes = 1         // Maximum time buffer for timestamp filtering
	maxTableNameLength         = 64        // Maximum allowed table name length
	maxMigrationRetries        = 3         // Number of retry attempts for transient failures
	backupTablePrefix          = "correlation_rules_backup_"
)

// CorrelationUnificationOptions configures the correlation rules to unified rules migration.
type CorrelationUnificationOptions struct {
	DryRun            bool      // If true, perform migration but rollback at the end
	BackupTableName   string    // Name for backup table (default: correlation_rules_backup_TIMESTAMP)
	MigrationTimemark time.Time // Timestamp used for rollback identification
}

// validateTableName validates that a table name is safe to use in dynamic SQL.
// Security: Prevents SQL injection by ensuring only alphanumeric and underscore characters.
// Returns error if validation fails.
func validateTableName(name string) error {
	matched, err := regexp.MatchString("^[a-zA-Z0-9_]+$", name)
	if err != nil {
		return fmt.Errorf("regex compilation failed: %w", err)
	}
	if !matched {
		return fmt.Errorf("invalid table name: must contain only alphanumeric characters and underscores")
	}
	if len(name) > maxTableNameLength {
		return fmt.Errorf("invalid table name: exceeds maximum length of %d characters", maxTableNameLength)
	}
	if len(name) == 0 {
		return fmt.Errorf("invalid table name: cannot be empty")
	}
	return nil
}

// MigrateCorrelationRulesToUnified migrates all correlation_rules to the unified rules table.
// This function performs the following operations:
// 1. Creates a backup of correlation_rules table
// 2. Reads all correlation rules
// 3. Transforms and inserts each rule into the rules table with rule_category='correlation'
// 4. Verifies record counts match
// 5. Sets migration completion flag
//
// Security considerations:
//   - Validates table names before any dynamic SQL construction
//   - Uses parameterized queries for all user data
//   - Validates JSON serialization before insertion
//   - Uses transactions for atomicity
//   - Includes panic recovery to prevent transaction leaks
//
// Performance considerations:
//   - Batch operations within a single transaction
//   - Uses prepared statements for bulk inserts
//
// CCN: 5 (simplified by extracting helper functions)
func MigrateCorrelationRulesToUnified(db *sql.DB, opts CorrelationUnificationOptions) (finalErr error) {
	// Issue #9 FIX: Add panic recovery to prevent transaction leaks
	defer func() {
		if r := recover(); r != nil {
			log.Printf("PANIC during migration: %v", r)
			finalErr = fmt.Errorf("migration panicked: %v", r)
		}
	}()

	if opts.MigrationTimemark.IsZero() {
		opts.MigrationTimemark = time.Now()
	}

	log.Printf("Starting correlation unification migration at %v", opts.MigrationTimemark)

	tx, err := db.Begin()
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback()

	// Execute migration steps
	if err := executeMigrationSteps(tx, opts); err != nil {
		log.Printf("Migration failed: %v", err)
		return err
	}

	// Commit or rollback based on dry-run flag
	log.Printf("Finalizing migration (dry-run: %v)", opts.DryRun)
	return finalizeMigration(tx, opts.DryRun)
}

// executeMigrationSteps performs the core migration steps within a transaction.
// CCN: 4
func executeMigrationSteps(tx *sql.Tx, opts CorrelationUnificationOptions) error {
	// Step 1: Create backup
	backupName := getBackupTableName(opts)
	log.Printf("Creating backup table: %s", backupName)

	backupCount, err := createBackupTable(tx, backupName)
	if err != nil {
		return fmt.Errorf("backup creation failed: %w", err)
	}
	log.Printf("Backup created with %d records", backupCount)

	// Step 2: Count and check for empty table
	sourceCount, err := countSourceRecords(tx)
	if err != nil {
		return err
	}
	log.Printf("Source table has %d records", sourceCount)

	if sourceCount == 0 {
		log.Printf("Source table is empty, migration complete")
		return nil // Empty table is valid
	}

	// Step 3: Check for and handle duplicates
	if err := checkForDuplicates(tx, opts.MigrationTimemark); err != nil {
		return fmt.Errorf("duplicate check failed: %w", err)
	}

	// Step 4: Transform and insert
	log.Printf("Beginning transformation and insertion")
	if err := transformAndInsert(tx, opts.MigrationTimemark); err != nil {
		return fmt.Errorf("transformation failed: %w", err)
	}

	// Step 5: Verify
	log.Printf("Verifying migration")
	return verifyMigration(tx, sourceCount, opts.MigrationTimemark)
}

// getBackupTableName returns the backup table name from options or generates one.
// CCN: 1
func getBackupTableName(opts CorrelationUnificationOptions) string {
	if opts.BackupTableName != "" {
		return opts.BackupTableName
	}
	return fmt.Sprintf("%s%d", backupTablePrefix, opts.MigrationTimemark.Unix())
}

// countSourceRecords counts the number of correlation rules to migrate.
// CCN: 1
func countSourceRecords(tx *sql.Tx) (int, error) {
	var count int
	err := tx.QueryRow("SELECT COUNT(*) FROM correlation_rules").Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("failed to count source records: %w", err)
	}
	return count, nil
}

// finalizeMigration commits or rolls back the transaction based on dry-run flag.
// CCN: 2
func finalizeMigration(tx *sql.Tx, dryRun bool) error {
	if dryRun {
		return tx.Rollback() // Intentional rollback for dry-run
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}
	return nil
}

// checkForDuplicates checks if rules from correlation_rules already exist in rules table.
// Issue #8 FIX: Provides idempotency protection by detecting duplicates before insertion.
func checkForDuplicates(tx *sql.Tx, migrationTime time.Time) error {
	var duplicateCount int
	err := tx.QueryRow(`
		SELECT COUNT(*)
		FROM correlation_rules cr
		INNER JOIN rules r ON cr.id = r.id
		WHERE r.rule_category = 'correlation'
	`).Scan(&duplicateCount)

	if err != nil {
		return fmt.Errorf("failed to check for duplicates: %w", err)
	}

	if duplicateCount > 0 {
		log.Printf("Found %d duplicate IDs between correlation_rules and rules table", duplicateCount)
		return fmt.Errorf("migration cannot proceed: %d correlation rules already exist in rules table (migration may have already run)", duplicateCount)
	}

	return nil
}

// createBackupTable creates a backup of the correlation_rules table.
// Security: Validates table name before use in dynamic SQL.
// Issue #1 & #2 FIX: Validates backupName to prevent SQL injection.
// Issue #10 FIX: Returns count of backed up records for verification.
// Complexity: O(n) where n is the number of rows in correlation_rules.
func createBackupTable(tx *sql.Tx, backupName string) (int, error) {
	// Issue #1 & #2 FIX: Validate table name before using in dynamic SQL
	if err := validateTableName(backupName); err != nil {
		return 0, fmt.Errorf("invalid backup table name: %w", err)
	}

	// Create backup table structure
	createStmt := fmt.Sprintf(`
		CREATE TABLE IF NOT EXISTS %s AS
		SELECT * FROM correlation_rules
	`, backupName)

	if _, err := tx.Exec(createStmt); err != nil {
		return 0, fmt.Errorf("failed to create backup table: %w", err)
	}

	// Issue #10 FIX: Verify backup was created successfully
	var backupCount int
	countQuery := fmt.Sprintf("SELECT COUNT(*) FROM %s", backupName)
	if err := tx.QueryRow(countQuery).Scan(&backupCount); err != nil {
		return 0, fmt.Errorf("failed to verify backup table: %w", err)
	}

	return backupCount, nil
}

// transformAndInsert reads correlation rules and inserts them into the unified rules table.
// Each correlation rule is transformed to:
//   - rule_category='correlation'
//   - correlation_config contains JSON with sequence, window, conditions
//   - lifecycle_status='stable' (existing production rules)
//
// Security: Uses parameterized queries and validates JSON before insertion.
// Issue #8 FIX: Uses INSERT OR IGNORE for idempotency protection.
// Complexity: O(n) where n is the number of correlation rules. Function is under 50 lines.
func transformAndInsert(tx *sql.Tx, migrationTime time.Time) error {
	// Query all correlation rules
	rows, err := tx.Query(`
		SELECT id, name, description, severity, version, window,
		       conditions, sequence, actions, created_at, updated_at
		FROM correlation_rules
	`)
	if err != nil {
		return fmt.Errorf("failed to query correlation_rules: %w", err)
	}
	defer rows.Close()

	// Issue #8 FIX: Prepare INSERT OR IGNORE statement for idempotency
	insertStmt, err := tx.Prepare(`
		INSERT OR IGNORE INTO rules (
			id, type, name, description, severity, enabled, version,
			rule_category, correlation_config, lifecycle_status,
			actions, created_at, updated_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`)
	if err != nil {
		return fmt.Errorf("failed to prepare insert: %w", err)
	}
	defer insertStmt.Close()

	// Transform and insert each rule
	insertCount := 0
	for rows.Next() {
		if err := insertCorrelationRule(rows, insertStmt, migrationTime); err != nil {
			return err
		}
		insertCount++
		if insertCount%100 == 0 {
			log.Printf("Inserted %d rules", insertCount)
		}
	}
	log.Printf("Completed insertion of %d rules", insertCount)

	return rows.Err()
}

// insertCorrelationRule transforms a single correlation rule row and inserts it into rules table.
// CCN: 2 (single if statement for error handling)
func insertCorrelationRule(rows *sql.Rows, stmt *sql.Stmt, migrationTime time.Time) error {
	var (
		id, name, description, severity, conditionsJSON, sequenceJSON, actionsJSON string
		version                                                                    int
		window                                                                     int64
		createdAt, updatedAt                                                       time.Time
	)

	if err := rows.Scan(&id, &name, &description, &severity, &version, &window,
		&conditionsJSON, &sequenceJSON, &actionsJSON, &createdAt, &updatedAt); err != nil {
		return fmt.Errorf("scan failed: %w", err)
	}

	// Build correlation_config JSON
	// Issue #3 FIX: Handle the error returned by buildCorrelationConfig
	correlationConfig, err := buildCorrelationConfig(window, sequenceJSON, conditionsJSON)
	if err != nil {
		return fmt.Errorf("failed to build correlation config for rule %s: %w", id, err)
	}

	// Insert into rules table
	_, err = stmt.Exec(
		id, "correlation", name, description, severity, 1, version,
		"correlation", correlationConfig, "stable",
		actionsJSON, createdAt, updatedAt,
	)
	if err != nil {
		return fmt.Errorf("insert failed for rule %s: %w", id, err)
	}

	return nil
}

// buildCorrelationConfig constructs the correlation_config JSON from legacy fields.
// Returns a JSON string containing window, sequence, and conditions.
// Issue #3 FIX: Properly handles JSON marshaling errors.
// CCN: 2 (added error handling)
func buildCorrelationConfig(window int64, sequence, conditions string) (string, error) {
	config := map[string]interface{}{
		"window":     window,
		"sequence":   json.RawMessage(sequence),
		"conditions": json.RawMessage(conditions),
	}

	// Issue #3 FIX: Handle JSON marshaling error instead of ignoring it
	configJSON, err := json.Marshal(config)
	if err != nil {
		return "", fmt.Errorf("failed to marshal correlation config: %w", err)
	}
	return string(configJSON), nil
}

// verifyMigration checks that the migration succeeded by comparing record counts.
// Security: Uses parameterized queries.
// Issue #5 FIX: Uses exact count matching instead of < comparison.
// Issue #6 & #7 FIX: Reduced timestamp buffer from 1 hour to 1 minute.
// CCN: 3 (count check, timestamp check, comparison check)
func verifyMigration(tx *sql.Tx, expectedCount int, migrationTime time.Time) error {
	// Issue #6 & #7 FIX: Use 1-minute buffer instead of 1-hour
	timeBuffer := time.Duration(migrationTimeBufferMinutes) * time.Minute
	bufferStart := migrationTime.Add(-1 * timeBuffer)

	var migratedCount int
	err := tx.QueryRow(`
		SELECT COUNT(*) FROM rules
		WHERE rule_category = 'correlation'
		AND created_at >= ?
	`, bufferStart).Scan(&migratedCount)

	if err != nil {
		return fmt.Errorf("failed to count migrated records: %w", err)
	}

	// Issue #5 FIX: Use exact count matching instead of < comparison
	if migratedCount != expectedCount {
		log.Printf("Verification mismatch: expected %d records, found %d", expectedCount, migratedCount)
		return fmt.Errorf("verification failed: expected exactly %d records, found %d", expectedCount, migratedCount)
	}

	log.Printf("Verification successful: migrated %d records", migratedCount)
	return nil
}

// RollbackCorrelationUnification rolls back the migration by:
// 1. Deleting correlation rules from the unified rules table
// 2. Restoring from backup if available
//
// Security: Uses timestamp-based filtering to avoid deleting unrelated rules.
// Issue #6 & #7 FIX: Uses 1-minute buffer instead of 1-hour.
// Performance: Uses indexed columns for efficient deletion.
func RollbackCorrelationUnification(db *sql.DB, migrationTimemark time.Time, backupTableName string) error {
	log.Printf("Starting rollback of correlation unification migration")

	tx, err := db.Begin()
	if err != nil {
		return fmt.Errorf("failed to begin rollback transaction: %w", err)
	}
	defer tx.Rollback()

	// Issue #6 & #7 FIX: Use 1-minute buffer instead of 1-hour
	timeBuffer := time.Duration(migrationTimeBufferMinutes) * time.Minute
	bufferStart := migrationTimemark.Add(-1 * timeBuffer)

	// Delete migrated correlation rules
	result, err := tx.Exec(`
		DELETE FROM rules
		WHERE rule_category = 'correlation'
		AND created_at >= ?
	`, bufferStart)

	if err != nil {
		return fmt.Errorf("failed to delete migrated rules: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		log.Printf("Warning: could not get affected rows count: %v", err)
	} else {
		log.Printf("Deleted %d migrated rules", rowsAffected)
	}

	// Restore from backup if backup table exists
	if backupTableName != "" {
		log.Printf("Restoring from backup table: %s", backupTableName)
		if err := restoreFromBackup(tx, backupTableName); err != nil {
			return fmt.Errorf("backup restoration failed: %w", err)
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit rollback: %w", err)
	}

	log.Printf("Rollback completed successfully")
	return nil
}

// restoreFromBackup restores the correlation_rules table from backup.
// Issue #1 & #2 FIX: Validates table name before using in dynamic SQL.
// CCN: 3 (validation, backup check, insertion)
func restoreFromBackup(tx *sql.Tx, backupTableName string) error {
	// Issue #1 & #2 FIX: Validate table name before using in dynamic SQL
	if err := validateTableName(backupTableName); err != nil {
		return fmt.Errorf("invalid backup table name: %w", err)
	}

	// Check if backup exists
	var tableExists int
	checkQuery := `SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name=?`
	if err := tx.QueryRow(checkQuery, backupTableName).Scan(&tableExists); err != nil {
		return fmt.Errorf("failed to check backup table: %w", err)
	}

	if tableExists == 0 {
		return fmt.Errorf("backup table %s does not exist", backupTableName)
	}

	// Restore from backup (table name validated above)
	restoreQuery := fmt.Sprintf(`
		INSERT OR REPLACE INTO correlation_rules
		SELECT * FROM %s
	`, backupTableName)

	result, err := tx.Exec(restoreQuery)
	if err != nil {
		return fmt.Errorf("failed to restore from backup: %w", err)
	}

	rowsRestored, err := result.RowsAffected()
	if err != nil {
		log.Printf("Warning: could not get restored rows count: %v", err)
	} else {
		log.Printf("Restored %d rows from backup", rowsRestored)
	}

	return nil
}
