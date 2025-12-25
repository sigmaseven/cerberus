package storage

// This file contains usage examples for the correlation rules migration functionality.
// These examples demonstrate how to use the migration in production scenarios.

import (
	"database/sql"
	"fmt"
	"log"
	"time"
)

// ExampleMigrateCorrelationRulesToUnified_Production demonstrates production usage.
func ExampleMigrateCorrelationRulesToUnified_Production() {
	// Open database connection
	db, err := sql.Open("sqlite", "cerberus.db")
	if err != nil {
		log.Fatalf("Failed to open database: %v", err)
	}
	defer db.Close()

	// Configure migration options
	opts := CorrelationUnificationOptions{
		DryRun:            false, // Set to true for testing
		BackupTableName:   fmt.Sprintf("correlation_rules_backup_%s", time.Now().Format("20060102_150405")),
		MigrationTimemark: time.Now(),
	}

	// Execute migration
	log.Printf("Starting correlation rules migration...")
	if err := MigrateCorrelationRulesToUnified(db, opts); err != nil {
		log.Fatalf("Migration failed: %v", err)
	}

	log.Printf("Migration completed successfully")
	log.Printf("Backup table: %s", opts.BackupTableName)
}

// ExampleMigrateCorrelationRulesToUnified_DryRun demonstrates testing before production.
func ExampleMigrateCorrelationRulesToUnified_DryRun() {
	db, err := sql.Open("sqlite", "cerberus.db")
	if err != nil {
		log.Fatalf("Failed to open database: %v", err)
	}
	defer db.Close()

	// Run with DryRun=true to test without committing
	opts := CorrelationUnificationOptions{
		DryRun:            true, // No changes will be persisted
		MigrationTimemark: time.Now(),
	}

	log.Printf("Running migration in dry-run mode...")
	if err := MigrateCorrelationRulesToUnified(db, opts); err != nil {
		log.Fatalf("Dry-run failed: %v", err)
	}

	log.Printf("Dry-run completed successfully (no changes committed)")

	// Verify nothing was actually changed
	var count int
	db.QueryRow("SELECT COUNT(*) FROM rules WHERE rule_category='correlation'").Scan(&count)
	log.Printf("Correlation rules in unified table: %d (should be 0 for dry-run)", count)
}

// ExampleRollbackCorrelationUnification demonstrates rollback functionality.
func ExampleRollbackCorrelationUnification() {
	db, err := sql.Open("sqlite", "cerberus.db")
	if err != nil {
		log.Fatalf("Failed to open database: %v", err)
	}
	defer db.Close()

	// Rollback using the migration timestamp and backup table name
	migrationTimestamp := time.Date(2025, 1, 15, 10, 30, 0, 0, time.UTC)
	backupTableName := "correlation_rules_backup_20250115_103000"

	log.Printf("Rolling back migration...")
	if err := RollbackCorrelationUnification(db, migrationTimestamp, backupTableName); err != nil {
		log.Fatalf("Rollback failed: %v", err)
	}

	log.Printf("Rollback completed successfully")
	log.Printf("Correlation rules restored from backup: %s", backupTableName)
}

// ExampleMigrateCorrelationRulesToUnified_WithVerification demonstrates post-migration verification.
func ExampleMigrateCorrelationRulesToUnified_WithVerification() {
	db, err := sql.Open("sqlite", "cerberus.db")
	if err != nil {
		log.Fatalf("Failed to open database: %v", err)
	}
	defer db.Close()

	// Count records before migration
	var countBefore int
	db.QueryRow("SELECT COUNT(*) FROM correlation_rules").Scan(&countBefore)
	log.Printf("Correlation rules before migration: %d", countBefore)

	// Execute migration
	opts := CorrelationUnificationOptions{
		DryRun:            false,
		BackupTableName:   "correlation_rules_backup_verification",
		MigrationTimemark: time.Now(),
	}

	if err := MigrateCorrelationRulesToUnified(db, opts); err != nil {
		log.Fatalf("Migration failed: %v", err)
	}

	// Verify record counts
	var countAfter int
	db.QueryRow("SELECT COUNT(*) FROM rules WHERE rule_category='correlation'").Scan(&countAfter)
	log.Printf("Correlation rules after migration: %d", countAfter)

	if countBefore != countAfter {
		log.Fatalf("Record count mismatch: before=%d, after=%d", countBefore, countAfter)
	}

	log.Printf("Migration verified successfully: %d rules migrated", countAfter)
}

// ExampleMigrateCorrelationRulesToUnified_Incremental demonstrates handling partial migrations.
func ExampleMigrateCorrelationRulesToUnified_Incremental() {
	db, err := sql.Open("sqlite", "cerberus.db")
	if err != nil {
		log.Fatalf("Failed to open database: %v", err)
	}
	defer db.Close()

	// Check if migration already partially complete
	var existingCount int
	db.QueryRow("SELECT COUNT(*) FROM rules WHERE rule_category='correlation'").Scan(&existingCount)

	if existingCount > 0 {
		log.Printf("Found %d existing correlation rules in unified table", existingCount)
		log.Printf("Migration may have already been run. Verify before proceeding.")

		// Option 1: Skip migration
		log.Printf("Skipping migration (already complete)")
		return
	}

	// Option 2: Proceed with migration
	opts := CorrelationUnificationOptions{
		DryRun:            false,
		MigrationTimemark: time.Now(),
	}

	if err := MigrateCorrelationRulesToUnified(db, opts); err != nil {
		log.Fatalf("Migration failed: %v", err)
	}

	log.Printf("Migration completed successfully")
}
