package storage

import (
	"database/sql"
	"fmt"
)

// RegisterSQLiteMigrations registers all SQLite migrations with the runner
func RegisterSQLiteMigrations(runner *MigrationRunner) {
	// Base schema version - represents initial table creation
	// This doesn't actually run CREATE TABLE statements (they're in createTables)
	// but marks the base schema version as "applied" for tracking
	runner.Register(Migration{
		Version:     "1.0.0",
		Name:        "initial_schema",
		Description: "Base schema with all tables (rules, actions, correlation_rules, users, etc.)",
		Database:    "sqlite",
		Up: func(tx *sql.Tx) error {
			// No-op: Base tables created by createTables()
			// This migration exists for version tracking purposes
			return nil
		},
		Down: nil, // Cannot rollback initial schema
	})

	// Migration 1.1.0: Add unified rule columns (type, tags, mitre_*, author, etc.)
	runner.Register(Migration{
		Version:     "1.1.0",
		Name:        "add_unified_rule_columns",
		Description: "Add type, tags, mitre_tactics, mitre_techniques, author, rule_references, false_positives, metadata, query, correlation columns to rules table",
		Database:    "sqlite",
		Up: func(tx *sql.Tx) error {
			columns := []struct {
				name       string
				definition string
			}{
				{"type", "TEXT NOT NULL DEFAULT 'sigma'"},
				{"tags", "TEXT"},
				{"mitre_tactics", "TEXT"},
				{"mitre_techniques", "TEXT"},
				{"author", "TEXT"},
				{"rule_references", "TEXT"},
				{"false_positives", "TEXT"},
				{"metadata", "TEXT"},
				{"query", "TEXT"},
				{"correlation", "TEXT"},
			}

			for _, col := range columns {
				if err := addColumnIfNotExists(tx, "rules", col.name, col.definition); err != nil {
					return err
				}
			}

			// Create index for type column
			return createIndexIfNotExists(tx, "idx_rules_type", "rules", "type")
		},
		Down: func(tx *sql.Tx) error {
			// SQLite doesn't support DROP COLUMN in older versions
			// Would require table recreation - return nil for now
			return nil
		},
	})

	// Migration 1.2.0: Add RBAC role_id column to users table
	runner.Register(Migration{
		Version:     "1.2.0",
		Name:        "add_rbac_role_id",
		Description: "Add role_id foreign key column to users table for RBAC support",
		Database:    "sqlite",
		Up: func(tx *sql.Tx) error {
			if err := addColumnIfNotExists(tx, "users", "role_id", "INTEGER"); err != nil {
				return err
			}
			return createIndexIfNotExists(tx, "idx_users_role_id", "users", "role_id")
		},
		Down: func(tx *sql.Tx) error {
			return nil // SQLite doesn't support DROP COLUMN easily
		},
	})

	// Migration 1.3.0: Add security columns (MFA, account lockout)
	runner.Register(Migration{
		Version:     "1.3.0",
		Name:        "add_security_columns",
		Description: "Add totp_secret, mfa_enabled, failed_login_attempts, locked_until, password_changed_at columns to users table",
		Database:    "sqlite",
		Up: func(tx *sql.Tx) error {
			columns := []struct {
				name       string
				definition string
			}{
				{"totp_secret", "TEXT"},
				{"mfa_enabled", "INTEGER NOT NULL DEFAULT 0"},
				{"failed_login_attempts", "INTEGER NOT NULL DEFAULT 0"},
				{"locked_until", "DATETIME"},
				{"password_changed_at", "DATETIME"},
			}

			for _, col := range columns {
				if err := addColumnIfNotExists(tx, "users", col.name, col.definition); err != nil {
					return err
				}
			}
			return nil
		},
		Down: func(tx *sql.Tx) error {
			return nil // SQLite doesn't support DROP COLUMN easily
		},
	})

	// Migration 1.4.0: Add SIGMA YAML columns
	runner.Register(Migration{
		Version:     "1.4.0",
		Name:        "add_sigma_yaml_columns",
		Description: "Add sigma_yaml and denormalized logsource columns to rules table",
		Database:    "sqlite",
		Up: func(tx *sql.Tx) error {
			columns := []struct {
				name       string
				definition string
			}{
				{"sigma_yaml", "TEXT"},
				{"logsource_category", "TEXT"},
				{"logsource_product", "TEXT"},
				{"logsource_service", "TEXT"},
			}

			for _, col := range columns {
				if err := addColumnIfNotExists(tx, "rules", col.name, col.definition); err != nil {
					return err
				}
			}

			// Create indexes for logsource fields for efficient filtering
			indexes := []struct {
				name  string
				table string
				col   string
			}{
				{"idx_rules_logsource_category", "rules", "logsource_category"},
				{"idx_rules_logsource_product", "rules", "logsource_product"},
				{"idx_rules_logsource_service", "rules", "logsource_service"},
			}

			for _, idx := range indexes {
				if err := createIndexIfNotExists(tx, idx.name, idx.table, idx.col); err != nil {
					return err
				}
			}

			return nil
		},
		Down: func(tx *sql.Tx) error {
			return nil // SQLite doesn't support DROP COLUMN easily
		},
	})

	// Migration 1.5.0: Add rule lifecycle management columns and audit table
	// TASK 169: Rule lifecycle management
	runner.Register(Migration{
		Version:     "1.5.0",
		Name:        "add_rule_lifecycle",
		Description: "Add lifecycle_status, deprecated_at, deprecated_reason, deprecated_by, sunset_date columns to rules table and create lifecycle_audit table",
		Database:    "sqlite",
		Up: func(tx *sql.Tx) error {
			// Add lifecycle columns to rules table
			columns := []struct {
				name       string
				definition string
			}{
				{"lifecycle_status", "TEXT NOT NULL DEFAULT 'experimental'"},
				{"deprecated_at", "DATETIME"},
				{"deprecated_reason", "TEXT"},
				{"deprecated_by", "TEXT"},
				{"sunset_date", "DATETIME"},
			}

			for _, col := range columns {
				if err := addColumnIfNotExists(tx, "rules", col.name, col.definition); err != nil {
					return err
				}
			}

			// Create index for lifecycle_status for efficient filtering
			if err := createIndexIfNotExists(tx, "idx_rules_lifecycle_status", "rules", "lifecycle_status"); err != nil {
				return err
			}

			// Create index for sunset_date for background job efficiency
			if err := createIndexIfNotExists(tx, "idx_rules_sunset_date", "rules", "sunset_date"); err != nil {
				return err
			}

			// CRITICAL-17 FIX: Create composite index for lifecycle enforcement queries
			// This index optimizes the LifecycleManager's GetDeprecatedRules query
			if _, err := tx.Exec(`
				CREATE INDEX IF NOT EXISTS idx_rules_lifecycle_enforcement
				ON rules(lifecycle_status, enabled, sunset_date)
			`); err != nil {
				return fmt.Errorf("failed to create lifecycle enforcement index: %w", err)
			}

			// Create lifecycle_audit table
			_, err := tx.Exec(`
				CREATE TABLE IF NOT EXISTS lifecycle_audit (
					id INTEGER PRIMARY KEY AUTOINCREMENT,
					rule_id TEXT NOT NULL,
					old_status TEXT NOT NULL,
					new_status TEXT NOT NULL,
					reason TEXT,
					changed_by TEXT NOT NULL,
					changed_at DATETIME NOT NULL,
					additional_data TEXT,
					FOREIGN KEY (rule_id) REFERENCES rules(id) ON DELETE CASCADE
				)
			`)
			if err != nil {
				return fmt.Errorf("failed to create lifecycle_audit table: %w", err)
			}

			// Create indexes for lifecycle_audit
			indexes := []struct {
				name  string
				cols  string
			}{
				{"idx_lifecycle_audit_rule_id", "rule_id"},
				{"idx_lifecycle_audit_changed_at", "changed_at DESC"},
				{"idx_lifecycle_audit_changed_by", "changed_by"},
			}

			for _, idx := range indexes {
				if err := createIndexIfNotExists(tx, idx.name, "lifecycle_audit", idx.cols); err != nil {
					return err
				}
			}

			return nil
		},
		Down: func(tx *sql.Tx) error {
			// Drop lifecycle_audit table
			_, err := tx.Exec("DROP TABLE IF EXISTS lifecycle_audit")
			return err
		},
	})

	// TASK 171: Rule performance tracking
	runner.Register(Migration{
		Version:     "1.6.0",
		Name:        "add_rule_performance_tracking",
		Description: "Create rule_performance table for tracking evaluation metrics",
		Database:    "sqlite",
		Up: func(tx *sql.Tx) error {
			// Create rule_performance table
			_, err := tx.Exec(`
				CREATE TABLE IF NOT EXISTS rule_performance (
					rule_id TEXT PRIMARY KEY,
					avg_eval_time_ms REAL NOT NULL DEFAULT 0,
					max_eval_time_ms REAL NOT NULL DEFAULT 0,
					p99_eval_time_ms REAL NOT NULL DEFAULT 0,
					total_evaluations INTEGER NOT NULL DEFAULT 0,
					total_matches INTEGER NOT NULL DEFAULT 0,
					false_positive_count INTEGER NOT NULL DEFAULT 0,
					last_evaluated DATETIME,
					updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
					FOREIGN KEY (rule_id) REFERENCES rules(id) ON DELETE CASCADE
				)
			`)
			if err != nil {
				return fmt.Errorf("failed to create rule_performance table: %w", err)
			}

			// Create index for slow rule queries (sorted by avg_eval_time_ms DESC)
			if err := createIndexIfNotExists(tx, "idx_rule_perf_avg_time", "rule_performance", "avg_eval_time_ms DESC"); err != nil {
				return err
			}

			// Create index for updated_at for cleanup operations
			if err := createIndexIfNotExists(tx, "idx_rule_perf_updated_at", "rule_performance", "updated_at"); err != nil {
				return err
			}

			// BLOCKING-4 FIX: Add index on rule_id for efficient CASCADE DELETE
			if err := createIndexIfNotExists(tx, "idx_rule_perf_rule_id", "rule_performance", "rule_id"); err != nil {
				return err
			}

			return nil
		},
		Down: func(tx *sql.Tx) error {
			// Drop rule_performance table
			_, err := tx.Exec("DROP TABLE IF EXISTS rule_performance")
			return err
		},
	})

	// TASK 180: Remove deprecated conditions column from rules table
	runner.Register(Migration{
		Version:     "1.7.0",
		Name:        "remove_conditions_column",
		Description: "Remove deprecated conditions column from rules table (replaced by sigma_yaml)",
		Database:    "sqlite",
		Up: func(tx *sql.Tx) error {
			// Check if conditions column exists before attempting migration
			exists, err := columnExists(tx, "rules", "conditions")
			if err != nil {
				return fmt.Errorf("failed to check if conditions column exists: %w", err)
			}
			if !exists {
				// Column already removed, migration is idempotent
				return nil
			}

			// SECURITY: Check for rules that still have data in conditions column
			// This shouldn't happen if Task 178 and 179 were completed, but we verify for safety
			var conditionsCount int
			err = tx.QueryRow(`
				SELECT COUNT(*) FROM rules
				WHERE conditions IS NOT NULL
				AND conditions != ''
				AND conditions != 'null'
				AND conditions != '[]'
			`).Scan(&conditionsCount)
			if err != nil {
				return fmt.Errorf("failed to check for rules with conditions data: %w", err)
			}
			if conditionsCount > 0 {
				return fmt.Errorf("migration aborted: %d rules still have conditions data (Tasks 178-179 must be completed first)", conditionsCount)
			}

			// BLOCKER-2 FIX: Verify SIGMA rules have sigma_yaml if conditions are being removed
			// This prevents rules from existing with neither conditions nor sigma_yaml
			var rulesWithNoDetection int
			err = tx.QueryRow(`
				SELECT COUNT(*) FROM rules
				WHERE UPPER(COALESCE(type, 'SIGMA')) = 'SIGMA'
				AND (sigma_yaml IS NULL OR sigma_yaml = '')
				AND (conditions IS NULL OR conditions = '' OR conditions = 'null' OR conditions = '[]')
			`).Scan(&rulesWithNoDetection)
			if err != nil {
				return fmt.Errorf("failed to check for SIGMA rules without detection logic: %w", err)
			}
			if rulesWithNoDetection > 0 {
				return fmt.Errorf("migration aborted: %d SIGMA rules have neither conditions nor sigma_yaml (data integrity violation - run migration tool first)", rulesWithNoDetection)
			}

			// BLOCKER-5 FIX: Store row count before migration for verification
			var rowCountBefore int
			err = tx.QueryRow("SELECT COUNT(*) FROM rules").Scan(&rowCountBefore)
			if err != nil {
				return fmt.Errorf("failed to get row count before migration: %w", err)
			}

			// SQLite doesn't support DROP COLUMN directly in older versions
			// We use the table recreation approach for maximum compatibility
			// Reference: https://www.sqlite.org/lang_altertable.html

			// Step 1: Get the table schema (for reference - we'll manually construct the new schema)
			// We don't use PRAGMA table_info here because we need to manually construct the schema

			// Step 2: Create new table without conditions column
			_, err = tx.Exec(`
				CREATE TABLE rules_new (
					id TEXT PRIMARY KEY,
					type TEXT NOT NULL DEFAULT 'sigma',
					name TEXT NOT NULL,
					description TEXT,
					severity TEXT NOT NULL,
					enabled INTEGER NOT NULL DEFAULT 1,
					version INTEGER NOT NULL DEFAULT 1,
					tags TEXT,
					mitre_tactics TEXT,
					mitre_techniques TEXT,
					author TEXT,
					rule_references TEXT,
					false_positives TEXT,
					metadata TEXT,
					detection TEXT,
					logsource TEXT,
					-- conditions column removed
					actions TEXT,
					query TEXT,
					correlation TEXT,
					sigma_yaml TEXT,
					logsource_category TEXT,
					logsource_product TEXT,
					logsource_service TEXT,
					lifecycle_status TEXT NOT NULL DEFAULT 'experimental',
					deprecated_at DATETIME,
					deprecated_reason TEXT,
					deprecated_by TEXT,
					sunset_date DATETIME,
					created_at DATETIME NOT NULL,
					updated_at DATETIME NOT NULL
				)
			`)
			if err != nil {
				return fmt.Errorf("failed to create new rules table: %w", err)
			}

			// Step 3: Copy data from old table to new table (excluding conditions column)
			_, err = tx.Exec(`
				INSERT INTO rules_new (
					id, type, name, description, severity, enabled, version,
					tags, mitre_tactics, mitre_techniques, author, rule_references,
					false_positives, metadata, detection, logsource,
					actions, query, correlation, sigma_yaml,
					logsource_category, logsource_product, logsource_service,
					lifecycle_status, deprecated_at, deprecated_reason, deprecated_by, sunset_date,
					created_at, updated_at
				)
				SELECT
					id, type, name, description, severity, enabled, version,
					tags, mitre_tactics, mitre_techniques, author, rule_references,
					false_positives, metadata, detection, logsource,
					actions, query, correlation, sigma_yaml,
					logsource_category, logsource_product, logsource_service,
					COALESCE(lifecycle_status, 'experimental'),
					deprecated_at, deprecated_reason, deprecated_by, sunset_date,
					created_at, updated_at
				FROM rules
			`)
			if err != nil {
				return fmt.Errorf("failed to copy data to new rules table: %w", err)
			}

			// Step 4: Drop old table
			_, err = tx.Exec("DROP TABLE rules")
			if err != nil {
				return fmt.Errorf("failed to drop old rules table: %w", err)
			}

			// Step 5: Rename new table to original name
			_, err = tx.Exec("ALTER TABLE rules_new RENAME TO rules")
			if err != nil {
				return fmt.Errorf("failed to rename new rules table: %w", err)
			}

			// Step 6: Recreate all indexes
			// Note: Some indexes use complex expressions (e.g., DESC) that can't use createIndexIfNotExists
			indexStatements := []string{
				"CREATE INDEX IF NOT EXISTS idx_rules_enabled ON rules(enabled)",
				"CREATE INDEX IF NOT EXISTS idx_rules_severity ON rules(severity)",
				"CREATE INDEX IF NOT EXISTS idx_rules_type ON rules(type)",
				"CREATE INDEX IF NOT EXISTS idx_rules_created_at ON rules(created_at DESC)",
				"CREATE INDEX IF NOT EXISTS idx_rules_updated_at ON rules(updated_at DESC)",
				"CREATE INDEX IF NOT EXISTS idx_rules_enabled_severity ON rules(enabled, severity)",
				"CREATE INDEX IF NOT EXISTS idx_rules_logsource_category ON rules(logsource_category)",
				"CREATE INDEX IF NOT EXISTS idx_rules_logsource_product ON rules(logsource_product)",
				"CREATE INDEX IF NOT EXISTS idx_rules_logsource_service ON rules(logsource_service)",
				"CREATE INDEX IF NOT EXISTS idx_rules_lifecycle_status ON rules(lifecycle_status)",
				"CREATE INDEX IF NOT EXISTS idx_rules_sunset_date ON rules(sunset_date)",
				"CREATE INDEX IF NOT EXISTS idx_rules_lifecycle_enforcement ON rules(lifecycle_status, enabled, sunset_date)",
			}

			for _, stmt := range indexStatements {
				if _, err := tx.Exec(stmt); err != nil {
					return fmt.Errorf("failed to recreate index: %w (statement: %s)", err, stmt)
				}
			}

			// BLOCKER-5 FIX: Verify data integrity after migration
			var rowCountAfter int
			err = tx.QueryRow("SELECT COUNT(*) FROM rules").Scan(&rowCountAfter)
			if err != nil {
				return fmt.Errorf("failed to verify row count after migration: %w", err)
			}
			if rowCountBefore != rowCountAfter {
				return fmt.Errorf("CRITICAL: row count mismatch after migration (before: %d, after: %d) - data may be lost", rowCountBefore, rowCountAfter)
			}

			// BLOCKER-3 FIX: Verify table exists and is accessible
			var tableExists int
			err = tx.QueryRow("SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='rules'").Scan(&tableExists)
			if err != nil || tableExists != 1 {
				return fmt.Errorf("CRITICAL: rules table missing or inaccessible after migration")
			}

			// Verify indexes were recreated
			expectedIndexes := []string{
				"idx_rules_enabled", "idx_rules_severity", "idx_rules_type",
				"idx_rules_created_at", "idx_rules_updated_at",
				"idx_rules_enabled_severity", "idx_rules_lifecycle_status",
				"idx_rules_sunset_date", "idx_rules_lifecycle_enforcement",
				"idx_rules_logsource_category", "idx_rules_logsource_product",
				"idx_rules_logsource_service",
			}
			for _, idx := range expectedIndexes {
				var idxExists int
				err = tx.QueryRow("SELECT COUNT(*) FROM sqlite_master WHERE type='index' AND name=?", idx).Scan(&idxExists)
				if err != nil {
					return fmt.Errorf("failed to verify index %s: %w", idx, err)
				}
				if idxExists == 0 {
					return fmt.Errorf("CRITICAL: index %s was not recreated during migration", idx)
				}
			}

			return nil
		},
		Down: func(tx *sql.Tx) error {
			// Rollback would require adding the conditions column back
			// Since this is a deprecated column removal, we don't support rollback
			// If rollback is needed, restore from backup
			return fmt.Errorf("rollback not supported for conditions column removal (restore from backup if needed)")
		},
	})

	// Migration 1.8.0: Add field mapping lifecycle management columns and audit table
	// TASK 185: Field mapping lifecycle management
	runner.Register(Migration{
		Version:     "1.8.0",
		Name:        "add_field_mapping_lifecycle",
		Description: "Add lifecycle_status, deprecated_at, deprecated_reason, deprecated_by, sunset_date columns to field_mappings table and create field_mapping_audit table",
		Database:    "sqlite",
		Up: func(tx *sql.Tx) error {
			// First, ensure field_mappings table exists (may not exist on fresh databases)
			// This handles the case where migrations run before NewSQLiteFieldMappingStorage creates the table
			if _, err := tx.Exec(`
				CREATE TABLE IF NOT EXISTS field_mappings (
					id TEXT PRIMARY KEY,
					name TEXT NOT NULL UNIQUE,
					description TEXT,
					mappings TEXT NOT NULL,
					is_builtin BOOLEAN DEFAULT FALSE,
					lifecycle_status TEXT NOT NULL DEFAULT 'experimental',
					deprecated_at DATETIME,
					deprecated_reason TEXT,
					deprecated_by TEXT,
					sunset_date DATETIME,
					created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
					updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
				)
			`); err != nil {
				return fmt.Errorf("failed to create field_mappings table: %w", err)
			}

			// Create index on name if not exists
			if err := createIndexIfNotExists(tx, "idx_field_mappings_name", "field_mappings", "name"); err != nil {
				return fmt.Errorf("failed to create name index: %w", err)
			}

			// Add lifecycle columns to field_mappings table (for existing databases)
			columns := []struct {
				name       string
				definition string
			}{
				{"lifecycle_status", "TEXT NOT NULL DEFAULT 'experimental'"},
				{"deprecated_at", "DATETIME"},
				{"deprecated_reason", "TEXT"},
				{"deprecated_by", "TEXT"},
				{"sunset_date", "DATETIME"},
			}

			for _, col := range columns {
				if err := addColumnIfNotExists(tx, "field_mappings", col.name, col.definition); err != nil {
					return err
				}
			}

			// Create index for lifecycle_status for efficient filtering
			if err := createIndexIfNotExists(tx, "idx_field_mappings_lifecycle_status", "field_mappings", "lifecycle_status"); err != nil {
				return err
			}

			// Create index for sunset_date for background job efficiency
			if err := createIndexIfNotExists(tx, "idx_field_mappings_sunset_date", "field_mappings", "sunset_date"); err != nil {
				return err
			}

			// Create composite index for lifecycle enforcement queries
			if _, err := tx.Exec(`
				CREATE INDEX IF NOT EXISTS idx_field_mappings_lifecycle_enforcement
				ON field_mappings(lifecycle_status, sunset_date)
			`); err != nil {
				return fmt.Errorf("failed to create lifecycle enforcement index: %w", err)
			}

			// Create field_mapping_audit table
			if _, err := tx.Exec(`
				CREATE TABLE IF NOT EXISTS field_mapping_audit (
					id INTEGER PRIMARY KEY AUTOINCREMENT,
					mapping_id TEXT NOT NULL,
					old_status TEXT NOT NULL,
					new_status TEXT NOT NULL,
					reason TEXT,
					changed_by TEXT NOT NULL,
					changed_at DATETIME NOT NULL,
					additional_data TEXT,
					FOREIGN KEY (mapping_id) REFERENCES field_mappings(id) ON DELETE CASCADE
				)
			`); err != nil {
				return fmt.Errorf("failed to create field_mapping_audit table: %w", err)
			}

			// Create indexes for field_mapping_audit table
			if err := createIndexIfNotExists(tx, "idx_field_mapping_audit_mapping_id", "field_mapping_audit", "mapping_id"); err != nil {
				return err
			}
			if err := createIndexIfNotExists(tx, "idx_field_mapping_audit_changed_at", "field_mapping_audit", "changed_at"); err != nil {
				return err
			}

			// Update existing builtin mappings to 'stable' status
			if _, err := tx.Exec(`
				UPDATE field_mappings SET lifecycle_status = 'stable' WHERE is_builtin = 1
			`); err != nil {
				return fmt.Errorf("failed to update builtin mappings to stable: %w", err)
			}

			return nil
		},
		Down: func(tx *sql.Tx) error {
			// Drop audit table first (due to foreign key)
			if _, err := tx.Exec("DROP TABLE IF EXISTS field_mapping_audit"); err != nil {
				return fmt.Errorf("failed to drop field_mapping_audit table: %w", err)
			}

			// Drop indexes
			indexes := []string{
				"idx_field_mappings_lifecycle_status",
				"idx_field_mappings_sunset_date",
				"idx_field_mappings_lifecycle_enforcement",
			}
			for _, idx := range indexes {
				if _, err := tx.Exec(fmt.Sprintf("DROP INDEX IF EXISTS %s", idx)); err != nil {
					return fmt.Errorf("failed to drop index %s: %w", idx, err)
				}
			}

			// Note: SQLite doesn't support DROP COLUMN in all versions
			// For full rollback, restore from backup
			return nil
		},
	})

	// Migration 1.9.0: Add correlation trigger fields to investigations table
	// Enables tracking how investigations were created (manual, correlation, playbook, ml_alert)
	runner.Register(Migration{
		Version:     "1.9.0",
		Name:        "add_investigation_correlation_fields",
		Description: "Add trigger_source, trigger_alert_id, correlation_rule_id columns to investigations table",
		Database:    "sqlite",
		Up: func(tx *sql.Tx) error {
			columns := []struct {
				name       string
				definition string
			}{
				// trigger_source: How this investigation was created (manual, correlation, playbook, ml_alert)
				{"trigger_source", "TEXT DEFAULT 'manual'"},
				// trigger_alert_id: The correlation alert that spawned this investigation
				{"trigger_alert_id", "TEXT"},
				// correlation_rule_id: Which correlation rule triggered this investigation
				{"correlation_rule_id", "TEXT"},
			}

			for _, col := range columns {
				if err := addColumnIfNotExists(tx, "investigations", col.name, col.definition); err != nil {
					return err
				}
			}

			// Create index for trigger_source filtering (useful for finding auto-created investigations)
			if err := createIndexIfNotExists(tx, "idx_investigations_trigger_source", "investigations", "trigger_source"); err != nil {
				return err
			}

			// Create index for correlation_rule_id (useful for finding investigations from specific rules)
			if err := createIndexIfNotExists(tx, "idx_investigations_correlation_rule_id", "investigations", "correlation_rule_id"); err != nil {
				return err
			}

			return nil
		},
		Down: func(tx *sql.Tx) error {
			// Note: SQLite doesn't support DROP COLUMN in all versions
			// For full rollback, restore from backup
			return nil
		},
	})
}
