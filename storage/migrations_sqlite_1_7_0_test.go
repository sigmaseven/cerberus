package storage

import (
	"database/sql"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"go.uber.org/zap"
)

// TestMigration_1_7_0_AddSigmaYAMLAndLogsourceColumns tests migration 1.7.0
// TASK 123.1: Comprehensive test for SIGMA YAML and logsource column migration
func TestMigration_1_7_0_AddSigmaYAMLAndLogsourceColumns(t *testing.T) {
	// Create temporary test database
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test_migration_1_7_0.db")

	// Create logger
	logger, err := zap.NewDevelopment()
	if err != nil {
		t.Fatalf("Failed to create logger: %v", err)
	}
	defer logger.Sync()
	sugaredLogger := logger.Sugar()

	// Open database
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("Failed to open database: %v", err)
	}
	defer db.Close()

	// Enable foreign keys for testing
	_, err = db.Exec("PRAGMA foreign_keys=ON")
	if err != nil {
		t.Fatalf("Failed to enable foreign keys: %v", err)
	}

	// Create base schema (rules table without migration 1.7.0 columns)
	baseSchema := `
	CREATE TABLE IF NOT EXISTS rules (
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
		conditions TEXT,
		actions TEXT,
		query TEXT,
		correlation TEXT,
		created_at DATETIME NOT NULL,
		updated_at DATETIME NOT NULL
	);
	CREATE INDEX IF NOT EXISTS idx_rules_enabled ON rules(enabled);
	CREATE INDEX IF NOT EXISTS idx_rules_severity ON rules(severity);
	CREATE INDEX IF NOT EXISTS idx_rules_type ON rules(type);
	`

	_, err = db.Exec(baseSchema)
	if err != nil {
		t.Fatalf("Failed to create base schema: %v", err)
	}

	// Verify columns don't exist before migration
	t.Run("verify_columns_dont_exist_before_migration", func(t *testing.T) {
		columnsToCheck := []string{
			"sigma_yaml",
			"logsource_category",
			"logsource_product",
			"logsource_service",
		}

		for _, column := range columnsToCheck {
			var count int
			err := db.QueryRow("SELECT COUNT(*) FROM pragma_table_info('rules') WHERE name=?", column).Scan(&count)
			if err != nil {
				t.Fatalf("Failed to check column %s: %v", column, err)
			}
			if count != 0 {
				t.Errorf("Column %s should not exist before migration, but it does", column)
			}
		}
	})

	// Verify indexes don't exist before migration
	t.Run("verify_indexes_dont_exist_before_migration", func(t *testing.T) {
		indexesToCheck := []string{
			"idx_rules_logsource_category",
			"idx_rules_logsource_product",
			"idx_rules_logsource_service",
		}

		for _, index := range indexesToCheck {
			var count int
			err := db.QueryRow("SELECT COUNT(*) FROM sqlite_master WHERE type='index' AND name=?", index).Scan(&count)
			if err != nil {
				t.Fatalf("Failed to check index %s: %v", index, err)
			}
			if count != 0 {
				t.Errorf("Index %s should not exist before migration, but it does", index)
			}
		}
	})

	// Insert test data before migration
	t.Run("insert_test_data_before_migration", func(t *testing.T) {
		now := time.Now().UTC()
		_, err := db.Exec(`
			INSERT INTO rules (id, name, severity, created_at, updated_at)
			VALUES (?, ?, ?, ?, ?)
		`, "test-rule-1", "Test Rule 1", "medium", now, now)
		if err != nil {
			t.Fatalf("Failed to insert test data: %v", err)
		}
	})

	// Run migration 1.7.0
	t.Run("run_migration_1_7_0", func(t *testing.T) {
		runner, err := NewMigrationRunner(db, sugaredLogger)
		if err != nil {
			t.Fatalf("Failed to create migration runner: %v", err)
		}

		// Register only migration 1.7.0
		runner.Register(Migration{
			Version:     "1.7.0",
			Name:        "add_sigma_yaml_and_logsource_columns",
			Description: "Add sigma_yaml, logsource_category, logsource_product, logsource_service columns to rules table with indexes for efficient querying",
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

				if err := createIndexIfNotExists(tx, "idx_rules_logsource_category", "rules", "logsource_category"); err != nil {
					return err
				}
				if err := createIndexIfNotExists(tx, "idx_rules_logsource_product", "rules", "logsource_product"); err != nil {
					return err
				}
				return createIndexIfNotExists(tx, "idx_rules_logsource_service", "rules", "logsource_service")
			},
		})

		// Run migrations
		if err := runner.RunMigrations(); err != nil {
			t.Fatalf("Failed to run migration: %v", err)
		}
	})

	// Verify columns exist after migration
	t.Run("verify_columns_exist_after_migration", func(t *testing.T) {
		columnsToCheck := []string{
			"sigma_yaml",
			"logsource_category",
			"logsource_product",
			"logsource_service",
		}

		for _, column := range columnsToCheck {
			var count int
			err := db.QueryRow("SELECT COUNT(*) FROM pragma_table_info('rules') WHERE name=?", column).Scan(&count)
			if err != nil {
				t.Fatalf("Failed to check column %s: %v", column, err)
			}
			if count != 1 {
				t.Errorf("Column %s should exist after migration, but count=%d", column, count)
			}
		}
	})

	// Verify indexes exist after migration
	t.Run("verify_indexes_exist_after_migration", func(t *testing.T) {
		indexesToCheck := []string{
			"idx_rules_logsource_category",
			"idx_rules_logsource_product",
			"idx_rules_logsource_service",
		}

		for _, index := range indexesToCheck {
			var count int
			err := db.QueryRow("SELECT COUNT(*) FROM sqlite_master WHERE type='index' AND name=?", index).Scan(&count)
			if err != nil {
				t.Fatalf("Failed to check index %s: %v", index, err)
			}
			if count != 1 {
				t.Errorf("Index %s should exist after migration, but count=%d", index, count)
			}
		}
	})

	// Verify existing data is preserved
	t.Run("verify_existing_data_preserved", func(t *testing.T) {
		var name string
		err := db.QueryRow("SELECT name FROM rules WHERE id=?", "test-rule-1").Scan(&name)
		if err != nil {
			t.Fatalf("Failed to query existing data: %v", err)
		}
		if name != "Test Rule 1" {
			t.Errorf("Expected name='Test Rule 1', got '%s'", name)
		}
	})

	// Verify new columns are NULL for existing rows
	t.Run("verify_new_columns_null_for_existing_rows", func(t *testing.T) {
		var sigmaYAML, logsourceCategory, logsourceProduct, logsourceService sql.NullString
		err := db.QueryRow(`
			SELECT sigma_yaml, logsource_category, logsource_product, logsource_service
			FROM rules WHERE id=?
		`, "test-rule-1").Scan(&sigmaYAML, &logsourceCategory, &logsourceProduct, &logsourceService)
		if err != nil {
			t.Fatalf("Failed to query new columns: %v", err)
		}

		if sigmaYAML.Valid {
			t.Error("sigma_yaml should be NULL for existing row")
		}
		if logsourceCategory.Valid {
			t.Error("logsource_category should be NULL for existing row")
		}
		if logsourceProduct.Valid {
			t.Error("logsource_product should be NULL for existing row")
		}
		if logsourceService.Valid {
			t.Error("logsource_service should be NULL for existing row")
		}
	})

	// Verify can insert data into new columns
	t.Run("verify_can_insert_new_column_data", func(t *testing.T) {
		now := time.Now().UTC()
		sigmaYAML := "title: Test SIGMA Rule\ndetection:\n  selection:\n    EventID: 4688"
		_, err := db.Exec(`
			INSERT INTO rules (id, name, severity, sigma_yaml, logsource_category, logsource_product, logsource_service, created_at, updated_at)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
		`, "test-rule-2", "Test Rule 2", "high", sigmaYAML, "process_creation", "windows", "sysmon", now, now)
		if err != nil {
			t.Fatalf("Failed to insert data with new columns: %v", err)
		}

		// Verify data was inserted correctly
		var retrievedYAML, category, product, service string
		err = db.QueryRow(`
			SELECT sigma_yaml, logsource_category, logsource_product, logsource_service
			FROM rules WHERE id=?
		`, "test-rule-2").Scan(&retrievedYAML, &category, &product, &service)
		if err != nil {
			t.Fatalf("Failed to query inserted data: %v", err)
		}

		if retrievedYAML != sigmaYAML {
			t.Errorf("sigma_yaml mismatch: expected %q, got %q", sigmaYAML, retrievedYAML)
		}
		if category != "process_creation" {
			t.Errorf("logsource_category mismatch: expected 'process_creation', got %q", category)
		}
		if product != "windows" {
			t.Errorf("logsource_product mismatch: expected 'windows', got %q", product)
		}
		if service != "sysmon" {
			t.Errorf("logsource_service mismatch: expected 'sysmon', got %q", service)
		}
	})

	// Verify can update new columns
	t.Run("verify_can_update_new_columns", func(t *testing.T) {
		newYAML := "title: Updated SIGMA Rule\ndetection:\n  selection:\n    EventID: 4689"
		_, err := db.Exec(`
			UPDATE rules
			SET sigma_yaml = ?, logsource_category = ?, logsource_product = ?, logsource_service = ?
			WHERE id = ?
		`, newYAML, "process_termination", "linux", "auditd", "test-rule-1")
		if err != nil {
			t.Fatalf("Failed to update new columns: %v", err)
		}

		// Verify update
		var retrievedYAML, category, product, service string
		err = db.QueryRow(`
			SELECT sigma_yaml, logsource_category, logsource_product, logsource_service
			FROM rules WHERE id=?
		`, "test-rule-1").Scan(&retrievedYAML, &category, &product, &service)
		if err != nil {
			t.Fatalf("Failed to query updated data: %v", err)
		}

		if retrievedYAML != newYAML {
			t.Errorf("sigma_yaml not updated correctly")
		}
		if category != "process_termination" {
			t.Errorf("logsource_category not updated correctly")
		}
		if product != "linux" {
			t.Errorf("logsource_product not updated correctly")
		}
		if service != "auditd" {
			t.Errorf("logsource_service not updated correctly")
		}
	})

	// Verify indexes can be used in queries
	t.Run("verify_query_with_logsource_filters", func(t *testing.T) {
		// Query by category
		rows, err := db.Query("SELECT id FROM rules WHERE logsource_category = ?", "process_creation")
		if err != nil {
			t.Fatalf("Failed to query by category: %v", err)
		}
		rows.Close()

		// Query by product
		rows, err = db.Query("SELECT id FROM rules WHERE logsource_product = ?", "windows")
		if err != nil {
			t.Fatalf("Failed to query by product: %v", err)
		}
		rows.Close()

		// Query by service
		rows, err = db.Query("SELECT id FROM rules WHERE logsource_service = ?", "sysmon")
		if err != nil {
			t.Fatalf("Failed to query by service: %v", err)
		}
		rows.Close()
	})
}

// TestMigration_1_7_0_Idempotency tests that migration 1.7.0 can be run multiple times safely
func TestMigration_1_7_0_Idempotency(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test_migration_idempotent.db")

	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("Failed to open database: %v", err)
	}
	defer db.Close()

	// Create base schema
	baseSchema := `
	CREATE TABLE IF NOT EXISTS rules (
		id TEXT PRIMARY KEY,
		name TEXT NOT NULL,
		severity TEXT NOT NULL,
		created_at DATETIME NOT NULL,
		updated_at DATETIME NOT NULL
	);
	`
	_, err = db.Exec(baseSchema)
	if err != nil {
		t.Fatalf("Failed to create base schema: %v", err)
	}

	// Define migration
	migration := Migration{
		Version:     "1.7.0",
		Name:        "add_sigma_yaml_and_logsource_columns",
		Description: "Add sigma_yaml, logsource_category, logsource_product, logsource_service columns to rules table with indexes",
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

			if err := createIndexIfNotExists(tx, "idx_rules_logsource_category", "rules", "logsource_category"); err != nil {
				return err
			}
			if err := createIndexIfNotExists(tx, "idx_rules_logsource_product", "rules", "logsource_product"); err != nil {
				return err
			}
			return createIndexIfNotExists(tx, "idx_rules_logsource_service", "rules", "logsource_service")
		},
	}

	// Run migration first time
	t.Run("first_run", func(t *testing.T) {
		tx, err := db.Begin()
		if err != nil {
			t.Fatalf("Failed to begin transaction: %v", err)
		}

		err = migration.Up(tx)
		if err != nil {
			tx.Rollback()
			t.Fatalf("First migration run failed: %v", err)
		}

		if err := tx.Commit(); err != nil {
			t.Fatalf("Failed to commit first run: %v", err)
		}
	})

	// Run migration second time (should be idempotent)
	t.Run("second_run_idempotent", func(t *testing.T) {
		tx, err := db.Begin()
		if err != nil {
			t.Fatalf("Failed to begin transaction: %v", err)
		}

		err = migration.Up(tx)
		if err != nil {
			tx.Rollback()
			t.Fatalf("Second migration run failed (not idempotent): %v", err)
		}

		if err := tx.Commit(); err != nil {
			t.Fatalf("Failed to commit second run: %v", err)
		}
	})

	// Verify columns still exist and count is correct
	t.Run("verify_single_column_set", func(t *testing.T) {
		columnsToCheck := []string{
			"sigma_yaml",
			"logsource_category",
			"logsource_product",
			"logsource_service",
		}

		for _, column := range columnsToCheck {
			var count int
			err := db.QueryRow("SELECT COUNT(*) FROM pragma_table_info('rules') WHERE name=?", column).Scan(&count)
			if err != nil {
				t.Fatalf("Failed to check column %s: %v", column, err)
			}
			if count != 1 {
				t.Errorf("Column %s should exist exactly once, but count=%d", column, count)
			}
		}
	})
}

// TestMigration_1_7_0_EdgeCases tests edge cases for migration 1.7.0
func TestMigration_1_7_0_EdgeCases(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test_migration_edge_cases.db")

	logger, err := zap.NewDevelopment()
	if err != nil {
		t.Fatalf("Failed to create logger: %v", err)
	}
	defer logger.Sync()
	sugaredLogger := logger.Sugar()

	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("Failed to open database: %v", err)
	}
	defer db.Close()

	// Create base schema
	baseSchema := `
	CREATE TABLE IF NOT EXISTS rules (
		id TEXT PRIMARY KEY,
		name TEXT NOT NULL,
		severity TEXT NOT NULL,
		created_at DATETIME NOT NULL,
		updated_at DATETIME NOT NULL
	);
	`
	_, err = db.Exec(baseSchema)
	if err != nil {
		t.Fatalf("Failed to create base schema: %v", err)
	}

	// Test with large YAML content
	t.Run("large_yaml_content", func(t *testing.T) {
		runner, err := NewMigrationRunner(db, sugaredLogger)
		if err != nil {
			t.Fatalf("Failed to create migration runner: %v", err)
		}

		// Register only migration 1.7.0
		runner.Register(Migration{
			Version:     "1.7.0",
			Name:        "add_sigma_yaml_and_logsource_columns",
			Description: "Add sigma_yaml and logsource columns",
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

				if err := createIndexIfNotExists(tx, "idx_rules_logsource_category", "rules", "logsource_category"); err != nil {
					return err
				}
				if err := createIndexIfNotExists(tx, "idx_rules_logsource_product", "rules", "logsource_product"); err != nil {
					return err
				}
				return createIndexIfNotExists(tx, "idx_rules_logsource_service", "rules", "logsource_service")
			},
		})

		// Run migration
		if err := runner.RunMigrations(); err != nil {
			t.Fatalf("Failed to run migration: %v", err)
		}

		// Insert large YAML content
		largeYAML := make([]byte, 100000) // 100KB
		for i := range largeYAML {
			largeYAML[i] = 'A' + byte(i%26)
		}

		now := time.Now().UTC()
		_, err = db.Exec(`
			INSERT INTO rules (id, name, severity, sigma_yaml, created_at, updated_at)
			VALUES (?, ?, ?, ?, ?, ?)
		`, "large-yaml-test", "Large YAML Test", "high", string(largeYAML), now, now)
		if err != nil {
			t.Fatalf("Failed to insert large YAML: %v", err)
		}

		// Verify retrieval
		var retrieved string
		err = db.QueryRow("SELECT sigma_yaml FROM rules WHERE id=?", "large-yaml-test").Scan(&retrieved)
		if err != nil {
			t.Fatalf("Failed to retrieve large YAML: %v", err)
		}

		if len(retrieved) != len(largeYAML) {
			t.Errorf("Large YAML length mismatch: expected %d, got %d", len(largeYAML), len(retrieved))
		}
	})

	// Test with special characters in logsource fields
	t.Run("special_characters_in_logsource", func(t *testing.T) {
		specialChars := []struct {
			category string
			product  string
			service  string
		}{
			{"process-creation", "windows_10", "sysmon-v12"},
			{"process/creation", "linux/ubuntu", "auditd/v2"},
			{"process creation", "windows server", "security log"},
			{"process_création", "windows™", "sysmon®"}, // Unicode
		}

		now := time.Now().UTC()
		for i, sc := range specialChars {
			id := fmt.Sprintf("special-chars-%d", i)
			_, err := db.Exec(`
				INSERT INTO rules (id, name, severity, logsource_category, logsource_product, logsource_service, created_at, updated_at)
				VALUES (?, ?, ?, ?, ?, ?, ?, ?)
			`, id, "Special Chars Test", "medium", sc.category, sc.product, sc.service, now, now)
			if err != nil {
				t.Fatalf("Failed to insert special characters (index %d): %v", i, err)
			}

			// Verify retrieval
			var category, product, service string
			err = db.QueryRow(`
				SELECT logsource_category, logsource_product, logsource_service
				FROM rules WHERE id=?
			`, id).Scan(&category, &product, &service)
			if err != nil {
				t.Fatalf("Failed to retrieve special characters: %v", err)
			}

			if category != sc.category || product != sc.product || service != sc.service {
				t.Errorf("Special characters not preserved correctly for index %d", i)
			}
		}
	})

	// Test NULL values explicitly
	t.Run("null_values", func(t *testing.T) {
		now := time.Now().UTC()
		_, err := db.Exec(`
			INSERT INTO rules (id, name, severity, sigma_yaml, logsource_category, logsource_product, logsource_service, created_at, updated_at)
			VALUES (?, ?, ?, NULL, NULL, NULL, NULL, ?, ?)
		`, "null-test", "NULL Test", "low", now, now)
		if err != nil {
			t.Fatalf("Failed to insert NULL values: %v", err)
		}

		var sigmaYAML, category, product, service sql.NullString
		err = db.QueryRow(`
			SELECT sigma_yaml, logsource_category, logsource_product, logsource_service
			FROM rules WHERE id=?
		`, "null-test").Scan(&sigmaYAML, &category, &product, &service)
		if err != nil {
			t.Fatalf("Failed to query NULL values: %v", err)
		}

		if sigmaYAML.Valid || category.Valid || product.Valid || service.Valid {
			t.Error("NULL values should remain NULL")
		}
	})
}

// TestMigration_1_7_0_Concurrent tests migration behavior under concurrent access
// BLOCKER 3: Verify migration safety with concurrent database connections
func TestMigration_1_7_0_Concurrent(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test_migration_concurrent.db")

	logger, err := zap.NewDevelopment()
	if err != nil {
		t.Fatalf("Failed to create logger: %v", err)
	}
	defer logger.Sync()

	// Create base database with schema
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("Failed to open database: %v", err)
	}
	defer db.Close()

	// Enable WAL mode for better concurrent access
	_, err = db.Exec("PRAGMA journal_mode=WAL")
	if err != nil {
		t.Fatalf("Failed to enable WAL mode: %v", err)
	}

	// Create base schema
	baseSchema := `
	CREATE TABLE IF NOT EXISTS rules (
		id TEXT PRIMARY KEY,
		name TEXT NOT NULL,
		severity TEXT NOT NULL,
		created_at DATETIME NOT NULL,
		updated_at DATETIME NOT NULL
	);
	`
	_, err = db.Exec(baseSchema)
	if err != nil {
		t.Fatalf("Failed to create base schema: %v", err)
	}

	// Define migration
	migration := Migration{
		Version:     "1.7.0",
		Name:        "add_sigma_yaml_and_logsource_columns",
		Description: "Add sigma_yaml and logsource columns",
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

			if err := createIndexIfNotExists(tx, "idx_rules_logsource_category", "rules", "logsource_category"); err != nil {
				return err
			}
			if err := createIndexIfNotExists(tx, "idx_rules_logsource_product", "rules", "logsource_product"); err != nil {
				return err
			}
			return createIndexIfNotExists(tx, "idx_rules_logsource_service", "rules", "logsource_service")
		},
	}

	// Run migration from multiple goroutines concurrently
	const numGoroutines = 10
	type result struct {
		id  int
		err error
	}
	results := make(chan result, numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		go func(id int) {
			// Each goroutine opens its own connection
			conn, err := sql.Open("sqlite", dbPath)
			if err != nil {
				results <- result{id, fmt.Errorf("failed to open connection: %w", err)}
				return
			}
			defer conn.Close()

			// Try to run migration
			tx, err := conn.Begin()
			if err != nil {
				results <- result{id, fmt.Errorf("failed to begin transaction: %w", err)}
				return
			}

			err = migration.Up(tx)
			if err != nil {
				tx.Rollback()
				results <- result{id, err}
				return
			}

			if err := tx.Commit(); err != nil {
				results <- result{id, fmt.Errorf("failed to commit: %w", err)}
				return
			}

			results <- result{id, nil}
		}(i)
	}

	// Collect results
	successCount := 0
	errorCount := 0
	var errors []error

	for i := 0; i < numGoroutines; i++ {
		res := <-results
		if res.err != nil {
			errorCount++
			errors = append(errors, res.err)
			t.Logf("Goroutine %d failed: %v", res.id, res.err)
		} else {
			successCount++
			t.Logf("Goroutine %d succeeded", res.id)
		}
	}

	// All goroutines should succeed due to idempotent design
	t.Logf("Concurrent migration test: %d succeeded, %d failed", successCount, errorCount)

	// At least one should succeed
	if successCount == 0 {
		t.Fatal("No migrations succeeded in concurrent test")
	}

	// Verify final state is correct (columns and indexes exist exactly once)
	columnsToCheck := []string{
		"sigma_yaml",
		"logsource_category",
		"logsource_product",
		"logsource_service",
	}

	for _, column := range columnsToCheck {
		var count int
		err := db.QueryRow("SELECT COUNT(*) FROM pragma_table_info('rules') WHERE name=?", column).Scan(&count)
		if err != nil {
			t.Fatalf("Failed to check column %s: %v", column, err)
		}
		if count != 1 {
			t.Errorf("Column %s should exist exactly once after concurrent migrations, but count=%d", column, count)
		}
	}

	indexesToCheck := []string{
		"idx_rules_logsource_category",
		"idx_rules_logsource_product",
		"idx_rules_logsource_service",
	}

	for _, index := range indexesToCheck {
		var count int
		err := db.QueryRow("SELECT COUNT(*) FROM sqlite_master WHERE type='index' AND name=?", index).Scan(&count)
		if err != nil {
			t.Fatalf("Failed to check index %s: %v", index, err)
		}
		if count != 1 {
			t.Errorf("Index %s should exist exactly once after concurrent migrations, but count=%d", index, count)
		}
	}
}

// TestMigration_1_7_0_Rollback tests the rollback functionality
func TestMigration_1_7_0_Rollback(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test_migration_rollback.db")

	logger, err := zap.NewDevelopment()
	if err != nil {
		t.Fatalf("Failed to create logger: %v", err)
	}
	defer logger.Sync()
	sugaredLogger := logger.Sugar()

	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("Failed to open database: %v", err)
	}
	defer db.Close()

	// Create base schema
	baseSchema := `
	CREATE TABLE IF NOT EXISTS rules (
		id TEXT PRIMARY KEY,
		name TEXT NOT NULL,
		severity TEXT NOT NULL,
		created_at DATETIME NOT NULL,
		updated_at DATETIME NOT NULL
	);
	`
	_, err = db.Exec(baseSchema)
	if err != nil {
		t.Fatalf("Failed to create base schema: %v", err)
	}

	runner, err := NewMigrationRunner(db, sugaredLogger)
	if err != nil {
		t.Fatalf("Failed to create migration runner: %v", err)
	}

	// Register migration with Down function
	runner.Register(Migration{
		Version:     "1.7.0",
		Name:        "add_sigma_yaml_and_logsource_columns",
		Description: "Add sigma_yaml and logsource columns",
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

			if err := createIndexIfNotExists(tx, "idx_rules_logsource_category", "rules", "logsource_category"); err != nil {
				return err
			}
			if err := createIndexIfNotExists(tx, "idx_rules_logsource_product", "rules", "logsource_product"); err != nil {
				return err
			}
			return createIndexIfNotExists(tx, "idx_rules_logsource_service", "rules", "logsource_service")
		},
		Down: func(tx *sql.Tx) error {
			indexes := []string{
				"idx_rules_logsource_service",
				"idx_rules_logsource_product",
				"idx_rules_logsource_category",
			}
			for _, idx := range indexes {
				if _, err := tx.Exec(fmt.Sprintf("DROP INDEX IF EXISTS %s", idx)); err != nil {
					return fmt.Errorf("failed to drop index %s: %w", idx, err)
				}
			}
			return nil
		},
	})

	// Run migration
	if err := runner.RunMigrations(); err != nil {
		t.Fatalf("Failed to run migration: %v", err)
	}

	// Verify indexes exist
	indexesToCheck := []string{
		"idx_rules_logsource_category",
		"idx_rules_logsource_product",
		"idx_rules_logsource_service",
	}

	for _, index := range indexesToCheck {
		var count int
		err := db.QueryRow("SELECT COUNT(*) FROM sqlite_master WHERE type='index' AND name=?", index).Scan(&count)
		if err != nil {
			t.Fatalf("Failed to check index %s: %v", index, err)
		}
		if count != 1 {
			t.Errorf("Index %s should exist after migration", index)
		}
	}

	// Rollback migration
	if err := runner.RollbackMigration("1.7.0", "test rollback"); err != nil {
		t.Fatalf("Failed to rollback migration: %v", err)
	}

	// Verify indexes are dropped
	for _, index := range indexesToCheck {
		var count int
		err := db.QueryRow("SELECT COUNT(*) FROM sqlite_master WHERE type='index' AND name=?", index).Scan(&count)
		if err != nil {
			t.Fatalf("Failed to check index %s after rollback: %v", index, err)
		}
		if count != 0 {
			t.Errorf("Index %s should be dropped after rollback, but count=%d", index, count)
		}
	}
}

// BenchmarkMigration_1_7_0_LargeDataset benchmarks migration performance with production-scale data
// BLOCKER 4: Performance test for large datasets (10,000+ rows)
func BenchmarkMigration_1_7_0_LargeDataset(b *testing.B) {
	tmpDir := b.TempDir()
	dbPath := filepath.Join(tmpDir, "bench_migration_large.db")

	logger, err := zap.NewDevelopment()
	if err != nil {
		b.Fatalf("Failed to create logger: %v", err)
	}
	defer logger.Sync()
	sugaredLogger := logger.Sugar()

	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		b.Fatalf("Failed to open database: %v", err)
	}
	defer db.Close()

	// Create base schema
	baseSchema := `
	CREATE TABLE IF NOT EXISTS rules (
		id TEXT PRIMARY KEY,
		name TEXT NOT NULL,
		description TEXT,
		severity TEXT NOT NULL,
		enabled INTEGER NOT NULL DEFAULT 1,
		type TEXT NOT NULL DEFAULT 'sigma',
		created_at DATETIME NOT NULL,
		updated_at DATETIME NOT NULL
	);
	CREATE INDEX IF NOT EXISTS idx_rules_enabled ON rules(enabled);
	CREATE INDEX IF NOT EXISTS idx_rules_severity ON rules(severity);
	`
	_, err = db.Exec(baseSchema)
	if err != nil {
		b.Fatalf("Failed to create base schema: %v", err)
	}

	// Insert 10,000 rows to simulate production dataset
	b.Log("Inserting 10,000 test rows...")
	now := time.Now().UTC()
	tx, err := db.Begin()
	if err != nil {
		b.Fatalf("Failed to begin transaction: %v", err)
	}

	stmt, err := tx.Prepare(`
		INSERT INTO rules (id, name, description, severity, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?)
	`)
	if err != nil {
		tx.Rollback()
		b.Fatalf("Failed to prepare statement: %v", err)
	}

	severities := []string{"low", "medium", "high", "critical"}
	for i := 0; i < 10000; i++ {
		id := fmt.Sprintf("rule-%d", i)
		name := fmt.Sprintf("Test Rule %d", i)
		desc := fmt.Sprintf("This is test rule number %d for benchmarking migration performance", i)
		severity := severities[i%len(severities)]

		_, err := stmt.Exec(id, name, desc, severity, now, now)
		if err != nil {
			tx.Rollback()
			stmt.Close()
			b.Fatalf("Failed to insert row %d: %v", i, err)
		}
	}

	stmt.Close()
	if err := tx.Commit(); err != nil {
		b.Fatalf("Failed to commit test data: %v", err)
	}

	b.Log("Test data inserted successfully")

	// Verify row count
	var count int
	err = db.QueryRow("SELECT COUNT(*) FROM rules").Scan(&count)
	if err != nil {
		b.Fatalf("Failed to count rows: %v", err)
	}
	b.Logf("Database contains %d rows", count)

	// Define migration
	migration := Migration{
		Version:     "1.7.0",
		Name:        "add_sigma_yaml_and_logsource_columns",
		Description: "Add sigma_yaml and logsource columns with indexes",
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

			if err := createIndexIfNotExists(tx, "idx_rules_logsource_category", "rules", "logsource_category"); err != nil {
				return err
			}
			if err := createIndexIfNotExists(tx, "idx_rules_logsource_product", "rules", "logsource_product"); err != nil {
				return err
			}
			return createIndexIfNotExists(tx, "idx_rules_logsource_service", "rules", "logsource_service")
		},
	}

	// Reset timer before benchmark
	b.ResetTimer()

	// Run migration (N times for benchmark)
	for i := 0; i < b.N; i++ {
		// For benchmarking, we only run once per b.N iteration
		// since migration is idempotent
		runner, err := NewMigrationRunner(db, sugaredLogger)
		if err != nil {
			b.Fatalf("Failed to create migration runner: %v", err)
		}

		runner.Register(migration)

		start := time.Now()
		if err := runner.RunMigrations(); err != nil {
			b.Fatalf("Migration failed: %v", err)
		}
		duration := time.Since(start)

		b.Logf("Migration iteration %d completed in %v", i+1, duration)
	}

	b.StopTimer()

	// Verify migration succeeded
	columnsToCheck := []string{
		"sigma_yaml",
		"logsource_category",
		"logsource_product",
		"logsource_service",
	}

	for _, column := range columnsToCheck {
		var colCount int
		err := db.QueryRow("SELECT COUNT(*) FROM pragma_table_info('rules') WHERE name=?", column).Scan(&colCount)
		if err != nil {
			b.Fatalf("Failed to verify column %s: %v", column, err)
		}
		if colCount != 1 {
			b.Errorf("Column %s not found after migration", column)
		}
	}

	// Verify all rows still exist
	err = db.QueryRow("SELECT COUNT(*) FROM rules").Scan(&count)
	if err != nil {
		b.Fatalf("Failed to count rows after migration: %v", err)
	}
	if count != 10000 {
		b.Errorf("Expected 10000 rows after migration, got %d", count)
	}

	b.Logf("Migration benchmark completed successfully with %d rows", count)
}
