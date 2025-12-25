package storage

import (
	"path/filepath"
	"testing"

	"go.uber.org/zap"
)

// TestSQLite_Migration_1_7_0_Integration tests that migration 1.7.0 runs correctly
// when creating a new SQLite database through NewSQLite()
func TestSQLite_Migration_1_7_0_Integration(t *testing.T) {
	// Create temporary test database
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test_migration_integration.db")

	// Create logger
	logger, err := zap.NewDevelopment()
	if err != nil {
		t.Fatalf("Failed to create logger: %v", err)
	}
	defer logger.Sync()
	sugaredLogger := logger.Sugar()

	// Create new SQLite database (should run all migrations including 1.7.0)
	sqlite, err := NewSQLite(dbPath, sugaredLogger)
	if err != nil {
		t.Fatalf("Failed to create SQLite database: %v", err)
	}
	defer sqlite.Close()

	// Verify migration 1.7.0 columns exist
	t.Run("verify_migration_1_7_0_columns_exist", func(t *testing.T) {
		columnsToCheck := []string{
			"sigma_yaml",
			"logsource_category",
			"logsource_product",
			"logsource_service",
		}

		for _, column := range columnsToCheck {
			var count int
			err := sqlite.DB.QueryRow("SELECT COUNT(*) FROM pragma_table_info('rules') WHERE name=?", column).Scan(&count)
			if err != nil {
				t.Fatalf("Failed to check column %s: %v", column, err)
			}
			if count != 1 {
				t.Errorf("Column %s should exist after SQLite initialization, but count=%d", column, count)
			}
		}
	})

	// Verify migration 1.7.0 indexes exist
	t.Run("verify_migration_1_7_0_indexes_exist", func(t *testing.T) {
		indexesToCheck := []string{
			"idx_rules_logsource_category",
			"idx_rules_logsource_product",
			"idx_rules_logsource_service",
		}

		for _, index := range indexesToCheck {
			var count int
			err := sqlite.DB.QueryRow("SELECT COUNT(*) FROM sqlite_master WHERE type='index' AND name=?", index).Scan(&count)
			if err != nil {
				t.Fatalf("Failed to check index %s: %v", index, err)
			}
			if count != 1 {
				t.Errorf("Index %s should exist after SQLite initialization, but count=%d", index, count)
			}
		}
	})

	// Verify migration 1.7.0 is recorded in schema_migrations
	t.Run("verify_migration_recorded", func(t *testing.T) {
		var count int
		err := sqlite.DB.QueryRow("SELECT COUNT(*) FROM schema_migrations WHERE version='1.7.0'").Scan(&count)
		if err != nil {
			t.Fatalf("Failed to check schema_migrations: %v", err)
		}
		if count != 1 {
			t.Errorf("Migration 1.7.0 should be recorded in schema_migrations, but count=%d", count)
		}
	})

	// Verify we can insert and query data using new columns
	t.Run("verify_new_columns_functional", func(t *testing.T) {
		// Insert test data directly
		_, err := sqlite.DB.Exec(`
			INSERT INTO rules (
				id, name, severity, sigma_yaml, logsource_category, logsource_product, logsource_service, created_at, updated_at
			) VALUES (
				'test-integration-rule', 'Integration Test Rule', 'high',
				'title: Test\ndetection:\n  selection:\n    EventID: 4688',
				'process_creation', 'windows', 'sysmon',
				datetime('now'), datetime('now')
			)
		`)
		if err != nil {
			t.Fatalf("Failed to insert test rule: %v", err)
		}

		// Query back to verify
		var sigmaYAML, category, product, service string
		err = sqlite.DB.QueryRow(`
			SELECT sigma_yaml, logsource_category, logsource_product, logsource_service
			FROM rules WHERE id='test-integration-rule'
		`).Scan(&sigmaYAML, &category, &product, &service)
		if err != nil {
			t.Fatalf("Failed to query test rule: %v", err)
		}

		if category != "process_creation" {
			t.Errorf("Expected category='process_creation', got '%s'", category)
		}
		if product != "windows" {
			t.Errorf("Expected product='windows', got '%s'", product)
		}
		if service != "sysmon" {
			t.Errorf("Expected service='sysmon', got '%s'", service)
		}

		// Verify index is used for query
		rows, err := sqlite.DB.Query("SELECT id FROM rules WHERE logsource_product = 'windows'")
		if err != nil {
			t.Fatalf("Failed to query by logsource_product: %v", err)
		}
		defer rows.Close()

		foundTestRule := false
		for rows.Next() {
			var id string
			if err := rows.Scan(&id); err != nil {
				t.Fatalf("Failed to scan result: %v", err)
			}
			if id == "test-integration-rule" {
				foundTestRule = true
			}
		}

		if !foundTestRule {
			t.Error("Failed to find test rule when querying by logsource_product")
		}
	})
}
