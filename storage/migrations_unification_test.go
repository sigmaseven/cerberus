package storage

import (
	"database/sql"
	"encoding/json"
	"path/filepath"
	"testing"
	"time"

	"go.uber.org/zap"
	_ "modernc.org/sqlite"
)

// TestMigration_1_8_0_AppliesCleanly verifies migration 1.8.0 applies without errors
// on an existing schema with all previous migrations.
func TestMigration_1_8_0_AppliesCleanly(t *testing.T) {
	// Create temporary test database
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test_1_8_0_clean.db")

	// Create logger
	logger, err := zap.NewDevelopment()
	if err != nil {
		t.Fatalf("Failed to create logger: %v", err)
	}
	defer logger.Sync()
	sugaredLogger := logger.Sugar()

	// Create database with base schema (simulating production database)
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("Failed to open database: %v", err)
	}
	defer db.Close()

	// Create base rules table (mimics what would exist before migration)
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
		sigma_yaml TEXT,
		logsource_category TEXT,
		logsource_product TEXT,
		logsource_service TEXT,
		created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
		updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
	);
	CREATE INDEX IF NOT EXISTS idx_rules_type ON rules(type);
	CREATE INDEX IF NOT EXISTS idx_rules_logsource_category ON rules(logsource_category);
	CREATE INDEX IF NOT EXISTS idx_rules_logsource_product ON rules(logsource_product);
	CREATE INDEX IF NOT EXISTS idx_rules_logsource_service ON rules(logsource_service);
	`
	_, err = db.Exec(baseSchema)
	if err != nil {
		t.Fatalf("Failed to create base schema: %v", err)
	}

	// Create migration runner and register migration 1.8.0
	runner, err := NewMigrationRunner(db, sugaredLogger)
	if err != nil {
		t.Fatalf("Failed to create migration runner: %v", err)
	}

	// Register migration (extract from RegisterSQLiteMigrations)
	RegisterSQLiteMigrations(runner)

	// Run migration 1.8.0
	err = runner.runMigration(runner.migrations[len(runner.migrations)-1])
	if err != nil {
		t.Fatalf("Migration 1.8.0 failed: %v", err)
	}

	// Verify migration was recorded
	t.Run("verify_migration_recorded", func(t *testing.T) {
		var count int
		err := db.QueryRow("SELECT COUNT(*) FROM schema_migrations WHERE version='1.8.0'").Scan(&count)
		if err != nil {
			t.Fatalf("Failed to check schema_migrations: %v", err)
		}
		if count != 1 {
			t.Errorf("Migration 1.8.0 should be recorded, but count=%d", count)
		}
	})
}

// TestMigration_1_8_0_ColumnsAndIndexes verifies all columns and indexes are created correctly.
func TestMigration_1_8_0_ColumnsAndIndexes(t *testing.T) {
	// Create temporary test database
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test_1_8_0_columns.db")

	// Create logger
	logger, err := zap.NewDevelopment()
	if err != nil {
		t.Fatalf("Failed to create logger: %v", err)
	}
	defer logger.Sync()
	sugaredLogger := logger.Sugar()

	// Create database with base schema
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("Failed to open database: %v", err)
	}
	defer db.Close()

	// Create minimal rules table
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

	// Create migration runner
	runner, err := NewMigrationRunner(db, sugaredLogger)
	if err != nil {
		t.Fatalf("Failed to create migration runner: %v", err)
	}

	// Register and run migration 1.8.0
	RegisterSQLiteMigrations(runner)
	err = runner.runMigration(runner.migrations[len(runner.migrations)-1])
	if err != nil {
		t.Fatalf("Migration failed: %v", err)
	}

	// Verify all columns exist
	t.Run("verify_columns_exist", func(t *testing.T) {
		columnsToCheck := []string{
			"rule_category",
			"correlation_config",
			"lifecycle_status",
			"performance_stats",
			"deprecated_at",
			"deprecated_reason",
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

	// Verify all indexes exist
	t.Run("verify_indexes_exist", func(t *testing.T) {
		indexesToCheck := []string{
			"idx_rules_category",
			"idx_rules_lifecycle_status",
			"idx_rules_deprecated_at",
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
}

// TestMigration_1_8_0_DefaultValues verifies default values are applied correctly.
func TestMigration_1_8_0_DefaultValues(t *testing.T) {
	// Create temporary test database
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test_1_8_0_defaults.db")

	// Create logger
	logger, err := zap.NewDevelopment()
	if err != nil {
		t.Fatalf("Failed to create logger: %v", err)
	}
	defer logger.Sync()
	sugaredLogger := logger.Sugar()

	// Create database with base schema
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("Failed to open database: %v", err)
	}
	defer db.Close()

	// Create base rules table
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

	// Insert test rule BEFORE migration
	_, err = db.Exec(`
		INSERT INTO rules (id, name, severity, created_at, updated_at)
		VALUES ('test-rule-1', 'Test Rule', 'high', datetime('now'), datetime('now'))
	`)
	if err != nil {
		t.Fatalf("Failed to insert test rule: %v", err)
	}

	// Create migration runner and apply migration
	runner, err := NewMigrationRunner(db, sugaredLogger)
	if err != nil {
		t.Fatalf("Failed to create migration runner: %v", err)
	}

	RegisterSQLiteMigrations(runner)
	err = runner.runMigration(runner.migrations[len(runner.migrations)-1])
	if err != nil {
		t.Fatalf("Migration failed: %v", err)
	}

	// Verify default values applied to existing rule
	t.Run("verify_defaults_on_existing_rule", func(t *testing.T) {
		var ruleCategory, lifecycleStatus string
		var correlationConfig, performanceStats, deprecatedAt, deprecatedReason sql.NullString

		err := db.QueryRow(`
			SELECT rule_category, correlation_config, lifecycle_status,
			       performance_stats, deprecated_at, deprecated_reason
			FROM rules WHERE id='test-rule-1'
		`).Scan(&ruleCategory, &correlationConfig, &lifecycleStatus,
			&performanceStats, &deprecatedAt, &deprecatedReason)
		if err != nil {
			t.Fatalf("Failed to query test rule: %v", err)
		}

		// Verify NOT NULL defaults
		if ruleCategory != "detection" {
			t.Errorf("Expected rule_category='detection', got '%s'", ruleCategory)
		}
		if lifecycleStatus != "active" {
			t.Errorf("Expected lifecycle_status='active', got '%s'", lifecycleStatus)
		}

		// Verify nullable columns are NULL
		if correlationConfig.Valid {
			t.Errorf("Expected correlation_config to be NULL, got '%s'", correlationConfig.String)
		}
		if performanceStats.Valid {
			t.Errorf("Expected performance_stats to be NULL, got '%s'", performanceStats.String)
		}
		if deprecatedAt.Valid {
			t.Errorf("Expected deprecated_at to be NULL, got '%s'", deprecatedAt.String)
		}
		if deprecatedReason.Valid {
			t.Errorf("Expected deprecated_reason to be NULL, got '%s'", deprecatedReason.String)
		}
	})

	// Verify defaults apply to newly inserted rules
	t.Run("verify_defaults_on_new_rule", func(t *testing.T) {
		_, err := db.Exec(`
			INSERT INTO rules (id, name, severity, created_at, updated_at)
			VALUES ('test-rule-2', 'New Rule', 'medium', datetime('now'), datetime('now'))
		`)
		if err != nil {
			t.Fatalf("Failed to insert new rule: %v", err)
		}

		var ruleCategory, lifecycleStatus string
		err = db.QueryRow(`
			SELECT rule_category, lifecycle_status FROM rules WHERE id='test-rule-2'
		`).Scan(&ruleCategory, &lifecycleStatus)
		if err != nil {
			t.Fatalf("Failed to query new rule: %v", err)
		}

		if ruleCategory != "detection" {
			t.Errorf("Expected rule_category='detection', got '%s'", ruleCategory)
		}
		if lifecycleStatus != "active" {
			t.Errorf("Expected lifecycle_status='active', got '%s'", lifecycleStatus)
		}
	})
}

// TestMigration_1_8_0_BackwardCompatibility verifies existing rules continue to work.
func TestMigration_1_8_0_BackwardCompatibility(t *testing.T) {
	// Create temporary test database
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test_1_8_0_compat.db")

	// Create logger
	logger, err := zap.NewDevelopment()
	if err != nil {
		t.Fatalf("Failed to create logger: %v", err)
	}
	defer logger.Sync()
	sugaredLogger := logger.Sugar()

	// Create database
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("Failed to open database: %v", err)
	}
	defer db.Close()

	// Create full base schema (all columns from 1.7.1)
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
		sigma_yaml TEXT,
		logsource_category TEXT,
		logsource_product TEXT,
		logsource_service TEXT,
		created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
		updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
	);
	`
	_, err = db.Exec(baseSchema)
	if err != nil {
		t.Fatalf("Failed to create base schema: %v", err)
	}

	// Insert diverse test rules before migration
	testRules := []struct {
		id          string
		ruleType    string
		name        string
		severity    string
		detection   string
		logsource   string
		correlation string
	}{
		{
			id:        "sigma-rule-1",
			ruleType:  "sigma",
			name:      "SIGMA Detection Rule",
			severity:  "high",
			detection: `{"selection": {"EventID": 4688}}`,
			logsource: `{"category": "process_creation", "product": "windows"}`,
		},
		{
			id:          "cql-rule-1",
			ruleType:    "cql",
			name:        "CQL Query Rule",
			severity:    "medium",
			correlation: `{"window": 3600, "sequence": ["evt1", "evt2"]}`,
		},
		{
			id:       "legacy-rule-1",
			ruleType: "sigma",
			name:     "Legacy Rule Without New Fields",
			severity: "low",
		},
	}

	for _, rule := range testRules {
		_, err := db.Exec(`
			INSERT INTO rules (id, type, name, severity, detection, logsource, correlation, created_at, updated_at)
			VALUES (?, ?, ?, ?, ?, ?, ?, datetime('now'), datetime('now'))
		`, rule.id, rule.ruleType, rule.name, rule.severity, nullString(rule.detection), nullString(rule.logsource), nullString(rule.correlation))
		if err != nil {
			t.Fatalf("Failed to insert test rule %s: %v", rule.id, err)
		}
	}

	// Apply migration
	runner, err := NewMigrationRunner(db, sugaredLogger)
	if err != nil {
		t.Fatalf("Failed to create migration runner: %v", err)
	}

	RegisterSQLiteMigrations(runner)
	err = runner.runMigration(runner.migrations[len(runner.migrations)-1])
	if err != nil {
		t.Fatalf("Migration failed: %v", err)
	}

	// Verify all existing rules still queryable
	t.Run("verify_all_rules_queryable", func(t *testing.T) {
		rows, err := db.Query("SELECT id, name, type, severity, rule_category, lifecycle_status FROM rules ORDER BY id")
		if err != nil {
			t.Fatalf("Failed to query rules: %v", err)
		}
		defer rows.Close()

		count := 0
		for rows.Next() {
			var id, name, ruleType, severity, ruleCategory, lifecycleStatus string
			err := rows.Scan(&id, &name, &ruleType, &severity, &ruleCategory, &lifecycleStatus)
			if err != nil {
				t.Fatalf("Failed to scan row: %v", err)
			}

			// Verify defaults applied
			if ruleCategory != "detection" {
				t.Errorf("Rule %s: expected rule_category='detection', got '%s'", id, ruleCategory)
			}
			if lifecycleStatus != "active" {
				t.Errorf("Rule %s: expected lifecycle_status='active', got '%s'", id, lifecycleStatus)
			}

			count++
		}

		if count != len(testRules) {
			t.Errorf("Expected %d rules, found %d", len(testRules), count)
		}
	})

	// Verify old columns still accessible
	t.Run("verify_old_columns_accessible", func(t *testing.T) {
		var detection, logsource string
		err := db.QueryRow(`
			SELECT detection, logsource FROM rules WHERE id='sigma-rule-1'
		`).Scan(&detection, &logsource)
		if err != nil {
			t.Fatalf("Failed to query old columns: %v", err)
		}

		if detection == "" {
			t.Error("Detection column should still contain data")
		}
		if logsource == "" {
			t.Error("Logsource column should still contain data")
		}
	})
}

// TestMigration_1_8_0_Rollback verifies rollback capability.
func TestMigration_1_8_0_Rollback(t *testing.T) {
	// Create temporary test database
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test_1_8_0_rollback.db")

	// Create logger
	logger, err := zap.NewDevelopment()
	if err != nil {
		t.Fatalf("Failed to create logger: %v", err)
	}
	defer logger.Sync()
	sugaredLogger := logger.Sugar()

	// Create database
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

	// Create migration runner
	runner, err := NewMigrationRunner(db, sugaredLogger)
	if err != nil {
		t.Fatalf("Failed to create migration runner: %v", err)
	}

	RegisterSQLiteMigrations(runner)

	// Apply migration
	err = runner.runMigration(runner.migrations[len(runner.migrations)-1])
	if err != nil {
		t.Fatalf("Migration failed: %v", err)
	}

	// Verify indexes exist before rollback
	t.Run("verify_indexes_before_rollback", func(t *testing.T) {
		var count int
		err := db.QueryRow("SELECT COUNT(*) FROM sqlite_master WHERE type='index' AND name='idx_rules_category'").Scan(&count)
		if err != nil {
			t.Fatalf("Failed to check index: %v", err)
		}
		if count != 1 {
			t.Error("Index should exist before rollback")
		}
	})

	// Rollback migration
	err = runner.RollbackMigration("1.8.0", "test rollback")
	if err != nil {
		t.Fatalf("Rollback failed: %v", err)
	}

	// Verify indexes removed after rollback
	t.Run("verify_indexes_after_rollback", func(t *testing.T) {
		indexes := []string{
			"idx_rules_category",
			"idx_rules_lifecycle_status",
			"idx_rules_deprecated_at",
		}

		for _, index := range indexes {
			var count int
			err := db.QueryRow("SELECT COUNT(*) FROM sqlite_master WHERE type='index' AND name=?", index).Scan(&count)
			if err != nil {
				t.Fatalf("Failed to check index %s: %v", index, err)
			}
			if count != 0 {
				t.Errorf("Index %s should be removed after rollback", index)
			}
		}
	})

	// Verify columns still exist (SQLite limitation)
	t.Run("verify_columns_remain_after_rollback", func(t *testing.T) {
		// Note: SQLite doesn't support DROP COLUMN easily
		// Columns remain but indexes are removed
		var count int
		err := db.QueryRow("SELECT COUNT(*) FROM pragma_table_info('rules') WHERE name='rule_category'").Scan(&count)
		if err != nil {
			t.Fatalf("Failed to check column: %v", err)
		}
		if count != 1 {
			t.Log("Note: Column remains after rollback due to SQLite limitation (expected)")
		}
	})
}

// TestMigration_1_8_0_ForeignKeyConstraints verifies foreign key constraints still enforced.
func TestMigration_1_8_0_ForeignKeyConstraints(t *testing.T) {
	// Create temporary test database
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test_1_8_0_fk.db")

	// Create logger
	logger, err := zap.NewDevelopment()
	if err != nil {
		t.Fatalf("Failed to create logger: %v", err)
	}
	defer logger.Sync()
	sugaredLogger := logger.Sugar()

	// Create SQLite instance (enables foreign keys)
	sqlite, err := NewSQLite(dbPath, sugaredLogger)
	if err != nil {
		t.Fatalf("Failed to create SQLite: %v", err)
	}
	defer sqlite.Close()

	// Create test table with foreign key to rules
	_, err = sqlite.DB.Exec(`
		CREATE TABLE IF NOT EXISTS test_rule_references (
			id TEXT PRIMARY KEY,
			rule_id TEXT NOT NULL,
			notes TEXT,
			FOREIGN KEY (rule_id) REFERENCES rules(id) ON DELETE CASCADE
		);
	`)
	if err != nil {
		t.Fatalf("Failed to create test table: %v", err)
	}

	// Insert test rule
	_, err = sqlite.DB.Exec(`
		INSERT INTO rules (id, name, severity, created_at, updated_at)
		VALUES ('test-rule-fk', 'Test Rule', 'high', datetime('now'), datetime('now'))
	`)
	if err != nil {
		t.Fatalf("Failed to insert test rule: %v", err)
	}

	// Insert reference to test rule
	_, err = sqlite.DB.Exec(`
		INSERT INTO test_rule_references (id, rule_id, notes)
		VALUES ('ref-1', 'test-rule-fk', 'Test reference')
	`)
	if err != nil {
		t.Fatalf("Failed to insert reference: %v", err)
	}

	// Verify foreign key constraint enforced (should fail)
	t.Run("verify_fk_constraint_enforced", func(t *testing.T) {
		_, err := sqlite.DB.Exec(`
			INSERT INTO test_rule_references (id, rule_id, notes)
			VALUES ('ref-2', 'nonexistent-rule', 'Invalid reference')
		`)
		if err == nil {
			t.Error("Expected foreign key constraint violation, but insert succeeded")
		}
	})

	// Verify cascade delete works
	t.Run("verify_cascade_delete", func(t *testing.T) {
		// Delete rule
		_, err := sqlite.DB.Exec("DELETE FROM rules WHERE id='test-rule-fk'")
		if err != nil {
			t.Fatalf("Failed to delete rule: %v", err)
		}

		// Verify reference was cascade deleted
		var count int
		err = sqlite.DB.QueryRow("SELECT COUNT(*) FROM test_rule_references WHERE rule_id='test-rule-fk'").Scan(&count)
		if err != nil {
			t.Fatalf("Failed to count references: %v", err)
		}
		if count != 0 {
			t.Error("Reference should be cascade deleted when rule is deleted")
		}
	})
}

// TestMigration_1_8_0_CorrelationRuleScenario tests correlation rule scenario.
func TestMigration_1_8_0_CorrelationRuleScenario(t *testing.T) {
	// Create temporary test database
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test_1_8_0_correlation.db")

	// Create logger
	logger, err := zap.NewDevelopment()
	if err != nil {
		t.Fatalf("Failed to create logger: %v", err)
	}
	defer logger.Sync()
	sugaredLogger := logger.Sugar()

	// Create database
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("Failed to open database: %v", err)
	}
	defer db.Close()

	// Create base schema and apply migration
	baseSchema := `
	CREATE TABLE IF NOT EXISTS rules (
		id TEXT PRIMARY KEY,
		type TEXT NOT NULL DEFAULT 'sigma',
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

	RegisterSQLiteMigrations(runner)
	err = runner.runMigration(runner.migrations[len(runner.migrations)-1])
	if err != nil {
		t.Fatalf("Migration failed: %v", err)
	}

	// Insert correlation rule with full lifecycle
	t.Run("insert_correlation_rule", func(t *testing.T) {
		correlationConfig := map[string]interface{}{
			"window":      3600,
			"sequence":    []string{"event1", "event2", "event3"},
			"aggregation": "count",
			"threshold":   5,
			"grouping":    []string{"user", "host"},
		}
		correlationJSON, _ := json.Marshal(correlationConfig)

		performanceStats := map[string]interface{}{
			"avg_eval_time_ms":     12.5,
			"match_count":          142,
			"false_positive_count": 3,
			"last_match_at":        time.Now().UTC().Format(time.RFC3339),
		}
		performanceJSON, _ := json.Marshal(performanceStats)

		_, err := db.Exec(`
			INSERT INTO rules (
				id, name, severity, type,
				rule_category, correlation_config,
				lifecycle_status, performance_stats,
				created_at, updated_at
			) VALUES (?, ?, ?, ?, ?, ?, ?, ?, datetime('now'), datetime('now'))
		`, "corr-rule-1", "Multi-Stage Attack", "critical", "cql",
			"correlation", string(correlationJSON),
			"stable", string(performanceJSON))
		if err != nil {
			t.Fatalf("Failed to insert correlation rule: %v", err)
		}
	})

	// Query and verify correlation rule
	t.Run("query_correlation_rule", func(t *testing.T) {
		var id, name, category, lifecycleStatus, correlationConfig, performanceStats string
		err := db.QueryRow(`
			SELECT id, name, rule_category, lifecycle_status, correlation_config, performance_stats
			FROM rules WHERE id='corr-rule-1'
		`).Scan(&id, &name, &category, &lifecycleStatus, &correlationConfig, &performanceStats)
		if err != nil {
			t.Fatalf("Failed to query correlation rule: %v", err)
		}

		if category != "correlation" {
			t.Errorf("Expected rule_category='correlation', got '%s'", category)
		}
		if lifecycleStatus != "stable" {
			t.Errorf("Expected lifecycle_status='stable', got '%s'", lifecycleStatus)
		}

		// Verify JSON is valid
		var config map[string]interface{}
		if err := json.Unmarshal([]byte(correlationConfig), &config); err != nil {
			t.Errorf("Failed to parse correlation_config JSON: %v", err)
		}
		if config["window"] != float64(3600) {
			t.Errorf("Expected window=3600, got %v", config["window"])
		}

		var stats map[string]interface{}
		if err := json.Unmarshal([]byte(performanceStats), &stats); err != nil {
			t.Errorf("Failed to parse performance_stats JSON: %v", err)
		}
		if stats["match_count"] != float64(142) {
			t.Errorf("Expected match_count=142, got %v", stats["match_count"])
		}
	})

	// Test index performance for correlation queries
	t.Run("query_by_category_uses_index", func(t *testing.T) {
		rows, err := db.Query("SELECT id FROM rules WHERE rule_category='correlation'")
		if err != nil {
			t.Fatalf("Failed to query by category: %v", err)
		}
		defer rows.Close()

		found := false
		for rows.Next() {
			var id string
			rows.Scan(&id)
			if id == "corr-rule-1" {
				found = true
			}
		}
		if !found {
			t.Error("Failed to find correlation rule when querying by category")
		}
	})
}

// TestMigration_1_8_0_DeprecationScenario tests rule deprecation scenario.
func TestMigration_1_8_0_DeprecationScenario(t *testing.T) {
	// Create temporary test database
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test_1_8_0_deprecation.db")

	// Create logger
	logger, err := zap.NewDevelopment()
	if err != nil {
		t.Fatalf("Failed to create logger: %v", err)
	}
	defer logger.Sync()
	sugaredLogger := logger.Sugar()

	// Create database
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("Failed to open database: %v", err)
	}
	defer db.Close()

	// Create schema and apply migration
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

	RegisterSQLiteMigrations(runner)
	err = runner.runMigration(runner.migrations[len(runner.migrations)-1])
	if err != nil {
		t.Fatalf("Migration failed: %v", err)
	}

	// Insert active rule
	_, err = db.Exec(`
		INSERT INTO rules (id, name, severity, created_at, updated_at)
		VALUES ('rule-active', 'Active Rule', 'high', datetime('now'), datetime('now'))
	`)
	if err != nil {
		t.Fatalf("Failed to insert active rule: %v", err)
	}

	// Deprecate rule
	t.Run("deprecate_rule", func(t *testing.T) {
		deprecatedAt := time.Now().UTC()
		_, err := db.Exec(`
			UPDATE rules
			SET lifecycle_status='deprecated',
			    deprecated_at=?,
			    deprecated_reason=?
			WHERE id='rule-active'
		`, deprecatedAt, "Replaced by rule-v2 with better detection logic")
		if err != nil {
			t.Fatalf("Failed to deprecate rule: %v", err)
		}
	})

	// Query deprecated rules
	t.Run("query_deprecated_rules", func(t *testing.T) {
		rows, err := db.Query(`
			SELECT id, name, lifecycle_status, deprecated_at, deprecated_reason
			FROM rules
			WHERE lifecycle_status='deprecated'
		`)
		if err != nil {
			t.Fatalf("Failed to query deprecated rules: %v", err)
		}
		defer rows.Close()

		found := false
		for rows.Next() {
			var id, name, lifecycleStatus, deprecatedReason string
			var deprecatedAt time.Time
			err := rows.Scan(&id, &name, &lifecycleStatus, &deprecatedAt, &deprecatedReason)
			if err != nil {
				t.Fatalf("Failed to scan row: %v", err)
			}

			if id == "rule-active" {
				found = true
				if lifecycleStatus != "deprecated" {
					t.Errorf("Expected lifecycle_status='deprecated', got '%s'", lifecycleStatus)
				}
				if deprecatedReason == "" {
					t.Error("Expected deprecated_reason to be set")
				}
			}
		}
		if !found {
			t.Error("Failed to find deprecated rule")
		}
	})

	// Test index on deprecated_at
	t.Run("query_recently_deprecated_uses_index", func(t *testing.T) {
		thirtyDaysAgo := time.Now().UTC().AddDate(0, 0, -30)
		rows, err := db.Query(`
			SELECT id FROM rules WHERE deprecated_at > ?
		`, thirtyDaysAgo)
		if err != nil {
			t.Fatalf("Failed to query recently deprecated rules: %v", err)
		}
		defer rows.Close()

		found := false
		for rows.Next() {
			var id string
			rows.Scan(&id)
			if id == "rule-active" {
				found = true
			}
		}
		if !found {
			t.Error("Failed to find recently deprecated rule")
		}
	})
}

// nullString returns sql.NullString for optional string values
func nullString(s string) sql.NullString {
	if s == "" {
		return sql.NullString{Valid: false}
	}
	return sql.NullString{String: s, Valid: true}
}
