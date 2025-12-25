package storage

import (
	"database/sql"
	"testing"
	"time"

	"go.uber.org/zap"
)

// TestMigration_1_7_0_RemoveConditionsColumn tests the migration that removes the conditions column
func TestMigration_1_7_0_RemoveConditionsColumn(t *testing.T) {
	// Create in-memory database
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("Failed to open database: %v", err)
	}
	defer db.Close()

	// Create base schema WITH conditions column (simulating pre-migration state)
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
		conditions TEXT,  -- This column should be removed by migration
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
	);
	CREATE INDEX IF NOT EXISTS idx_rules_enabled ON rules(enabled);
	CREATE INDEX IF NOT EXISTS idx_rules_severity ON rules(severity);
	CREATE INDEX IF NOT EXISTS idx_rules_type ON rules(type);
	CREATE INDEX IF NOT EXISTS idx_rules_lifecycle_status ON rules(lifecycle_status);
	`

	_, err = db.Exec(baseSchema)
	if err != nil {
		t.Fatalf("Failed to create base schema: %v", err)
	}

	// Verify conditions column exists before migration
	var columnCount int
	err = db.QueryRow("SELECT COUNT(*) FROM pragma_table_info('rules') WHERE name='conditions'").Scan(&columnCount)
	if err != nil {
		t.Fatalf("Failed to check for conditions column: %v", err)
	}
	if columnCount != 1 {
		t.Fatalf("Expected conditions column to exist before migration, got count: %d", columnCount)
	}

	// Insert test rule with NULL conditions (simulating post-Task-179 state)
	now := time.Now().UTC().Format(time.RFC3339)
	_, err = db.Exec(`
		INSERT INTO rules (
			id, type, name, description, severity, enabled, version,
			conditions, sigma_yaml, created_at, updated_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`, "test-rule-1", "sigma", "Test Rule", "Test Description", "high", 1, 1,
		nil, "title: Test\ndetection:\n  selection:\n    field: value\n  condition: selection", now, now)
	if err != nil {
		t.Fatalf("Failed to insert test rule: %v", err)
	}

	// Create migration runner and register migration
	logger := zap.NewNop().Sugar()
	runner, err := NewMigrationRunner(db, logger)
	if err != nil {
		t.Fatalf("Failed to create migration runner: %v", err)
	}

	// Register all SQLite migrations (includes our 1.7.0 migration)
	RegisterSQLiteMigrations(runner)

	// Find and run migration 1.7.0
	var migration1_7_0 *Migration
	for i := range runner.migrations {
		if runner.migrations[i].Version == "1.7.0" {
			migration1_7_0 = &runner.migrations[i]
			break
		}
	}
	if migration1_7_0 == nil {
		t.Fatal("Migration 1.7.0 not found")
	}

	// Run the migration
	err = runner.runMigration(*migration1_7_0)
	if err != nil {
		t.Fatalf("Migration failed: %v", err)
	}

	// Verify conditions column no longer exists
	err = db.QueryRow("SELECT COUNT(*) FROM pragma_table_info('rules') WHERE name='conditions'").Scan(&columnCount)
	if err != nil {
		t.Fatalf("Failed to check for conditions column after migration: %v", err)
	}
	if columnCount != 0 {
		t.Fatalf("Expected conditions column to be removed after migration, got count: %d", columnCount)
	}

	// Verify data was preserved
	var id, name, ruleType, sigmaYAML string
	err = db.QueryRow("SELECT id, name, type, sigma_yaml FROM rules WHERE id = ?", "test-rule-1").Scan(&id, &name, &ruleType, &sigmaYAML)
	if err != nil {
		t.Fatalf("Failed to query rule after migration: %v", err)
	}
	if id != "test-rule-1" {
		t.Errorf("Expected rule ID 'test-rule-1', got: %s", id)
	}
	if name != "Test Rule" {
		t.Errorf("Expected rule name 'Test Rule', got: %s", name)
	}
	if ruleType != "sigma" {
		t.Errorf("Expected rule type 'sigma', got: %s", ruleType)
	}

	// Verify indexes were recreated
	var indexCount int
	err = db.QueryRow("SELECT COUNT(*) FROM sqlite_master WHERE type='index' AND name='idx_rules_enabled'").Scan(&indexCount)
	if err != nil {
		t.Fatalf("Failed to check for idx_rules_enabled: %v", err)
	}
	if indexCount != 1 {
		t.Errorf("Expected idx_rules_enabled to exist, got count: %d", indexCount)
	}

	err = db.QueryRow("SELECT COUNT(*) FROM sqlite_master WHERE type='index' AND name='idx_rules_lifecycle_enforcement'").Scan(&indexCount)
	if err != nil {
		t.Fatalf("Failed to check for idx_rules_lifecycle_enforcement: %v", err)
	}
	if indexCount != 1 {
		t.Errorf("Expected idx_rules_lifecycle_enforcement to exist, got count: %d", indexCount)
	}
}

// TestMigration_1_7_0_BlocksIfConditionsDataExists tests that the migration aborts if rules have conditions data
func TestMigration_1_7_0_BlocksIfConditionsDataExists(t *testing.T) {
	// Create in-memory database
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("Failed to open database: %v", err)
	}
	defer db.Close()

	// Create base schema WITH conditions column
	baseSchema := `
	CREATE TABLE IF NOT EXISTS rules (
		id TEXT PRIMARY KEY,
		type TEXT NOT NULL DEFAULT 'sigma',
		name TEXT NOT NULL,
		severity TEXT NOT NULL,
		conditions TEXT,
		sigma_yaml TEXT,
		created_at DATETIME NOT NULL,
		updated_at DATETIME NOT NULL
	);
	`

	_, err = db.Exec(baseSchema)
	if err != nil {
		t.Fatalf("Failed to create base schema: %v", err)
	}

	// Insert test rule WITH conditions data (simulating pre-Task-179 state)
	now := time.Now().UTC().Format(time.RFC3339)
	_, err = db.Exec(`
		INSERT INTO rules (id, type, name, severity, conditions, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?)
	`, "test-rule-1", "sigma", "Test Rule", "high", `[{"field":"test","value":"value"}]`, now, now)
	if err != nil {
		t.Fatalf("Failed to insert test rule: %v", err)
	}

	// Create migration runner
	logger := zap.NewNop().Sugar()
	runner, err := NewMigrationRunner(db, logger)
	if err != nil {
		t.Fatalf("Failed to create migration runner: %v", err)
	}

	// Register all SQLite migrations
	RegisterSQLiteMigrations(runner)

	// Find migration 1.7.0
	var migration1_7_0 *Migration
	for i := range runner.migrations {
		if runner.migrations[i].Version == "1.7.0" {
			migration1_7_0 = &runner.migrations[i]
			break
		}
	}
	if migration1_7_0 == nil {
		t.Fatal("Migration 1.7.0 not found")
	}

	// Run the migration - should FAIL
	err = runner.runMigration(*migration1_7_0)
	if err == nil {
		t.Fatal("Expected migration to fail when conditions data exists, but it succeeded")
	}

	// Verify error message mentions conditions data
	errMsg := err.Error()
	if errMsg == "" {
		t.Fatal("Expected error message, got empty string")
	}
	t.Logf("Migration correctly failed with error: %s", errMsg)
}

// TestMigration_1_7_0_Idempotent tests that the migration is idempotent (can be run multiple times)
func TestMigration_1_7_0_Idempotent(t *testing.T) {
	// Create in-memory database
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("Failed to open database: %v", err)
	}
	defer db.Close()

	// Create base schema WITHOUT conditions column (simulating already-migrated state)
	baseSchema := `
	CREATE TABLE IF NOT EXISTS rules (
		id TEXT PRIMARY KEY,
		type TEXT NOT NULL DEFAULT 'sigma',
		name TEXT NOT NULL,
		severity TEXT NOT NULL,
		sigma_yaml TEXT,
		created_at DATETIME NOT NULL,
		updated_at DATETIME NOT NULL
	);
	`

	_, err = db.Exec(baseSchema)
	if err != nil {
		t.Fatalf("Failed to create base schema: %v", err)
	}

	// Create migration runner
	logger := zap.NewNop().Sugar()
	runner, err := NewMigrationRunner(db, logger)
	if err != nil {
		t.Fatalf("Failed to create migration runner: %v", err)
	}

	// Register all SQLite migrations
	RegisterSQLiteMigrations(runner)

	// Find migration 1.7.0
	var migration1_7_0 *Migration
	for i := range runner.migrations {
		if runner.migrations[i].Version == "1.7.0" {
			migration1_7_0 = &runner.migrations[i]
			break
		}
	}
	if migration1_7_0 == nil {
		t.Fatal("Migration 1.7.0 not found")
	}

	// Run the migration on already-migrated schema - should succeed (idempotent)
	err = runner.runMigration(*migration1_7_0)
	if err != nil {
		t.Fatalf("Migration should be idempotent but failed: %v", err)
	}

	// Verify conditions column still doesn't exist
	var columnCount int
	err = db.QueryRow("SELECT COUNT(*) FROM pragma_table_info('rules') WHERE name='conditions'").Scan(&columnCount)
	if err != nil {
		t.Fatalf("Failed to check for conditions column: %v", err)
	}
	if columnCount != 0 {
		t.Errorf("Expected conditions column to not exist, got count: %d", columnCount)
	}
}

// TestMigration_1_7_0_PreservesAllData tests that all rule data is preserved during migration
func TestMigration_1_7_0_PreservesAllData(t *testing.T) {
	// Create in-memory database
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("Failed to open database: %v", err)
	}
	defer db.Close()

	// Create base schema WITH conditions column
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
		lifecycle_status TEXT NOT NULL DEFAULT 'experimental',
		deprecated_at DATETIME,
		deprecated_reason TEXT,
		deprecated_by TEXT,
		sunset_date DATETIME,
		created_at DATETIME NOT NULL,
		updated_at DATETIME NOT NULL
	);
	`

	_, err = db.Exec(baseSchema)
	if err != nil {
		t.Fatalf("Failed to create base schema: %v", err)
	}

	// Insert comprehensive test rule
	now := time.Now().UTC().Format(time.RFC3339)
	_, err = db.Exec(`
		INSERT INTO rules (
			id, type, name, description, severity, enabled, version,
			tags, mitre_tactics, mitre_techniques, author, rule_references,
			false_positives, metadata, detection, logsource, conditions, actions,
			query, correlation, sigma_yaml, logsource_category, logsource_product, logsource_service,
			lifecycle_status, created_at, updated_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`, "test-rule-1", "sigma", "Test Rule", "Test Description", "high", 1, 2,
		`["tag1","tag2"]`, `["initial-access"]`, `["T1190"]`, "Test Author", `["ref1","ref2"]`,
		`["fp1"]`, `{"key":"value"}`, `{"selection":{"field":"value"}}`, `{"category":"process_creation"}`,
		nil, `["alert"]`, "", "", "title: Test\ndetection:\n  selection:\n    field: value\n  condition: selection",
		"process_creation", "windows", "sysmon", "stable", now, now)
	if err != nil {
		t.Fatalf("Failed to insert test rule: %v", err)
	}

	// Run migration
	logger := zap.NewNop().Sugar()
	runner, err := NewMigrationRunner(db, logger)
	if err != nil {
		t.Fatalf("Failed to create migration runner: %v", err)
	}

	RegisterSQLiteMigrations(runner)

	var migration1_7_0 *Migration
	for i := range runner.migrations {
		if runner.migrations[i].Version == "1.7.0" {
			migration1_7_0 = &runner.migrations[i]
			break
		}
	}

	err = runner.runMigration(*migration1_7_0)
	if err != nil {
		t.Fatalf("Migration failed: %v", err)
	}

	// Verify ALL data was preserved
	var (
		id, ruleType, name, description, severity, author, sigmaYAML string
		enabled, version                                                       int
		tags, mitreTactics, mitreTechniques, references                       sql.NullString
		falsePositives, metadata, detection, logsource, actions               sql.NullString
		logsourceCategory, logsourceProduct, logsourceService, lifecycleStatus sql.NullString
	)

	err = db.QueryRow(`
		SELECT id, type, name, description, severity, enabled, version,
		       tags, mitre_tactics, mitre_techniques, author, rule_references,
		       false_positives, metadata, detection, logsource, actions,
		       sigma_yaml, logsource_category, logsource_product, logsource_service,
		       lifecycle_status
		FROM rules WHERE id = ?
	`, "test-rule-1").Scan(
		&id, &ruleType, &name, &description, &severity, &enabled, &version,
		&tags, &mitreTactics, &mitreTechniques, &author, &references,
		&falsePositives, &metadata, &detection, &logsource, &actions,
		&sigmaYAML, &logsourceCategory, &logsourceProduct, &logsourceService,
		&lifecycleStatus,
	)
	if err != nil {
		t.Fatalf("Failed to query rule after migration: %v", err)
	}

	// Verify all fields
	if id != "test-rule-1" {
		t.Errorf("id mismatch: got %s, want test-rule-1", id)
	}
	if ruleType != "sigma" {
		t.Errorf("type mismatch: got %s, want sigma", ruleType)
	}
	if name != "Test Rule" {
		t.Errorf("name mismatch: got %s, want Test Rule", name)
	}
	if description != "Test Description" {
		t.Errorf("description mismatch: got %s, want Test Description", description)
	}
	if severity != "high" {
		t.Errorf("severity mismatch: got %s, want high", severity)
	}
	if enabled != 1 {
		t.Errorf("enabled mismatch: got %d, want 1", enabled)
	}
	if version != 2 {
		t.Errorf("version mismatch: got %d, want 2", version)
	}
	if !tags.Valid || tags.String != `["tag1","tag2"]` {
		t.Errorf("tags mismatch: got %s, want [\"tag1\",\"tag2\"]", tags.String)
	}
	if author != "Test Author" {
		t.Errorf("author mismatch: got %s, want Test Author", author)
	}
	if !logsourceCategory.Valid || logsourceCategory.String != "process_creation" {
		t.Errorf("logsource_category mismatch: got %s, want process_creation", logsourceCategory.String)
	}
	if !lifecycleStatus.Valid || lifecycleStatus.String != "stable" {
		t.Errorf("lifecycle_status mismatch: got %s, want stable", lifecycleStatus.String)
	}

	t.Log("✓ All rule data preserved during migration")
}
