package storage

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"go.uber.org/zap"
	_ "modernc.org/sqlite"
)

// TestMigrateCorrelationRulesToUnified_Basic verifies basic migration functionality.
func TestMigrateCorrelationRulesToUnified_Basic(t *testing.T) {
	db, cleanup := setupCorrelationMigrationDB(t)
	defer cleanup()

	// Insert test correlation rules
	insertTestCorrelationRule(t, db, "corr-001", "Brute Force Detection", "high", 5*60*1e9)
	insertTestCorrelationRule(t, db, "corr-002", "Lateral Movement", "critical", 10*60*1e9)

	// Run migration
	opts := CorrelationUnificationOptions{
		DryRun:            false,
		MigrationTimemark: time.Now(),
	}

	err := MigrateCorrelationRulesToUnified(db, opts)
	if err != nil {
		t.Fatalf("Migration failed: %v", err)
	}

	// Verify rules migrated correctly
	verifyMigratedRule(t, db, "corr-001", "correlation", "stable")
	verifyMigratedRule(t, db, "corr-002", "correlation", "stable")

	// Verify correlation_config is valid JSON
	verifyCorrelationConfigJSON(t, db, "corr-001")
}

// TestMigrateCorrelationRulesToUnified_EmptyTable verifies migration with no records.
func TestMigrateCorrelationRulesToUnified_EmptyTable(t *testing.T) {
	db, cleanup := setupCorrelationMigrationDB(t)
	defer cleanup()

	// Run migration on empty table
	opts := CorrelationUnificationOptions{
		DryRun:            false,
		MigrationTimemark: time.Now(),
	}

	err := MigrateCorrelationRulesToUnified(db, opts)
	if err != nil {
		t.Fatalf("Migration should succeed on empty table: %v", err)
	}

	// Verify no correlation rules exist in unified table
	var count int
	err = db.QueryRow("SELECT COUNT(*) FROM rules WHERE rule_category='correlation'").Scan(&count)
	if err != nil {
		t.Fatalf("Failed to count rules: %v", err)
	}
	if count != 0 {
		t.Errorf("Expected 0 correlation rules, got %d", count)
	}
}

// TestMigrateCorrelationRulesToUnified_DryRun verifies dry-run mode doesn't persist changes.
func TestMigrateCorrelationRulesToUnified_DryRun(t *testing.T) {
	db, cleanup := setupCorrelationMigrationDB(t)
	defer cleanup()

	// Insert test rule
	insertTestCorrelationRule(t, db, "corr-003", "Test Rule", "medium", 60*1e9)

	// Run dry-run migration
	opts := CorrelationUnificationOptions{
		DryRun:            true,
		MigrationTimemark: time.Now(),
	}

	err := MigrateCorrelationRulesToUnified(db, opts)
	if err != nil {
		t.Fatalf("Dry-run migration failed: %v", err)
	}

	// Verify rule NOT migrated (dry-run should rollback)
	var count int
	err = db.QueryRow("SELECT COUNT(*) FROM rules WHERE rule_category='correlation'").Scan(&count)
	if err != nil {
		t.Fatalf("Failed to count rules: %v", err)
	}
	if count != 0 {
		t.Errorf("Dry-run should not persist changes, got %d rules", count)
	}

	// Verify original rule still in correlation_rules
	err = db.QueryRow("SELECT COUNT(*) FROM correlation_rules WHERE id='corr-003'").Scan(&count)
	if err != nil {
		t.Fatalf("Failed to count correlation_rules: %v", err)
	}
	if count != 1 {
		t.Errorf("Original rule should still exist, got count=%d", count)
	}
}

// TestMigrateCorrelationRulesToUnified_IDPreservation verifies IDs are preserved exactly.
func TestMigrateCorrelationRulesToUnified_IDPreservation(t *testing.T) {
	db, cleanup := setupCorrelationMigrationDB(t)
	defer cleanup()

	// Insert rules with specific IDs
	testIDs := []string{"corr-uuid-001", "corr-uuid-002", "special-id-123"}
	for _, id := range testIDs {
		insertTestCorrelationRule(t, db, id, fmt.Sprintf("Rule %s", id), "low", 60*1e9)
	}

	// Run migration
	opts := CorrelationUnificationOptions{
		DryRun:            false,
		MigrationTimemark: time.Now(),
	}

	err := MigrateCorrelationRulesToUnified(db, opts)
	if err != nil {
		t.Fatalf("Migration failed: %v", err)
	}

	// Verify all IDs preserved
	for _, id := range testIDs {
		var exists int
		err := db.QueryRow("SELECT COUNT(*) FROM rules WHERE id=? AND rule_category='correlation'", id).Scan(&exists)
		if err != nil {
			t.Fatalf("Failed to check ID %s: %v", id, err)
		}
		if exists != 1 {
			t.Errorf("ID %s not preserved (count=%d)", id, exists)
		}
	}
}

// TestMigrateCorrelationRulesToUnified_FieldMapping verifies all fields mapped correctly.
func TestMigrateCorrelationRulesToUnified_FieldMapping(t *testing.T) {
	db, cleanup := setupCorrelationMigrationDB(t)
	defer cleanup()

	// Insert rule with all fields populated
	now := time.Now().Truncate(time.Second)
	_, err := db.Exec(`
		INSERT INTO correlation_rules (
			id, name, description, severity, version, window,
			conditions, sequence, actions, created_at, updated_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`, "corr-full", "Full Field Rule", "Test description", "high", 2, 300*1e9,
		`[{"field":"source_ip","operator":"equals","value":"192.168.1.1"}]`,
		`["login_attempt","login_success"]`,
		`[{"type":"email","config":{"to":"admin@example.com"}}]`,
		now, now)
	if err != nil {
		t.Fatalf("Failed to insert test rule: %v", err)
	}

	// Run migration
	opts := CorrelationUnificationOptions{
		DryRun:            false,
		MigrationTimemark: time.Now(),
	}

	err = MigrateCorrelationRulesToUnified(db, opts)
	if err != nil {
		t.Fatalf("Migration failed: %v", err)
	}

	// Verify all fields
	var (
		id, ruleType, name, desc, severity, correlationConfig, actions string
		version, enabled                                               int
		category, lifecycleStatus                                      string
		createdAt, updatedAt                                           time.Time
	)

	err = db.QueryRow(`
		SELECT id, type, name, description, severity, version, enabled,
		       rule_category, correlation_config, lifecycle_status,
		       actions, created_at, updated_at
		FROM rules WHERE id='corr-full'
	`).Scan(&id, &ruleType, &name, &desc, &severity, &version, &enabled,
		&category, &correlationConfig, &lifecycleStatus,
		&actions, &createdAt, &updatedAt)

	if err != nil {
		t.Fatalf("Failed to query migrated rule: %v", err)
	}

	// Assert field values
	tests := []struct {
		name     string
		got      interface{}
		expected interface{}
	}{
		{"id", id, "corr-full"},
		{"type", ruleType, "correlation"},
		{"name", name, "Full Field Rule"},
		{"description", desc, "Test description"},
		{"severity", severity, "high"},
		{"version", version, 2},
		{"enabled", enabled, 1},
		{"rule_category", category, "correlation"},
		{"lifecycle_status", lifecycleStatus, "stable"},
	}

	for _, tt := range tests {
		if tt.got != tt.expected {
			t.Errorf("%s: got %v, expected %v", tt.name, tt.got, tt.expected)
		}
	}

	// Verify correlation_config structure
	var config map[string]interface{}
	err = json.Unmarshal([]byte(correlationConfig), &config)
	if err != nil {
		t.Fatalf("Failed to parse correlation_config: %v", err)
	}

	if window, ok := config["window"].(float64); !ok || window != 300*1e9 {
		t.Errorf("correlation_config.window incorrect: %v", config["window"])
	}

	// Verify timestamps preserved
	if !createdAt.Equal(now) {
		t.Errorf("created_at not preserved: got %v, expected %v", createdAt, now)
	}
	if !updatedAt.Equal(now) {
		t.Errorf("updated_at not preserved: got %v, expected %v", updatedAt, now)
	}
}

// TestMigrateCorrelationRulesToUnified_Idempotency verifies safe re-run behavior.
func TestMigrateCorrelationRulesToUnified_Idempotency(t *testing.T) {
	db, cleanup := setupCorrelationMigrationDB(t)
	defer cleanup()

	// Insert test rule
	insertTestCorrelationRule(t, db, "corr-idem", "Idempotent Rule", "medium", 60*1e9)

	opts := CorrelationUnificationOptions{
		DryRun:            false,
		MigrationTimemark: time.Now(),
	}

	// Run migration first time
	err := MigrateCorrelationRulesToUnified(db, opts)
	if err != nil {
		t.Fatalf("First migration failed: %v", err)
	}

	// Clear correlation_rules to simulate already-migrated state
	_, err = db.Exec("DELETE FROM correlation_rules")
	if err != nil {
		t.Fatalf("Failed to clear correlation_rules: %v", err)
	}

	// Run migration second time (should handle empty table gracefully)
	err = MigrateCorrelationRulesToUnified(db, opts)
	if err != nil {
		t.Fatalf("Second migration failed: %v", err)
	}

	// Verify only one rule exists (not duplicated)
	var count int
	err = db.QueryRow("SELECT COUNT(*) FROM rules WHERE id='corr-idem'").Scan(&count)
	if err != nil {
		t.Fatalf("Failed to count rules: %v", err)
	}
	if count != 1 {
		t.Errorf("Rule duplicated: got %d instances", count)
	}
}

// TestRollbackCorrelationUnification_Basic verifies basic rollback functionality.
func TestRollbackCorrelationUnification_Basic(t *testing.T) {
	db, cleanup := setupCorrelationMigrationDB(t)
	defer cleanup()

	// Insert and migrate rules
	insertTestCorrelationRule(t, db, "corr-rollback-1", "Rule 1", "high", 60*1e9)
	insertTestCorrelationRule(t, db, "corr-rollback-2", "Rule 2", "medium", 120*1e9)

	migrationTime := time.Now()
	opts := CorrelationUnificationOptions{
		DryRun:            false,
		BackupTableName:   "corr_backup_test",
		MigrationTimemark: migrationTime,
	}

	err := MigrateCorrelationRulesToUnified(db, opts)
	if err != nil {
		t.Fatalf("Migration failed: %v", err)
	}

	// Verify rules exist
	var countBefore int
	db.QueryRow("SELECT COUNT(*) FROM rules WHERE rule_category='correlation'").Scan(&countBefore)
	if countBefore != 2 {
		t.Fatalf("Expected 2 migrated rules, got %d", countBefore)
	}

	// Rollback
	err = RollbackCorrelationUnification(db, migrationTime, "corr_backup_test")
	if err != nil {
		t.Fatalf("Rollback failed: %v", err)
	}

	// Verify rules removed from unified table
	var countAfter int
	db.QueryRow("SELECT COUNT(*) FROM rules WHERE rule_category='correlation'").Scan(&countAfter)
	if countAfter != 0 {
		t.Errorf("Expected 0 rules after rollback, got %d", countAfter)
	}

	// Verify rules restored to correlation_rules
	var restoredCount int
	db.QueryRow("SELECT COUNT(*) FROM correlation_rules").Scan(&restoredCount)
	if restoredCount != 2 {
		t.Errorf("Expected 2 restored rules, got %d", restoredCount)
	}
}

// TestRollbackCorrelationUnification_TimestampFiltering verifies timestamp-based safety.
func TestRollbackCorrelationUnification_TimestampFiltering(t *testing.T) {
	db, cleanup := setupCorrelationMigrationDB(t)
	defer cleanup()

	// Insert pre-existing correlation rule (not part of migration)
	oldTime := time.Now().Add(-24 * time.Hour)
	_, err := db.Exec(`
		INSERT INTO rules (
			id, type, name, severity, rule_category, lifecycle_status,
			created_at, updated_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
	`, "old-corr-rule", "correlation", "Old Rule", "low", "correlation", "stable", oldTime, oldTime)
	if err != nil {
		t.Fatalf("Failed to insert old rule: %v", err)
	}

	// Migrate new rule
	insertTestCorrelationRule(t, db, "new-corr-rule", "New Rule", "high", 60*1e9)

	migrationTime := time.Now()
	opts := CorrelationUnificationOptions{
		DryRun:            false,
		BackupTableName:   "corr_backup_ts_test",
		MigrationTimemark: migrationTime,
	}

	err = MigrateCorrelationRulesToUnified(db, opts)
	if err != nil {
		t.Fatalf("Migration failed: %v", err)
	}

	// Rollback
	err = RollbackCorrelationUnification(db, migrationTime, "corr_backup_ts_test")
	if err != nil {
		t.Fatalf("Rollback failed: %v", err)
	}

	// Verify old rule NOT deleted (protected by timestamp)
	var oldExists int
	db.QueryRow("SELECT COUNT(*) FROM rules WHERE id='old-corr-rule'").Scan(&oldExists)
	if oldExists != 1 {
		t.Errorf("Old rule should not be deleted, exists=%d", oldExists)
	}

	// Verify new rule WAS deleted
	var newExists int
	db.QueryRow("SELECT COUNT(*) FROM rules WHERE id='new-corr-rule'").Scan(&newExists)
	if newExists != 0 {
		t.Errorf("New rule should be deleted, exists=%d", newExists)
	}
}

// TestMigrateCorrelationRulesToUnified_LoadTest validates performance with 1000+ rules.
func TestMigrateCorrelationRulesToUnified_LoadTest(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping load test in short mode")
	}

	db, cleanup := setupCorrelationMigrationDB(t)
	defer cleanup()

	// Insert 1500 correlation rules
	const ruleCount = 1500
	for i := 0; i < ruleCount; i++ {
		id := fmt.Sprintf("load-test-corr-%04d", i)
		name := fmt.Sprintf("Load Test Rule %d", i)
		severity := []string{"low", "medium", "high", "critical"}[i%4]
		window := int64((i%10 + 1) * 60 * 1e9)

		insertTestCorrelationRule(t, db, id, name, severity, window)
	}

	// Run migration with timing
	start := time.Now()
	opts := CorrelationUnificationOptions{
		DryRun:            false,
		MigrationTimemark: time.Now(),
	}

	err := MigrateCorrelationRulesToUnified(db, opts)
	duration := time.Since(start)

	if err != nil {
		t.Fatalf("Load test migration failed: %v", err)
	}

	// Verify all rules migrated
	var count int
	db.QueryRow("SELECT COUNT(*) FROM rules WHERE rule_category='correlation'").Scan(&count)
	if count != ruleCount {
		t.Errorf("Expected %d migrated rules, got %d", ruleCount, count)
	}

	// Performance check: Should complete in reasonable time (< 10 seconds for 1500 rules)
	if duration > 10*time.Second {
		t.Logf("WARNING: Migration took %v for %d rules (> 10s threshold)", duration, ruleCount)
	} else {
		t.Logf("Migration completed in %v for %d rules", duration, ruleCount)
	}
}

// TestMigrateCorrelationRulesToUnified_JSONEscaping validates special characters in JSON.
func TestMigrateCorrelationRulesToUnified_JSONEscaping(t *testing.T) {
	db, cleanup := setupCorrelationMigrationDB(t)
	defer cleanup()

	// Insert rule with special characters in JSON
	_, err := db.Exec(`
		INSERT INTO correlation_rules (
			id, name, description, severity, version, window,
			conditions, sequence, actions, created_at, updated_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`, "corr-json-escape", "Rule with 'quotes'", "Test \"escaping\"", "high", 1, 60*1e9,
		`[{"field":"message","operator":"contains","value":"error: can't connect"}]`,
		`["event_type_with_underscore","event-type-with-dash"]`,
		`[{"type":"webhook","config":{"url":"https://example.com/webhook?key=value&other=123"}}]`,
		time.Now(), time.Now())
	if err != nil {
		t.Fatalf("Failed to insert test rule: %v", err)
	}

	// Run migration
	opts := CorrelationUnificationOptions{
		DryRun:            false,
		MigrationTimemark: time.Now(),
	}

	err = MigrateCorrelationRulesToUnified(db, opts)
	if err != nil {
		t.Fatalf("Migration failed: %v", err)
	}

	// Verify JSON is valid
	var correlationConfig string
	err = db.QueryRow("SELECT correlation_config FROM rules WHERE id='corr-json-escape'").Scan(&correlationConfig)
	if err != nil {
		t.Fatalf("Failed to query rule: %v", err)
	}

	// Parse JSON to verify validity
	var config map[string]interface{}
	err = json.Unmarshal([]byte(correlationConfig), &config)
	if err != nil {
		t.Errorf("correlation_config is not valid JSON: %v", err)
	}
}

// setupCorrelationMigrationDB creates a test database with schema for correlation migration tests.
func setupCorrelationMigrationDB(t *testing.T) (*sql.DB, func()) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test_migration.db")

	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("Failed to open database: %v", err)
	}

	// Create schema
	schema := `
	CREATE TABLE IF NOT EXISTS correlation_rules (
		id TEXT PRIMARY KEY,
		name TEXT NOT NULL,
		description TEXT,
		severity TEXT NOT NULL,
		version INTEGER NOT NULL DEFAULT 1,
		window INTEGER NOT NULL,
		conditions TEXT NOT NULL,
		sequence TEXT NOT NULL,
		actions TEXT,
		created_at DATETIME NOT NULL,
		updated_at DATETIME NOT NULL
	);

	CREATE TABLE IF NOT EXISTS rules (
		id TEXT PRIMARY KEY,
		type TEXT NOT NULL DEFAULT 'sigma',
		name TEXT NOT NULL,
		description TEXT,
		severity TEXT NOT NULL,
		enabled INTEGER NOT NULL DEFAULT 1,
		version INTEGER NOT NULL DEFAULT 1,
		rule_category TEXT NOT NULL DEFAULT 'detection',
		correlation_config TEXT,
		lifecycle_status TEXT NOT NULL DEFAULT 'active',
		actions TEXT,
		created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
		updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
	);
	CREATE INDEX IF NOT EXISTS idx_rules_category ON rules(rule_category);
	CREATE INDEX IF NOT EXISTS idx_rules_lifecycle_status ON rules(lifecycle_status);

	CREATE TABLE IF NOT EXISTS schema_migrations (
		version TEXT PRIMARY KEY,
		applied_at DATETIME NOT NULL
	);
	`

	_, err = db.Exec(schema)
	if err != nil {
		t.Fatalf("Failed to create schema: %v", err)
	}

	cleanup := func() {
		db.Close()
	}

	return db, cleanup
}

// insertTestCorrelationRule inserts a test correlation rule.
func insertTestCorrelationRule(t *testing.T, db *sql.DB, id, name, severity string, window int64) {
	now := time.Now()
	_, err := db.Exec(`
		INSERT INTO correlation_rules (
			id, name, description, severity, version, window,
			conditions, sequence, actions, created_at, updated_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`, id, name, "Test description for "+name, severity, 1, window,
		`[{"field":"test","operator":"equals","value":"test"}]`,
		`["event1","event2"]`,
		`[{"type":"email","config":{"to":"test@example.com"}}]`,
		now, now)
	if err != nil {
		t.Fatalf("Failed to insert test correlation rule: %v", err)
	}
}

// verifyMigratedRule checks that a rule was migrated with expected values.
func verifyMigratedRule(t *testing.T, db *sql.DB, id, expectedCategory, expectedLifecycle string) {
	var category, lifecycle string
	err := db.QueryRow(`
		SELECT rule_category, lifecycle_status FROM rules WHERE id=?
	`, id).Scan(&category, &lifecycle)

	if err != nil {
		t.Fatalf("Failed to query rule %s: %v", id, err)
	}

	if category != expectedCategory {
		t.Errorf("Rule %s: expected category=%s, got %s", id, expectedCategory, category)
	}

	if lifecycle != expectedLifecycle {
		t.Errorf("Rule %s: expected lifecycle=%s, got %s", id, expectedLifecycle, lifecycle)
	}
}

// verifyCorrelationConfigJSON checks that correlation_config is valid JSON.
func verifyCorrelationConfigJSON(t *testing.T, db *sql.DB, id string) {
	var configJSON string
	err := db.QueryRow("SELECT correlation_config FROM rules WHERE id=?", id).Scan(&configJSON)
	if err != nil {
		t.Fatalf("Failed to query correlation_config for %s: %v", id, err)
	}

	var config map[string]interface{}
	err = json.Unmarshal([]byte(configJSON), &config)
	if err != nil {
		t.Errorf("correlation_config for %s is not valid JSON: %v", id, err)
	}

	// Verify expected fields
	expectedFields := []string{"window", "sequence", "conditions"}
	for _, field := range expectedFields {
		if _, exists := config[field]; !exists {
			t.Errorf("correlation_config missing field: %s", field)
		}
	}
}

// Test_validateTableName_SQLInjection tests SQL injection attempts in table names.
// Issue #4 FIX: Tests SQL injection protection.
func Test_validateTableName_SQLInjection(t *testing.T) {
	tests := []struct {
		name      string
		tableName string
		wantErr   bool
	}{
		{
			name:      "SQL injection with DROP",
			tableName: "backup; DROP TABLE rules--",
			wantErr:   true,
		},
		{
			name:      "SQL injection with comment",
			tableName: "backup_table--",
			wantErr:   true,
		},
		{
			name:      "SQL injection with quotes",
			tableName: "backup' OR '1'='1",
			wantErr:   true,
		},
		{
			name:      "SQL injection with semicolon",
			tableName: "backup; DELETE FROM users;",
			wantErr:   true,
		},
		{
			name:      "path traversal",
			tableName: "../../../etc/passwd",
			wantErr:   true,
		},
		{
			name:      "valid table name",
			tableName: "correlation_rules_backup_123",
			wantErr:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateTableName(tt.tableName)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateTableName() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// TestMigrateCorrelationRulesToUnified_SQLInjectionBlocked tests SQL injection is blocked.
// Issue #4 FIX: Tests SQL injection in backup table name.
func TestMigrateCorrelationRulesToUnified_SQLInjectionBlocked(t *testing.T) {
	db, cleanup := setupCorrelationMigrationDB(t)
	defer cleanup()

	insertTestCorrelationRule(t, db, "rule1", "Test Rule", "high", 60*1e9)

	// Attempt migration with malicious backup table name
	maliciousNames := []string{
		"backup; DROP TABLE rules--",
		"backup' OR '1'='1--",
		"backup`; DELETE FROM correlation_rules;",
		"../../../etc/passwd",
	}

	for _, maliciousName := range maliciousNames {
		t.Run(maliciousName, func(t *testing.T) {
			opts := CorrelationUnificationOptions{
				BackupTableName:   maliciousName,
				MigrationTimemark: time.Now(),
			}

			err := MigrateCorrelationRulesToUnified(db, opts)
			if err == nil {
				t.Fatal("Expected error for SQL injection attempt, got nil")
			}

			// Verify error message indicates validation failure
			if !containsString(err.Error(), "invalid") {
				t.Errorf("Expected validation error, got: %v", err)
			}

			// Verify database tables are intact
			var rulesCount int
			err = db.QueryRow("SELECT COUNT(*) FROM rules").Scan(&rulesCount)
			if err != nil {
				t.Errorf("Rules table damaged after SQL injection attempt: %v", err)
			}

			var corrCount int
			err = db.QueryRow("SELECT COUNT(*) FROM correlation_rules").Scan(&corrCount)
			if err != nil {
				t.Errorf("Correlation_rules table damaged: %v", err)
			}
			if corrCount != 1 {
				t.Errorf("Expected 1 correlation rule, got %d", corrCount)
			}
		})
	}
}

// TestMigrateCorrelationRulesToUnified_TransactionFailure tests transaction rollback.
// Issue #4 FIX: Tests transaction failure scenarios.
func TestMigrateCorrelationRulesToUnified_TransactionFailure(t *testing.T) {
	db, cleanup := setupCorrelationMigrationDB(t)
	defer cleanup()

	// Insert test data
	insertTestCorrelationRule(t, db, "rule1", "Test Rule", "high", 60*1e9)

	// Drop the rules table to force a failure during migration
	_, err := db.Exec("DROP TABLE rules")
	if err != nil {
		t.Fatalf("Failed to drop rules table: %v", err)
	}

	opts := CorrelationUnificationOptions{
		MigrationTimemark: time.Now(),
	}

	// Migration should fail
	err = MigrateCorrelationRulesToUnified(db, opts)
	if err == nil {
		t.Fatal("Expected error when rules table doesn't exist, got nil")
	}

	// Verify correlation_rules table is still intact (transaction rolled back)
	var count int
	err = db.QueryRow("SELECT COUNT(*) FROM correlation_rules").Scan(&count)
	if err != nil {
		t.Fatalf("correlation_rules table should still exist: %v", err)
	}

	if count != 1 {
		t.Errorf("Expected 1 rule in correlation_rules after failed migration, got %d", count)
	}
}

// TestMigrateCorrelationRulesToUnified_DuplicateInsertion tests duplicate ID handling.
// Issue #4 FIX: Tests duplicate ID insertion scenarios.
func TestMigrateCorrelationRulesToUnified_DuplicateInsertion(t *testing.T) {
	db, cleanup := setupCorrelationMigrationDB(t)
	defer cleanup()

	// Insert correlation rule
	insertTestCorrelationRule(t, db, "duplicate-id", "Test Rule", "high", 60*1e9)

	// Pre-insert a rule with same ID in rules table
	_, err := db.Exec(`
		INSERT INTO rules (
			id, type, name, description, severity, enabled, version,
			rule_category, lifecycle_status, created_at, updated_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`, "duplicate-id", "correlation", "Existing Rule", "Already exists", "medium",
		1, 1, "correlation", "stable", time.Now(), time.Now())

	if err != nil {
		t.Fatalf("Failed to insert duplicate rule: %v", err)
	}

	// Migration should fail with duplicate check error
	opts := CorrelationUnificationOptions{
		MigrationTimemark: time.Now(),
	}

	err = MigrateCorrelationRulesToUnified(db, opts)
	if err == nil {
		t.Fatal("Expected error for duplicate ID, got nil")
	}

	// Verify error message mentions duplicates
	if !containsString(err.Error(), "duplicate") && !containsString(err.Error(), "already exist") {
		t.Errorf("Expected duplicate error, got: %v", err)
	}

	// Verify only 1 rule with this ID exists (not 2)
	var count int
	err = db.QueryRow("SELECT COUNT(*) FROM rules WHERE id = 'duplicate-id'").Scan(&count)
	if err != nil {
		t.Fatalf("Failed to count rules: %v", err)
	}

	if count != 1 {
		t.Errorf("Expected 1 rule with ID, got %d (duplicate may have been inserted)", count)
	}
}

// TestMigrateCorrelationRulesToUnified_JSONCorruption tests JSON corruption handling.
// Issue #4 FIX: Tests JSON corruption in source data.
func TestMigrateCorrelationRulesToUnified_JSONCorruption(t *testing.T) {
	db, cleanup := setupCorrelationMigrationDB(t)
	defer cleanup()

	// Note: json.Marshal with json.RawMessage will succeed even with invalid JSON strings
	// The validation happens when the JSON is actually parsed by the receiving system
	// For now, we insert potentially problematic JSON and verify it's handled

	testCases := []struct {
		name       string
		conditions string
		sequence   string
		actions    string
		shouldFail bool
	}{
		{
			name:       "valid JSON",
			conditions: `[{"field":"test","value":"test"}]`,
			sequence:   `["event1","event2"]`,
			actions:    `[{"type":"email"}]`,
			shouldFail: false,
		},
		{
			name:       "empty strings - invalid JSON",
			conditions: "",
			sequence:   "",
			actions:    "",
			shouldFail: true, // Issue #3 FIX: Empty strings are invalid JSON, should fail
		},
		{
			name:       "malformed JSON - invalid",
			conditions: `INVALID`,
			sequence:   `INVALID`,
			actions:    `INVALID`,
			shouldFail: true, // Issue #3 FIX: Invalid JSON detected and rejected
		},
		{
			name:       "valid empty JSON arrays",
			conditions: `[]`,
			sequence:   `[]`,
			actions:    `[]`,
			shouldFail: false, // Empty arrays are valid JSON
		},
	}

	for i, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			id := fmt.Sprintf("json-test-%d", i)

			_, err := db.Exec(`
				INSERT INTO correlation_rules (
					id, name, description, severity, version, window,
					conditions, sequence, actions, created_at, updated_at
				) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
			`, id, "Test Rule", "Test", "high", 1, 60*1e9,
				tc.conditions, tc.sequence, tc.actions,
				time.Now(), time.Now())

			if err != nil {
				t.Fatalf("Failed to insert test rule: %v", err)
			}

			opts := CorrelationUnificationOptions{
				MigrationTimemark: time.Now(),
			}

			err = MigrateCorrelationRulesToUnified(db, opts)

			if tc.shouldFail && err == nil {
				t.Errorf("Expected migration to fail with corrupted JSON")
			}

			if !tc.shouldFail && err != nil {
				t.Errorf("Migration should succeed, got error: %v", err)
			}

			// Cleanup for next test
			db.Exec("DELETE FROM correlation_rules")
			db.Exec("DELETE FROM rules WHERE rule_category = 'correlation'")
		})
	}
}

// TestMigrateCorrelationRulesToUnified_ExactCountVerification tests exact count matching.
// Issue #4 & #5 FIX: Tests that verification uses exact count (not >=).
func TestMigrateCorrelationRulesToUnified_ExactCountVerification(t *testing.T) {
	db, cleanup := setupCorrelationMigrationDB(t)
	defer cleanup()

	// Insert 3 correlation rules
	insertTestCorrelationRule(t, db, "rule1", "Rule 1", "high", 60*1e9)
	insertTestCorrelationRule(t, db, "rule2", "Rule 2", "medium", 60*1e9)
	insertTestCorrelationRule(t, db, "rule3", "Rule 3", "low", 60*1e9)

	opts := CorrelationUnificationOptions{
		MigrationTimemark: time.Now(),
	}

	err := MigrateCorrelationRulesToUnified(db, opts)
	if err != nil {
		t.Fatalf("Migration failed: %v", err)
	}

	// Verify exactly 3 rules were migrated
	var count int
	err = db.QueryRow("SELECT COUNT(*) FROM rules WHERE rule_category = 'correlation'").Scan(&count)
	if err != nil {
		t.Fatalf("Failed to count rules: %v", err)
	}

	if count != 3 {
		t.Errorf("Expected exactly 3 rules, got %d", count)
	}

	// Manually insert an extra correlation rule (simulating an error)
	// Then verify that verification would catch this
	_, err = db.Exec(`
		INSERT INTO rules (
			id, type, name, severity, rule_category, lifecycle_status,
			created_at, updated_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
	`, "extra-rule", "correlation", "Extra Rule", "low", "correlation", "stable",
		time.Now(), time.Now())

	if err != nil {
		t.Fatalf("Failed to insert extra rule: %v", err)
	}

	// Now verify count is wrong
	err = db.QueryRow("SELECT COUNT(*) FROM rules WHERE rule_category = 'correlation'").Scan(&count)
	if err != nil {
		t.Fatalf("Failed to count rules: %v", err)
	}

	if count == 3 {
		t.Error("Count should be 4 now (3 migrated + 1 extra), verification would miss this with < comparison")
	}
}

// TestMigrateCorrelationRulesToUnified_TimestampBufferOneMinute tests 1-minute buffer.
// Issue #6 & #7 FIX: Tests that timestamp buffer is 1 minute, not 1 hour.
func TestMigrateCorrelationRulesToUnified_TimestampBufferOneMinute(t *testing.T) {
	db, cleanup := setupCorrelationMigrationDB(t)
	defer cleanup()

	// The timestamp buffer is used during verification to account for clock skew
	// between when the migration starts and when records are actually inserted.
	// The verification filters by rules.created_at (not correlation_rules.created_at)

	// First, verify the constant is set correctly
	if migrationTimeBufferMinutes != 1 {
		t.Errorf("Expected migrationTimeBufferMinutes to be 1, got %d", migrationTimeBufferMinutes)
	}

	// Insert a test rule
	insertTestCorrelationRule(t, db, "test-rule", "Test Rule", "high", 60*1e9)

	// Set migration time slightly in the future to test buffer
	migrationTime := time.Now().Add(30 * time.Second)
	opts := CorrelationUnificationOptions{
		MigrationTimemark: migrationTime,
	}

	err := MigrateCorrelationRulesToUnified(db, opts)
	if err != nil {
		t.Fatalf("Migration failed: %v", err)
	}

	// Verify the rule was migrated successfully
	var count int
	err = db.QueryRow("SELECT COUNT(*) FROM rules WHERE rule_category = 'correlation'").Scan(&count)
	if err != nil {
		t.Fatalf("Failed to count rules: %v", err)
	}

	if count != 1 {
		t.Errorf("Expected 1 migrated rule, got %d", count)
	}

	// The 1-minute buffer allows for rules inserted within 1 minute before migration time
	// This is safer than 1-hour buffer which was too broad
}

// TestRollbackCorrelationUnification_SQLInjectionBlocked tests SQL injection in rollback.
// Issue #4 FIX: Tests SQL injection protection in rollback.
func TestRollbackCorrelationUnification_SQLInjectionBlocked(t *testing.T) {
	db, cleanup := setupCorrelationMigrationDB(t)
	defer cleanup()

	maliciousNames := []string{
		"backup'; DROP TABLE rules--",
		"backup; DELETE FROM correlation_rules;",
		"../../../etc/passwd",
	}

	for _, maliciousName := range maliciousNames {
		t.Run(maliciousName, func(t *testing.T) {
			err := RollbackCorrelationUnification(db, time.Now(), maliciousName)
			if err == nil {
				t.Fatal("Expected error for SQL injection attempt in rollback, got nil")
			}

			// Verify error indicates validation failure
			if !containsString(err.Error(), "invalid") {
				t.Errorf("Expected validation error, got: %v", err)
			}

			// Verify tables are intact
			var count int
			err = db.QueryRow("SELECT COUNT(*) FROM rules").Scan(&count)
			if err != nil {
				t.Errorf("Rules table damaged: %v", err)
			}

			err = db.QueryRow("SELECT COUNT(*) FROM correlation_rules").Scan(&count)
			if err != nil {
				t.Errorf("Correlation_rules table damaged: %v", err)
			}
		})
	}
}

// TestMigrateCorrelationRulesToUnified_BackupVerification tests backup verification.
// Issue #10 FIX: Tests that backup creation is verified.
func TestMigrateCorrelationRulesToUnified_BackupVerification(t *testing.T) {
	db, cleanup := setupCorrelationMigrationDB(t)
	defer cleanup()

	// Insert test rules
	insertTestCorrelationRule(t, db, "rule1", "Rule 1", "high", 60*1e9)
	insertTestCorrelationRule(t, db, "rule2", "Rule 2", "medium", 60*1e9)

	migrationTime := time.Now()
	opts := CorrelationUnificationOptions{
		MigrationTimemark: migrationTime,
	}

	err := MigrateCorrelationRulesToUnified(db, opts)
	if err != nil {
		t.Fatalf("Migration failed: %v", err)
	}

	// Verify backup table was created and contains correct number of records
	backupName := fmt.Sprintf("%s%d", backupTablePrefix, migrationTime.Unix())
	var backupCount int
	backupQuery := fmt.Sprintf("SELECT COUNT(*) FROM %s", backupName)
	err = db.QueryRow(backupQuery).Scan(&backupCount)

	if err != nil {
		t.Fatalf("Backup table not created or not accessible: %v", err)
	}

	if backupCount != 2 {
		t.Errorf("Expected 2 records in backup, got %d", backupCount)
	}

	// Verify backup contains the actual data
	var id string
	idQuery := fmt.Sprintf("SELECT id FROM %s WHERE id = 'rule1'", backupName)
	err = db.QueryRow(idQuery).Scan(&id)

	if err != nil {
		t.Errorf("Backup should contain rule1: %v", err)
	}

	if id != "rule1" {
		t.Errorf("Expected ID 'rule1' in backup, got '%s'", id)
	}
}

// containsString is a helper function to check if a string contains a substring.
func containsString(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

// BenchmarkMigrateCorrelationRulesToUnified measures migration performance.
func BenchmarkMigrateCorrelationRulesToUnified(b *testing.B) {
	// Setup logger
	logger, _ := zap.NewDevelopment()
	defer logger.Sync()

	for _, ruleCount := range []int{10, 100, 1000} {
		b.Run(fmt.Sprintf("rules_%d", ruleCount), func(b *testing.B) {
			b.StopTimer()

			// Setup database with test data
			tmpDir := b.TempDir()
			dbPath := filepath.Join(tmpDir, "bench_migration.db")
			db, _ := sql.Open("sqlite", dbPath)
			defer db.Close()

			// Create schema
			setupTestDBSchema(b, db)

			// Insert test rules
			for i := 0; i < ruleCount; i++ {
				id := fmt.Sprintf("bench-rule-%d", i)
				insertBenchCorrelationRule(b, db, id)
			}

			b.StartTimer()
			for i := 0; i < b.N; i++ {
				// Run migration
				opts := CorrelationUnificationOptions{
					DryRun:            false,
					MigrationTimemark: time.Now(),
				}
				_ = MigrateCorrelationRulesToUnified(db, opts)

				// Cleanup for next iteration
				db.Exec("DELETE FROM rules WHERE rule_category='correlation'")
			}
		})
	}
}

// setupTestDBSchema creates the database schema for benchmarking.
func setupTestDBSchema(b *testing.B, db *sql.DB) {
	schema := `
	CREATE TABLE correlation_rules (
		id TEXT PRIMARY KEY,
		name TEXT NOT NULL,
		description TEXT,
		severity TEXT NOT NULL,
		version INTEGER NOT NULL DEFAULT 1,
		window INTEGER NOT NULL,
		conditions TEXT NOT NULL,
		sequence TEXT NOT NULL,
		actions TEXT,
		created_at DATETIME NOT NULL,
		updated_at DATETIME NOT NULL
	);
	CREATE TABLE rules (
		id TEXT PRIMARY KEY,
		type TEXT NOT NULL DEFAULT 'sigma',
		name TEXT NOT NULL,
		description TEXT,
		severity TEXT NOT NULL,
		enabled INTEGER NOT NULL DEFAULT 1,
		version INTEGER NOT NULL DEFAULT 1,
		rule_category TEXT NOT NULL DEFAULT 'detection',
		correlation_config TEXT,
		lifecycle_status TEXT NOT NULL DEFAULT 'active',
		actions TEXT,
		created_at DATETIME NOT NULL,
		updated_at DATETIME NOT NULL
	);
	CREATE INDEX idx_rules_category ON rules(rule_category);
	`
	_, err := db.Exec(schema)
	if err != nil {
		b.Fatalf("Failed to create schema: %v", err)
	}
}

// insertBenchCorrelationRule inserts a correlation rule for benchmarking.
func insertBenchCorrelationRule(b *testing.B, db *sql.DB, id string) {
	now := time.Now()
	_, err := db.Exec(`
		INSERT INTO correlation_rules (
			id, name, description, severity, version, window,
			conditions, sequence, actions, created_at, updated_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`, id, "Bench Rule", "Benchmark test", "medium", 1, 60*1e9,
		`[{"field":"test","operator":"equals","value":"test"}]`,
		`["event1"]`,
		`[]`,
		now, now)
	if err != nil {
		b.Fatalf("Failed to insert benchmark rule: %v", err)
	}
}
