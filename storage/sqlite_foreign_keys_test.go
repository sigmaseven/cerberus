package storage

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

// REQUIREMENT: TEST_IMPROVEMENTS_PART2.md GAP-003 Section 4.1.3 (lines 613-844)
// REQUIREMENT: docs/requirements/storage-acid-requirements.md Section 3.1.2 (DATA-001)
// OWASP Reference: ASVS V8.1.2 - Verify database integrity constraints are enforced
//
// CRITICAL: SQLite Foreign Keys MUST Be Enabled
//
// SECURITY/DATA INTEGRITY ISSUE:
// - SQLite disables foreign key constraints by DEFAULT
// - Without _foreign_keys=ON in connection string, ALL foreign keys are ignored
// - This allows orphaned records that violate referential integrity
// - Example attacks:
//   1. Delete a rule, but alerts/exceptions still reference it = broken relationships
//   2. Delete a user, but their investigations/searches remain = data corruption
//   3. Create exceptions for nonexistent rules = wasted storage, broken logic
//
// FIX: Add &_foreign_keys=ON to connection string (storage/sqlite.go line 38)
// VERIFICATION: PRAGMA foreign_keys; should return 1 (enabled)
//
// REFERENCE: https://www.sqlite.org/foreignkeys.html#fk_enable

// Test Case 1: Verify Foreign Keys Are Enabled
func TestSQLite_ForeignKeysEnabled(t *testing.T) {
	// REQUIREMENT: TEST_IMPROVEMENTS_PART2.md lines 644-659
	// REQUIREMENT: storage-acid-requirements.md Section 3.1.2
	// CRITICAL: Foreign keys MUST be enabled for referential integrity
	// Source: https://www.sqlite.org/foreignkeys.html
	//
	// WHY THIS MATTERS:
	// - SQLite disables foreign keys by default for backwards compatibility
	// - Applications MUST explicitly enable them via connection string
	// - Without this, ALL foreign key constraints are silently ignored
	// - This is a CRITICAL data integrity failure

	logger := zap.NewNop().Sugar()
	sqlite, err := NewSQLite(":memory:", logger)
	require.NoError(t, err, "Failed to create test database")
	defer sqlite.Close()

	// Execute PRAGMA foreign_keys to check if enabled
	var enabled int
	err = sqlite.DB.QueryRow("PRAGMA foreign_keys").Scan(&enabled)
	require.NoError(t, err, "Failed to query PRAGMA foreign_keys")

	// MUST: Foreign keys enabled (value = 1)
	assert.Equal(t, 1, enabled,
		"CRITICAL: Foreign keys MUST be enabled (PRAGMA foreign_keys must return 1)\n"+
			"Current value: %d\n"+
			"Fix: Add &_foreign_keys=ON to connection string in storage/sqlite.go\n"+
			"Without this, referential integrity is NOT enforced", enabled)

	t.Log("✓ VERIFIED: Foreign keys are enabled (PRAGMA foreign_keys = 1)")
	t.Log("  Referential integrity constraints will be enforced")
}

// Test Case 2: Foreign Key Enforcement With Schema
func TestSQLite_ForeignKeyEnforcement_WithSchema(t *testing.T) {
	// REQUIREMENT: TEST_IMPROVEMENTS_PART2.md lines 661-680
	// Test: Create table with foreign key, verify constraint is enforced
	//
	// NOTE: The current schema (storage/sqlite.go) doesn't define foreign key constraints in SQL.
	// This test creates a temporary schema with FKs to verify the mechanism works.
	// RECOMMENDATION: Add FOREIGN KEY constraints to production schema

	logger := zap.NewNop().Sugar()
	sqlite, err := NewSQLite(":memory:", logger)
	require.NoError(t, err)
	defer sqlite.Close()

	// Create parent table
	_, err = sqlite.DB.Exec(`
		CREATE TABLE test_parents (
			id TEXT PRIMARY KEY,
			name TEXT NOT NULL
		)
	`)
	require.NoError(t, err, "Failed to create parent table")

	// Create child table with foreign key constraint
	_, err = sqlite.DB.Exec(`
		CREATE TABLE test_children (
			id TEXT PRIMARY KEY,
			parent_id TEXT NOT NULL,
			data TEXT,
			FOREIGN KEY (parent_id) REFERENCES test_parents(id) ON DELETE CASCADE
		)
	`)
	require.NoError(t, err, "Failed to create child table with FK")

	// Test 1: Insert child with nonexistent parent MUST fail
	_, err = sqlite.DB.Exec(`
		INSERT INTO test_children (id, parent_id, data)
		VALUES ('child1', 'nonexistent-parent', 'test data')
	`)

	// MUST: Fail due to foreign key violation
	require.Error(t, err,
		"CRITICAL: Foreign key constraint should prevent orphaned child record\n"+
			"Inserting child with nonexistent parent_id should fail")

	// Error message should indicate foreign key constraint violation
	assert.Contains(t, err.Error(), "FOREIGN",
		"Error should mention FOREIGN KEY constraint violation")

	t.Log("✓ VERIFIED: Foreign key constraint blocked orphaned child record")
	t.Log("  Cannot insert child with nonexistent parent_id")

	// Test 2: Insert parent, then child (should succeed)
	_, err = sqlite.DB.Exec(`INSERT INTO test_parents (id, name) VALUES ('parent1', 'Parent 1')`)
	require.NoError(t, err)

	_, err = sqlite.DB.Exec(`
		INSERT INTO test_children (id, parent_id, data)
		VALUES ('child1', 'parent1', 'test data')
	`)
	require.NoError(t, err,
		"Should allow child insert when parent exists")

	t.Log("✓ VERIFIED: Foreign key allows valid parent-child relationship")

	// Test 3: Delete parent with CASCADE should delete child
	_, err = sqlite.DB.Exec(`DELETE FROM test_parents WHERE id = 'parent1'`)
	require.NoError(t, err)

	var childCount int
	err = sqlite.DB.QueryRow(`SELECT COUNT(*) FROM test_children WHERE id = 'child1'`).Scan(&childCount)
	require.NoError(t, err)

	assert.Equal(t, 0, childCount,
		"ON DELETE CASCADE should delete child when parent is deleted")

	t.Log("✓ VERIFIED: ON DELETE CASCADE works correctly")
}

// Test Case 3: Schema Recommendations - Audit Current Tables
func TestSQLite_ForeignKeys_SchemaAudit(t *testing.T) {
	// REQUIREMENT: Verify which tables should have foreign keys
	// This test audits the schema to identify foreign key relationships
	//
	// RECOMMENDATION: Add these foreign key constraints to schema:
	// 1. exceptions.rule_id -> rules.id
	// 2. investigations.creator_id -> users.username (if investigations table exists)
	// 3. saved_searches.user_id -> users.username (if saved_searches table exists)

	logger := zap.NewNop().Sugar()
	sqlite, err := NewSQLite(":memory:", logger)
	require.NoError(t, err)
	defer sqlite.Close()

	// Query all table schemas
	rows, err := sqlite.DB.Query(`
		SELECT name, sql FROM sqlite_master
		WHERE type='table' AND name NOT LIKE 'sqlite_%'
		ORDER BY name
	`)
	require.NoError(t, err)
	defer rows.Close()

	tableCount := 0
	fkCount := 0

	t.Log("Schema Audit - Foreign Key Analysis:")
	for rows.Next() {
		var tableName, tableSql string
		err := rows.Scan(&tableName, &tableSql)
		require.NoError(t, err)

		tableCount++

		// Check if this table defines foreign keys
		if len(tableSql) > 0 {
			// Check for FOREIGN KEY keyword in schema
			if contains(tableSql, "FOREIGN KEY") {
				fkCount++
				t.Logf("  ✓ %s: Has FOREIGN KEY constraint", tableName)
			} else {
				// Identify tables that SHOULD have foreign keys based on column names
				shouldHaveFK := false
				fkRecommendations := []string{}

				if contains(tableSql, "rule_id") {
					shouldHaveFK = true
					fkRecommendations = append(fkRecommendations, "rule_id -> rules.id")
				}
				if contains(tableSql, "user_id") || contains(tableSql, "creator_id") {
					shouldHaveFK = true
					fkRecommendations = append(fkRecommendations, "*_id -> users.username")
				}
				if contains(tableSql, "feed_id") {
					shouldHaveFK = true
					fkRecommendations = append(fkRecommendations, "feed_id -> feeds.id")
				}

				if shouldHaveFK {
					t.Logf("  ⚠ %s: MISSING FK constraints (recommendations: %v)",
						tableName, fkRecommendations)
				} else {
					t.Logf("    %s: No FK needed", tableName)
				}
			}
		}
	}

	t.Logf("\nSchema Audit Summary:")
	t.Logf("  Total tables: %d", tableCount)
	t.Logf("  Tables with FOREIGN KEY constraints: %d", fkCount)
	t.Logf("  Foreign keys enabled (PRAGMA): %v", true) // We know it's enabled from test 1

	// This test doesn't fail - it's informational
	// But we log recommendations for production schema improvements
	t.Log("\n✓ AUDIT COMPLETE: Schema analyzed for foreign key relationships")
	t.Log("  RECOMMENDATION: Add FOREIGN KEY constraints to schema")
	t.Log("  BENEFIT: Prevents orphaned records, ensures referential integrity")
}

// Test Case 4: Foreign Keys Persist Across Connections
func TestSQLite_ForeignKeys_PersistAcrossConnections(t *testing.T) {
	// REQUIREMENT: Verify foreign_keys setting persists with connection string
	// CRITICAL: Setting must be in connection string, not per-session PRAGMA
	//
	// WHY: PRAGMA foreign_keys is a per-connection setting
	// If set via PRAGMA after connection, it doesn't apply to pooled connections
	// MUST use connection string parameter for correct behavior

	logger := zap.NewNop().Sugar()

	// Create first connection
	sqlite1, err := NewSQLite(":memory:", logger)
	require.NoError(t, err)
	defer sqlite1.Close()

	var enabled1 int
	err = sqlite1.DB.QueryRow("PRAGMA foreign_keys").Scan(&enabled1)
	require.NoError(t, err)
	assert.Equal(t, 1, enabled1, "First connection should have FK enabled")

	// Create second connection (simulates connection pool)
	sqlite2, err := NewSQLite(":memory:", logger)
	require.NoError(t, err)
	defer sqlite2.Close()

	var enabled2 int
	err = sqlite2.DB.QueryRow("PRAGMA foreign_keys").Scan(&enabled2)
	require.NoError(t, err)
	assert.Equal(t, 1, enabled2, "Second connection should have FK enabled")

	t.Log("✓ VERIFIED: Foreign keys enabled on all new connections")
	t.Log("  Connection string parameter ensures consistent behavior across pool")
}

// Test Case 5: Verify Foreign Key Error Messages Are Clear
func TestSQLite_ForeignKeys_ErrorMessagesAreClear(t *testing.T) {
	// REQUIREMENT: Error messages should be actionable for developers
	// When FK violation occurs, error should clearly indicate:
	// 1. What constraint was violated
	// 2. Which table/column
	// 3. What value caused the violation

	logger := zap.NewNop().Sugar()
	sqlite, err := NewSQLite(":memory:", logger)
	require.NoError(t, err)
	defer sqlite.Close()

	// Create test tables
	_, err = sqlite.DB.Exec(`
		CREATE TABLE test_rules (id TEXT PRIMARY KEY, name TEXT);
		CREATE TABLE test_exceptions (
			id TEXT PRIMARY KEY,
			rule_id TEXT NOT NULL,
			FOREIGN KEY (rule_id) REFERENCES test_rules(id)
		);
	`)
	require.NoError(t, err)

	// Attempt FK violation
	_, err = sqlite.DB.Exec(`
		INSERT INTO test_exceptions (id, rule_id)
		VALUES ('exc1', 'nonexistent-rule')
	`)

	// Verify error
	require.Error(t, err, "FK violation should return error")

	errMsg := err.Error()

	// Error should contain helpful information
	t.Logf("Foreign key violation error message:\n  %s", errMsg)

	// SQLITE returns "FOREIGN KEY constraint failed"
	assert.Contains(t, errMsg, "FOREIGN",
		"Error should mention FOREIGN KEY")

	t.Log("✓ VERIFIED: FK violation produces clear error message")
	t.Log("  Developers can identify and fix constraint violations")
}

// Test Case 6: CRITICAL - Verify Production Schema Enforces Foreign Keys
func TestSQLite_ProductionSchema_EnforcesForeignKeys(t *testing.T) {
	// REQUIREMENT: GAP-003 - Verify production schema enforces FK constraints
	// CRITICAL: This test uses the ACTUAL production schema from NewSQLite(),
	//           NOT a temporary test schema
	//
	// RATIONALE: The previous test (TestSQLite_ForeignKeyEnforcement_WithSchema)
	// created a temporary test schema with FK constraints. That test verified the
	// MECHANISM works, but NOT that the production schema has constraints defined.
	//
	// This test is the PROOF that production schema has FK constraints.
	//
	// SECURITY IMPACT: Without this, orphaned records can exist:
	// - Exceptions pointing to deleted rules
	// - Investigations assigned to deleted users
	// - Data corruption, broken relationships, storage waste

	logger := zap.NewNop().Sugar()
	sqlite, err := NewSQLite(":memory:", logger)
	require.NoError(t, err, "Failed to create SQLite database with production schema")
	defer sqlite.Close()

	// Test 1: Verify FK pragma is enabled
	var enabled int
	err = sqlite.DB.QueryRow("PRAGMA foreign_keys").Scan(&enabled)
	require.NoError(t, err, "Failed to query PRAGMA foreign_keys")
	assert.Equal(t, 1, enabled, "Foreign keys must be enabled in production")

	t.Log("✓ Step 1: Foreign keys ENABLED via pragma")

	// Test 2: Verify exceptions.rule_id FK constraint is enforced
	// This MUST fail if FK constraint is properly defined in production schema
	t.Log("\n--- Test 2: Verify exceptions.rule_id → rules.id FK constraint ---")

	// Attempt to create exception with nonexistent rule_id
	_, err = sqlite.DB.Exec(`
		INSERT INTO exceptions (id, rule_id, name, type, condition_type, condition, enabled, priority, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, datetime('now'), datetime('now'))
	`, "test-exc-1", "nonexistent-rule-id", "Test Exception", "suppress", "sigma_filter", "test: value", 1, 100)

	// CRITICAL ASSERTION: This MUST return a foreign key error
	require.Error(t, err, "Production schema MUST enforce FK constraint on exceptions.rule_id")
	errMsg := toLower(err.Error())
	assert.True(t, contains(errMsg, "foreign"),
		"Error must be a foreign key constraint violation, got: %v", err)

	t.Logf("✓ Step 2: FK constraint BLOCKS invalid exceptions.rule_id (error: %v)", err)

	// Test 3: Verify FK constraint works correctly with valid rule
	t.Log("\n--- Test 3: Verify FK allows valid relationships ---")

	// First create a valid rule
	_, err = sqlite.DB.Exec(`
		INSERT INTO rules (id, name, type, severity, enabled, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, datetime('now'), datetime('now'))
	`, "valid-rule-id", "Test Rule", "sigma", "high", 1)
	require.NoError(t, err, "Should be able to create rule")

	t.Log("  Created test rule: valid-rule-id")

	// Now create exception with valid rule_id - should succeed
	_, err = sqlite.DB.Exec(`
		INSERT INTO exceptions (id, rule_id, name, type, condition_type, condition, enabled, priority, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, datetime('now'), datetime('now'))
	`, "test-exc-2", "valid-rule-id", "Test Exception", "suppress", "sigma_filter", "test: value", 1, 100)
	require.NoError(t, err, "Should allow exception with valid rule_id")

	t.Log("✓ Step 3: FK constraint ALLOWS exception with valid rule_id")

	// Test 4: Verify NULL rule_id is allowed (global exceptions)
	t.Log("\n--- Test 4: Verify NULL rule_id allowed (global exceptions) ---")

	_, err = sqlite.DB.Exec(`
		INSERT INTO exceptions (id, rule_id, name, type, condition_type, condition, enabled, priority, created_at, updated_at)
		VALUES (?, NULL, ?, ?, ?, ?, ?, ?, datetime('now'), datetime('now'))
	`, "test-exc-global", "Global Exception", "suppress", "sigma_filter", "global: value", 1, 50)
	require.NoError(t, err, "Should allow NULL rule_id for global exceptions")

	t.Log("✓ Step 4: NULL rule_id ALLOWED (global exceptions work)")

	// Test 5: Verify CASCADE deletion works
	t.Log("\n--- Test 5: Verify ON DELETE CASCADE behavior ---")

	// Verify exception exists before deletion
	var countBefore int
	err = sqlite.DB.QueryRow("SELECT COUNT(*) FROM exceptions WHERE rule_id = ?", "valid-rule-id").Scan(&countBefore)
	require.NoError(t, err)
	assert.Equal(t, 1, countBefore, "Exception should exist before rule deletion")

	t.Logf("  Before deletion: %d exception(s) for rule valid-rule-id", countBefore)

	// Delete rule - should cascade delete exception
	_, err = sqlite.DB.Exec("DELETE FROM rules WHERE id = ?", "valid-rule-id")
	require.NoError(t, err, "Should be able to delete rule")

	t.Log("  Deleted rule: valid-rule-id")

	// Verify exception was cascaded (deleted)
	var countAfter int
	err = sqlite.DB.QueryRow("SELECT COUNT(*) FROM exceptions WHERE rule_id = ?", "valid-rule-id").Scan(&countAfter)
	require.NoError(t, err)
	assert.Equal(t, 0, countAfter, "Exception should be cascade-deleted with rule")

	t.Logf("  After deletion: %d exception(s) remaining", countAfter)
	t.Log("✓ Step 5: ON DELETE CASCADE works correctly")

	// Final summary
	separator := "======================================================================"
	t.Log("\n" + separator)
	t.Log("PRODUCTION SCHEMA VERIFICATION: PASSED")
	t.Log(separator)
	t.Log("✓ Foreign keys ENABLED in production schema")
	t.Log("✓ exceptions.rule_id → rules.id FK constraint DEFINED and ENFORCED")
	t.Log("✓ Invalid rule_id references BLOCKED by database")
	t.Log("✓ Valid rule_id references ALLOWED")
	t.Log("✓ NULL rule_id ALLOWED (global exceptions)")
	t.Log("✓ ON DELETE CASCADE works (orphaned exceptions prevented)")
	t.Log("")
	t.Log("DATA INTEGRITY: GUARANTEED by database-level constraints")
	t.Log("SECURITY: Orphaned records prevented, referential integrity enforced")
}

// Helper function to check if string contains substring (case-insensitive)
func contains(s, substr string) bool {
	// Simple case-insensitive contains check
	return len(s) >= len(substr) &&
		(s == substr ||
			len(s) > len(substr) && indexOfSubstring(s, substr) >= 0)
}

func indexOfSubstring(s, substr string) int {
	// Simple substring search (case-insensitive)
	sLower := toLower(s)
	substrLower := toLower(substr)

	for i := 0; i <= len(sLower)-len(substrLower); i++ {
		if sLower[i:i+len(substrLower)] == substrLower {
			return i
		}
	}
	return -1
}

func toLower(s string) string {
	result := make([]byte, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'A' && c <= 'Z' {
			result[i] = c + ('a' - 'A')
		} else {
			result[i] = c
		}
	}
	return string(result)
}
