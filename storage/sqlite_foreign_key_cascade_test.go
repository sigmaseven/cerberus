package storage

import (
	"os"
	"testing"
	"time"

	"cerberus/core"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

// TestForeignKeysCascadeDeleteException verifies that foreign key constraints
// are enforced and CASCADE deletes work correctly.
//
// REQUIREMENT: TEST_IMPROVEMENTS_PART2.md GAP-003 (DATA-001)
// REQUIREMENT: docs/requirements/storage-acid-requirements.md Section 3.1.2
// SECURITY FIX: Verifies orphaned exceptions are prevented via CASCADE
//
// When a rule is deleted, all exceptions referencing that rule should also be deleted.
// This test verifies the FOREIGN KEY ON DELETE CASCADE constraint works correctly.
//
// Schema constraint (sqlite.go line 212):
//
//	FOREIGN KEY (rule_id) REFERENCES rules(id) ON DELETE CASCADE
func TestForeignKeysCascadeDeleteException(t *testing.T) {
	// Use temporary file-based database
	logger := zap.NewNop().Sugar()
	dbPath := "test_cascade_" + t.Name() + ".db"
	sqlite, err := NewSQLite(dbPath, logger)
	require.NoError(t, err, "Failed to create SQLite database")
	defer func() {
		sqlite.Close()
		os.Remove(dbPath)
		os.Remove(dbPath + "-shm")
		os.Remove(dbPath + "-wal")
	}()

	// Create rule storage
	ruleStorage := NewSQLiteRuleStorage(sqlite, 5*time.Second, sqlite.Logger)
	exceptionStorage := NewSQLiteExceptionStorage(sqlite)

	// Create test rule
	ruleID := "test-rule-cascade-001"
	rule := &core.Rule{
		ID:          ruleID,
		Name:        "Test Rule for CASCADE",
		Description: "Testing foreign key CASCADE delete",
		Severity:    "High",
		Type:        "sigma",
		Enabled:     true,
		Version:     1,
		SigmaYAML: `title: Test Rule for CASCADE
logsource:
  product: test
detection:
  selection:
    test: cascade
  condition: selection
`,
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}

	err = ruleStorage.CreateRule(rule)
	require.NoError(t, err, "Rule creation should succeed")

	// Create exception referencing rule (foreign key relationship)
	exception := &core.Exception{
		ID:            "test-exception-cascade-001",
		Name:          "Test Exception for CASCADE",
		Description:   "Testing CASCADE delete behavior",
		RuleID:        ruleID, // Foreign key reference to rules table
		Type:          core.ExceptionSuppress,
		ConditionType: core.ConditionTypeSigmaFilter,
		Condition:     "EventID: 4624",
		Enabled:       true,
		Priority:      100,
		CreatedAt:     time.Now(),
		UpdatedAt:     time.Now(),
		Tags:          []string{},
	}

	err = exceptionStorage.CreateException(exception)
	require.NoError(t, err, "Exception creation should succeed")

	// Verify exception exists before cascade delete
	retrieved, err := exceptionStorage.GetException("test-exception-cascade-001")
	require.NoError(t, err, "Exception should exist before rule deletion")
	assert.Equal(t, ruleID, retrieved.RuleID, "Exception should reference the correct rule")
	assert.Equal(t, "Test Exception for CASCADE", retrieved.Name)

	// Delete rule - should CASCADE delete exception
	err = ruleStorage.DeleteRule(ruleID)
	require.NoError(t, err, "Rule deletion should succeed")

	// Verify exception was CASCADE deleted automatically
	_, err = exceptionStorage.GetException("test-exception-cascade-001")
	assert.Error(t, err, "Exception should be CASCADE deleted when rule is deleted")
	assert.Contains(t, err.Error(), "not found", "Error should indicate exception not found")

	t.Log("✓ P0-1 VERIFIED: Foreign key CASCADE delete works correctly")
	t.Log("✓ SECURITY: Orphaned exceptions are prevented")
	t.Log("✓ DATA INTEGRITY: Referential integrity enforced")
}

// TestForeignKeysCascadeMultipleExceptions verifies CASCADE delete with multiple exceptions
func TestForeignKeysCascadeMultipleExceptions(t *testing.T) {
	// Use temporary file-based database
	logger := zap.NewNop().Sugar()
	dbPath := "test_cascade_" + t.Name() + ".db"
	sqlite, err := NewSQLite(dbPath, logger)
	require.NoError(t, err, "Failed to create SQLite database")
	defer func() {
		sqlite.Close()
		os.Remove(dbPath)
		os.Remove(dbPath + "-shm")
		os.Remove(dbPath + "-wal")
	}()

	ruleStorage := NewSQLiteRuleStorage(sqlite, 5*time.Second, sqlite.Logger)
	exceptionStorage := NewSQLiteExceptionStorage(sqlite)

	// Create rule
	ruleID := "test-rule-cascade-multi-001"
	rule := &core.Rule{
		ID:          ruleID,
		Name:        "Test Rule for Multiple CASCADE",
		Description: "Testing CASCADE with multiple exceptions",
		Severity:    "Medium",
		Type:        "sigma",
		Enabled:     true,
		Version:     1,
		SigmaYAML: `title: Test Rule for Multiple CASCADE
logsource:
  product: test
detection:
  selection:
    test: multi_cascade
  condition: selection
`,
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}

	err = ruleStorage.CreateRule(rule)
	require.NoError(t, err)

	// Create multiple exceptions referencing the same rule
	exceptionIDs := []string{
		"test-exception-multi-001",
		"test-exception-multi-002",
		"test-exception-multi-003",
	}

	for i, exID := range exceptionIDs {
		exception := &core.Exception{
			ID:            exID,
			Name:          "Exception " + string(rune('A'+i)),
			RuleID:        ruleID,
			Type:          core.ExceptionSuppress,
			ConditionType: core.ConditionTypeSigmaFilter,
			Condition:     "EventID: 4624",
			Enabled:       true,
			Priority:      100 + i,
			CreatedAt:     time.Now(),
			UpdatedAt:     time.Now(),
			Tags:          []string{},
		}
		err = exceptionStorage.CreateException(exception)
		require.NoError(t, err, "Exception %s creation should succeed", exID)
	}

	// Verify all exceptions exist
	exceptions, err := exceptionStorage.GetExceptionsByRuleID(ruleID)
	require.NoError(t, err)
	assert.Equal(t, 3, len(exceptions), "Should have 3 exceptions")

	// Delete rule - should CASCADE delete all exceptions
	err = ruleStorage.DeleteRule(ruleID)
	require.NoError(t, err)

	// Verify all exceptions were CASCADE deleted
	for _, exID := range exceptionIDs {
		_, err := exceptionStorage.GetException(exID)
		assert.Error(t, err, "Exception %s should be CASCADE deleted", exID)
	}

	// Verify GetExceptionsByRuleID returns empty
	exceptions, err = exceptionStorage.GetExceptionsByRuleID(ruleID)
	require.NoError(t, err)
	assert.Equal(t, 0, len(exceptions), "Should have no exceptions after CASCADE delete")

	t.Log("✓ CASCADE delete works with multiple exceptions")
}

// TestForeignKeysPreventOrphanedExceptions verifies foreign key constraint prevents orphaned exceptions
func TestForeignKeysPreventOrphanedExceptions(t *testing.T) {
	// Use temporary file-based database
	logger := zap.NewNop().Sugar()
	dbPath := "test_cascade_" + t.Name() + ".db"
	sqlite, err := NewSQLite(dbPath, logger)
	require.NoError(t, err, "Failed to create SQLite database")
	defer func() {
		sqlite.Close()
		os.Remove(dbPath)
		os.Remove(dbPath + "-shm")
		os.Remove(dbPath + "-wal")
	}()

	exceptionStorage := NewSQLiteExceptionStorage(sqlite)

	// Try to create exception referencing non-existent rule
	// This should FAIL due to foreign key constraint
	orphanedException := &core.Exception{
		ID:            "test-exception-orphaned-001",
		Name:          "Orphaned Exception",
		RuleID:        "nonexistent-rule-id", // References non-existent rule
		Type:          core.ExceptionSuppress,
		ConditionType: core.ConditionTypeSigmaFilter,
		Condition:     "EventID: 4624",
		Enabled:       true,
		Priority:      100,
		CreatedAt:     time.Now(),
		UpdatedAt:     time.Now(),
		Tags:          []string{},
	}

	err = exceptionStorage.CreateException(orphanedException)
	assert.Error(t, err, "Creating exception with non-existent rule_id should FAIL")
	assert.Contains(t, err.Error(), "constraint", "Error should indicate constraint violation")

	t.Log("✓ Foreign key constraint prevents orphaned exceptions")
	t.Log("✓ Cannot create exception referencing non-existent rule")
}
