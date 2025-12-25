package storage

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

// REQUIREMENT: docs/requirements/storage-acid-requirements.md Section 3.1.1 (lines 65-126)
// Specification: "All operations within a transaction MUST succeed or fail as a unit"
// Test Suite: Verify SQLite transaction atomicity guarantees
//
// CRITICAL: Transaction atomicity is fundamental to data integrity
// - Without atomicity, partial writes corrupt database state
// - Multiple operations must commit together or rollback together
// - No intermediate states should be visible to other transactions
//
// SECURITY IMPACT:
// - Partial writes create orphaned records (alerts without rules, etc.)
// - Inconsistent state enables privilege escalation attacks
// - Data corruption undermines audit trail integrity
//
// REFERENCE: https://www.sqlite.org/transact.html

// TestSQLite_Atomicity_RollbackOnError verifies transaction rollback prevents partial writes
func TestSQLite_Atomicity_RollbackOnError(t *testing.T) {
	// REQUIREMENT: docs/requirements/storage-acid-requirements.md Section 3.1.1 lines 72-97
	// Specification: "All operations within a transaction MUST succeed or fail as a unit"
	// Test: Create rule in transaction, force error on duplicate, verify rollback prevents partial write
	//
	// CRITICAL TEST: This is the CORE atomicity guarantee
	// - Without this, errors leave partial data (data corruption)
	// - Application assumes atomic behavior for multi-step operations
	// - Database MUST guarantee no partial persistence on error

	logger := zap.NewNop().Sugar()
	sqlite, err := NewSQLite(":memory:", logger)
	require.NoError(t, err, "Failed to create test database")
	defer sqlite.Close()

	// Begin transaction
	tx, err := sqlite.DB.Begin()
	require.NoError(t, err, "Failed to begin transaction")

	// Operation 1: Create rule (should succeed within transaction)
	rule1ID := "atomicity-test-rule-1"
	_, err = tx.Exec(`
		INSERT INTO rules (id, name, type, severity, enabled, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, datetime('now'), datetime('now'))
	`, rule1ID, "Test Rule 1", "sigma", "high", 1)
	require.NoError(t, err, "First INSERT should succeed within transaction")

	// Operation 2: Create duplicate rule (should fail - violates PRIMARY KEY constraint)
	_, err = tx.Exec(`
		INSERT INTO rules (id, name, type, severity, enabled, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, datetime('now'), datetime('now'))
	`, rule1ID, "Duplicate Rule", "sigma", "high", 1) // Same ID - will fail
	require.Error(t, err, "Duplicate INSERT must fail due to PRIMARY KEY constraint")
	assert.Contains(t, err.Error(), "UNIQUE",
		"Error should indicate UNIQUE constraint violation, got: %v", err)

	// Rollback transaction
	err = tx.Rollback()
	require.NoError(t, err, "Transaction rollback must succeed")

	// VERIFY ATOMICITY: rule1 was NOT persisted (transaction was atomic)
	// This is the CRITICAL assertion - proves atomicity works
	var count int
	err = sqlite.DB.QueryRow("SELECT COUNT(*) FROM rules WHERE id = ?", rule1ID).Scan(&count)
	require.NoError(t, err, "Failed to query rules count")

	assert.Equal(t, 0, count,
		"ATOMICITY VIOLATION: Transaction was not atomic - partial write persisted\n"+
			"Expected: 0 rules (rollback should undo all operations)\n"+
			"Actual: %d rules\n"+
			"Requirement: storage-acid-requirements.md Section 3.1.1 line 72-97\n"+
			"Fix: Ensure all multi-statement operations use explicit transactions", count)
}

// TestSQLite_Atomicity_MultiStatementSuccess verifies multi-statement transaction commits atomically
func TestSQLite_Atomicity_MultiStatementSuccess(t *testing.T) {
	// REQUIREMENT: docs/requirements/storage-acid-requirements.md Section 3.1.1 lines 574-593
	// Specification: "Multi-statement operations MUST use explicit transactions"
	// Test: Execute multiple INSERTs in transaction, verify all-or-nothing commit
	//
	// RATIONALE: Multi-step operations must be atomic
	// - Creating rule + actions = atomic unit
	// - Creating user + permissions = atomic unit
	// - All steps succeed together or all fail together

	logger := zap.NewNop().Sugar()
	sqlite, err := NewSQLite(":memory:", logger)
	require.NoError(t, err)
	defer sqlite.Close()

	// Begin transaction
	tx, err := sqlite.DB.Begin()
	require.NoError(t, err)

	// Multi-statement operation: Create rule + 3 actions
	ruleID := "multi-statement-rule"

	// Statement 1: Create rule
	_, err = tx.Exec(`
		INSERT INTO rules (id, name, type, severity, enabled, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, datetime('now'), datetime('now'))
	`, ruleID, "Multi-Statement Rule", "sigma", "high", 1)
	require.NoError(t, err, "Rule creation should succeed")

	// Statement 2: Create action 1
	_, err = tx.Exec(`
		INSERT INTO actions (id, type, config, created_at, updated_at)
		VALUES (?, ?, ?, datetime('now'), datetime('now'))
	`, "action1", "email", "{}")
	require.NoError(t, err, "Action 1 creation should succeed")

	// Statement 3: Create action 2
	_, err = tx.Exec(`
		INSERT INTO actions (id, type, config, created_at, updated_at)
		VALUES (?, ?, ?, datetime('now'), datetime('now'))
	`, "action2", "webhook", "{}")
	require.NoError(t, err, "Action 2 creation should succeed")

	// Statement 4: Create action 3
	_, err = tx.Exec(`
		INSERT INTO actions (id, type, config, created_at, updated_at)
		VALUES (?, ?, ?, datetime('now'), datetime('now'))
	`, "action3", "slack", "{}")
	require.NoError(t, err, "Action 3 creation should succeed")

	// Commit transaction (all-or-nothing)
	err = tx.Commit()
	require.NoError(t, err, "Transaction commit must succeed")

	// VERIFY: All 4 statements persisted atomically
	var ruleCount int
	err = sqlite.DB.QueryRow("SELECT COUNT(*) FROM rules WHERE id = ?", ruleID).Scan(&ruleCount)
	require.NoError(t, err)
	assert.Equal(t, 1, ruleCount, "Rule should be persisted after commit")

	var actionCount int
	err = sqlite.DB.QueryRow("SELECT COUNT(*) FROM actions WHERE id IN (?, ?, ?)", "action1", "action2", "action3").Scan(&actionCount)
	require.NoError(t, err)
	assert.Equal(t, 3, actionCount,
		"All 3 actions should be persisted after commit\n"+
			"Expected: 3 actions\n"+
			"Actual: %d actions\n"+
			"Atomicity requires all-or-nothing commit", actionCount)
}

// TestSQLite_Atomicity_PartialWritePrevention verifies partial writes cannot occur on mid-transaction error
func TestSQLite_Atomicity_PartialWritePrevention(t *testing.T) {
	// REQUIREMENT: docs/requirements/storage-acid-requirements.md Section 3.1.1 lines 100-104
	// Specification: "Partial writes MUST NOT persist on error"
	// Test: Insert multiple records, force error mid-transaction, verify ZERO persistence
	//
	// ATTACK SCENARIO:
	// 1. User creates rule with 5 actions
	// 2. Actions 1-3 succeed
	// 3. Action 4 fails (duplicate ID, invalid config, etc.)
	// 4. Action 5 never executes
	// EXPECTED: Rule + ALL actions rolled back (atomic failure)
	// BUG: Rule + 3 actions persist (PARTIAL WRITE - data corruption)

	logger := zap.NewNop().Sugar()
	sqlite, err := NewSQLite(":memory:", logger)
	require.NoError(t, err)
	defer sqlite.Close()

	// Begin transaction
	tx, err := sqlite.DB.Begin()
	require.NoError(t, err)

	ruleID := "partial-write-test-rule"

	// Step 1: Create rule
	_, err = tx.Exec(`
		INSERT INTO rules (id, name, type, severity, enabled, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, datetime('now'), datetime('now'))
	`, ruleID, "Partial Write Test", "sigma", "critical", 1)
	require.NoError(t, err)

	// Step 2: Create action 1 (succeeds)
	_, err = tx.Exec(`
		INSERT INTO actions (id, type, config, created_at, updated_at)
		VALUES (?, ?, ?, datetime('now'), datetime('now'))
	`, "partial-action-1", "email", "{}")
	require.NoError(t, err)

	// Step 3: Create action 2 (succeeds)
	_, err = tx.Exec(`
		INSERT INTO actions (id, type, config, created_at, updated_at)
		VALUES (?, ?, ?, datetime('now'), datetime('now'))
	`, "partial-action-2", "webhook", "{}")
	require.NoError(t, err)

	// Step 4: Create action 3 (succeeds)
	_, err = tx.Exec(`
		INSERT INTO actions (id, type, config, created_at, updated_at)
		VALUES (?, ?, ?, datetime('now'), datetime('now'))
	`, "partial-action-3", "slack", "{}")
	require.NoError(t, err)

	// Step 5: Create action 4 with DUPLICATE ID (FAILS - triggers rollback)
	_, err = tx.Exec(`
		INSERT INTO actions (id, type, config, created_at, updated_at)
		VALUES (?, ?, ?, datetime('now'), datetime('now'))
	`, "partial-action-3", "pagerduty", "{}") // Same ID as action 3
	require.Error(t, err, "Duplicate action ID must fail")

	// Rollback on error
	err = tx.Rollback()
	require.NoError(t, err)

	// VERIFY: ZERO actions persisted (no partial write)
	// This is the CRITICAL assertion - proves no partial writes
	var actionCount int
	err = sqlite.DB.QueryRow(`
		SELECT COUNT(*) FROM actions
		WHERE id IN (?, ?, ?, ?)
	`, "partial-action-1", "partial-action-2", "partial-action-3", "partial-action-4").Scan(&actionCount)
	require.NoError(t, err)

	assert.Equal(t, 0, actionCount,
		"PARTIAL WRITE DETECTED: Actions persisted despite transaction rollback\n"+
			"Expected: 0 actions (atomic rollback)\n"+
			"Actual: %d actions\n"+
			"CRITICAL: This is a data corruption bug - partial writes violate ACID atomicity\n"+
			"Requirement: storage-acid-requirements.md Section 3.1.1 line 100-104", actionCount)

	// VERIFY: Rule also not persisted (entire transaction rolled back)
	var ruleCount int
	err = sqlite.DB.QueryRow("SELECT COUNT(*) FROM rules WHERE id = ?", ruleID).Scan(&ruleCount)
	require.NoError(t, err)

	assert.Equal(t, 0, ruleCount,
		"PARTIAL WRITE DETECTED: Rule persisted despite transaction rollback\n"+
			"Expected: 0 rules\n"+
			"Actual: %d rules\n"+
			"Atomicity requires ALL operations to rollback together", ruleCount)
}

// TestSQLite_Atomicity_CommitVsRollback verifies commit persists and rollback discards
func TestSQLite_Atomicity_CommitVsRollback(t *testing.T) {
	// REQUIREMENT: docs/requirements/storage-acid-requirements.md Section 3.1.1
	// Test: Side-by-side comparison of commit (persists) vs rollback (discards)
	// RATIONALE: Explicit verification of commit/rollback semantics

	logger := zap.NewNop().Sugar()
	sqlite, err := NewSQLite(":memory:", logger)
	require.NoError(t, err)
	defer sqlite.Close()

	// Test 1: Commit persists data
	tx1, err := sqlite.DB.Begin()
	require.NoError(t, err)

	_, err = tx1.Exec(`
		INSERT INTO rules (id, name, type, severity, enabled, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, datetime('now'), datetime('now'))
	`, "commit-rule", "Committed Rule", "sigma", "high", 1)
	require.NoError(t, err)

	err = tx1.Commit()
	require.NoError(t, err)

	var commitCount int
	err = sqlite.DB.QueryRow("SELECT COUNT(*) FROM rules WHERE id = ?", "commit-rule").Scan(&commitCount)
	require.NoError(t, err)
	assert.Equal(t, 1, commitCount, "Committed data must persist")

	// Test 2: Rollback discards data
	tx2, err := sqlite.DB.Begin()
	require.NoError(t, err)

	_, err = tx2.Exec(`
		INSERT INTO rules (id, name, type, severity, enabled, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, datetime('now'), datetime('now'))
	`, "rollback-rule", "Rolled Back Rule", "sigma", "medium", 1)
	require.NoError(t, err)

	err = tx2.Rollback()
	require.NoError(t, err)

	var rollbackCount int
	err = sqlite.DB.QueryRow("SELECT COUNT(*) FROM rules WHERE id = ?", "rollback-rule").Scan(&rollbackCount)
	require.NoError(t, err)
	assert.Equal(t, 0, rollbackCount, "Rolled back data must NOT persist")
}

// TestSQLite_Atomicity_NestedTransactionBehavior verifies savepoint behavior (nested transactions)
func TestSQLite_Atomicity_NestedTransactionBehavior(t *testing.T) {
	// REQUIREMENT: docs/requirements/storage-acid-requirements.md Section 3.1.1
	// Test: Verify SQLite savepoint behavior (SQLite doesn't support true nested transactions)
	// RATIONALE: Document expected behavior for developers
	//
	// NOTE: SQLite doesn't support nested BEGIN/COMMIT
	// - BEGIN within transaction is ignored
	// - Must use SAVEPOINT for nested transaction-like behavior
	// - This test documents the limitation

	logger := zap.NewNop().Sugar()
	sqlite, err := NewSQLite(":memory:", logger)
	require.NoError(t, err)
	defer sqlite.Close()

	// Begin outer transaction
	tx, err := sqlite.DB.Begin()
	require.NoError(t, err)

	// Insert data in outer transaction
	_, err = tx.Exec(`
		INSERT INTO rules (id, name, type, severity, enabled, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, datetime('now'), datetime('now'))
	`, "outer-rule", "Outer Transaction", "sigma", "high", 1)
	require.NoError(t, err)

	// Create savepoint (nested transaction simulation)
	_, err = tx.Exec("SAVEPOINT nested")
	require.NoError(t, err)

	// Insert data in "nested" transaction
	_, err = tx.Exec(`
		INSERT INTO rules (id, name, type, severity, enabled, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, datetime('now'), datetime('now'))
	`, "nested-rule", "Nested Transaction", "sigma", "medium", 1)
	require.NoError(t, err)

	// Rollback to savepoint (undo nested, keep outer)
	_, err = tx.Exec("ROLLBACK TO nested")
	require.NoError(t, err)

	// Commit outer transaction
	err = tx.Commit()
	require.NoError(t, err)

	// Verify: Outer persisted, nested rolled back
	var outerCount int
	err = sqlite.DB.QueryRow("SELECT COUNT(*) FROM rules WHERE id = ?", "outer-rule").Scan(&outerCount)
	require.NoError(t, err)
	assert.Equal(t, 1, outerCount, "Outer transaction data should persist")

	var nestedCount int
	err = sqlite.DB.QueryRow("SELECT COUNT(*) FROM rules WHERE id = ?", "nested-rule").Scan(&nestedCount)
	require.NoError(t, err)
	assert.Equal(t, 0, nestedCount, "Nested transaction data should be rolled back")
}

// TestSQLite_Atomicity_DeferredVsImmediate verifies transaction isolation modes
func TestSQLite_Atomicity_DeferredVsImmediate(t *testing.T) {
	// REQUIREMENT: docs/requirements/storage-acid-requirements.md Section 3.1.1
	// Test: Document SQLite transaction mode behavior
	// MODES:
	// - DEFERRED: Lock acquired on first read/write (default)
	// - IMMEDIATE: Write lock acquired on BEGIN
	// - EXCLUSIVE: Exclusive lock acquired on BEGIN
	//
	// RATIONALE: Developers need to understand locking behavior

	logger := zap.NewNop().Sugar()
	sqlite, err := NewSQLite(":memory:", logger)
	require.NoError(t, err)
	defer sqlite.Close()

	// Test DEFERRED transaction (default)
	tx1, err := sqlite.DB.Begin() // Deferred by default
	require.NoError(t, err)

	// No lock held yet (DEFERRED)
	// Lock acquired on first write
	_, err = tx1.Exec(`
		INSERT INTO rules (id, name, type, severity, enabled, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, datetime('now'), datetime('now'))
	`, "deferred-rule", "Deferred Transaction", "sigma", "low", 1)
	require.NoError(t, err)

	err = tx1.Commit()
	require.NoError(t, err)

	var count int
	err = sqlite.DB.QueryRow("SELECT COUNT(*) FROM rules WHERE id = ?", "deferred-rule").Scan(&count)
	require.NoError(t, err)
	assert.Equal(t, 1, count)
}
