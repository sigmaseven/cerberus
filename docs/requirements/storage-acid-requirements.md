# Storage Layer ACID Requirements

**Document Owner**: Data Engineering Team
**Created**: 2025-11-16
**Status**: DRAFT - Pending Technical Review
**Authoritative Sources**:
- "Designing Data-Intensive Applications" by Martin Kleppmann (2017), Chapter 7
- SQLite Documentation: https://www.sqlite.org/transact.html
- ClickHouse Documentation: https://clickhouse.com/docs/en/guides/developer/transactional

**Purpose**: Define ACID guarantees and transactional requirements for Cerberus storage layer

---

## 1. EXECUTIVE SUMMARY

This document defines the expected transactional behavior and data consistency guarantees for Cerberus's dual-storage architecture:
- **SQLite**: Metadata storage (rules, users, actions, correlation rules)
- **ClickHouse**: Time-series storage (events, alerts)

**Critical Principle**: Different storage engines provide different ACID guarantees. Tests MUST verify actual behavior, not assumed behavior.

---

## 2. STORAGE ARCHITECTURE OVERVIEW

### 2.1 SQLite (Metadata Storage)

**Purpose**: Store configuration and metadata
**Data**: Rules, correlation rules, actions, users, exceptions, investigations, saved searches
**Expected Usage**: Low-volume writes (<100 writes/sec), high consistency requirements

**ACID Capabilities** (from SQLite documentation):
- **Atomicity**: ✅ Full support via transactions
- **Consistency**: ✅ Full support via constraints and triggers
- **Isolation**: ✅ Serializable isolation (with caveats in WAL mode)
- **Durability**: ✅ Full support (fsync after transaction commit)

**File**: `storage/sqlite.go`, `storage/sqlite_*.go`

---

### 2.2 ClickHouse (Time-Series Storage)

**Purpose**: Store high-volume time-series data
**Data**: Events, alerts
**Expected Usage**: High-volume writes (>10,000 events/sec), eventual consistency acceptable

**ACID Capabilities** (from ClickHouse documentation):
- **Atomicity**: ⚠️ **LIMITED** - INSERT atomicity only, no UPDATE atomicity
- **Consistency**: ⚠️ **EVENTUAL** - MergeTree engine merges asynchronously
- **Isolation**: ⚠️ **NONE** - No transaction isolation between queries
- **Durability**: ✅ Configurable (depends on replication settings)

**File**: `storage/clickhouse.go`, `storage/clickhouse_*.go`

**Critical Note**: ClickHouse is NOT an ACID-compliant database. Tests must reflect actual behavior.

---

## 3. ACID REQUIREMENTS BY COMPONENT

### 3.1 SQLite ACID Requirements

#### 3.1.1 Atomicity (A)

**Requirement**: All operations within a transaction MUST succeed or fail as a unit.

**Test Requirements**:

```go
func TestSQLite_Atomicity_RollbackOnError(t *testing.T) {
    storage := setupSQLiteStorage(t)

    // Begin transaction
    tx, err := storage.DB.Begin()
    require.NoError(t, err)

    // Operation 1: Create rule (should succeed)
    rule1 := &core.Rule{ID: "rule1", Name: "Test Rule 1"}
    _, err = tx.Exec("INSERT INTO rules (id, name, ...) VALUES (?, ?, ...)", rule1.ID, rule1.Name)
    require.NoError(t, err)

    // Operation 2: Create duplicate rule (should fail - violates PRIMARY KEY)
    _, err = tx.Exec("INSERT INTO rules (id, name, ...) VALUES (?, ?, ...)", rule1.ID, "Duplicate")
    require.Error(t, err)

    // Rollback transaction
    err = tx.Rollback()
    require.NoError(t, err)

    // Verify: rule1 was NOT persisted (atomicity)
    var count int
    err = storage.DB.QueryRow("SELECT COUNT(*) FROM rules WHERE id = ?", rule1.ID).Scan(&count)
    require.NoError(t, err)
    assert.Equal(t, 0, count, "Transaction was not atomic - partial write persisted")
}
```

**Current Implementation**:
- **Status**: ⚠️ UNKNOWN - Most operations use direct `Exec()` without explicit transactions
- **Gap**: No transaction usage detected in `storage/sqlite_rules.go`, `sqlite_actions.go`, etc.
- **Risk**: Partial writes may occur on errors

**TBD - DECISION NEEDED**:
```
Question: Should all multi-statement operations use explicit transactions?

Owner: Data Engineering Team
Deadline: Week 1

Current Behavior: Single statements are implicitly transactional (SQLite auto-commit)
Problem: Multi-statement operations (e.g., creating rule + actions) may be non-atomic

Options:
1. Explicit transactions for all multi-statement operations
   - Pro: Guaranteed atomicity
   - Con: More complex code, potential deadlocks

2. Keep implicit transactions (status quo)
   - Pro: Simple code
   - Con: No atomicity guarantees for multi-statement operations

Recommendation: Option 1 (explicit transactions) for production reliability
```

---

#### 3.1.2 Consistency (C)

**Requirement**: Database constraints (PRIMARY KEY, FOREIGN KEY, UNIQUE, CHECK) MUST be enforced.

**Test Requirements**:

```go
func TestSQLite_Consistency_PrimaryKeyEnforcement(t *testing.T) {
    storage := setupSQLiteStorage(t)

    // Create rule with ID "rule1"
    rule1 := &core.Rule{ID: "rule1", Name: "Original"}
    err := storage.CreateRule(rule1)
    require.NoError(t, err)

    // Attempt to create duplicate rule with same ID
    rule2 := &core.Rule{ID: "rule1", Name: "Duplicate"}
    err = storage.CreateRule(rule2)

    // MUST fail due to PRIMARY KEY constraint
    assert.Error(t, err)
    assert.Contains(t, err.Error(), "UNIQUE constraint")

    // Verify original rule unchanged
    retrieved, err := storage.GetRule("rule1")
    require.NoError(t, err)
    assert.Equal(t, "Original", retrieved.Name)
}

func TestSQLite_Consistency_ForeignKeyEnforcement(t *testing.T) {
    storage := setupSQLiteStorage(t)

    // SETUP: Enable foreign key constraints (SQLite defaults to OFF!)
    _, err := storage.DB.Exec("PRAGMA foreign_keys = ON")
    require.NoError(t, err)

    // Create exception referencing non-existent rule
    exception := &core.Exception{
        ID:     "exc1",
        RuleID: "nonexistent-rule",  // FK violation
    }

    err = storage.CreateException(exception)

    // MUST fail due to FOREIGN KEY constraint
    // NOTE: Only if PRAGMA foreign_keys is ON
    assert.Error(t, err)
}
```

**Current Implementation**:
- **Schema**: `storage/sqlite.go:createTables()` defines constraints
- **Status**: ⚠️ VERIFY - Check if `PRAGMA foreign_keys = ON` is set
- **Default Behavior**: SQLite disables foreign key constraints by default!

**CRITICAL FINDING**:
```go
// storage/sqlite.go line 32
db, err := sql.Open("sqlite", dbPath+"?_journal_mode=WAL&_busy_timeout=5000")
```

**Missing**: `&_foreign_keys=ON` query parameter

**Test Requirement**:
```go
func TestSQLite_ForeignKeysEnabled(t *testing.T) {
    storage := setupSQLiteStorage(t)

    var enabled int
    err := storage.DB.QueryRow("PRAGMA foreign_keys").Scan(&enabled)
    require.NoError(t, err)
    assert.Equal(t, 1, enabled, "Foreign keys MUST be enabled for referential integrity")
}
```

---

#### 3.1.3 Isolation (I)

**Requirement**: Concurrent transactions MUST NOT interfere with each other.

**SQLite Isolation Levels**:
- **Default (WAL mode)**: Snapshot isolation (read committed)
- **Readers**: Always see consistent snapshot
- **Writers**: Serialized (only one writer at a time)

**Test Requirements**:

```go
func TestSQLite_Isolation_ReadCommitted(t *testing.T) {
    storage := setupSQLiteStorage(t)

    // Create initial rule
    rule := &core.Rule{ID: "rule1", Name: "Version 1"}
    storage.CreateRule(rule)

    // Start read transaction (T1)
    tx1, err := storage.DB.Begin()
    require.NoError(t, err)

    // Read rule in T1
    var nameT1 string
    err = tx1.QueryRow("SELECT name FROM rules WHERE id = ?", "rule1").Scan(&nameT1)
    require.NoError(t, err)
    assert.Equal(t, "Version 1", nameT1)

    // Concurrent write transaction (T2) - commits
    tx2, err := storage.DB.Begin()
    require.NoError(t, err)
    _, err = tx2.Exec("UPDATE rules SET name = ? WHERE id = ?", "Version 2", "rule1")
    require.NoError(t, err)
    err = tx2.Commit()
    require.NoError(t, err)

    // Read again in T1 (still uncommitted)
    var nameT1After string
    err = tx1.QueryRow("SELECT name FROM rules WHERE id = ?", "rule1").Scan(&nameT1After)
    require.NoError(t, err)

    // MUST: See original snapshot ("Version 1"), NOT committed change
    // This verifies snapshot isolation
    assert.Equal(t, "Version 1", nameT1After, "Isolation violated - saw uncommitted change")

    tx1.Rollback()
}
```

**Current Implementation**:
- **Connection Pool**: `db.SetMaxOpenConns(1)` (line 41) - single writer
- **Journal Mode**: WAL (Write-Ahead Logging) - enables concurrent readers
- **Status**: ✅ LIKELY CORRECT - WAL mode provides snapshot isolation

**Test Gap**: No explicit isolation tests found in codebase

---

#### 3.1.4 Durability (D)

**Requirement**: Committed transactions MUST survive system crashes.

**Test Requirements**:

```go
func TestSQLite_Durability_SurvivesCrash(t *testing.T) {
    dbPath := t.TempDir() + "/test.db"

    // Create storage and insert rule
    storage1, err := storage.NewSQLite(dbPath, logger)
    require.NoError(t, err)

    rule := &core.Rule{ID: "rule1", Name: "Critical Rule"}
    err = storage1.CreateRule(rule)
    require.NoError(t, err)

    // Simulate crash (close without explicit flush)
    storage1.Close()

    // Reopen database (simulates recovery after crash)
    storage2, err := storage.NewSQLite(dbPath, logger)
    require.NoError(t, err)
    defer storage2.Close()

    // Verify rule persisted
    retrieved, err := storage2.GetRule("rule1")
    require.NoError(t, err)
    assert.Equal(t, "Critical Rule", retrieved.Name)
}
```

**Current Implementation**:
- **Journal Mode**: WAL (Write-Ahead Logging)
- **Synchronous Mode**: Default (FULL - fsync after commit)
- **Status**: ✅ LIKELY DURABLE - WAL + FULL sync ensures durability

**Test Gap**: No crash recovery tests found

**TBD - DECISION NEEDED**:
```
Question: Should we relax durability for performance?

Owner: Performance Team
Deadline: Week 2

Options:
1. PRAGMA synchronous = FULL (current default)
   - Pro: Full durability guarantee
   - Con: ~10x slower writes (requires fsync)

2. PRAGMA synchronous = NORMAL
   - Pro: Much faster writes
   - Con: May lose last transaction on power loss (OS crash OK)

3. PRAGMA synchronous = OFF
   - Pro: Maximum write performance
   - Con: May corrupt database on crash (UNACCEPTABLE)

Recommendation: Keep FULL for metadata (rules, users), consider NORMAL for non-critical data
```

---

### 3.2 ClickHouse ACID Requirements

#### 3.2.1 Atomicity - INSERT Operations Only

**ClickHouse Guarantee**: INSERT statements are atomic within a single block.

**NOT Guaranteed**: Multi-statement transactions (no BEGIN/COMMIT support)

**Test Requirements**:

```go
func TestClickHouse_Atomicity_InsertBlock(t *testing.T) {
    storage := setupClickHouseStorage(t)

    // Insert batch of 1000 events
    events := make([]*core.Event, 1000)
    for i := range events {
        events[i] = createTestEvent(fmt.Sprintf("event-%d", i))
    }

    // Insert in single batch (atomic)
    err := storage.InsertEvents(events)
    require.NoError(t, err)

    // Verify: All 1000 events inserted (not partial batch)
    count, err := storage.GetEventCount()
    require.NoError(t, err)
    assert.Equal(t, int64(1000), count)
}

func TestClickHouse_NoAtomicity_MultipleStatements(t *testing.T) {
    storage := setupClickHouseStorage(t)

    // EXPECTATION: ClickHouse does NOT support multi-statement transactions

    // Insert event 1
    err := storage.InsertEvent(event1)
    require.NoError(t, err)

    // Insert event 2 (fails for some reason)
    err = storage.InsertEvent(invalidEvent)
    require.Error(t, err)

    // Verify: event1 is persisted (no rollback)
    count, err := storage.GetEventCount()
    require.NoError(t, err)
    assert.Equal(t, int64(1), count, "ClickHouse does not rollback - this is expected behavior")
}
```

**Current Implementation**:
- **Batch Inserts**: `storage/clickhouse_events.go` likely uses batch INSERT
- **Status**: ⚠️ NEEDS VERIFICATION - Check if using PreparedBatch API
- **Documentation Needed**: Tests must document lack of multi-statement atomicity

---

#### 3.2.2 Consistency - Eventual (MergeTree)

**ClickHouse Guarantee**: MergeTree engine performs background merges asynchronously.

**Implication**: Queries may see data in different states of merging.

**Test Requirements**:

```go
func TestClickHouse_EventualConsistency_BackgroundMerges(t *testing.T) {
    storage := setupClickHouseStorage(t)

    // Insert many small parts (forces multiple table parts)
    for i := 0; i < 100; i++ {
        event := createTestEvent(fmt.Sprintf("event-%d", i))
        storage.InsertEvent(event) // Separate INSERT creates separate part
    }

    // Query immediately (before merges complete)
    count1, err := storage.GetEventCount()
    require.NoError(t, err)
    assert.Equal(t, int64(100), count1)

    // Force table optimization (merge all parts)
    err = storage.Conn.Exec(context.Background(), "OPTIMIZE TABLE events FINAL")
    require.NoError(t, err)

    // Query after merge
    count2, err := storage.GetEventCount()
    require.NoError(t, err)
    assert.Equal(t, int64(100), count2)

    // Verify: Counts are eventually consistent (may differ during merges)
    // This test documents expected behavior, not a bug
}
```

**Current Implementation**:
- **Table Engine**: MergeTree (defined in `storage/clickhouse.go:CreateTablesIfNotExist()`)
- **Status**: ✅ CORRECT - MergeTree is appropriate for time-series data
- **Documentation**: Tests must document eventual consistency model

---

#### 3.2.3 Isolation - None

**ClickHouse Guarantee**: No isolation between concurrent queries.

**Implication**: Queries may see partial results from concurrent INSERTs.

**Test Requirements**:

```go
func TestClickHouse_NoIsolation_ConcurrentQueries(t *testing.T) {
    storage := setupClickHouseStorage(t)

    // Insert initial 100 events
    insertEvents(storage, 100)

    var wg sync.WaitGroup
    results := make(chan int64, 2)

    // Concurrent query 1
    wg.Add(1)
    go func() {
        defer wg.Done()
        count, _ := storage.GetEventCount()
        results <- count
    }()

    // Concurrent insert
    wg.Add(1)
    go func() {
        defer wg.Done()
        time.Sleep(10 * time.Millisecond) // Delay to interleave with query
        insertEvents(storage, 50)
    }()

    // Concurrent query 2
    wg.Add(1)
    go func() {
        defer wg.Done()
        time.Sleep(20 * time.Millisecond)
        count, _ := storage.GetEventCount()
        results <- count
    }()

    wg.Wait()
    close(results)

    // Collect results
    counts := []int64{}
    for c := range results {
        counts = append(counts, c)
    }

    // EXPECTATION: May see 100, 100, 150 or 100, 150, 150 (no isolation)
    // This test documents expected behavior
    t.Logf("Observed counts: %v (demonstrates lack of isolation)", counts)
}
```

---

#### 3.2.4 Durability - Configurable

**ClickHouse Guarantee**: Durability depends on `fsync` settings and replication.

**Default**: Asynchronous writes for performance.

**Test Requirements**:

```go
func TestClickHouse_Durability_AsyncWrites(t *testing.T) {
    // NOTE: Testing durability requires simulating crashes, which is complex
    // Document expected behavior instead

    t.Skip("Durability testing requires crash simulation - document behavior instead")

    // Expected behavior (from ClickHouse docs):
    // - INSERT acknowledged before fsync (async_insert=1)
    // - Data may be lost on server crash if not fsynced
    // - Replication provides durability across nodes
}
```

**TBD - DECISION NEEDED**:
```
Question: What durability guarantees do we need for events/alerts?

Owner: Architecture Team
Deadline: Week 2

Options:
1. Async inserts (current) - High throughput, may lose recent data on crash
2. Sync inserts - Guaranteed durability, 10x slower
3. Replication - Durability via multiple nodes

Considerations:
- Events are already persisted at source (log files, syslog)
- Losing 1-2 seconds of events may be acceptable
- Alerts are critical - may need stronger durability

Recommendation: Async for events, sync or replicated for alerts
```

---

## 4. TRANSACTION PATTERNS

### 4.1 Required Transaction Pattern (SQLite)

**Pattern**: Explicit transactions for multi-statement operations

**Example**:
```go
func (s *SQLiteStorage) CreateRuleWithActions(rule *core.Rule, actions []core.Action) error {
    // Begin transaction
    tx, err := s.DB.Begin()
    if err != nil {
        return fmt.Errorf("failed to begin transaction: %w", err)
    }
    defer tx.Rollback() // Rollback if not committed

    // Insert rule
    if err := insertRule(tx, rule); err != nil {
        return err // Rollback happens in defer
    }

    // Insert actions
    for _, action := range actions {
        if err := insertAction(tx, action); err != nil {
            return err // Rollback happens in defer
        }
    }

    // Commit transaction (success)
    if err := tx.Commit(); err != nil {
        return fmt.Errorf("failed to commit transaction: %w", err)
    }

    return nil
}
```

**Test Requirements**:
```go
func TestSQLite_TransactionPattern_MultiStatementAtomicity(t *testing.T) {
    storage := setupSQLiteStorage(t)

    rule := &core.Rule{ID: "rule1", Name: "Test"}
    actions := []core.Action{
        {ID: "action1", Type: "email"},
        {ID: "action1", Type: "slack"}, // Duplicate ID - will fail
    }

    err := storage.CreateRuleWithActions(rule, actions)
    assert.Error(t, err)

    // Verify: Neither rule nor actions persisted (atomic rollback)
    _, err = storage.GetRule("rule1")
    assert.Error(t, err) // Rule not found

    _, err = storage.GetAction("action1")
    assert.Error(t, err) // Action not found
}
```

---

### 4.2 Idempotency Pattern

**Requirement**: Operations MUST be idempotent to support retries.

**Pattern**: Use "INSERT OR REPLACE" / "UPDATE OR INSERT"

**Test Requirements**:
```go
func TestSQLite_Idempotency_DuplicateInserts(t *testing.T) {
    storage := setupSQLiteStorage(t)

    rule := &core.Rule{ID: "rule1", Name: "Original"}

    // First insert
    err := storage.UpsertRule(rule)
    require.NoError(t, err)

    // Second insert with same ID (retry scenario)
    rule.Name = "Updated"
    err = storage.UpsertRule(rule)
    require.NoError(t, err) // Should succeed (not error)

    // Verify: Updated value persisted
    retrieved, err := storage.GetRule("rule1")
    require.NoError(t, err)
    assert.Equal(t, "Updated", retrieved.Name)
}
```

---

## 5. CONCURRENCY REQUIREMENTS

### 5.1 SQLite Concurrency Model

**Write Concurrency**: Single writer (enforced by `SetMaxOpenConns(1)`)
**Read Concurrency**: Multiple readers (WAL mode)

**Test Requirements**:
```go
func TestSQLite_Concurrency_MultipleReaders(t *testing.T) {
    storage := setupSQLiteStorage(t)

    // Insert test data
    for i := 0; i < 100; i++ {
        storage.CreateRule(&core.Rule{ID: fmt.Sprintf("rule%d", i)})
    }

    // 10 concurrent readers
    var wg sync.WaitGroup
    for i := 0; i < 10; i++ {
        wg.Add(1)
        go func(id int) {
            defer wg.Done()

            // Read all rules
            rules, err := storage.GetAllRules()
            assert.NoError(t, err)
            assert.Equal(t, 100, len(rules))
        }(i)
    }

    wg.Wait()
}

func TestSQLite_Concurrency_SingleWriter(t *testing.T) {
    storage := setupSQLiteStorage(t)

    // 10 concurrent writers
    var wg sync.WaitGroup
    errChan := make(chan error, 10)

    for i := 0; i < 10; i++ {
        wg.Add(1)
        go func(id int) {
            defer wg.Done()

            rule := &core.Rule{ID: fmt.Sprintf("rule%d", id)}
            if err := storage.CreateRule(rule); err != nil {
                errChan <- err
            }
        }(i)
    }

    wg.Wait()
    close(errChan)

    // Verify: No database locked errors (single writer prevents conflicts)
    for err := range errChan {
        assert.NotContains(t, err.Error(), "database is locked")
    }
}
```

---

### 5.2 ClickHouse Concurrency Model

**Write Concurrency**: Multiple writers (no locking)
**Read Concurrency**: Multiple readers (MVCC-like)

**Test Requirements**:
```go
func TestClickHouse_Concurrency_MultipleWriters(t *testing.T) {
    storage := setupClickHouseStorage(t)

    // 10 concurrent writers
    var wg sync.WaitGroup
    for i := 0; i < 10; i++ {
        wg.Add(1)
        go func(id int) {
            defer wg.Done()

            events := make([]*core.Event, 100)
            for j := range events {
                events[j] = createTestEvent(fmt.Sprintf("writer%d-event%d", id, j))
            }

            err := storage.InsertEvents(events)
            assert.NoError(t, err)
        }(i)
    }

    wg.Wait()

    // Verify: All 1000 events inserted (10 writers × 100 events)
    count, err := storage.GetEventCount()
    require.NoError(t, err)
    assert.Equal(t, int64(1000), count)
}
```

---

## 6. COMPLIANCE VERIFICATION CHECKLIST

### 6.1 SQLite ACID Compliance
- [ ] Atomicity: Transaction rollback tests
- [ ] Atomicity: Multi-statement atomicity tests
- [ ] Consistency: PRIMARY KEY enforcement tests
- [ ] Consistency: FOREIGN KEY enforcement tests (verify enabled)
- [ ] Consistency: UNIQUE constraint tests
- [ ] Consistency: CHECK constraint tests
- [ ] Isolation: Snapshot isolation tests (WAL mode)
- [ ] Isolation: Read committed tests
- [ ] Durability: Crash recovery tests

### 6.2 ClickHouse Behavior Documentation
- [ ] Document INSERT atomicity (single block)
- [ ] Document lack of multi-statement atomicity
- [ ] Document eventual consistency (MergeTree merges)
- [ ] Document lack of transaction isolation
- [ ] Document durability configuration (async vs sync)

### 6.3 Transaction Pattern Compliance
- [ ] Explicit transactions for multi-statement operations
- [ ] Idempotent operations (upsert support)
- [ ] Error handling and rollback tests

### 6.4 Concurrency Compliance
- [ ] SQLite single-writer enforcement
- [ ] SQLite multi-reader support
- [ ] ClickHouse multi-writer support
- [ ] No database locked errors under load

---

## 7. TBD TRACKER

| Item | Question | Owner | Deadline | Status |
|------|----------|-------|----------|--------|
| TBD-ACID-001 | Use explicit transactions? | Data Team | Week 1 | OPEN |
| TBD-ACID-002 | Enable foreign keys by default? | Data Team | Week 1 | OPEN |
| TBD-ACID-003 | SQLite synchronous mode | Performance Team | Week 2 | OPEN |
| TBD-ACID-004 | ClickHouse durability requirements | Architecture Team | Week 2 | OPEN |
| TBD-ACID-005 | Replication strategy | Operations Team | Week 3 | OPEN |

---

## 8. REFERENCES

### 8.1 Books
1. **"Designing Data-Intensive Applications"** by Martin Kleppmann
   - Chapter 7: Transactions
   - Chapter 9: Consistency and Consensus

### 8.2 SQLite Documentation
1. **SQLite ACID**: https://www.sqlite.org/transact.html
2. **WAL Mode**: https://www.sqlite.org/wal.html
3. **Foreign Keys**: https://www.sqlite.org/foreignkeys.html
4. **PRAGMA statements**: https://www.sqlite.org/pragma.html

### 8.3 ClickHouse Documentation
1. **MergeTree Engine**: https://clickhouse.com/docs/en/engines/table-engines/mergetree-family/mergetree
2. **Transactions**: https://clickhouse.com/docs/en/guides/developer/transactional
3. **Asynchronous Inserts**: https://clickhouse.com/docs/en/optimize/asynchronous-inserts

---

**Document Status**: DRAFT - CRITICAL GAPS IDENTIFIED
**Next Review Date**: Week 1
**Approver**: Data Engineering Lead + Architect
**Version**: 1.0-DRAFT

---

## APPENDIX A: CRITICAL GAPS IDENTIFIED

1. **SQLite Foreign Keys**: ❌ NOT ENABLED BY DEFAULT
   - Fix: Add `?_foreign_keys=ON` to connection string
   - Risk: Referential integrity not enforced

2. **Explicit Transactions**: ⚠️ NOT USED CONSISTENTLY
   - Gap: Multi-statement operations may be non-atomic
   - Risk: Partial writes on errors

3. **No Crash Recovery Tests**: ❌ NOT IMPLEMENTED
   - Gap: Durability not verified
   - Risk: Unknown behavior after crashes

4. **No Isolation Tests**: ❌ NOT IMPLEMENTED
   - Gap: Concurrent behavior untested
   - Risk: Race conditions possible
