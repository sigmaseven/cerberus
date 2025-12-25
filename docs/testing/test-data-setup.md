# Test Data Management Guide

**Purpose:** Guide for managing test data, fixtures, and database seeding in Cerberus SIEM tests.

---

## Table of Contents

1. [Test Data Fixture Management](#test-data-fixture-management)
2. [Factory Pattern for Test Objects](#factory-pattern-for-test-objects)
3. [Database Seeding for Integration Tests](#database-seeding-for-integration-tests)
4. [Cleanup Strategies](#cleanup-strategies)
5. [Test Data Versioning](#test-data-versioning)
6. [Best Practices](#best-practices)

---

## Test Data Fixture Management

### Static Fixtures

Static fixtures are defined in `tests/integration/fixtures.go`:

```go
package integration

import (
    "cerberus/core"
    "time"
)

// TestEvent creates a standard test event
func TestEvent(t *testing.T, overrides ...func(*core.Event)) *core.Event {
    event := &core.Event{
        EventID:   generateID(),
        Timestamp: time.Now(),
        RawData:   "Test event data",
        Fields: map[string]interface{}{
            "src_ip": "192.168.1.100",
            "user":   "testuser",
        },
    }
    
    // Apply overrides
    for _, override := range overrides {
        override(event)
    }
    
    return event
}

// Usage:
event := TestEvent(t, func(e *core.Event) {
    e.Severity = "high"
    e.RawData = "Failed login attempt"
})
```

### Dynamic Fixtures

For tests requiring dynamic data:

```go
// EventFactory generates sequential test events
type EventFactory struct {
    counter int
    mu      sync.Mutex
}

func NewEventFactory() *EventFactory {
    return &EventFactory{}
}

func (f *EventFactory) NewEvent() *core.Event {
    f.mu.Lock()
    defer f.mu.Unlock()
    
    f.counter++
    return &core.Event{
        EventID:   fmt.Sprintf("event-%d", f.counter),
        Timestamp: time.Now().Add(time.Duration(f.counter) * time.Second),
        RawData:   fmt.Sprintf("Test event %d", f.counter),
    }
}

// Usage in tests:
factory := NewEventFactory()
event1 := factory.NewEvent()
event2 := factory.NewEvent()
```

---

## Factory Pattern for Test Objects

### Alert Factory

```go
package fixtures

type AlertFactory struct {
    counter int
}

func NewAlertFactory() *AlertFactory {
    return &AlertFactory{}
}

func (f *AlertFactory) NewAlert(severity string) *core.Alert {
    f.counter++
    return &core.Alert{
        ID:       fmt.Sprintf("alert-%d", f.counter),
        RuleID:   "rule-1",
        Severity: severity,
        Status:   "new",
        CreatedAt: time.Now(),
    }
}

func (f *AlertFactory) NewHighSeverityAlert() *core.Alert {
    return f.NewAlert("high")
}

func (f *AlertFactory) NewLowSeverityAlert() *core.Alert {
    return f.NewAlert("low")
}
```

### User Factory

```go
type UserFactory struct {
    counter int
}

func (f *UserFactory) NewUser(role string) *core.User {
    f.counter++
    return &core.User{
        ID:       fmt.Sprintf("user-%d", f.counter),
        Username: fmt.Sprintf("testuser%d", f.counter),
        Email:    fmt.Sprintf("test%d@example.com", f.counter),
        Role:     role,
    }
}

func (f *UserFactory) NewAdminUser() *core.User {
    return f.NewUser("admin")
}

func (f *UserFactory) NewAnalystUser() *core.User {
    return f.NewUser("analyst")
}
```

### Rule Factory

```go
type RuleFactory struct {
    counter int
}

func (f *RuleFactory) NewRule(name string, query string) *core.Rule {
    f.counter++
    return &core.Rule{
        ID:      fmt.Sprintf("rule-%d", f.counter),
        Name:    name,
        Query:   query,
        Enabled: true,
        Severity: "medium",
    }
}
```

---

## Database Seeding for Integration Tests

### Setup Functions

Create setup functions that seed test data:

```go
package integration

import (
    "database/sql"
    "testing"
    "cerberus/storage"
)

// setupTestDB creates and seeds a test database
func setupTestDB(t *testing.T) *sql.DB {
    db, err := sql.Open("sqlite3", ":memory:")
    require.NoError(t, err)
    
    // Create schema
    _, err = db.Exec(schemaSQL)
    require.NoError(t, err)
    
    // Seed test data
    seedTestUsers(t, db)
    seedTestRules(t, db)
    seedTestEvents(t, db)
    
    t.Cleanup(func() {
        db.Close()
    })
    
    return db
}

// seedTestUsers creates test users
func seedTestUsers(t *testing.T, db *sql.DB) {
    users := []struct {
        id       string
        username string
        role     string
    }{
        {"user-1", "admin", "admin"},
        {"user-2", "analyst1", "analyst"},
        {"user-3", "analyst2", "analyst"},
        {"user-4", "viewer", "viewer"},
    }
    
    for _, u := range users {
        _, err := db.Exec(
            "INSERT INTO users (id, username, role) VALUES (?, ?, ?)",
            u.id, u.username, u.role,
        )
        require.NoError(t, err)
    }
}

// seedTestRules creates test rules
func seedTestRules(t *testing.T, db *sql.DB) {
    rules := []struct {
        id      string
        name    string
        query   string
        enabled bool
    }{
        {
            id:      "rule-1",
            name:    "Failed Login",
            query:   "event.action == 'login' AND event.result == 'failure'",
            enabled: true,
        },
        {
            id:      "rule-2",
            name:    "Admin Access",
            query:   "event.user.role == 'admin'",
            enabled: true,
        },
    }
    
    for _, r := range rules {
        _, err := db.Exec(
            "INSERT INTO rules (id, name, query, enabled) VALUES (?, ?, ?, ?)",
            r.id, r.name, r.query, r.enabled,
        )
        require.NoError(t, err)
    }
}
```

### ClickHouse Seeding

For ClickHouse integration tests using testcontainers:

```go
import (
    "context"
    "github.com/testcontainers/testcontainers-go"
    "github.com/testcontainers/testcontainers-go/modules/clickhouse"
)

func setupClickHouse(t *testing.T) (clickhouse.ClickHouseContainer, *sql.DB) {
    ctx := context.Background()
    
    clickhouseContainer, err := clickhouse.RunContainer(ctx,
        testcontainers.WithImage("clickhouse/clickhouse-server:latest"),
    )
    require.NoError(t, err)
    
    connStr, err := clickhouseContainer.ConnectionString(ctx)
    require.NoError(t, err)
    
    db, err := sql.Open("clickhouse", connStr)
    require.NoError(t, err)
    
    // Create schema
    _, err = db.Exec(clickhouseSchemaSQL)
    require.NoError(t, err)
    
    // Seed test events
    seedClickHouseEvents(t, db, 1000) // 1000 test events
    
    t.Cleanup(func() {
        db.Close()
        clickhouseContainer.Terminate(ctx)
    })
    
    return clickhouseContainer, db
}

func seedClickHouseEvents(t *testing.T, db *sql.DB, count int) {
    for i := 0; i < count; i++ {
        _, err := db.Exec(
            "INSERT INTO events (event_id, timestamp, raw_data) VALUES (?, ?, ?)",
            fmt.Sprintf("event-%d", i),
            time.Now().Add(time.Duration(i)*time.Second),
            fmt.Sprintf("Test event %d", i),
        )
        require.NoError(t, err)
    }
}
```

---

## Cleanup Strategies

### Transaction Rollback

Use transactions for test isolation:

```go
func TestWithTransaction(t *testing.T) {
    db := setupTestDB(t)
    
    tx, err := db.Begin()
    require.NoError(t, err)
    defer tx.Rollback() // Always rollback
    
    // Test code that uses tx
    _, err = tx.Exec("INSERT INTO users (id, username) VALUES (?, ?)", "test-1", "testuser")
    require.NoError(t, err)
    
    // Verify insertion
    var username string
    err = tx.QueryRow("SELECT username FROM users WHERE id = ?", "test-1").Scan(&username)
    require.NoError(t, err)
    assert.Equal(t, "testuser", username)
    
    // Transaction is rolled back automatically
}
```

### Table Truncation

Clean up tables between tests:

```go
func cleanupTables(t *testing.T, db *sql.DB) {
    tables := []string{"alerts", "events", "rules", "users"}
    
    for _, table := range tables {
        _, err := db.Exec(fmt.Sprintf("DELETE FROM %s", table))
        require.NoError(t, err)
    }
}

func TestWithCleanup(t *testing.T) {
    db := setupTestDB(t)
    defer cleanupTables(t, db)
    
    // Test code...
}
```

### Testcontainers Cleanup

Testcontainers automatically clean up containers:

```go
func TestWithContainer(t *testing.T) {
    ctx := context.Background()
    
    container, db := setupClickHouse(t)
    defer func() {
        db.Close()
        container.Terminate(ctx) // Explicit cleanup
    }()
    
    // Test code...
}
```

### In-Memory Database

Use in-memory databases for fast tests:

```go
func setupInMemoryDB(t *testing.T) *sql.DB {
    db, err := sql.Open("sqlite3", ":memory:")
    require.NoError(t, err)
    
    // Schema is automatically cleaned up when connection closes
    t.Cleanup(func() {
        db.Close()
    })
    
    return db
}
```

---

## Test Data Versioning

### Versioned Fixtures

Maintain fixtures with version numbers:

```go
const (
    FixtureVersionV1 = "v1"
    FixtureVersionV2 = "v2"
)

// Load fixtures based on version
func LoadFixtures(version string) ([]*core.Event, error) {
    switch version {
    case FixtureVersionV1:
        return loadV1Fixtures()
    case FixtureVersionV2:
        return loadV2Fixtures()
    default:
        return nil, fmt.Errorf("unknown fixture version: %s", version)
    }
}
```

### Migration Tests

Test data migration:

```go
func TestDataMigration(t *testing.T) {
    // Load old format data
    oldData := loadOldFormatFixtures()
    
    // Migrate to new format
    newData, err := MigrateFixtures(oldData, FixtureVersionV1, FixtureVersionV2)
    require.NoError(t, err)
    
    // Verify migration
    assert.Equal(t, len(oldData), len(newData))
    for i := range oldData {
        assert.Equal(t, oldData[i].ID, newData[i].ID)
    }
}
```

---

## Best Practices

### Isolation

- **Each test should be independent:** Don't rely on test execution order
- **Clean up after each test:** Use `defer` and `t.Cleanup()`
- **Use unique IDs:** Prevent collisions between tests

### Performance

- **Use in-memory databases for unit tests:** Faster than file-based databases
- **Reuse testcontainers across tests:** Start once, use multiple times
- **Batch operations:** Insert multiple rows in single transaction

### Maintainability

- **Centralize fixtures:** Define in `fixtures.go`
- **Use factories:** Generate test objects programmatically
- **Document test data:** Explain what data represents

### Examples

```go
// ✅ Good: Isolated test with cleanup
func TestCreateAlert(t *testing.T) {
    db := setupInMemoryDB(t)
    defer db.Close()
    
    alert := NewTestAlert(t, core.Alert{
        RuleID:   "rule-1",
        Severity: "high",
    })
    
    err := CreateAlert(db, alert)
    require.NoError(t, err)
}

// ❌ Bad: Shared state between tests
var globalDB *sql.DB

func TestCreateAlert(t *testing.T) {
    if globalDB == nil {
        globalDB = setupDB() // Shared across tests!
    }
    // ...
}
```

---

**Last Updated:** 2025-11-20  
**Maintainer:** Cerberus Development Team

