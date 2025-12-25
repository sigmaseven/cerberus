# Service Layer Testing Documentation

## Overview

The service layer sits between HTTP handlers and storage, implementing all business logic. This document describes the testing philosophy, requirements, and best practices for service layer tests.

## Testing Philosophy

### Separation of Concerns

**Service Layer** = Business Logic + Data Transformation + Validation
- Test with **unit tests** using mocked storage
- Focus on business rules, edge cases, error handling
- Target: **90%+ code coverage**

**Handler Layer** = HTTP Contract (Status Codes, JSON Schema)
- Test with **contract tests** using mocked services
- Focus on HTTP status codes, response structure, request parsing
- See: `api/handler_contract_test.go`

**Integration Tests** = Full Stack (End-to-End Flows)
- Test with **real storage** (SQLite for API tests)
- Focus on component integration, auth workflows
- See: `api/*_integration_test.go`

### What to Test in Service Layer

✅ **DO Test:**
- Business logic (validation rules, data transformations)
- Error handling paths (storage errors, validation failures)
- Edge cases (nil inputs, empty data, boundary conditions)
- Defensive copying (mutation prevention)
- Context cancellation handling
- Atomicity guarantees (rollback on partial failures)

❌ **DON'T Test:**
- HTTP status codes → Handler layer
- JSON parsing → Handler layer
- Authentication/authorization → Middleware/integration tests
- Database implementation details → Storage layer tests
- Query performance → Performance tests

## Running Tests

### Run All Service Tests
```bash
go test -v ./service/...
```

### Run with Coverage
```bash
go test -coverprofile=coverage.out ./service/...
go tool cover -html=coverage.out
```

### Run Specific Test File
```bash
go test -v ./service -run TestAlertService
go test -v ./service -run TestRuleService
```

### Check Coverage by Function
```bash
go test -coverprofile=coverage.out ./service/...
go tool cover -func=coverage.out
```

## Coverage Requirements

- **Minimum Coverage**: 90%
- **Current Coverage**: 90.6% (as of Task 145.5)
- **Measurement**: `go test -cover ./service/...`

### Coverage by Service

| Service | Coverage | Key Files |
|---------|----------|-----------|
| Alert Service | 89.2% | `alert_service.go`, `alert_service_test.go` |
| Playbook Service | 90.3% | `playbook_service.go`, `playbook_service_test.go` |
| Event Service | 88.4% | `event_service.go`, `event_service_test.go` |
| Rule Service | 88.4% | `rule_service.go`, `rule_service_test.go` |

## Test Structure

### Standard Test Pattern

```go
func TestServiceMethod_Scenario(t *testing.T) {
    // 1. Setup mocks
    mockStorage := &mockStorageType{
        methodFunc: func(args) (return, values) {
            // Mock implementation
            return expectedValues
        },
    }

    // 2. Create service with mocks
    service := NewServiceType(mockStorage, logger)

    // 3. Execute method under test
    result, err := service.MethodUnderTest(ctx, args)

    // 4. Assert results
    if err != nil {
        t.Errorf("Unexpected error: %v", err)
    }
    if result != expected {
        t.Errorf("Expected %v, got %v", expected, result)
    }

    // 5. Verify mock interactions (if needed)
    if len(mockStorage.methodCalls) != 1 {
        t.Errorf("Expected 1 call to method, got %d", len(mockStorage.methodCalls))
    }
}
```

### Table-Driven Tests

```go
func TestServiceMethod_MultipleScenarios(t *testing.T) {
    tests := []struct {
        name        string
        input       InputType
        mockReturn  ReturnType
        mockError   error
        expectError bool
        errorMsg    string
    }{
        {
            name:       "successful operation",
            input:      validInput,
            mockReturn: validReturn,
            mockError:  nil,
            expectError: false,
        },
        {
            name:        "storage error",
            input:       validInput,
            mockReturn:  nil,
            mockError:   errors.New("database error"),
            expectError: true,
            errorMsg:    "failed to",
        },
        // ... more test cases
    }

    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            // Test implementation
        })
    }
}
```

## Mock Patterns

### Simple Mock Storage

```go
type mockAlertStorage struct {
    getAlertFunc func(id string) (*core.Alert, error)
    getAlertCalls []string // Track calls for verification
}

func (m *mockAlertStorage) GetAlert(ctx context.Context, id string) (*core.Alert, error) {
    m.getAlertCalls = append(m.getAlertCalls, id)
    if m.getAlertFunc != nil {
        return m.getAlertFunc(id)
    }
    return nil, errors.New("not implemented")
}
```

### Using testify/mock (Advanced)

```go
import "github.com/stretchr/testify/mock"

type MockAlertStorage struct {
    mock.Mock
}

func (m *MockAlertStorage) GetAlert(ctx context.Context, id string) (*core.Alert, error) {
    args := m.Called(ctx, id)
    if args.Get(0) == nil {
        return nil, args.Error(1)
    }
    return args.Get(0).(*core.Alert), args.Error(1)
}

// In test:
mockStorage.On("GetAlert", mock.Anything, "alert-1").Return(alert, nil)
```

## Common Testing Patterns

### Testing Error Paths

```go
t.Run("storage error handling", func(t *testing.T) {
    mockStorage := &mockStorage{
        getFunc: func(id string) (*core.Entity, error) {
            return nil, errors.New("database connection failed")
        },
    }

    service := NewService(mockStorage, logger)
    _, err := service.GetByID(ctx, "id-1")

    if err == nil {
        t.Error("Expected error, got nil")
    }
    if !strings.Contains(err.Error(), "failed to") {
        t.Errorf("Expected error to contain 'failed to', got: %s", err.Error())
    }
})
```

### Testing Context Cancellation

```go
t.Run("context cancellation", func(t *testing.T) {
    ctx, cancel := context.WithCancel(context.Background())
    cancel() // Cancel immediately

    service := NewService(mockStorage, logger)
    _, err := service.MethodRequiringContext(ctx, args)

    if err == nil {
        t.Error("Expected context cancellation error")
    }
    if !strings.Contains(err.Error(), "context cancel") {
        t.Errorf("Expected context cancellation error, got: %s", err.Error())
    }
})
```

### Testing Defensive Copying

```go
t.Run("mutation prevention", func(t *testing.T) {
    original := createTestEntity()
    original.Tags = []string{"tag1", "tag2"}

    service := NewService(mockStorage, logger)
    returned, _ := service.GetByID(ctx, original.ID)

    // Mutate returned entity
    returned.Tags[0] = "modified"

    // Verify original is unchanged
    if original.Tags[0] != "tag1" {
        t.Error("Service did not return defensive copy")
    }
})
```

### Testing Atomicity (Rollback on Failure)

```go
t.Run("rollback on partial failure", func(t *testing.T) {
    mockStorage := &mockStorage{
        updateFunc: func(id string, entity *core.Entity) error {
            return nil // Success
        },
        reloadFunc: func() error {
            return errors.New("reload failed") // Failure
        },
    }

    service := NewService(mockStorage, logger)
    err := service.UpdateEntity(ctx, "id-1", updatedEntity)

    // Should rollback update due to reload failure
    if err == nil {
        t.Error("Expected error due to reload failure")
    }

    // Verify rollback was attempted
    if len(mockStorage.updateCalls) < 2 {
        t.Error("Expected rollback update call")
    }
})
```

## Test File Organization

Each service has a corresponding test file:

```
service/
├── alert_service.go          # Alert business logic
├── alert_service_test.go     # Alert service tests
├── playbook_service.go       # Playbook business logic
├── playbook_service_test.go  # Playbook service tests
├── rule_service.go           # Rule business logic
├── rule_service_test.go      # Rule service tests
├── event_service.go          # Event business logic
├── event_service_test.go     # Event service tests
├── helpers.go                # Shared helpers (deepCopyValue, etc.)
├── helpers_test.go           # Helper function tests
└── README.md                 # This file
```

### Test File Structure

```go
package service

import (
    "context"
    "errors"
    "testing"
    // ... imports
)

// ============================================================================
// Mock Implementations
// ============================================================================

type mockStorageType struct {
    // Mock function fields
    // Call tracking fields
}

func (m *mockStorageType) Method(...) (...) {
    // Mock implementation
}

// ============================================================================
// Constructor Tests
// ============================================================================

func TestNewService(t *testing.T) {
    // Test service creation
}

// ============================================================================
// Method Tests - Happy Path
// ============================================================================

func TestService_MethodName(t *testing.T) {
    // Test successful execution
}

// ============================================================================
// Method Tests - Error Cases
// ============================================================================

func TestService_MethodName_ErrorCases(t *testing.T) {
    // Test error handling
}

// ============================================================================
// Helper Function Tests
// ============================================================================

func TestHelperFunction(t *testing.T) {
    // Test internal helpers
}
```

## Code Coverage Tips

### Finding Low Coverage Functions

```bash
go test -coverprofile=coverage.out ./service/...
go tool cover -func=coverage.out | grep -v "100.0%"
```

### Improving Coverage

1. **Identify uncovered branches** using coverage HTML report
2. **Add table-driven tests** for multiple scenarios
3. **Test error paths** (storage errors, validation failures)
4. **Test edge cases** (nil inputs, empty slices, boundary values)
5. **Test helper functions** that may be overlooked

### Common Uncovered Code

- **Error paths**: Storage errors, validation failures
- **Defensive checks**: nil pointer checks, empty slice checks
- **Edge cases**: Empty strings, zero values, max values
- **Rollback logic**: Atomicity guarantees
- **Context cancellation**: Early termination paths

## Best Practices

### 1. Use Descriptive Test Names

✅ Good:
```go
func TestAlertService_GetAlertByID_ReturnsAlertWhenExists(t *testing.T)
func TestAlertService_GetAlertByID_ReturnsErrorWhenNotFound(t *testing.T)
```

❌ Bad:
```go
func TestGetAlert(t *testing.T)
func TestGetAlert2(t *testing.T)
```

### 2. Test One Thing Per Test

✅ Good:
```go
func TestRuleService_CreateRule_ValidatesRequiredName(t *testing.T) {
    // Only test name validation
}

func TestRuleService_CreateRule_ValidatesRuleType(t *testing.T) {
    // Only test type validation
}
```

❌ Bad:
```go
func TestRuleService_CreateRule(t *testing.T) {
    // Tests name, type, detection, and storage all at once
}
```

### 3. Use Table-Driven Tests for Similar Cases

✅ Good:
```go
tests := []struct {
    name     string
    severity string
    expected core.Priority
}{
    {"critical maps to critical", "critical", core.PriorityCritical},
    {"high maps to high", "high", core.PriorityHigh},
    {"unknown defaults to medium", "unknown", core.PriorityMedium},
}
```

### 4. Mock Only What You Need

✅ Good:
```go
mockStorage := &mockAlertStorage{
    getAlertFunc: func(id string) (*core.Alert, error) {
        return testAlert, nil
    },
}
```

❌ Bad:
```go
mockStorage := &fullMockStorage{
    // Implements all 50 storage methods when test only needs 1
}
```

### 5. Verify Mock Interactions When Relevant

```go
// Verify method was called with expected arguments
if len(mockStorage.createCalls) != 1 {
    t.Errorf("Expected 1 create call, got %d", len(mockStorage.createCalls))
}

// Verify atomicity (rollback was attempted)
if len(mockStorage.updateCalls) != 2 {
    t.Error("Expected rollback update after failure")
}
```

## Common Pitfalls

### ❌ Testing HTTP Details in Service Tests

```go
// WRONG - This belongs in handler tests
func TestService_ReturnsHTTP404(t *testing.T) {
    // Services don't know about HTTP status codes
}
```

### ❌ Testing Storage Implementation

```go
// WRONG - This belongs in storage tests
func TestService_SQLQueryCorrect(t *testing.T) {
    // Service layer shouldn't know about SQL
}
```

### ❌ Not Testing Error Paths

```go
// INCOMPLETE - Only tests happy path
func TestService_Method(t *testing.T) {
    result, _ := service.Method(validInput)
    // What if storage returns an error?
}
```

### ❌ Ignoring Context Cancellation

```go
// INCOMPLETE - Doesn't test context cancellation
func TestService_Method(t *testing.T) {
    ctx := context.Background()
    // Should test cancelled context
}
```

## Related Documentation

- **Handler Testing**: `api/handler_contract_test.go`
- **Integration Testing**: `api/*_integration_test.go`
- **Storage Testing**: `storage/*_test.go`
- **Test Utilities**: `api/test_helpers.go`

## Continuous Improvement

### Adding New Service Methods

When adding a new service method:

1. ✅ Write tests FIRST (TDD approach recommended)
2. ✅ Test happy path AND error paths
3. ✅ Test edge cases (nil, empty, boundary values)
4. ✅ Verify 90%+ coverage for the new method
5. ✅ Run full test suite to ensure no regressions

### Maintaining Coverage

- Run coverage checks in CI/CD pipeline
- Set minimum coverage threshold (90%)
- Review coverage reports for gaps
- Add tests for uncovered branches

## Questions?

For questions about service layer testing:
- See examples in existing test files
- Check `api/handler_contract_test.go` for handler vs service separation
- Review Go testing best practices: https://go.dev/doc/tutorial/add-a-test

---

**Last Updated**: Task 145.5 - Service layer achieved 90.6% coverage
