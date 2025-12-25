# Error Handling Requirements & Standards

**Document Owner**: Engineering Standards Team
**Created**: 2025-11-16
**Status**: DRAFT - Pending Team Review
**Authoritative Sources**:
- "Error Handling in Go" by Rob Pike: https://go.dev/blog/errors-are-values
- "Go Proverbs" by Rob Pike: https://go-proverbs.github.io/
- Effective Go: https://go.dev/doc/effective_go#errors
- Go 1.13+ error wrapping: https://go.dev/blog/go1.13-errors

**Purpose**: Define error handling patterns and testing requirements for Cerberus

---

## 1. EXECUTIVE SUMMARY

This document defines how Cerberus MUST handle, wrap, and test errors. Go's error handling is explicit and central to reliability—errors are values that must be handled thoughtfully.

**Core Principles**:
1. **Errors are values**: Treat errors as first-class values, not exceptions
2. **Handle at the right level**: Don't blindly propagate or ignore errors
3. **Add context**: Wrap errors with useful context for debugging
4. **Make errors actionable**: Error messages should help fix the problem

---

## 2. ERROR HANDLING PATTERNS

### 2.1 Standard Error Wrapping Pattern

**Pattern**: Use `fmt.Errorf` with `%w` verb to wrap errors with context

**Correct Pattern**:
```go
func LoadRuleFromFile(path string) (*core.Rule, error) {
    data, err := os.ReadFile(path)
    if err != nil {
        return nil, fmt.Errorf("failed to read rule file %q: %w", path, err)
    }

    var rule core.Rule
    if err := yaml.Unmarshal(data, &rule); err != nil {
        return nil, fmt.Errorf("failed to parse rule file %q: %w", path, err)
    }

    if err := rule.Validate(); err != nil {
        return nil, fmt.Errorf("invalid rule in file %q: %w", path, err)
    }

    return &rule, nil
}
```

**Benefits**:
- Preserves error chain for `errors.Is()` and `errors.As()`
- Adds context (file path) for debugging
- Clear error messages at each level

**Test Requirements**:
```go
func TestLoadRuleFromFile_ErrorWrapping(t *testing.T) {
    // Test Case 1: File not found error is wrapped
    _, err := LoadRuleFromFile("/nonexistent/file.yaml")
    require.Error(t, err)

    // Verify error is wrapped (not replaced)
    assert.True(t, errors.Is(err, os.ErrNotExist),
        "Error should wrap os.ErrNotExist, not replace it")

    // Verify context is added
    assert.Contains(t, err.Error(), "/nonexistent/file.yaml",
        "Error message should include file path for debugging")

    // Test Case 2: Parse error is wrapped
    writeFile(t, "invalid.yaml", "invalid: yaml: content:")
    _, err = LoadRuleFromFile("invalid.yaml")
    require.Error(t, err)

    // Verify it's a parse error (can use errors.As() if custom error type)
    assert.Contains(t, err.Error(), "failed to parse",
        "Error message should indicate parsing failure")
}
```

---

### 2.2 Sentinel Errors for Expected Error Conditions

**Pattern**: Define sentinel errors for expected, recoverable error conditions

**When to Use**:
- Expected errors that callers should handle differently
- Errors that callers check with `errors.Is()`
- Errors that don't need stack traces (not bugs)

**Example**:
```go
package core

import "errors"

// Sentinel errors (exported for caller checking)
var (
    ErrRuleNotFound    = errors.New("rule not found")
    ErrRuleExists      = errors.New("rule already exists")
    ErrInvalidRuleID   = errors.New("invalid rule ID")
    ErrCircuitBreakerOpen = errors.New("circuit breaker is open")
)

// Usage
func (s *SQLiteStorage) GetRule(id string) (*core.Rule, error) {
    // Validate input
    if id == "" {
        return nil, ErrInvalidRuleID
    }

    var rule core.Rule
    err := s.DB.QueryRow("SELECT ... FROM rules WHERE id = ?", id).Scan(&rule)
    if err != nil {
        if errors.Is(err, sql.ErrNoRows) {
            return nil, ErrRuleNotFound // Wrap expected error as sentinel
        }
        return nil, fmt.Errorf("failed to query rule %q: %w", id, err)
    }

    return &rule, nil
}

// Caller can check for expected errors
rule, err := storage.GetRule("rule1")
if errors.Is(err, core.ErrRuleNotFound) {
    // Handle missing rule (expected, not fatal)
    return http.StatusNotFound
}
if err != nil {
    // Handle unexpected error (database issue, etc.)
    return http.StatusInternalServerError
}
```

**Test Requirements**:
```go
func TestGetRule_SentinelErrors(t *testing.T) {
    storage := setupStorage(t)

    // Test Case 1: Invalid ID returns ErrInvalidRuleID
    _, err := storage.GetRule("")
    assert.ErrorIs(t, err, core.ErrInvalidRuleID,
        "Empty ID should return ErrInvalidRuleID")

    // Test Case 2: Missing rule returns ErrRuleNotFound
    _, err = storage.GetRule("nonexistent")
    assert.ErrorIs(t, err, core.ErrRuleNotFound,
        "Missing rule should return ErrRuleNotFound")

    // Test Case 3: Valid rule returns no error
    storage.CreateRule(&core.Rule{ID: "rule1", Name: "Test"})
    rule, err := storage.GetRule("rule1")
    assert.NoError(t, err)
    assert.Equal(t, "Test", rule.Name)
}
```

**Current Implementation Status**:
- File: `core/circuitbreaker.go` line 22-26
- Status: ✅ CORRECT - Defines sentinel errors
- Gap: Not all packages define sentinel errors consistently

---

### 2.3 Custom Error Types for Rich Error Information

**Pattern**: Define custom error types when errors need additional data

**When to Use**:
- Error needs to carry additional context (not just string message)
- Caller needs to extract error details programmatically
- Error represents validation failure with multiple fields

**Example**:
```go
package core

// ValidationError carries validation failure details
type ValidationError struct {
    Field   string // Field that failed validation
    Value   interface{} // Invalid value
    Rule    string // Validation rule that failed
    Message string // Human-readable message
}

func (e *ValidationError) Error() string {
    return fmt.Sprintf("validation failed for field %q: %s (value: %v, rule: %s)",
        e.Field, e.Message, e.Value, e.Rule)
}

// Usage
func (r *Rule) Validate() error {
    if r.ID == "" {
        return &ValidationError{
            Field:   "ID",
            Value:   r.ID,
            Rule:    "required",
            Message: "rule ID cannot be empty",
        }
    }

    if len(r.ID) > 64 {
        return &ValidationError{
            Field:   "ID",
            Value:   r.ID,
            Rule:    "max_length=64",
            Message: fmt.Sprintf("rule ID too long (%d > 64 characters)", len(r.ID)),
        }
    }

    return nil
}

// Caller can extract validation details
if err := rule.Validate(); err != nil {
    var valErr *ValidationError
    if errors.As(err, &valErr) {
        // Return structured error to API client
        return &APIError{
            Status: 400,
            Field:  valErr.Field,
            Message: valErr.Message,
        }
    }
    // Handle other errors
}
```

**Test Requirements**:
```go
func TestRule_Validate_CustomErrorType(t *testing.T) {
    // Test Case 1: Empty ID returns ValidationError
    rule := &core.Rule{ID: "", Name: "Test"}
    err := rule.Validate()

    require.Error(t, err)

    var valErr *core.ValidationError
    require.True(t, errors.As(err, &valErr),
        "Validation error should be *ValidationError type")

    assert.Equal(t, "ID", valErr.Field)
    assert.Equal(t, "required", valErr.Rule)
    assert.Contains(t, valErr.Message, "cannot be empty")

    // Test Case 2: Too-long ID returns ValidationError with details
    rule = &core.Rule{ID: strings.Repeat("a", 65), Name: "Test"}
    err = rule.Validate()

    require.Error(t, err)
    require.True(t, errors.As(err, &valErr))
    assert.Equal(t, "ID", valErr.Field)
    assert.Equal(t, "max_length=64", valErr.Rule)
}
```

**Current Implementation Status**:
- Location: Search for `type.*Error.*struct` in codebase
- Status: ⚠️ LIMITED - Few custom error types found
- Gap: Validation errors not consistently structured

---

### 2.4 Error Handling at Boundaries

**Pattern**: Convert internal errors to appropriate forms at system boundaries

**Boundaries in Cerberus**:
1. **API Boundary**: HTTP handlers
2. **Storage Boundary**: Database operations
3. **External Service Boundary**: Webhooks, APIs

**API Boundary Example**:
```go
func (a *API) getRule(w http.ResponseWriter, r *http.Request) {
    ruleID := mux.Vars(r)["id"]

    rule, err := a.ruleStorage.GetRule(ruleID)
    if err != nil {
        // Convert internal errors to HTTP responses
        if errors.Is(err, core.ErrRuleNotFound) {
            a.writeError(w, http.StatusNotFound, "Rule not found")
            return
        }
        if errors.Is(err, core.ErrInvalidRuleID) {
            a.writeError(w, http.StatusBadRequest, "Invalid rule ID")
            return
        }

        // Unexpected error - log details, return generic message
        a.logger.Errorw("Failed to get rule",
            "rule_id", ruleID,
            "error", err,
        )
        a.writeError(w, http.StatusInternalServerError, "Internal server error")
        return
    }

    a.writeJSON(w, http.StatusOK, rule)
}
```

**Security Consideration**: Never leak internal error details to clients
```go
// WRONG: Leaks database schema
a.writeError(w, 500, err.Error()) // "failed to query rules table: column 'xyz' does not exist"

// CORRECT: Generic message to client, detailed log for operators
a.logger.Error("Database error", "error", err)
a.writeError(w, 500, "Internal server error")
```

**Test Requirements**:
```go
func TestAPI_ErrorHandling_NoDatabaseDetailsLeaked(t *testing.T) {
    // Simulate database error
    mockStorage := &MockRuleStorage{
        GetRuleFunc: func(id string) (*core.Rule, error) {
            return nil, errors.New("SQL error: column 'secret_column' does not exist")
        },
    }

    api := setupAPIWithStorage(mockStorage)
    resp := makeRequest(api, "GET", "/api/v1/rules/rule1")

    // Verify: Client sees generic error
    assert.Equal(t, 500, resp.StatusCode)
    body := readBody(resp)
    assert.NotContains(t, body, "SQL")
    assert.NotContains(t, body, "column")
    assert.NotContains(t, body, "secret_column")
    assert.Contains(t, body, "Internal server error")
}
```

---

### 2.5 Panic vs. Error

**Rule**: Use `panic` ONLY for programming errors detected at startup. Use errors for all runtime errors.

**When to Panic** (rare):
- Invalid configuration at startup (prevents server from starting)
- Nil pointer that indicates programmer error (not user error)
- Contract violations that should never happen in production

**Example (Panic Appropriate)**:
```go
func NewCircuitBreaker(config CircuitBreakerConfig) *CircuitBreaker {
    if err := config.Validate(); err != nil {
        // Panic is OK: This is a programming error (invalid config in code)
        // Should be caught in development, not production
        panic(fmt.Sprintf("invalid circuit breaker config: %v", err))
    }
    // ...
}
```

**Example (Error Appropriate)**:
```go
func (s *Storage) GetEvent(id string) (*Event, error) {
    if id == "" {
        // Error, not panic: This is a runtime error (bad user input)
        return nil, ErrInvalidEventID
    }
    // ...
}
```

**Test Requirements**:
```go
func TestNewCircuitBreaker_PanicsOnInvalidConfig(t *testing.T) {
    invalidConfig := CircuitBreakerConfig{
        MaxFailures: 0, // Invalid: must be > 0
    }

    assert.Panics(t, func() {
        NewCircuitBreaker(invalidConfig)
    }, "NewCircuitBreaker should panic on invalid config")
}

func TestGetEvent_ReturnsErrorOnInvalidID(t *testing.T) {
    storage := setupStorage(t)

    // Should return error, NOT panic
    event, err := storage.GetEvent("")
    assert.Error(t, err)
    assert.Nil(t, event)
    assert.ErrorIs(t, err, ErrInvalidEventID)
}
```

**Current Implementation Status**:
- Circuit Breaker: ✅ CORRECT - Panics on invalid config (line 77)
- Other components: ⚠️ AUDIT NEEDED - Check for inappropriate panics

---

## 3. ERROR MESSAGE QUALITY

### 3.1 Error Message Checklist

**EVERY error message MUST answer these questions**:
1. **What happened?** (operation that failed)
2. **Why did it fail?** (underlying cause)
3. **What context?** (IDs, file paths, values involved)
4. **How to fix?** (if possible)

**Bad Error Messages**:
```go
return errors.New("invalid") // What is invalid?
return errors.New("error") // What error?
return fmt.Errorf("failed") // What failed?
return err // No context added
```

**Good Error Messages**:
```go
return fmt.Errorf("invalid rule ID %q: must be 1-64 alphanumeric characters", ruleID)
return fmt.Errorf("failed to parse YAML rule file %q: %w", path, err)
return fmt.Errorf("rule %q references non-existent action %q", ruleID, actionID)
```

**Test Requirements**:
```go
func TestErrorMessages_QualityChecklist(t *testing.T) {
    storage := setupStorage(t)

    // Test: Error message includes context
    _, err := storage.GetRule("nonexistent-rule-id-12345")
    require.Error(t, err)

    errMsg := err.Error()

    // Check: What happened?
    assert.Contains(t, errMsg, "rule", "Error should indicate it's about a rule")

    // Check: What context?
    assert.Contains(t, errMsg, "nonexistent-rule-id-12345",
        "Error should include the specific rule ID")

    // Check: Why did it fail?
    assert.Contains(t, errMsg, "not found",
        "Error should indicate the rule doesn't exist")
}
```

---

### 3.2 Error Message Consistency

**Pattern**: Use consistent verbs and structure

**Standard Verbs**:
- `failed to {verb}`: Operation attempted but failed
- `invalid {noun}`: Input validation failure
- `{noun} not found`: Resource doesn't exist
- `{noun} already exists`: Conflict with existing resource
- `cannot {verb}`: Operation not possible in current state

**Examples**:
```go
fmt.Errorf("failed to connect to database: %w", err)
fmt.Errorf("invalid email address %q", email)
fmt.Errorf("rule %q not found", ruleID)
fmt.Errorf("rule %q already exists", ruleID)
fmt.Errorf("cannot delete rule %q: rule is enabled", ruleID)
```

---

### 3.3 Error Message Security

**Rule**: NEVER include sensitive data in error messages

**Sensitive Data Includes**:
- Passwords (even hashed)
- API keys / tokens
- JWT tokens
- PII (email addresses, IP addresses in some contexts)
- Internal file paths (in production)

**Example**:
```go
// WRONG: Leaks password in error message
return fmt.Errorf("failed to authenticate user %s with password %s", user, password)

// CORRECT: No sensitive data
return fmt.Errorf("failed to authenticate user %q: invalid credentials", user)
```

**Test Requirements**:
```go
func TestErrorMessages_NoSensitiveData(t *testing.T) {
    auth := setupAuth(t)

    // Attempt login with password
    err := auth.Login("user@example.com", "SecretPassword123!")
    require.Error(t, err)

    errMsg := err.Error()

    // Verify: Password not in error message
    assert.NotContains(t, errMsg, "SecretPassword123!",
        "Error message MUST NOT contain password")

    // Verify: Generic message
    assert.Contains(t, errMsg, "invalid credentials")
}
```

---

## 4. ERROR TESTING REQUIREMENTS

### 4.1 Test Error Paths, Not Just Happy Paths

**Problem**: Most tests only test success cases

**Solution**: For every function, test:
1. Success case (happy path)
2. All expected error cases
3. Unexpected error cases (if applicable)

**Example**:
```go
func TestCreateRule_AllErrorPaths(t *testing.T) {
    storage := setupStorage(t)

    t.Run("Success", func(t *testing.T) {
        rule := &core.Rule{ID: "rule1", Name: "Test"}
        err := storage.CreateRule(rule)
        assert.NoError(t, err)
    })

    t.Run("EmptyID", func(t *testing.T) {
        rule := &core.Rule{ID: "", Name: "Test"}
        err := storage.CreateRule(rule)
        assert.ErrorIs(t, err, core.ErrInvalidRuleID)
    })

    t.Run("DuplicateID", func(t *testing.T) {
        rule1 := &core.Rule{ID: "rule1", Name: "Original"}
        storage.CreateRule(rule1)

        rule2 := &core.Rule{ID: "rule1", Name: "Duplicate"}
        err := storage.CreateRule(rule2)
        assert.ErrorIs(t, err, core.ErrRuleExists)
    })

    t.Run("DatabaseError", func(t *testing.T) {
        // Close database to simulate error
        storage.Close()

        rule := &core.Rule{ID: "rule2", Name: "Test"}
        err := storage.CreateRule(rule)
        assert.Error(t, err)
        assert.NotErrorIs(t, err, core.ErrInvalidRuleID) // Different error
    })
}
```

---

### 4.2 Verify Error Wrapping with errors.Is()

**Pattern**: Use `errors.Is()` to verify errors are wrapped correctly

**Test Requirements**:
```go
func TestErrorWrapping_PreservesErrorChain(t *testing.T) {
    storage := setupStorage(t)

    // Create scenario where os.ErrNotExist occurs
    _, err := storage.LoadRuleFromFile("/nonexistent/file.yaml")
    require.Error(t, err)

    // Verify: Original error preserved in chain
    assert.True(t, errors.Is(err, os.ErrNotExist),
        "Error chain should include os.ErrNotExist")

    // Verify: Context added
    assert.Contains(t, err.Error(), "/nonexistent/file.yaml")
}
```

---

### 4.3 Verify Custom Error Types with errors.As()

**Pattern**: Use `errors.As()` to verify custom error types and extract details

**Test Requirements**:
```go
func TestValidation_CustomErrorType(t *testing.T) {
    rule := &core.Rule{ID: strings.Repeat("a", 100)} // Too long
    err := rule.Validate()
    require.Error(t, err)

    // Verify: Error is ValidationError type
    var valErr *core.ValidationError
    require.True(t, errors.As(err, &valErr),
        "Validation error should be *core.ValidationError")

    // Verify: Error details are correct
    assert.Equal(t, "ID", valErr.Field)
    assert.Equal(t, "max_length=64", valErr.Rule)
}
```

---

## 5. ERROR HANDLING ANTI-PATTERNS

### 5.1 Anti-Pattern: Ignoring Errors

**WRONG**:
```go
data, _ := os.ReadFile(path) // Ignores error
config, _ := parseConfig(data) // Ignores error
```

**CORRECT**:
```go
data, err := os.ReadFile(path)
if err != nil {
    return fmt.Errorf("failed to read config file: %w", err)
}

config, err := parseConfig(data)
if err != nil {
    return fmt.Errorf("failed to parse config: %w", err)
}
```

**Test Requirement**: Code review to find `_` error ignores

---

### 5.2 Anti-Pattern: Blind Error Propagation

**WRONG**:
```go
func GetRule(id string) (*Rule, error) {
    return db.QueryRule(id) // Just returns error as-is
}
```

**CORRECT**:
```go
func GetRule(id string) (*Rule, error) {
    rule, err := db.QueryRule(id)
    if err != nil {
        return nil, fmt.Errorf("failed to get rule %q: %w", id, err)
    }
    return rule, nil
}
```

---

### 5.3 Anti-Pattern: Error String Comparison

**WRONG**:
```go
if err.Error() == "rule not found" { // Fragile
    // ...
}
```

**CORRECT**:
```go
if errors.Is(err, core.ErrRuleNotFound) { // Robust
    // ...
}
```

**Test Requirement**:
```go
func TestErrorChecking_UseErrorsIs(t *testing.T) {
    _, err := storage.GetRule("nonexistent")

    // Verify: errors.Is works (proves error is wrapped correctly)
    assert.True(t, errors.Is(err, core.ErrRuleNotFound))

    // Anti-pattern check: String comparison SHOULD work but is fragile
    // (This is a negative test - showing what NOT to do)
    // assert.Contains(t, err.Error(), "not found") // Don't do this in production
}
```

---

### 5.4 Anti-Pattern: Creating Errors Without Context

**WRONG**:
```go
return errors.New("validation failed")
```

**CORRECT**:
```go
return fmt.Errorf("validation failed for rule %q: field %q is required", ruleID, fieldName)
```

---

## 6. LOGGING VS. RETURNING ERRORS

### 6.1 When to Log vs. Return

**Rule**: Return errors up the stack, log at the boundary

**Pattern**:
```go
// Low-level function: Return error (don't log)
func (s *Storage) GetRule(id string) (*Rule, error) {
    rule, err := s.db.QueryRule(id)
    if err != nil {
        return nil, fmt.Errorf("failed to query rule: %w", err)
        // NO LOGGING HERE
    }
    return rule, nil
}

// High-level function (API handler): Log and return
func (a *API) handleGetRule(w http.ResponseWriter, r *http.Request) {
    rule, err := a.storage.GetRule(id)
    if err != nil {
        // LOG HERE (at the boundary)
        a.logger.Errorw("Failed to get rule",
            "rule_id", id,
            "error", err,
        )
        a.writeError(w, 500, "Internal error")
        return
    }
    // ...
}
```

**Why**: Avoids duplicate log entries, logs only once at the right level

---

### 6.2 Structured Logging for Errors

**Pattern**: Use structured logging with error context

**Example**:
```go
logger.Errorw("Failed to create rule",
    "rule_id", rule.ID,
    "rule_name", rule.Name,
    "error", err,
    "user", userID,
)
```

**Test Requirement**:
```go
func TestLogging_ErrorContext(t *testing.T) {
    // Capture log output
    logBuffer := captureLogOutput(t)

    // Trigger error
    api.handleCreateRule(request)

    logs := logBuffer.String()

    // Verify: Error logged with context
    assert.Contains(t, logs, "Failed to create rule")
    assert.Contains(t, logs, "rule_id")
    assert.Contains(t, logs, "error")
}
```

---

## 7. COMPLIANCE VERIFICATION CHECKLIST

### 7.1 Error Wrapping Compliance
- [ ] All errors wrapped with `fmt.Errorf` and `%w`
- [ ] No errors replaced (losing original error)
- [ ] Context added at each level
- [ ] tests use `errors.Is()` to verify wrapping

### 7.2 Sentinel Error Compliance
- [ ] Sentinel errors defined for expected conditions
- [ ] Sentinel errors exported and documented
- [ ] Tests use `errors.Is()` to check sentinel errors
- [ ] Callers check sentinel errors before generic errors

### 7.3 Custom Error Type Compliance
- [ ] Custom error types implement `Error()` method
- [ ] Custom error types carry useful context
- [ ] Tests use `errors.As()` to verify custom types
- [ ] Custom errors used consistently across packages

### 7.4 Error Message Quality
- [ ] All error messages answer: What? Why? Context?
- [ ] Consistent verb usage (failed to, invalid, not found)
- [ ] No sensitive data in error messages
- [ ] Error messages tested for quality

### 7.5 Error Testing Compliance
- [ ] All functions test error paths, not just success
- [ ] Error wrapping verified with errors.Is()
- [ ] Custom error types verified with errors.As()
- [ ] Edge cases tested (nil, empty, invalid input)

### 7.6 Panic vs. Error Compliance
- [ ] Panics only for programming errors at startup
- [ ] Runtime errors return errors (not panic)
- [ ] Tests verify panics for invalid config
- [ ] Tests verify errors for invalid input

---

## 8. TBD TRACKER

| Item | Question | Owner | Deadline | Status |
|------|----------|-------|----------|--------|
| TBD-ERR-001 | Define standard ValidationError type | Engineering Team | Week 1 | OPEN |
| TBD-ERR-002 | Audit all error messages for quality | Engineering Team | Week 2 | OPEN |
| TBD-ERR-003 | Review all panic() calls for appropriateness | Engineering Team | Week 1 | OPEN |
| TBD-ERR-004 | Standardize error logging format | Observability Team | Week 2 | OPEN |

---

## 9. REFERENCES

### 9.1 Go Error Handling Resources
1. **Effective Go - Errors**: https://go.dev/doc/effective_go#errors
2. **Error handling and Go**: https://go.dev/blog/error-handling-and-go
3. **Working with Errors in Go 1.13**: https://go.dev/blog/go1.13-errors
4. **Errors are values**: https://go.dev/blog/errors-are-values

### 9.2 Best Practices
1. **Uber Go Style Guide - Errors**: https://github.com/uber-go/guide/blob/master/style.md#errors
2. **Dave Cheney - Don't just check errors, handle them gracefully**: https://dave.cheney.net/2016/04/27/dont-just-check-errors-handle-them-gracefully

---

**Document Status**: DRAFT
**Next Review Date**: Week 1 (error handling audit)
**Approver**: Engineering Lead + Architect
**Version**: 1.0-DRAFT
