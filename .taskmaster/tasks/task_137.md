# Task ID: 137

**Title:** Eliminate Panic Usage in Production Code

**Status:** done

**Dependencies:** None

**Priority:** high

**Description:** Replace all panic calls with proper error returns in production paths to prevent service crashes

**Details:**

**HIGH PRIORITY - PRODUCTION STABILITY**

Affected files (8 production files):
- `storage/migrations_sigma_yaml.go`
- `storage/migrations.go`
- `storage/sqlite.go`
- `core/alert.go`
- `core/circuitbreaker.go`

Implementation strategy:

1. **Migration files**: Replace panic with error returns
   ```go
   // BEFORE
   if err := runMigration(); err != nil {
       panic(fmt.Sprintf("migration failed: %v", err))
   }
   
   // AFTER
   if err := runMigration(); err != nil {
       return fmt.Errorf("migration failed: %w", err)
   }
   ```

2. **Alert/CircuitBreaker**: Add validation functions
   ```go
   // BEFORE
   func (a *Alert) Validate() {
       if a.Severity == "" {
           panic("severity required")
       }
   }
   
   // AFTER
   func (a *Alert) Validate() error {
       if a.Severity == "" {
           return fmt.Errorf("severity required")
       }
       return nil
   }
   ```

3. Review panic recovery middleware in `api/security.go` - ensure it logs and reports panics

4. Add startup validation to catch configuration errors early (where panic might be acceptable)

5. Document acceptable panic usage:
   - init() functions only
   - Impossible conditions with clear comments

Keep panic in:
- Test code (acceptable for test failures)
- Init functions (startup validation)

**Test Strategy:**

1. Search for remaining panics: `grep -r 'panic(' --include='*.go' --exclude='*_test.go'`
2. Test error paths: Trigger conditions that previously caused panics
3. Verify graceful error handling and logging
4. Test migration failures: Ensure service continues with degraded state
5. Load test: Verify no service crashes under error conditions
6. Check panic recovery middleware catches any remaining panics
7. Review logs for panic recovery events in staging

## Subtasks

### 137.1. Replace panic with error returns in migration files

**Status:** done  
**Dependencies:** None  

Refactor storage/migrations_sigma_yaml.go and storage/migrations.go to return errors instead of calling panic, ensuring all migration failures propagate as errors

**Details:**

Update all panic calls in migration files to return fmt.Errorf with error wrapping. Ensure migration functions have error return types. Update function signatures: if err := runMigration(); err != nil { return fmt.Errorf("migration failed: %w", err) }. Handle both migrations_sigma_yaml.go and migrations.go. Ensure storage/sqlite.go migration callers handle returned errors properly.

### 137.2. Refactor validation in core/alert.go and core/circuitbreaker.go to return errors

**Status:** done  
**Dependencies:** None  

Convert validation functions from panic-based to error-returning pattern in core components

**Details:**

Update Alert.Validate() and CircuitBreaker validation methods to return error instead of calling panic. Change signature from func (a *Alert) Validate() to func (a *Alert) Validate() error. Replace panic("severity required") with return fmt.Errorf("severity required"). Apply same pattern to all validation logic in both files. Ensure all validation errors are descriptive and wrapped appropriately.

### 137.3. Update all callers to handle new error returns

**Status:** done  
**Dependencies:** 137.1, 137.2  

Modify all functions that call the refactored validation and migration functions to properly handle the new error return values

**Details:**

Search codebase for all callers of modified functions using grep/IDE search. Update each caller to check and handle returned errors. Add error propagation up the call stack. For API handlers, convert errors to appropriate HTTP responses. For background workers, ensure errors are logged and metrics updated. Review storage/sqlite.go, API handlers, and initialization code paths. Ensure no error is silently ignored.

### 137.4. Review and enhance panic recovery middleware in api/security.go

**Status:** done  
**Dependencies:** 137.1, 137.2, 137.3  

Audit existing panic recovery middleware to ensure comprehensive logging, metrics, and error reporting for any remaining panics

**Details:**

Review panic recovery implementation in api/security.go. Ensure it logs full stack traces with structured logging. Add metrics for panic occurrences (panic_count counter). Include request context (method, path, user) in panic logs. Verify recovery sends 500 status with sanitized error message (no stack traces to client). Consider adding panic alerting integration. Document acceptable panic scenarios (init functions only).

### 137.5. Add comprehensive error path testing for previously-panic scenarios

**Status:** done  
**Dependencies:** 137.1, 137.2, 137.3, 137.4  

Create thorough test coverage for all error conditions that previously caused panics to ensure graceful degradation

**Details:**

Add test cases for: 1) Migration failures with corrupted schemas, 2) Invalid alert severity values, 3) CircuitBreaker misconfiguration, 4) Missing required fields in validation. Test concurrent error scenarios. Verify service degradation patterns (continue with reduced functionality vs fail fast). Add fuzzing tests for validation functions. Create integration tests simulating production error conditions. Document expected behavior for each error scenario.
