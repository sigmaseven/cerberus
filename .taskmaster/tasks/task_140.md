# Task ID: 140

**Title:** Standardize Error Wrapping with %w Format

**Status:** done

**Dependencies:** None

**Priority:** medium

**Description:** Convert error formatting from %v to %w to preserve error chains for errors.Is/As functionality

**Details:**

**CODE QUALITY - ERROR HANDLING**

Problem: Inconsistent error wrapping breaks error chain inspection.

Implementation:

1. **Search and identify %v error formatting:**
   ```bash
   grep -rn 'fmt.Errorf.*%v.*err' --include='*.go' .
   ```

2. **Replace with %w:**
   ```go
   // BEFORE - breaks error chain
   return fmt.Errorf("failed to parse rule: %v", err)
   
   // AFTER - preserves error chain
   return fmt.Errorf("failed to parse rule: %w", err)
   ```

3. **Audit pattern categories:**
   - Database errors: Critical for retry logic
   - Validation errors: Important for error type checking
   - Network errors: Used for circuit breaker decisions
   - Parse errors: Used in SIGMA/CQL engines

4. **Update error handling code to use errors.Is/As:**
   ```go
   // Enable this pattern
   if errors.Is(err, sql.ErrNoRows) {
       // Handle not found
   }
   
   var validationErr *ValidationError
   if errors.As(err, &validationErr) {
       // Handle validation error
   }
   ```

5. **Special cases to keep %v:**
   - When intentionally hiding error details from logs
   - When error is not being returned (log-only)
   - When combining multiple errors into summary

6. **Add linter rule:**
   - Configure staticcheck or golangci-lint to enforce %w
   - Add pre-commit hook to catch violations

**Test Strategy:**

1. Static analysis: `go vet` to find suspicious error formatting
2. Unit tests: Verify errors.Is works for wrapped errors
3. Test error chain:
   ```go
   err := someFunc() // returns wrapped error
   assert.True(t, errors.Is(err, ExpectedError))
   ```
4. Integration test: Verify circuit breaker recognizes network errors
5. Check log output: Ensure full error context is preserved
6. Regression test: Run full test suite to catch behavioral changes
7. Code review: Manual review of critical error paths

## Subtasks

### 140.1. Search and catalog all fmt.Errorf with %v error formatting

**Status:** done  
**Dependencies:** None  

Use grep to find all instances of fmt.Errorf using %v for error formatting across the codebase and create a comprehensive list for replacement

**Details:**

Run `grep -rn 'fmt.Errorf.*%v.*err' --include='*.go' .` to identify all instances. Document each occurrence with file path, line number, and context. Categorize by type: database errors, validation errors, network errors, and parse errors. This will provide a complete inventory before making changes.

### 140.2. Replace %v with %w in error formatting statements

**Status:** done  
**Dependencies:** 140.1  

Systematically replace fmt.Errorf %v format verbs with %w to preserve error chains, excluding special cases where %v is intentional

**Details:**

For each instance found in subtask 1, replace `fmt.Errorf("message: %v", err)` with `fmt.Errorf("message: %w", err)`. Preserve special cases: intentional error detail hiding, log-only errors not being returned, and multi-error summaries. Focus on critical areas: database errors (retry logic), validation errors (type checking), network errors (circuit breaker), and SIGMA/CQL parse errors.

### 140.3. Verify errors.Is and errors.As functionality with wrapped errors

**Status:** done  
**Dependencies:** 140.2  

Test that error chain inspection works correctly after %w conversions by verifying errors.Is and errors.As patterns

**Details:**

Write or update unit tests to verify error wrapping works correctly. Test patterns like `errors.Is(err, sql.ErrNoRows)` for database errors and `errors.As(err, &validationErr)` for typed errors. Focus on critical paths: circuit breaker decisions, retry logic, and validation error handling. Ensure error chains are preserved through multiple wrapping levels.

### 140.4. Run go vet and static analysis to detect error handling issues

**Status:** done  
**Dependencies:** 140.2  

Execute go vet and other static analysis tools to identify any remaining suspicious error formatting or error handling issues

**Details:**

Run `go vet ./...` to catch common error handling mistakes. Use additional static analysis if available (staticcheck, golangci-lint). Review any warnings related to error formatting, error wrapping, or error handling patterns. Fix any issues discovered that weren't caught in the grep search.

### 140.5. Configure linter rule to enforce %w error wrapping

**Status:** done  
**Dependencies:** 140.3, 140.4  

Add linter configuration and pre-commit hook to enforce %w usage and prevent future %v violations in error formatting

**Details:**

Configure staticcheck or golangci-lint with rules to enforce %w for error wrapping. Add the rule to .golangci.yml or equivalent config file. Create pre-commit hook to run linter and catch violations before commit. Update CONTRIBUTING.md or development documentation to explain the %w requirement and rationale for error chain preservation.
