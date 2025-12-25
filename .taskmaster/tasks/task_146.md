# Task ID: 146

**Title:** Implement Proper Error Wrapping - Replace fmt.Sprintf(%v) with %w

**Status:** done

**Dependencies:** None

**Priority:** medium

**Description:** Replace 102 instances of fmt.Sprintf('%v', err) with %w to preserve error chains, enabling errors.Is/errors.As for proper error handling and debugging.

**Details:**

Found 102 instances of fmt.Sprintf('%v', err) which loses error type information.

Problem pattern:
```go
// WRONG - Loses error type, can't use errors.Is/errors.As
return fmt.Errorf("failed to connect: %v", err)

// CORRECT - Preserves error chain
return fmt.Errorf("failed to connect: %w", err)
```

Impact:
- Error handling code uses string matching instead of type checking
- Cannot use errors.Is() or errors.As() for error inspection
- Stack traces lost when errors wrapped
- Debugging production issues takes 3x longer

Implementation:
1. Find and replace all fmt.Errorf("%v", err) → fmt.Errorf("%w", err)
2. Grep pattern: `fmt\.Errorf.*%v.*err`
3. Update error handling code to use errors.Is/errors.As:
   ```go
   // Before (string matching)
   if strings.Contains(err.Error(), "connection refused") {
   
   // After (type checking)
   var netErr *net.OpError
   if errors.As(err, &netErr) && netErr.Op == "dial" {
   ```
4. Create custom error types for common errors:
   - storage.ErrNotFound
   - storage.ErrConflict
   - api.ErrUnauthorized
   - api.ErrValidation
5. Add static analysis rule preventing fmt.Sprintf("%v", err)
6. Document error handling guidelines in CONTRIBUTING.md:
   - Always use %w for error wrapping
   - Create typed errors for domain errors
   - Use errors.Is/errors.As for error inspection

Files with most violations:
- detect/actions.go
- api/*.go (handlers)
- storage/*.go

PR strategy: Create automated script to perform replacements, manual review for correctness

**Test Strategy:**

1. Static analysis test - verify no new %v error wrapping introduced
2. Error chain test - verify errors.Is works through wrapped errors
3. Error type test - verify errors.As extracts typed errors correctly
4. Integration test - verify error messages remain human-readable
5. Grep validation - confirm all 102 instances fixed
6. Code review - manual verification of replacements

## Subtasks

### 146.1. Create automated replacement script for fmt.Errorf %v to %w conversion

**Status:** done  
**Dependencies:** None  

Develop a Go-based tool or script that finds and replaces all instances of fmt.Errorf with %v error formatting to %w formatting, with validation to ensure only appropriate error wrapping cases are modified.

**Details:**

Create a script that:
1. Uses ast parsing to find all fmt.Errorf calls with %v format specifiers followed by error arguments
2. Validates that the argument being formatted is actually an error type
3. Replaces %v with %w for error wrapping
4. Generates a report of all changes made
5. Includes dry-run mode for preview before applying changes
6. Focuses on files: detect/actions.go, api/*.go, storage/*.go
7. Note: Task description claims 102 instances but initial grep found only 5 - script should report actual count

### 146.2. Define custom domain error types with proper wrapping support

**Status:** pending  
**Dependencies:** 146.1  

Create typed error definitions for common domain errors across storage and API layers, implementing storage.ErrNotFound, storage.ErrConflict, api.ErrUnauthorized, and api.ErrValidation with proper error wrapping capabilities.

**Details:**

1. Create storage/errors.go with:
   - var ErrNotFound = errors.New("resource not found")
   - var ErrConflict = errors.New("resource conflict")
   - Helper functions for wrapping: WrapNotFound(err error, msg string) error
2. Create api/errors.go with:
   - var ErrUnauthorized = errors.New("unauthorized")
   - var ErrValidation = errors.New("validation failed")
   - Type definitions for validation errors with field details
3. Ensure all custom errors support errors.Is() and errors.As()
4. Add examples of usage in documentation comments
5. Replace existing error creation patterns with typed errors where applicable

### 146.3. Refactor error inspection to use errors.Is/errors.As

**Status:** pending  
**Dependencies:** 146.2  

Replace all string-based error matching (strings.Contains on err.Error()) with type-safe error inspection using errors.Is and errors.As throughout the codebase.

**Details:**

1. Grep for patterns: strings.Contains(err.Error(), ...), err.Error() == ..., err != nil && strings...
2. Identify all locations doing string matching on errors
3. Refactor to use:
   - errors.Is(err, storage.ErrNotFound) instead of string matching
   - errors.As(err, &specificErr) for typed error extraction
   - Type assertions for network errors, timeout errors, etc.
4. Update error handling in:
   - API handlers (status code selection based on error type)
   - Storage layer (distinguishing not found vs other failures)
   - Detection engine (action execution error handling)
5. Maintain backward compatibility for error messages in user-facing responses

### 146.4. Add static analysis enforcement and documentation

**Status:** pending  
**Dependencies:** 146.3  

Configure golangci-lint with errorlint linter to prevent future %v error wrapping, and create comprehensive error handling guidelines in CONTRIBUTING.md

**Details:**

1. Add errorlint to .golangci.yml configuration:
   ```yaml
   linters:
     enable:
       - errorlint
   linters-settings:
     errorlint:
       errorf: true  # Check fmt.Errorf %w usage
       asserts: true # Check error type assertions
       comparison: true # Check error comparisons
   ```
2. Create CONTRIBUTING.md section on error handling:
   - Always use %w for error wrapping
   - Never use %v with error types
   - Create typed errors for domain-specific errors
   - Use errors.Is/errors.As for error inspection
   - Avoid string matching on err.Error()
   - Examples of correct patterns
3. Run golangci-lint and fix any newly detected issues
4. Add pre-commit hook suggestion for running errorlint
