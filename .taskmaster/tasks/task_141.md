# Task ID: 141

**Title:** Refactor Large Functions for Testability

**Status:** done

**Dependencies:** None

**Priority:** medium

**Description:** Break down complex functions exceeding 100 lines into smaller, testable units

**Details:**

**CODE QUALITY - MAINTAINABILITY**

Target functions (high cyclomatic complexity):

1. **`api/auth_handlers.go:login()` - 400+ lines**
   - Extract validation to `validateLoginRequest()`
   - Extract auth check to `authenticateUser()`
   - Extract MFA to `handleMFAFlow()`
   - Extract token generation to `generateAuthToken()`
   - Extract response to `sendLoginResponse()`

2. **`storage/sqlite.go:createTables()` - Large schema**
   - Use table-driven schema definitions
   - Separate table creation from index creation
   - Extract migration helpers

3. **Various handler functions**
   - Extract validation logic
   - Extract business logic
   - Keep handlers thin (HTTP concern only)

Refactoring pattern:
```go
// BEFORE
func (a *API) login(w http.ResponseWriter, r *http.Request) {
    // 400 lines of validation, auth, MFA, tokens, etc.
}

// AFTER
func (a *API) login(w http.ResponseWriter, r *http.Request) {
    creds, err := a.parseLoginRequest(r)
    if err != nil {
        writeError(w, http.StatusBadRequest, "Invalid request", err, a.logger)
        return
    }
    
    user, err := a.authenticateUser(r.Context(), creds)
    if err != nil {
        a.handleAuthFailure(w, r, creds.Username, err)
        return
    }
    
    if user.MFAEnabled {
        err = a.handleMFAChallenge(w, r, user, creds)
        if err != nil {
            writeError(w, http.StatusUnauthorized, "MFA failed", err, a.logger)
            return
        }
    }
    
    token, err := a.generateAuthToken(user)
    if err != nil {
        writeError(w, http.StatusInternalServerError, "Token generation failed", err, a.logger)
        return
    }
    
    a.sendLoginResponse(w, user, token)
}

// Each helper is 20-50 lines, easily testable
```

Principles:
- Single Responsibility Principle
- Each function <50 lines ideally
- Clear function names describing purpose
- Testable in isolation

**Test Strategy:**

1. Before refactoring: Ensure existing tests pass
2. Extract function: Create unit test for extracted logic
3. Refactor: Replace inline code with function call
4. Verify: Original tests still pass
5. Add: New tests for extracted functions
6. Coverage: Aim for 80%+ coverage on refactored code
7. Integration: Verify E2E tests pass
8. Benchmark: Ensure no performance regression
9. Use table-driven tests for validation functions:
   ```go
   tests := []struct{
       name string
       input LoginRequest
       wantErr bool
   }{
       {"valid", validReq, false},
       {"empty username", emptyUser, true},
   }
   ```

## Subtasks

### 141.1. Analyze api/auth_handlers.go login() and plan refactoring strategy

**Status:** done  
**Dependencies:** None  

Audit the current login() function implementation, measure actual line count, identify logical boundaries for extraction, and create detailed refactoring plan with function signatures

**Details:**

1. Read api/auth_handlers.go and locate login() function
2. Count actual lines and measure cyclomatic complexity
3. Identify distinct responsibilities: request parsing/validation, user authentication, MFA handling, token generation, response formatting
4. Design function signatures for extracted helpers: parseLoginRequest(), authenticateUser(), handleMFAChallenge(), generateAuthToken(), sendLoginResponse()
5. Document data flow between extracted functions
6. Identify shared dependencies (logger, storage, config)
7. Plan error handling strategy to maintain existing behavior
8. Create refactoring checklist with security considerations

### 141.2. Extract and test login request parsing and validation logic

**Status:** done  
**Dependencies:** 141.1  

Extract parseLoginRequest() and validateLoginRequest() functions from login() with comprehensive unit tests for all validation scenarios

**Details:**

1. Create parseLoginRequest(r *http.Request) (*LoginCredentials, error) function
2. Move JSON decoding and initial validation logic
3. Create validateLoginRequest(creds *LoginCredentials) error function
4. Move username/password validation rules
5. Ensure proper error messages for each validation failure
6. Write unit tests covering:
   - Valid credentials
   - Missing username/password
   - Invalid JSON format
   - Malformed input (XSS attempts, SQL injection patterns)
   - Boundary cases (empty strings, excessive length)
7. Verify extracted functions are pure/stateless where possible

### 141.3. Extract and test user authentication and MFA flow logic

**Status:** done  
**Dependencies:** 141.2  

Extract authenticateUser() and handleMFAChallenge() functions with isolated unit tests and security-focused test cases

**Details:**

1. Create authenticateUser(ctx context.Context, creds *LoginCredentials) (*core.User, error)
2. Move password verification, account lockout checks, user retrieval logic
3. Create handleMFAChallenge(w http.ResponseWriter, r *http.Request, user *core.User, creds *LoginCredentials) error
4. Move MFA token validation, TOTP verification logic
5. Preserve rate limiting and brute force protection
6. Ensure audit logging for failed attempts is maintained
7. Write unit tests with mocked storage layer:
   - Successful authentication
   - Invalid password
   - Account locked
   - MFA success/failure
   - TOTP window edge cases
8. Security tests: timing attacks, enumeration prevention

### 141.4. Extract and test token generation and response formatting

**Status:** done  
**Dependencies:** 141.3  

Extract generateAuthToken() and sendLoginResponse() functions with JWT validation and response formatting tests

**Details:**

1. Create generateAuthToken(user *core.User) (string, error) function
2. Move JWT creation, signing, claims population logic
3. Ensure token expiration, refresh token logic preserved
4. Create sendLoginResponse(w http.ResponseWriter, user *core.User, token string)
5. Move response JSON marshaling, header setting, cookie creation
6. Preserve CSRF token generation if present
7. Write unit tests:
   - Valid token generation with correct claims
   - Token expiration validation
   - Refresh token flow
   - Response structure validation
   - Cookie attributes (HttpOnly, Secure, SameSite)
8. Integration test: full login flow with extracted functions

### 141.5. Refactor storage/sqlite.go createTables() using table-driven schema

**Status:** done  
**Dependencies:** None  

Restructure createTables() into modular, table-driven schema definitions with separate index creation and migration helpers

**Details:**

1. Create TableDefinition struct: {Name string, Schema string, Indexes []string}
2. Define tableDefinitions []TableDefinition with all table schemas
3. Create createTable(tx *sql.Tx, def TableDefinition) error helper
4. Create createIndexes(tx *sql.Tx, tableName string, indexes []string) error helper
5. Refactor createTables() to iterate over tableDefinitions
6. Separate foreign key creation into createForeignKeys() helper
7. Extract migration logic to applyMigrations() helper
8. Reduce createTables() to <50 lines orchestration code
9. Add comments documenting table purposes
10. Write unit tests for each helper function using in-memory SQLite

### 141.6. Identify and refactor remaining large handler functions

**Status:** done  
**Dependencies:** 141.4, 141.5  

Audit all api/*_handlers.go files for functions >100 lines, apply same refactoring pattern, create comprehensive test suite, and benchmark performance

**Details:**

1. Run cyclomatic complexity analysis on api/ directory (gocyclo or similar)
2. Identify functions >100 lines or complexity >15
3. Prioritize by: security impact, test coverage gaps, modification frequency
4. Apply refactoring pattern from login() to 3-5 additional handlers
5. Candidate functions: rule creation, alert handling, event ingestion handlers
6. Extract validation, business logic, response formatting for each
7. Create unit tests for all extracted functions (80%+ coverage target)
8. Run integration tests to verify no regression
9. Benchmark critical paths (auth, event ingestion) before/after
10. Document refactoring in code review summary
