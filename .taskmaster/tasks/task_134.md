# Task ID: 134

**Title:** Implement Type-Safe Context Keys

**Status:** done

**Dependencies:** None

**Priority:** high

**Description:** Replace built-in string type context keys with custom types to prevent context value collisions

**Details:**

**BLOCKING SECURITY ISSUE**

Affected files:
- `api/auth.go:242,243,275,276`
- `api/middleware_rbac.go:47,49,94-96`
- `api/security.go:103`
- Multiple test files

Implementation:
1. Create new file `api/context_keys.go` with type-safe context key definitions:
   ```go
   package api
   
   type contextKey string
   
   const (
       ContextKeyUsername    contextKey = "username"
       ContextKeyRoles       contextKey = "roles"
       ContextKeyRole        contextKey = "role"
       ContextKeyPermissions contextKey = "permissions"
   )
   ```

2. Update `api/auth.go` (lines 242-243, 275-276):
   ```go
   // Replace
   ctx := context.WithValue(r.Context(), "username", "anonymous")
   ctx = context.WithValue(ctx, "roles", []string{"admin"})
   
   // With
   ctx := context.WithValue(r.Context(), ContextKeyUsername, "anonymous")
   ctx = context.WithValue(ctx, ContextKeyRoles, []string{"admin"})
   ```

3. Update `api/middleware_rbac.go` (lines 47, 49, 94-96)
4. Update `api/security.go` (line 103)
5. Update all context value retrievals to use typed keys
6. Add helper functions for type-safe context value extraction:
   ```go
   func GetUsername(ctx context.Context) (string, bool) {
       username, ok := ctx.Value(ContextKeyUsername).(string)
       return username, ok
   }
   ```

Security Impact:
- Prevents context value collisions between packages
- Eliminates potential RBAC bypass via context pollution
- Type safety for context operations

**Test Strategy:**

1. Compile test: Ensure all context operations compile without errors
2. Unit test: Verify context values are correctly set and retrieved
3. Integration test: Test full auth flow with context propagation
4. Security test: Attempt to override context values with string keys (should fail)
5. Run all existing auth and RBAC tests
6. Verify no test failures from context key changes

## Subtasks

### 134.1. Create context_keys.go with type-safe definitions and helper functions

**Status:** done  
**Dependencies:** None  

Create a new file api/context_keys.go with custom contextKey type, constants for all context keys (username, roles, role, permissions), and type-safe helper functions for extracting values from context

**Details:**

1. Create api/context_keys.go file
2. Define private contextKey type as string
3. Define constants: ContextKeyUsername, ContextKeyRoles, ContextKeyRole, ContextKeyPermissions
4. Implement helper functions: GetUsername(ctx), GetRoles(ctx), GetRole(ctx), GetPermissions(ctx)
5. Each helper should return (value, bool) for safe type assertion
6. Add package documentation explaining the security rationale for typed context keys

### 134.2. Update api/auth.go to use type-safe context keys

**Status:** done  
**Dependencies:** 134.1  

Replace all string-based context operations in api/auth.go (lines 242-243, 275-276) with the new type-safe context keys and helper functions

**Details:**

1. Update lines 242-243: Replace context.WithValue(r.Context(), "username", ...) with context.WithValue(r.Context(), ContextKeyUsername, ...)
2. Update lines 275-276: Replace context.WithValue(ctx, "roles", ...) with context.WithValue(ctx, ContextKeyRoles, ...)
3. Update all context.Value() retrievals to use helper functions from context_keys.go
4. Search for any other hardcoded string context keys in auth.go and replace them
5. Ensure all context operations use the typed constants

### 134.3. Update api/middleware_rbac.go and api/security.go with typed context keys

**Status:** done  
**Dependencies:** 134.1  

Replace string-based context operations in middleware_rbac.go (lines 47, 49, 94-96) and security.go (line 103) with type-safe context keys

**Details:**

1. Update api/middleware_rbac.go line 47, 49: Replace string context keys with ContextKeyRole, ContextKeyPermissions
2. Update api/middleware_rbac.go lines 94-96: Use helper functions for context value retrieval
3. Update api/security.go line 103: Replace string context key with appropriate typed constant
4. Use helper functions for all context.Value() calls to ensure type safety
5. Verify RBAC logic remains functionally identical after refactoring

### 134.4. Update test files and add context collision security tests

**Status:** done  
**Dependencies:** 134.2, 134.3  

Update all test files that use context operations to use typed keys, and create comprehensive security tests to verify context collision prevention

**Details:**

1. Search for all test files using string-based context keys ("username", "roles", "role", "permissions")
2. Update each test to use ContextKey constants and helper functions
3. Create api/context_keys_test.go with security tests:
   - Test that string keys don't collide with typed keys
   - Test context pollution attempts fail gracefully
   - Test type assertion failures are handled correctly
4. Add integration test covering full auth flow with context propagation
5. Run full test suite to ensure no regressions in auth, RBAC, or security modules
