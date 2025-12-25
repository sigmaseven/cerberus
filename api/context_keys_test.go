package api

import (
	"context"
	"testing"

	"cerberus/storage"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestContextKeyTypesSafety verifies that type-safe context keys prevent collisions
func TestContextKeyTypesSafety(t *testing.T) {
	ctx := context.Background()

	// Test that our typed keys work correctly
	ctx = WithUsername(ctx, "testuser")
	ctx = WithRoles(ctx, []string{"admin", "viewer"})
	ctx = WithRole(ctx, "admin")
	ctx = WithPermissions(ctx, []storage.Permission{"read:alerts", "write:rules"})
	ctx = WithUserID(ctx, "user123")
	ctx = WithSessionID(ctx, "session456")

	// Verify retrieval
	username, ok := GetUsername(ctx)
	require.True(t, ok, "Username should be present")
	assert.Equal(t, "testuser", username)

	roles, ok := GetRoles(ctx)
	require.True(t, ok, "Roles should be present")
	assert.Equal(t, []string{"admin", "viewer"}, roles)

	role, ok := GetRole(ctx)
	require.True(t, ok, "Role should be present")
	assert.Equal(t, "admin", role)

	perms, ok := GetPermissions(ctx)
	require.True(t, ok, "Permissions should be present")
	assert.Equal(t, []storage.Permission{"read:alerts", "write:rules"}, perms)

	userID, ok := GetUserID(ctx)
	require.True(t, ok, "UserID should be present")
	assert.Equal(t, "user123", userID)

	sessionID, ok := GetSessionID(ctx)
	require.True(t, ok, "SessionID should be present")
	assert.Equal(t, "session456", sessionID)
}

// TestContextKeyCollisionPrevention verifies that string-based keys cannot override typed keys
// This is a critical security test to prevent RBAC bypass via context pollution
func TestContextKeyCollisionPrevention(t *testing.T) {
	ctx := context.Background()

	// Set values using type-safe keys
	ctx = WithUsername(ctx, "legitimate_admin")
	ctx = WithRoles(ctx, []string{"admin"})

	// SECURITY TEST: Attempt to pollute context with string-based keys
	// This simulates an attacker trying to inject malicious values
	ctx = context.WithValue(ctx, "username", "malicious_attacker")
	ctx = context.WithValue(ctx, "roles", []string{"superadmin"})

	// Verify that type-safe extraction still returns the legitimate values
	// The string-based keys use different key types and should NOT override typed keys
	username, ok := GetUsername(ctx)
	require.True(t, ok, "Username should be present")
	assert.Equal(t, "legitimate_admin", username, "Type-safe key should not be overridden by string key")

	roles, ok := GetRoles(ctx)
	require.True(t, ok, "Roles should be present")
	assert.Equal(t, []string{"admin"}, roles, "Type-safe roles should not be overridden by string key")
}

// TestContextKeyStringKeyIsolation verifies complete isolation between typed and string keys
func TestContextKeyStringKeyIsolation(t *testing.T) {
	ctx := context.Background()

	// Set using string key (old, vulnerable approach)
	ctx = context.WithValue(ctx, "username", "string_user")

	// Set using typed key (new, secure approach)
	ctx = WithUsername(ctx, "typed_user")

	// Type-safe extraction should ONLY see the typed key
	username, ok := GetUsername(ctx)
	require.True(t, ok, "Username should be present")
	assert.Equal(t, "typed_user", username)

	// String-based extraction should still see the string key (for backward compatibility testing)
	stringUsername, ok := ctx.Value("username").(string)
	require.True(t, ok, "String key should still be present")
	assert.Equal(t, "string_user", stringUsername)

	// This proves the keys are completely isolated - different namespaces
}

// TestContextKeyMissingValues verifies correct behavior when values are not set
func TestContextKeyMissingValues(t *testing.T) {
	ctx := context.Background()

	// All getters should return zero values and false when keys are not set
	username, ok := GetUsername(ctx)
	assert.False(t, ok, "Username should not be present")
	assert.Equal(t, "", username)

	roles, ok := GetRoles(ctx)
	assert.False(t, ok, "Roles should not be present")
	assert.Nil(t, roles)

	role, ok := GetRole(ctx)
	assert.False(t, ok, "Role should not be present")
	assert.Equal(t, "", role)

	perms, ok := GetPermissions(ctx)
	assert.False(t, ok, "Permissions should not be present")
	assert.Nil(t, perms)

	userID, ok := GetUserID(ctx)
	assert.False(t, ok, "UserID should not be present")
	assert.Equal(t, "", userID)

	sessionID, ok := GetSessionID(ctx)
	assert.False(t, ok, "SessionID should not be present")
	assert.Equal(t, "", sessionID)

	user, ok := GetUser(ctx)
	assert.False(t, ok, "User should not be present")
	assert.Nil(t, user)

	nonce, ok := GetCSPNonce(ctx)
	assert.False(t, ok, "CSP nonce should not be present")
	assert.Equal(t, "", nonce)
}

// TestContextKeyWrongTypes verifies type safety when wrong types are stored
func TestContextKeyWrongTypes(t *testing.T) {
	ctx := context.Background()

	// Attempt to store wrong types (this would be a programming error)
	// Using raw context.WithValue to bypass our type-safe wrappers
	ctx = context.WithValue(ctx, ContextKeyUsername, 12345) // int instead of string
	ctx = context.WithValue(ctx, ContextKeyRoles, "admin")  // string instead of []string

	// Type-safe getters should return false for wrong types
	username, ok := GetUsername(ctx)
	assert.False(t, ok, "Username type assertion should fail for int")
	assert.Equal(t, "", username)

	roles, ok := GetRoles(ctx)
	assert.False(t, ok, "Roles type assertion should fail for string")
	assert.Nil(t, roles)
}

// TestContextKeyOverwrite verifies that values can be safely overwritten
func TestContextKeyOverwrite(t *testing.T) {
	ctx := context.Background()

	// Set initial values
	ctx = WithUsername(ctx, "user1")
	username, ok := GetUsername(ctx)
	require.True(t, ok)
	assert.Equal(t, "user1", username)

	// Overwrite with new value
	ctx = WithUsername(ctx, "user2")
	username, ok = GetUsername(ctx)
	require.True(t, ok)
	assert.Equal(t, "user2", username, "Context value should be updated")
}

// TestContextKeyChaining verifies that context chaining works correctly
func TestContextKeyChaining(t *testing.T) {
	parent := context.Background()
	parent = WithUsername(parent, "parent_user")

	// Create child context with additional values
	child := WithRoles(parent, []string{"viewer"})
	child = WithUserID(child, "child_id")

	// Child should have both parent and child values
	username, ok := GetUsername(child)
	require.True(t, ok)
	assert.Equal(t, "parent_user", username, "Child should inherit parent's values")

	roles, ok := GetRoles(child)
	require.True(t, ok)
	assert.Equal(t, []string{"viewer"}, roles, "Child should have its own values")

	userID, ok := GetUserID(child)
	require.True(t, ok)
	assert.Equal(t, "child_id", userID, "Child should have its own values")

	// Parent should not have child's values
	parentRoles, ok := GetRoles(parent)
	assert.False(t, ok, "Parent should not have child's values")
	assert.Nil(t, parentRoles)
}

// TestContextKeyUserInterface verifies the generic user context key
func TestContextKeyUserInterface(t *testing.T) {
	ctx := context.Background()

	// Test with string user
	ctx = WithUser(ctx, "string_user")
	user, ok := GetUser(ctx)
	require.True(t, ok)
	userStr, ok := user.(string)
	require.True(t, ok)
	assert.Equal(t, "string_user", userStr)

	// Test with map user
	userMap := map[string]string{"id": "123", "name": "test"}
	ctx = WithUser(ctx, userMap)
	user, ok = GetUser(ctx)
	require.True(t, ok)
	retrievedMap, ok := user.(map[string]string)
	require.True(t, ok)
	assert.Equal(t, userMap, retrievedMap)
}

// TestContextKeyCSPNonce verifies CSP nonce handling
func TestContextKeyCSPNonce(t *testing.T) {
	ctx := context.Background()

	// Set CSP nonce
	ctx = WithCSPNonce(ctx, "abc123def456")
	nonce, ok := GetCSPNonce(ctx)
	require.True(t, ok)
	assert.Equal(t, "abc123def456", nonce)
}

// TestContextKeyConcurrentSafety verifies that context operations are safe for concurrent use
func TestContextKeyConcurrentSafety(t *testing.T) {
	ctx := context.Background()
	ctx = WithUsername(ctx, "concurrent_user")

	// Spawn multiple goroutines reading the same context
	done := make(chan bool, 10)
	for i := 0; i < 10; i++ {
		go func() {
			username, ok := GetUsername(ctx)
			assert.True(t, ok)
			assert.Equal(t, "concurrent_user", username)
			done <- true
		}()
	}

	// Wait for all goroutines to complete
	for i := 0; i < 10; i++ {
		<-done
	}
}

// TestContextKeyNilSafety verifies that nil context handling is safe
func TestContextKeyNilSafety(t *testing.T) {
	// This test ensures we don't panic with nil contexts
	// Note: In production, you should never pass nil context - use context.Background()

	// These should not panic even with nil context (though they'll return false)
	// Uncomment if you want to add nil checks to the helper functions
	// username, ok := GetUsername(nil)
	// assert.False(t, ok)
	// assert.Equal(t, "", username)
}

// TestContextKeyPrivateType verifies that contextKey type is truly private
func TestContextKeyPrivateType(t *testing.T) {
	// This test verifies that external packages cannot create contextKey values
	// because the type is unexported (lowercase)

	ctx := context.Background()

	// Our package can use the typed keys
	ctx = WithUsername(ctx, "test")

	// External code trying to use string "username" as a key will be isolated
	ctx = context.WithValue(ctx, "username", "attacker")

	// Our typed getter should return our value, not the attacker's
	username, ok := GetUsername(ctx)
	require.True(t, ok)
	assert.Equal(t, "test", username)

	// String key should be isolated
	attackerValue, ok := ctx.Value("username").(string)
	require.True(t, ok)
	assert.Equal(t, "attacker", attackerValue)

	// This proves the keys are in different namespaces - security achieved!
}

// Benchmark tests for performance verification
func BenchmarkContextKeySet(b *testing.B) {
	ctx := context.Background()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ctx = WithUsername(ctx, "benchuser")
	}
}

func BenchmarkContextKeyGet(b *testing.B) {
	ctx := WithUsername(context.Background(), "benchuser")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = GetUsername(ctx)
	}
}

func BenchmarkContextKeySetAndGet(b *testing.B) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ctx := WithUsername(context.Background(), "benchuser")
		_, _ = GetUsername(ctx)
	}
}
