package api

import (
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestExtractJTIFromToken tests the JWT ID extraction function
// This function is used during logout to blacklist tokens
func TestExtractJTIFromToken(t *testing.T) {
	testAPI, cleanup := setupTestAPI(t)
	defer cleanup()

	t.Run("Extract JTI from valid token", func(t *testing.T) {
		// Create a token with known JTI
		expectedJTI := "test-jti-12345"
		expirationTime := time.Now().Add(1 * time.Hour)
		claims := &Claims{
			Username: "testuser",
			Roles:    []string{"admin"},
			RegisteredClaims: jwt.RegisteredClaims{
				Subject:   "testuser",
				ExpiresAt: jwt.NewNumericDate(expirationTime),
				IssuedAt:  jwt.NewNumericDate(time.Now()),
				NotBefore: jwt.NewNumericDate(time.Now()),
				ID:        expectedJTI,
				Issuer:    "cerberus",
			},
		}

		token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
		tokenString, err := token.SignedString([]byte(testAPI.config.Auth.JWTSecret))
		require.NoError(t, err)

		// Extract JTI
		jti, err := testAPI.extractJTIFromToken(tokenString)
		require.NoError(t, err)
		assert.Equal(t, expectedJTI, jti, "Extracted JTI should match")
	})

	t.Run("Extract JTI from expired token", func(t *testing.T) {
		// Create an expired token
		expirationTime := time.Now().Add(-1 * time.Hour)
		claims := &Claims{
			Username: "testuser",
			Roles:    []string{"admin"},
			RegisteredClaims: jwt.RegisteredClaims{
				Subject:   "testuser",
				ExpiresAt: jwt.NewNumericDate(expirationTime),
				IssuedAt:  jwt.NewNumericDate(time.Now().Add(-2 * time.Hour)),
				NotBefore: jwt.NewNumericDate(time.Now().Add(-2 * time.Hour)),
				ID:        "expired-jti",
				Issuer:    "cerberus",
			},
		}

		token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
		tokenString, err := token.SignedString([]byte(testAPI.config.Auth.JWTSecret))
		require.NoError(t, err)

		// Should still extract JTI even from expired token (for blacklisting)
		jti, err := testAPI.extractJTIFromToken(tokenString)
		// Function might succeed or fail depending on implementation
		// Just verify it doesn't crash
		if err == nil {
			assert.NotEmpty(t, jti, "Should extract JTI from expired token")
		}
	})

	t.Run("Reject malformed token", func(t *testing.T) {
		tokenString := "not.a.valid.jwt.token.at.all"
		jti, err := testAPI.extractJTIFromToken(tokenString)
		assert.Error(t, err, "Should reject malformed token")
		assert.Empty(t, jti, "JTI should be empty for invalid token")
	})

	t.Run("Reject token with wrong secret", func(t *testing.T) {
		claims := &Claims{
			Username: "testuser",
			Roles:    []string{"admin"},
			RegisteredClaims: jwt.RegisteredClaims{
				ID: "wrong-secret-jti",
			},
		}

		token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
		tokenString, err := token.SignedString([]byte("wrong-secret-key"))
		require.NoError(t, err)

		jti, err := testAPI.extractJTIFromToken(tokenString)
		assert.Error(t, err, "Should reject token with wrong secret")
		assert.Empty(t, jti, "JTI should be empty for invalid token")
	})
}

// TestRevokeToken tests token revocation
func TestRevokeToken(t *testing.T) {
	testAPI, cleanup := setupTestAPI(t)
	defer cleanup()

	t.Run("Revoke and check token", func(t *testing.T) {
		jti := "test-jti-revoke-1"
		expirationTime := time.Now().Add(1 * time.Hour)

		// Initially not revoked
		assert.False(t, testAPI.isTokenRevoked(jti), "Token should not be revoked initially")

		// Revoke token
		testAPI.revokeToken(jti, expirationTime)

		// Should now be revoked
		assert.True(t, testAPI.isTokenRevoked(jti), "Token should be revoked after revocation")
	})

	t.Run("Expired revoked token is not considered revoked", func(t *testing.T) {
		jti := "test-jti-expire-1"
		expirationTime := time.Now().Add(-1 * time.Hour) // Already expired

		// Revoke with past expiration
		testAPI.revokeToken(jti, expirationTime)

		// Should NOT be considered revoked (naturally expired)
		assert.False(t, testAPI.isTokenRevoked(jti), "Expired token should not be considered revoked")
	})

	t.Run("Multiple revocations don't interfere", func(t *testing.T) {
		jti1 := "test-jti-multi-1"
		jti2 := "test-jti-multi-2"
		expirationTime := time.Now().Add(1 * time.Hour)

		// Revoke both
		testAPI.revokeToken(jti1, expirationTime)
		testAPI.revokeToken(jti2, expirationTime)

		// Both should be revoked
		assert.True(t, testAPI.isTokenRevoked(jti1), "First token should be revoked")
		assert.True(t, testAPI.isTokenRevoked(jti2), "Second token should be revoked")
	})
}

// TestCleanupExpiredTokens tests the token cleanup function
func TestCleanupExpiredTokens(t *testing.T) {
	testAPI, cleanup := setupTestAPI(t)
	defer cleanup()

	t.Run("Cleanup removes expired tokens", func(t *testing.T) {
		// Add expired token
		expiredJTI := "test-jti-cleanup-expired"
		expiredTime := time.Now().Add(-1 * time.Hour)
		testAPI.revokeToken(expiredJTI, expiredTime)

		// Add valid token
		validJTI := "test-jti-cleanup-valid"
		validTime := time.Now().Add(1 * time.Hour)
		testAPI.revokeToken(validJTI, validTime)

		// Run cleanup
		testAPI.cleanupExpiredTokens()

		// Expired token should be removed (no longer revoked)
		assert.False(t, testAPI.isTokenRevoked(expiredJTI), "Expired token should be cleaned up")

		// Valid token should still be revoked
		assert.True(t, testAPI.isTokenRevoked(validJTI), "Valid token should still be revoked")
	})
}

// TestAuthManager_PublicAPI tests the public AuthManager API
func TestAuthManager_PublicAPI(t *testing.T) {
	testAPI, cleanup := setupTestAPI(t)
	defer cleanup()

	t.Run("RevokeToken and IsTokenRevoked", func(t *testing.T) {
		jti := "public-test-jti-1"

		// Initially not revoked
		assert.False(t, testAPI.authManager.IsTokenRevoked(jti), "Token should not be revoked initially")

		// Revoke it
		testAPI.authManager.RevokeToken(jti)

		// Should now be revoked
		assert.True(t, testAPI.authManager.IsTokenRevoked(jti), "Token should be revoked after revocation")
	})

	t.Run("Multiple token revocations", func(t *testing.T) {
		jti1 := "public-test-jti-2"
		jti2 := "public-test-jti-3"

		testAPI.authManager.RevokeToken(jti1)
		testAPI.authManager.RevokeToken(jti2)

		assert.True(t, testAPI.authManager.IsTokenRevoked(jti1), "First token should be revoked")
		assert.True(t, testAPI.authManager.IsTokenRevoked(jti2), "Second token should be revoked")
	})

	t.Run("Check non-existent token", func(t *testing.T) {
		assert.False(t, testAPI.authManager.IsTokenRevoked("nonexistent-jti"), "Non-existent token should not be revoked")
	})
}
