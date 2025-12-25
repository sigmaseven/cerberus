package api

import (
	"cerberus/config"
	"cerberus/core"
	"cerberus/storage"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// Claims represents JWT claims
type Claims struct {
	Username string   `json:"username"`
	Roles    []string `json:"roles,omitempty"`
	jwt.RegisteredClaims
}

// generateJWT generates a JWT token for the given username with roles from user storage
func generateJWT(ctx context.Context, username string, config *config.Config, userStorage storage.UserStorage, authManager *AuthManager) (string, error) {
	expirationTime := time.Now().Add(config.Auth.JWTExpiry)

	// Generate a unique JTI (JWT ID) for token revocation
	jti, err := generateJTI()
	if err != nil {
		return "", err
	}

	// Get user role from storage - fallback to analyst role if user not found
	// TASK 31.5: Include user's role in JWT claims
	var roles []string
	if userStorage != nil {
		// Use context with timeout to prevent indefinite blocking on database operations
		ctx, cancel := context.WithTimeout(ctx, core.DBHealthTimeout)
		defer cancel()

		user, role, err := userStorage.GetUserWithRole(ctx, username)
		if err == nil && user != nil {
			// TASK 31.5: Use role name from GetUserWithRole instead of deprecated Roles field
			if role != nil {
				roles = []string{role.Name}
			} else if len(user.Roles) > 0 {
				// Fallback to deprecated Roles field for backward compatibility
				roles = user.Roles
			} else {
				// Fallback to default role
				roles = []string{"analyst"}
			}
		} else {
			// Fallback to default role for backward compatibility
			roles = []string{"analyst"}
		}
	} else {
		// Fallback for backward compatibility when userStorage is not available
		roles = []string{"analyst"}
	}

	claims := &Claims{
		Username: username,
		Roles:    roles,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expirationTime),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			NotBefore: jwt.NewNumericDate(time.Now()),
			Issuer:    "cerberus",
			Subject:   username,
			ID:        jti,
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString([]byte(config.Auth.JWTSecret))
	if err != nil {
		return "", err
	}

	// Track the token for the user (for session management)
	if authManager != nil {
		authManager.trackUserToken(username, jti, expirationTime)
	}

	return tokenString, nil
}

// validateJWT validates a JWT token and returns the claims
// checkRevocation parameter controls whether to check token revocation (requires API instance)
func validateJWT(tokenString string, config *config.Config, checkRevocation bool, apiInstance *API) (*Claims, error) {
	claims := &Claims{}

	token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
		// Validate signing method
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.New("unexpected signing method")
		}
		return []byte(config.Auth.JWTSecret), nil
	})

	if err != nil {
		return nil, err
	}

	if !token.Valid {
		return nil, errors.New("invalid token")
	}

	// Explicitly check token expiration
	if claims.ExpiresAt != nil && claims.ExpiresAt.Before(time.Now()) {
		return nil, errors.New("token has expired")
	}

	// Check if token is not yet valid (not before time)
	if claims.NotBefore != nil && claims.NotBefore.After(time.Now()) {
		return nil, errors.New("token not yet valid")
	}

	// Check if token has been revoked (only if requested and API instance provided)
	if checkRevocation && apiInstance != nil && claims.ID != "" && apiInstance.isTokenRevoked(claims.ID) {
		return nil, errors.New("token has been revoked")
	}

	return claims, nil
}

// validateJWT validates a JWT token and returns the claims (for testing without API instance)
func validateJWTStandalone(tokenString string, config *config.Config) (*Claims, error) {
	return validateJWT(tokenString, config, false, nil)
}

// validateJWT validates a JWT token and returns the claims with revocation checking
func (a *API) validateJWT(tokenString string, config *config.Config) (*Claims, error) {
	return validateJWT(tokenString, config, true, a)
}

// generateJTI generates a unique JWT ID for token revocation with 256-bit entropy
func generateJTI() (string, error) {
	bytes := make([]byte, 32) // 256 bits
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}

// revokeToken adds a token JTI to the blacklist until its natural expiration
func (a *API) revokeToken(jti string, expirationTime time.Time) {
	a.authManager.tokenBlacklist.Store(jti, expirationTime)
}

// isTokenRevoked checks if a token JTI has been revoked
func (a *API) isTokenRevoked(jti string) bool {
	value, exists := a.authManager.tokenBlacklist.Load(jti)
	if !exists {
		return false
	}

	// Check if the stored expiration time has passed
	expirationTime, ok := value.(time.Time)
	if !ok {
		// If we can't parse the expiration time, consider it revoked for safety
		return true
	}

	// SECURITY FIX: Token is revoked if it's in the blacklist AND hasn't expired yet
	// If current time is after expiration, the token is naturally expired (not "revoked")
	// Return true (revoked) if we're still before the expiration time
	return time.Now().Before(expirationTime)
}

// cleanupExpiredTokens removes expired tokens from the blacklist
func (a *API) cleanupExpiredTokens() {
	now := time.Now()
	var expiredJTIs []string

	// First pass: collect expired JTIs
	a.authManager.tokenBlacklist.Range(func(key, value interface{}) bool {
		jti, okKey := key.(string)
		expiration, okVal := value.(time.Time)
		if !okKey || !okVal {
			a.logger.Errorf("Invalid tokenBlacklist entry: key type %T, value type %T", key, value)
			return true
		}
		if now.After(expiration) {
			expiredJTIs = append(expiredJTIs, jti)
		}
		return true
	})

	// Second pass: delete expired JTIs
	cleanedCount := len(expiredJTIs)
	for _, jti := range expiredJTIs {
		a.authManager.tokenBlacklist.Delete(jti)
	}

	// Log cleanup activity if any tokens were cleaned
	if cleanedCount > 0 {
		a.logger.Infow("Cleaned up expired tokens from blacklist",
			"count", cleanedCount)
	}
}

// revokeAllUserTokens revokes all active tokens for a specific user
// This should be called when a user's password is changed or when suspicious activity is detected
func (a *API) revokeAllUserTokens(username string) error {
	revokedCount := a.authManager.revokeAllUserTokens(username)

	if revokedCount > 0 {
		a.logger.Infow("Revoked all active tokens for user due to security event",
			"username", username, "tokens_revoked", revokedCount)
	}

	return nil
}

// cleanupTokenBlacklist runs the token blacklist cleanup in a loop
func (a *API) cleanupTokenBlacklist() {
	ticker := time.NewTicker(core.JWTCleanupInterval) // FIX #103: Use constant for better memory management
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			a.cleanupExpiredTokens()
		case <-a.stopCh: // Allow graceful shutdown
			return
		}
	}
}

// generateCSRFToken generates a random CSRF token
func generateCSRFToken() (string, error) {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}
