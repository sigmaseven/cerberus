package api

import (
	"cerberus/config"
	"context"
	"sync"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"go.uber.org/zap"
)

func TestGenerateJWT_Success(t *testing.T) {
	cfg := &config.Config{
		Auth: struct {
			Enabled          bool   `mapstructure:"enabled"`
			Username         string `mapstructure:"username"`
			Password         string `mapstructure:"password"`
			HashedPassword   string
			BcryptCost       int           `mapstructure:"bcrypt_cost"`
			JWTSecret        string        `mapstructure:"jwt_secret"`
			JWTExpiry        time.Duration `mapstructure:"jwt_expiry"`
			LockoutThreshold int           `mapstructure:"lockout_threshold"`
			LockoutDuration  time.Duration `mapstructure:"lockout_duration"`
		}{
			JWTSecret: "test-secret-key-for-jwt-generation",
			JWTExpiry: time.Hour,
		},
	}

	// Create a minimal API instance for testing
	logger := zap.NewNop().Sugar()
	api := &API{
		config: cfg,
		authManager: &AuthManager{
			tokenBlacklist: sync.Map{},
		},
		logger: logger,
	}

	username := "testuser"
	token, err := generateJWT(context.Background(), username, cfg, nil, api.authManager)

	assert.NoError(t, err)
	assert.NotEmpty(t, token)

	// Validate the token to ensure it's properly formed
	claims, err := api.validateJWT(token, cfg)
	assert.NoError(t, err)
	assert.Equal(t, username, claims.Username)
	assert.Equal(t, username, claims.Subject)
	assert.Equal(t, "cerberus", claims.Issuer)
	assert.NotEmpty(t, claims.ID) // JTI should be present
}

func TestValidateJWT_Success(t *testing.T) {
	cfg := &config.Config{
		Auth: struct {
			Enabled          bool   `mapstructure:"enabled"`
			Username         string `mapstructure:"username"`
			Password         string `mapstructure:"password"`
			HashedPassword   string
			BcryptCost       int           `mapstructure:"bcrypt_cost"`
			JWTSecret        string        `mapstructure:"jwt_secret"`
			JWTExpiry        time.Duration `mapstructure:"jwt_expiry"`
			LockoutThreshold int           `mapstructure:"lockout_threshold"`
			LockoutDuration  time.Duration `mapstructure:"lockout_duration"`
		}{
			JWTSecret: "test-secret-key-for-validation",
			JWTExpiry: time.Hour,
		},
	}

	// Create a minimal API instance for testing
	logger := zap.NewNop().Sugar()
	api := &API{
		config: cfg,
		authManager: &AuthManager{
			tokenBlacklist: sync.Map{},
		},
		logger: logger,
	}

	username := "validuser"
	token, err := generateJWT(context.Background(), username, cfg, nil, api.authManager)
	assert.NoError(t, err)

	claims, err := api.validateJWT(token, cfg)

	assert.NoError(t, err)
	assert.NotNil(t, claims)
	assert.Equal(t, username, claims.Username)
	assert.True(t, claims.ExpiresAt.After(time.Now()))
}

func TestValidateJWT_InvalidToken(t *testing.T) {
	cfg := &config.Config{
		Auth: struct {
			Enabled          bool   `mapstructure:"enabled"`
			Username         string `mapstructure:"username"`
			Password         string `mapstructure:"password"`
			HashedPassword   string
			BcryptCost       int           `mapstructure:"bcrypt_cost"`
			JWTSecret        string        `mapstructure:"jwt_secret"`
			JWTExpiry        time.Duration `mapstructure:"jwt_expiry"`
			LockoutThreshold int           `mapstructure:"lockout_threshold"`
			LockoutDuration  time.Duration `mapstructure:"lockout_duration"`
		}{
			JWTSecret: "test-secret-key",
			JWTExpiry: time.Hour,
		},
	}

	// Create a minimal API instance for testing
	logger := zap.NewNop().Sugar()
	api := &API{
		config: cfg,
		authManager: &AuthManager{
			tokenBlacklist: sync.Map{},
		},
		logger: logger,
	}

	invalidToken := "not.a.valid.token"
	claims, err := api.validateJWT(invalidToken, cfg)

	assert.Error(t, err)
	assert.Nil(t, claims)
}

func TestValidateJWT_WrongSecret(t *testing.T) {
	cfg1 := &config.Config{
		Auth: struct {
			Enabled          bool   `mapstructure:"enabled"`
			Username         string `mapstructure:"username"`
			Password         string `mapstructure:"password"`
			HashedPassword   string
			BcryptCost       int           `mapstructure:"bcrypt_cost"`
			JWTSecret        string        `mapstructure:"jwt_secret"`
			JWTExpiry        time.Duration `mapstructure:"jwt_expiry"`
			LockoutThreshold int           `mapstructure:"lockout_threshold"`
			LockoutDuration  time.Duration `mapstructure:"lockout_duration"`
		}{
			JWTSecret: "secret-one",
		},
	}

	cfg2 := &config.Config{
		Auth: struct {
			Enabled          bool   `mapstructure:"enabled"`
			Username         string `mapstructure:"username"`
			Password         string `mapstructure:"password"`
			HashedPassword   string
			BcryptCost       int           `mapstructure:"bcrypt_cost"`
			JWTSecret        string        `mapstructure:"jwt_secret"`
			JWTExpiry        time.Duration `mapstructure:"jwt_expiry"`
			LockoutThreshold int           `mapstructure:"lockout_threshold"`
			LockoutDuration  time.Duration `mapstructure:"lockout_duration"`
		}{
			JWTSecret: "secret-two",
		},
	}

	token, err := generateJWT(context.Background(), "testuser", cfg1, nil, nil)
	assert.NoError(t, err)

	// Try to validate with different secret
	claims, err := validateJWTStandalone(token, cfg2)

	assert.Error(t, err)
	assert.Nil(t, claims)
}

func TestValidateJWT_ExpiredToken(t *testing.T) {
	cfg := &config.Config{
		Auth: struct {
			Enabled          bool   `mapstructure:"enabled"`
			Username         string `mapstructure:"username"`
			Password         string `mapstructure:"password"`
			HashedPassword   string
			BcryptCost       int           `mapstructure:"bcrypt_cost"`
			JWTSecret        string        `mapstructure:"jwt_secret"`
			JWTExpiry        time.Duration `mapstructure:"jwt_expiry"`
			LockoutThreshold int           `mapstructure:"lockout_threshold"`
			LockoutDuration  time.Duration `mapstructure:"lockout_duration"`
		}{
			JWTSecret: "test-secret-expired",
		},
	}

	// Create an expired token manually
	expirationTime := time.Now().Add(-1 * time.Hour) // Expired 1 hour ago
	claims := &Claims{
		Username: "expireduser",
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expirationTime),
			IssuedAt:  jwt.NewNumericDate(time.Now().Add(-2 * time.Hour)),
			NotBefore: jwt.NewNumericDate(time.Now().Add(-2 * time.Hour)),
			Issuer:    "cerberus",
			Subject:   "expireduser",
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString([]byte(cfg.Auth.JWTSecret))
	assert.NoError(t, err)

	// Validate the expired token
	validatedClaims, err := validateJWTStandalone(tokenString, cfg)

	assert.Error(t, err)
	assert.Nil(t, validatedClaims)
}

func TestClaims_Structure(t *testing.T) {
	claims := &Claims{
		Username: "structuser",
		RegisteredClaims: jwt.RegisteredClaims{
			Subject: "structuser",
			Issuer:  "cerberus",
		},
	}

	assert.Equal(t, "structuser", claims.Username)
	assert.Equal(t, "structuser", claims.Subject)
	assert.Equal(t, "cerberus", claims.Issuer)
}
