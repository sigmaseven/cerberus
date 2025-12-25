package api

import (
	"context"
	"errors"

	"cerberus/config"
	"cerberus/storage"
	"cerberus/util"

	"golang.org/x/crypto/bcrypt"
)

// PasswordPolicyManager manages password policy enforcement
// TASK 38: Centralized password policy management
type PasswordPolicyManager struct {
	config         *config.Config
	policy         *util.PasswordPolicy
	historyStorage *storage.SQLitePasswordHistoryStorage
	logger         interface {
		Infof(string, ...interface{})
		Warnf(string, ...interface{})
		Errorf(string, ...interface{})
	}
}

// NewPasswordPolicyManager creates a new password policy manager
// TASK 38.5: Initialize password policy manager with config
func NewPasswordPolicyManager(cfg *config.Config, historyStorage *storage.SQLitePasswordHistoryStorage, logger interface {
	Infof(string, ...interface{})
	Warnf(string, ...interface{})
	Errorf(string, ...interface{})
}) *PasswordPolicyManager {
	policy := util.DefaultPasswordPolicy()

	// Override defaults with config values if provided
	if cfg.Security.PasswordPolicy.MinLength > 0 {
		policy.MinLength = cfg.Security.PasswordPolicy.MinLength
	}
	if cfg.Security.PasswordPolicy.RequireClasses > 0 {
		policy.RequireClasses = cfg.Security.PasswordPolicy.RequireClasses
	}
	if cfg.Security.PasswordPolicy.MaxHistory > 0 {
		policy.MaxHistory = cfg.Security.PasswordPolicy.MaxHistory
	}
	if cfg.Security.PasswordPolicy.ExpirationDays > 0 {
		policy.ExpirationDays = cfg.Security.PasswordPolicy.ExpirationDays
	}
	if cfg.Security.PasswordPolicy.WarningDays > 0 {
		policy.WarningDays = cfg.Security.PasswordPolicy.WarningDays
	}
	if cfg.Security.PasswordPolicy.CommonPasswordFile != "" {
		policy.CommonPasswordFile = cfg.Security.PasswordPolicy.CommonPasswordFile
	}

	// Load common passwords in background (best effort)
	go func() {
		if err := policy.LoadCommonPasswords(); err != nil {
			logger.Warnf("Failed to load common passwords: %v", err)
		}
	}()

	return &PasswordPolicyManager{
		config:         cfg,
		policy:         policy,
		historyStorage: historyStorage,
		logger:         logger,
	}
}

// ValidatePassword validates a password against the policy, including history check
// TASK 38.5: Comprehensive password validation with history checking
func (ppm *PasswordPolicyManager) ValidatePassword(ctx context.Context, password, username, userID string) error {
	// First validate basic policy (complexity, common passwords, username variations)
	if err := ppm.policy.Validate(password, username, userID); err != nil {
		return err
	}

	// Check password history if userID provided and history storage available
	if ppm.historyStorage != nil && userID != "" {
		history, err := ppm.historyStorage.GetPasswordHistory(ctx, userID, ppm.policy.MaxHistory)
		if err != nil {
			// Log error but don't fail validation (history check is best effort)
			ppm.logger.Warnf("Failed to get password history for user %s: %v", userID, err)
		} else {
			// Check if password hash exists in history using bcrypt comparison
			// Note: bcrypt hashes include salt, so we must use CompareHashAndPassword, not direct comparison
			for _, hash := range history {
				if err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)); err == nil {
					// Password matches a previous password in history
					return errors.New("password was used recently and cannot be reused")
				}
			}
		}
	}

	return nil
}

// AddPasswordToHistory adds a password hash to the user's password history
// TASK 38.3: Track password in history when changed
func (ppm *PasswordPolicyManager) AddPasswordToHistory(ctx context.Context, userID, passwordHash string) error {
	if ppm.historyStorage == nil {
		return nil // History tracking not available, skip silently
	}

	if err := ppm.historyStorage.AddPasswordToHistory(ctx, userID, passwordHash); err != nil {
		ppm.logger.Warnf("Failed to add password to history for user %s: %v", userID, err)
		// Don't fail password change if history tracking fails (best effort)
		return nil
	}

	return nil
}

// CheckPasswordExpired checks if a user's password has expired
// TASK 38.4: Password expiration checking
func (ppm *PasswordPolicyManager) CheckPasswordExpired(user *storage.User) (bool, error) {
	return ppm.policy.IsPasswordExpired(user.PasswordChangedAt), nil
}

// CheckPasswordExpirationWarning checks if password expires within warning period
// TASK 38.4: Password expiration warning calculation
func (ppm *PasswordPolicyManager) CheckPasswordExpirationWarning(user *storage.User) (bool, int) {
	return ppm.policy.CheckPasswordExpirationWarning(user.PasswordChangedAt)
}

// GetPasswordPolicy returns the password policy configuration
// TASK 38.1: Get policy configuration for API responses
func (ppm *PasswordPolicyManager) GetPasswordPolicy() *util.PasswordPolicy {
	return ppm.policy
}
