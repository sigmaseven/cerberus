package storage

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"go.uber.org/zap"
	"golang.org/x/crypto/bcrypt"
)

// SQLiteUserStorage implements UserStorage using SQLite
type SQLiteUserStorage struct {
	sqlite      *SQLite
	logger      *zap.SugaredLogger
	roleStorage RoleStorage // Reference to role storage for permission checks
}

// NewSQLiteUserStorage creates a new SQLite-based user storage
func NewSQLiteUserStorage(sqlite *SQLite, logger *zap.SugaredLogger) *SQLiteUserStorage {
	return &SQLiteUserStorage{
		sqlite: sqlite,
		logger: logger,
	}
}

// SetRoleStorage sets the role storage reference (circular dependency resolution)
func (sus *SQLiteUserStorage) SetRoleStorage(roleStorage RoleStorage) {
	sus.roleStorage = roleStorage
}

// CreateUser creates a new user
func (sus *SQLiteUserStorage) CreateUser(ctx context.Context, user *User) error {
	// Check if user already exists
	existing, err := sus.GetUserByUsername(ctx, user.Username)
	if err != nil && err.Error() != "user not found" {
		return fmt.Errorf("failed to check existing user: %w", err)
	}
	if existing != nil {
		return errors.New("user already exists")
	}

	// Hash password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("failed to hash password: %w", err)
	}

	// Serialize roles
	rolesJSON, err := json.Marshal(user.Roles)
	if err != nil {
		return fmt.Errorf("failed to marshal roles: %w", err)
	}

	// Set timestamps
	now := time.Now()
	user.CreatedAt = now
	user.UpdatedAt = now
	user.Active = true

	// SECURITY: Validate role_id if provided
	if user.RoleID != nil && sus.roleStorage != nil {
		_, err := sus.roleStorage.GetRoleByID(ctx, *user.RoleID)
		if err != nil {
			return fmt.Errorf("invalid role_id: %w", err)
		}
	}

	// TASK 8.4: Set password_changed_at on user creation
	if user.PasswordChangedAt == nil {
		now := time.Now()
		user.PasswordChangedAt = &now
	}

	mfaEnabledInt := 0
	if user.MFAEnabled {
		mfaEnabledInt = 1
	}

	var lockedUntilPtr, passwordChangedAtPtr interface{}
	if user.LockedUntil != nil {
		lockedUntilPtr = user.LockedUntil.Format(time.RFC3339)
	}
	if user.PasswordChangedAt != nil {
		passwordChangedAtPtr = user.PasswordChangedAt.Format(time.RFC3339)
	}

	// TASK 38.3: Set must_change_password to true for new users (default)
	mustChangePasswordInt := 1
	if !user.MustChangePassword {
		// Allow override if explicitly set to false
		mustChangePasswordInt = 0
	} else {
		// Default to true for new users
		user.MustChangePassword = true
	}

	query := `
		INSERT INTO users (username, password_hash, roles, role_id, active, created_at, updated_at,
		                   totp_secret, mfa_enabled, failed_login_attempts, locked_until, password_changed_at, must_change_password)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`

	_, err = sus.sqlite.DB.ExecContext(ctx, query,
		user.Username,
		string(hashedPassword),
		string(rolesJSON),
		user.RoleID,
		user.Active,
		user.CreatedAt.Format(time.RFC3339),
		user.UpdatedAt.Format(time.RFC3339),
		user.TOTPSecret,
		mfaEnabledInt,
		user.FailedLoginAttempts,
		lockedUntilPtr,
		passwordChangedAtPtr,
		mustChangePasswordInt,
	)

	if err != nil {
		return fmt.Errorf("failed to create user: %w", err)
	}

	sus.logger.Infof("Created user %s", user.Username)
	return nil
}

// GetUserByUsername retrieves a user by username
func (sus *SQLiteUserStorage) GetUserByUsername(ctx context.Context, username string) (*User, error) {
	query := `
		SELECT username, password_hash, roles, active, created_at, updated_at,
		       totp_secret, mfa_enabled, failed_login_attempts, locked_until, password_changed_at, must_change_password
		FROM users
		WHERE username = ?
	`

	var user User
	var rolesJSON string
	var createdAt, updatedAt string
	var active int
	var mfaEnabled int
	var failedLoginAttempts int
	var mustChangePassword int
	var totpSecret, lockedUntil, passwordChangedAt sql.NullString

	err := sus.sqlite.ReadDB.QueryRowContext(ctx, query, username).Scan(
		&user.Username,
		&user.Password,
		&rolesJSON,
		&active,
		&createdAt,
		&updatedAt,
		&totpSecret,
		&mfaEnabled,
		&failedLoginAttempts,
		&lockedUntil,
		&passwordChangedAt,
		&mustChangePassword,
	)

	if err == sql.ErrNoRows {
		return nil, errors.New("user not found")
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get user: %w", err)
	}

	// Parse JSON roles
	if err := json.Unmarshal([]byte(rolesJSON), &user.Roles); err != nil {
		return nil, fmt.Errorf("failed to parse roles: %w", err)
	}

	// Parse timestamps and active
	user.Active = active == 1
	user.CreatedAt, _ = time.Parse(time.RFC3339, createdAt)
	user.UpdatedAt, _ = time.Parse(time.RFC3339, updatedAt)

	// TASK 8.3 & 8.5: Parse security fields
	if totpSecret.Valid {
		user.TOTPSecret = totpSecret.String
	}
	user.MFAEnabled = mfaEnabled == 1
	user.FailedLoginAttempts = failedLoginAttempts
	if lockedUntil.Valid {
		if t, err := time.Parse(time.RFC3339, lockedUntil.String); err == nil {
			user.LockedUntil = &t
		}
	}
	if passwordChangedAt.Valid {
		if t, err := time.Parse(time.RFC3339, passwordChangedAt.String); err == nil {
			user.PasswordChangedAt = &t
		}
	}
	// TASK 38.3: Parse must_change_password field
	user.MustChangePassword = mustChangePassword == 1

	return &user, nil
}

// UpdateUser updates an existing user
func (sus *SQLiteUserStorage) UpdateUser(ctx context.Context, user *User) error {
	// Check if user exists
	existing, err := sus.GetUserByUsername(ctx, user.Username)
	if err != nil {
		return err
	}

	// Preserve creation time
	user.CreatedAt = existing.CreatedAt
	user.UpdatedAt = time.Now()

	// Hash password if it's being changed (non-empty)
	passwordToStore := existing.Password
	passwordChanged := false
	if user.Password != "" {
		hashedPassword, err := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.DefaultCost)
		if err != nil {
			return fmt.Errorf("failed to hash password: %w", err)
		}
		passwordToStore = string(hashedPassword)
		passwordChanged = true
	}

	// TASK 8.4: Update password_changed_at when password is changed
	if passwordChanged {
		now := time.Now()
		user.PasswordChangedAt = &now
	} else {
		// Preserve existing password_changed_at if password is not being changed
		user.PasswordChangedAt = existing.PasswordChangedAt
	}

	// TASK 8.3 & 8.5: Preserve security fields if not being updated
	if user.TOTPSecret == "" && existing.TOTPSecret != "" {
		user.TOTPSecret = existing.TOTPSecret
	}
	if user.FailedLoginAttempts == 0 && existing.FailedLoginAttempts > 0 && user.LockedUntil == nil {
		// Preserve failed_login_attempts if not explicitly reset
		user.FailedLoginAttempts = existing.FailedLoginAttempts
	}
	if user.LockedUntil == nil && existing.LockedUntil != nil {
		user.LockedUntil = existing.LockedUntil
	}

	// Serialize roles
	rolesJSON, err := json.Marshal(user.Roles)
	if err != nil {
		return fmt.Errorf("failed to marshal roles: %w", err)
	}

	// TASK 8.3 & 8.5: Update security fields in addition to basic fields
	// TASK 38.3: Include must_change_password field
	mfaEnabledInt := 0
	if user.MFAEnabled {
		mfaEnabledInt = 1
	}
	mustChangePasswordInt := 0
	if user.MustChangePassword {
		mustChangePasswordInt = 1
	}

	query := `
		UPDATE users
		SET password_hash = ?, roles = ?, active = ?, updated_at = ?,
		    totp_secret = ?, mfa_enabled = ?, failed_login_attempts = ?,
		    locked_until = ?, password_changed_at = ?, must_change_password = ?
		WHERE username = ?
	`

	var lockedUntilPtr, passwordChangedAtPtr interface{}
	if user.LockedUntil != nil {
		lockedUntilPtr = user.LockedUntil.Format(time.RFC3339)
	}
	if user.PasswordChangedAt != nil {
		passwordChangedAtPtr = user.PasswordChangedAt.Format(time.RFC3339)
	}

	result, err := sus.sqlite.DB.ExecContext(ctx, query,
		passwordToStore,
		string(rolesJSON),
		user.Active,
		user.UpdatedAt.Format(time.RFC3339),
		user.TOTPSecret,
		mfaEnabledInt,
		user.FailedLoginAttempts,
		lockedUntilPtr,
		passwordChangedAtPtr,
		mustChangePasswordInt,
		user.Username,
	)

	if err != nil {
		return fmt.Errorf("failed to update user: %w", err)
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return errors.New("user not found")
	}

	sus.logger.Infof("Updated user %s", user.Username)
	return nil
}

// DeleteUser deletes a user
func (sus *SQLiteUserStorage) DeleteUser(ctx context.Context, username string) error {
	result, err := sus.sqlite.DB.ExecContext(ctx, "DELETE FROM users WHERE username = ?", username)
	if err != nil {
		return fmt.Errorf("failed to delete user: %w", err)
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return errors.New("user not found")
	}

	sus.logger.Infof("Deleted user %s", username)
	return nil
}

// ListUsers retrieves all users
func (sus *SQLiteUserStorage) ListUsers(ctx context.Context) ([]*User, error) {
	query := `
		SELECT username, password_hash, roles, active, created_at, updated_at,
		       totp_secret, mfa_enabled, failed_login_attempts, locked_until, password_changed_at, must_change_password
		FROM users
		ORDER BY created_at DESC
	`

	rows, err := sus.sqlite.ReadDB.QueryContext(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("failed to query users: %w", err)
	}
	defer rows.Close()

	var users []*User
	for rows.Next() {
		var user User
		var rolesJSON string
		var createdAt, updatedAt string
		var active int
		var mfaEnabled int
		var failedLoginAttempts int
		var mustChangePassword int
		var totpSecret, lockedUntil, passwordChangedAt sql.NullString

		err := rows.Scan(
			&user.Username,
			&user.Password,
			&rolesJSON,
			&active,
			&createdAt,
			&updatedAt,
			&totpSecret,
			&mfaEnabled,
			&failedLoginAttempts,
			&lockedUntil,
			&passwordChangedAt,
			&mustChangePassword,
		)

		if err != nil {
			return nil, fmt.Errorf("failed to scan user: %w", err)
		}

		// Parse JSON roles
		if err := json.Unmarshal([]byte(rolesJSON), &user.Roles); err != nil {
			sus.logger.Warnf("Failed to parse roles for user %s: %v", user.Username, err)
			continue
		}

		// Parse timestamps and active
		user.Active = active == 1
		user.CreatedAt, _ = time.Parse(time.RFC3339, createdAt)
		user.UpdatedAt, _ = time.Parse(time.RFC3339, updatedAt)

		// TASK 8.3 & 8.5: Parse security fields
		if totpSecret.Valid {
			user.TOTPSecret = totpSecret.String
		}
		user.MFAEnabled = mfaEnabled == 1
		user.FailedLoginAttempts = failedLoginAttempts
		if lockedUntil.Valid {
			if t, err := time.Parse(time.RFC3339, lockedUntil.String); err == nil {
				user.LockedUntil = &t
			}
		}
		if passwordChangedAt.Valid {
			if t, err := time.Parse(time.RFC3339, passwordChangedAt.String); err == nil {
				user.PasswordChangedAt = &t
			}
		}
		// TASK 38.3: Parse must_change_password field
		user.MustChangePassword = mustChangePassword == 1

		users = append(users, &user)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating users: %w", err)
	}

	return users, nil
}

// ValidateCredentials validates user credentials
func (sus *SQLiteUserStorage) ValidateCredentials(ctx context.Context, username, password string) (*User, error) {
	user, err := sus.GetUserByUsername(ctx, username)
	if err != nil {
		return nil, err
	}

	if !user.Active {
		return nil, errors.New("user is not active")
	}

	// Compare password with hash
	err = bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(password))
	if err != nil {
		return nil, errors.New("invalid credentials")
	}

	return user, nil
}

// EnsureIndexes ensures database indexes exist (compatibility with MongoDB interface)
func (sus *SQLiteUserStorage) EnsureIndexes(ctx context.Context) error {
	// Indexes are created in the schema during table creation
	return nil
}

// UpdateUserRole updates a user's role assignment
func (sus *SQLiteUserStorage) UpdateUserRole(ctx context.Context, username string, roleID int64) error {
	// SECURITY: Validate that the role exists before assignment
	if sus.roleStorage != nil {
		_, err := sus.roleStorage.GetRoleByID(ctx, roleID)
		if err != nil {
			return fmt.Errorf("invalid role_id: %w", err)
		}
	}

	// SECURITY: Check if user exists
	_, err := sus.GetUserByUsername(ctx, username)
	if err != nil {
		return err
	}

	query := `
		UPDATE users
		SET role_id = ?, updated_at = ?
		WHERE username = ?
	`

	result, err := sus.sqlite.DB.ExecContext(ctx, query,
		roleID,
		time.Now().Format(time.RFC3339),
		username,
	)

	if err != nil {
		return fmt.Errorf("failed to update user role: %w", err)
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return errors.New("user not found")
	}

	sus.logger.Infof("Updated role for user %s to role_id %d", username, roleID)
	return nil
}

// GetUserWithRole retrieves a user along with their role details
func (sus *SQLiteUserStorage) GetUserWithRole(ctx context.Context, username string) (*User, *Role, error) {
	query := `
		SELECT u.username, u.password_hash, u.roles, u.role_id, u.active, u.created_at, u.updated_at,
		       u.totp_secret, u.mfa_enabled, u.failed_login_attempts, u.locked_until, u.password_changed_at, u.must_change_password
		FROM users u
		WHERE u.username = ?
	`

	var user User
	var rolesJSON sql.NullString
	var roleID sql.NullInt64
	var createdAt, updatedAt string
	var active int
	var mfaEnabled int
	var failedLoginAttempts int
	var mustChangePassword int
	var totpSecret, lockedUntil, passwordChangedAt sql.NullString

	err := sus.sqlite.ReadDB.QueryRowContext(ctx, query, username).Scan(
		&user.Username,
		&user.Password,
		&rolesJSON,
		&roleID,
		&active,
		&createdAt,
		&updatedAt,
		&totpSecret,
		&mfaEnabled,
		&failedLoginAttempts,
		&lockedUntil,
		&passwordChangedAt,
		&mustChangePassword,
	)

	if err == sql.ErrNoRows {
		return nil, nil, errors.New("user not found")
	}
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get user: %w", err)
	}

	// Parse legacy roles if present
	if rolesJSON.Valid && rolesJSON.String != "" {
		if err := json.Unmarshal([]byte(rolesJSON.String), &user.Roles); err != nil {
			sus.logger.Warnf("Failed to parse legacy roles for user %s: %v", username, err)
		}
	}

	// Set user fields
	user.Active = active == 1
	user.CreatedAt, _ = time.Parse(time.RFC3339, createdAt)
	user.UpdatedAt, _ = time.Parse(time.RFC3339, updatedAt)

	// TASK 8.3 & 8.5: Parse security fields
	if totpSecret.Valid {
		user.TOTPSecret = totpSecret.String
	}
	user.MFAEnabled = mfaEnabled == 1
	user.FailedLoginAttempts = failedLoginAttempts
	if lockedUntil.Valid {
		if t, err := time.Parse(time.RFC3339, lockedUntil.String); err == nil {
			user.LockedUntil = &t
		}
	}
	if passwordChangedAt.Valid {
		if t, err := time.Parse(time.RFC3339, passwordChangedAt.String); err == nil {
			user.PasswordChangedAt = &t
		}
	}
	// TASK 38.3: Parse must_change_password field
	user.MustChangePassword = mustChangePassword == 1

	// Get role if assigned
	var role *Role
	if roleID.Valid && sus.roleStorage != nil {
		user.RoleID = &roleID.Int64
		role, err = sus.roleStorage.GetRoleByID(ctx, roleID.Int64)
		if err != nil {
			return &user, nil, fmt.Errorf("failed to get user's role: %w", err)
		}
		user.RoleName = role.Name
	}

	return &user, role, nil
}
