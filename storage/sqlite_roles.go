package storage

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"go.uber.org/zap"
)

// SQLiteRoleStorage implements RoleStorage using SQLite
type SQLiteRoleStorage struct {
	sqlite *SQLite
	logger *zap.SugaredLogger
}

// NewSQLiteRoleStorage creates a new SQLite-based role storage
func NewSQLiteRoleStorage(sqlite *SQLite, logger *zap.SugaredLogger) *SQLiteRoleStorage {
	return &SQLiteRoleStorage{
		sqlite: sqlite,
		logger: logger,
	}
}

// GetRoleByID retrieves a role by ID
func (srs *SQLiteRoleStorage) GetRoleByID(ctx context.Context, id int64) (*Role, error) {
	query := `
		SELECT id, name, description, permissions, created_at, updated_at
		FROM roles
		WHERE id = ?
	`

	var role Role
	var permissionsJSON string
	var createdAt, updatedAt string

	err := srs.sqlite.ReadDB.QueryRowContext(ctx, query, id).Scan(
		&role.ID,
		&role.Name,
		&role.Description,
		&permissionsJSON,
		&createdAt,
		&updatedAt,
	)

	if err == sql.ErrNoRows {
		return nil, errors.New("role not found")
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get role by id: %w", err)
	}

	// Parse JSON permissions
	if err := json.Unmarshal([]byte(permissionsJSON), &role.Permissions); err != nil {
		return nil, fmt.Errorf("failed to parse permissions: %w", err)
	}

	// Parse timestamps
	role.CreatedAt, _ = time.Parse(time.RFC3339, createdAt)
	role.UpdatedAt, _ = time.Parse(time.RFC3339, updatedAt)

	return &role, nil
}

// GetRoleByName retrieves a role by name
func (srs *SQLiteRoleStorage) GetRoleByName(ctx context.Context, name string) (*Role, error) {
	query := `
		SELECT id, name, description, permissions, created_at, updated_at
		FROM roles
		WHERE name = ?
	`

	var role Role
	var permissionsJSON string
	var createdAt, updatedAt string

	err := srs.sqlite.ReadDB.QueryRowContext(ctx, query, name).Scan(
		&role.ID,
		&role.Name,
		&role.Description,
		&permissionsJSON,
		&createdAt,
		&updatedAt,
	)

	if err == sql.ErrNoRows {
		return nil, errors.New("role not found")
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get role by name: %w", err)
	}

	// Parse JSON permissions
	if err := json.Unmarshal([]byte(permissionsJSON), &role.Permissions); err != nil {
		return nil, fmt.Errorf("failed to parse permissions: %w", err)
	}

	// Parse timestamps
	role.CreatedAt, _ = time.Parse(time.RFC3339, createdAt)
	role.UpdatedAt, _ = time.Parse(time.RFC3339, updatedAt)

	return &role, nil
}

// ListRoles retrieves all roles
func (srs *SQLiteRoleStorage) ListRoles(ctx context.Context) ([]Role, error) {
	query := `
		SELECT id, name, description, permissions, created_at, updated_at
		FROM roles
		ORDER BY id ASC
	`

	rows, err := srs.sqlite.ReadDB.QueryContext(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("failed to query roles: %w", err)
	}
	defer rows.Close()

	var roles []Role
	for rows.Next() {
		var role Role
		var permissionsJSON string
		var createdAt, updatedAt string

		err := rows.Scan(
			&role.ID,
			&role.Name,
			&role.Description,
			&permissionsJSON,
			&createdAt,
			&updatedAt,
		)

		if err != nil {
			return nil, fmt.Errorf("failed to scan role: %w", err)
		}

		// Parse JSON permissions
		if err := json.Unmarshal([]byte(permissionsJSON), &role.Permissions); err != nil {
			srs.logger.Warnf("Failed to parse permissions for role %s: %v", role.Name, err)
			continue
		}

		// Parse timestamps
		role.CreatedAt, _ = time.Parse(time.RFC3339, createdAt)
		role.UpdatedAt, _ = time.Parse(time.RFC3339, updatedAt)

		roles = append(roles, role)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating roles: %w", err)
	}

	return roles, nil
}

// CreateRole creates a new role
func (srs *SQLiteRoleStorage) CreateRole(ctx context.Context, role *Role) error {
	// SECURITY: Validate role name to prevent injection
	if role.Name == "" {
		return errors.New("role name cannot be empty")
	}
	if len(role.Name) > 50 {
		return errors.New("role name exceeds maximum length of 50 characters")
	}

	// Check if role already exists
	existing, err := srs.GetRoleByName(ctx, role.Name)
	if err == nil && existing != nil {
		return fmt.Errorf("role with name '%s' already exists", role.Name)
	}

	// Serialize permissions
	permissionsJSON, err := json.Marshal(role.Permissions)
	if err != nil {
		return fmt.Errorf("failed to marshal permissions: %w", err)
	}

	// Set timestamps
	now := time.Now()
	role.CreatedAt = now
	role.UpdatedAt = now

	query := `
		INSERT INTO roles (name, description, permissions, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?)
	`

	result, err := srs.sqlite.DB.ExecContext(ctx, query,
		role.Name,
		role.Description,
		string(permissionsJSON),
		role.CreatedAt.Format(time.RFC3339),
		role.UpdatedAt.Format(time.RFC3339),
	)

	if err != nil {
		return fmt.Errorf("failed to create role: %w", err)
	}

	// Get the generated ID
	id, err := result.LastInsertId()
	if err != nil {
		return fmt.Errorf("failed to get last insert id: %w", err)
	}
	role.ID = id

	srs.logger.Infof("Created role %s (ID: %d)", role.Name, role.ID)
	return nil
}

// UpdateRole updates an existing role
func (srs *SQLiteRoleStorage) UpdateRole(ctx context.Context, role *Role) error {
	// SECURITY: Validate role exists before update
	existing, err := srs.GetRoleByID(ctx, role.ID)
	if err != nil {
		return err
	}

	// Preserve creation time
	role.CreatedAt = existing.CreatedAt
	role.UpdatedAt = time.Now()

	// Serialize permissions
	permissionsJSON, err := json.Marshal(role.Permissions)
	if err != nil {
		return fmt.Errorf("failed to marshal permissions: %w", err)
	}

	query := `
		UPDATE roles
		SET name = ?, description = ?, permissions = ?, updated_at = ?
		WHERE id = ?
	`

	result, err := srs.sqlite.DB.ExecContext(ctx, query,
		role.Name,
		role.Description,
		string(permissionsJSON),
		role.UpdatedAt.Format(time.RFC3339),
		role.ID,
	)

	if err != nil {
		return fmt.Errorf("failed to update role: %w", err)
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return errors.New("role not found")
	}

	srs.logger.Infof("Updated role %s (ID: %d)", role.Name, role.ID)
	return nil
}

// DeleteRole deletes a role
func (srs *SQLiteRoleStorage) DeleteRole(ctx context.Context, id int64) error {
	// SECURITY: Prevent deletion of default roles
	role, err := srs.GetRoleByID(ctx, id)
	if err != nil {
		return err
	}

	// Prevent deletion of built-in roles
	if role.Name == RoleAdmin || role.Name == RoleEngineer ||
		role.Name == RoleAnalyst || role.Name == RoleViewer {
		return fmt.Errorf("cannot delete built-in role: %s", role.Name)
	}

	// SECURITY: Check if any users are assigned this role
	var userCount int
	err = srs.sqlite.ReadDB.QueryRowContext(ctx, "SELECT COUNT(*) FROM users WHERE role_id = ?", id).Scan(&userCount)
	if err != nil {
		return fmt.Errorf("failed to check role usage: %w", err)
	}
	if userCount > 0 {
		return fmt.Errorf("cannot delete role: %d users are assigned this role", userCount)
	}

	result, err := srs.sqlite.DB.ExecContext(ctx, "DELETE FROM roles WHERE id = ?", id)
	if err != nil {
		return fmt.Errorf("failed to delete role: %w", err)
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return errors.New("role not found")
	}

	srs.logger.Infof("Deleted role ID: %d", id)
	return nil
}

// SeedDefaultRoles initializes the default roles on first startup
func (srs *SQLiteRoleStorage) SeedDefaultRoles(ctx context.Context) error {
	// Check if roles already exist
	existingRoles, err := srs.ListRoles(ctx)
	if err != nil {
		return fmt.Errorf("failed to check existing roles: %w", err)
	}

	if len(existingRoles) > 0 {
		srs.logger.Info("Roles already seeded, skipping default role creation")
		return nil
	}

	// Insert default roles
	defaultRoles := GetDefaultRoles()
	for _, role := range defaultRoles {
		// Don't use the predefined IDs - let SQLite auto-generate them
		roleToCreate := role
		roleToCreate.ID = 0 // Reset ID to let database auto-generate

		if err := srs.CreateRole(ctx, &roleToCreate); err != nil {
			return fmt.Errorf("failed to seed role %s: %w", role.Name, err)
		}
		srs.logger.Infof("Seeded default role: %s (ID: %d)", roleToCreate.Name, roleToCreate.ID)
	}

	srs.logger.Info("Successfully seeded default roles")
	return nil
}
