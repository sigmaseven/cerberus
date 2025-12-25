// Package storage provides system-level metadata storage.
// TASK 160.1: System metadata storage for first-run wizard and application settings.
package storage

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"
)

// SystemMetadataKey defines the keys used in the system_metadata table
type SystemMetadataKey string

const (
	// SystemKeySetupCompleted indicates whether the initial setup wizard has been completed
	SystemKeySetupCompleted SystemMetadataKey = "setup_completed"
)

// SystemMetadataInterface defines methods for system-level settings storage
type SystemMetadataInterface interface {
	// IsFirstRun checks if this is the first run of the application
	// Returns true if no feeds exist and setup has not been completed
	IsFirstRun(ctx context.Context) (bool, error)

	// GetSystemMetadata retrieves a system metadata value by key
	GetSystemMetadata(ctx context.Context, key SystemMetadataKey) (string, error)

	// SetSystemMetadata sets a system metadata value
	SetSystemMetadata(ctx context.Context, key SystemMetadataKey, value string) error

	// SetSetupCompleted marks the setup wizard as completed
	SetSetupCompleted(ctx context.Context) error
}

// IsFirstRun checks if this is the first run of the application.
// TASK 160.1: Returns true if no feeds exist and setup has not been completed.
// PRODUCTION: Uses short-circuit evaluation for efficiency.
func (s *SQLite) IsFirstRun(ctx context.Context) (bool, error) {
	// Check if setup has already been completed
	setupCompleted, err := s.GetSystemMetadata(ctx, SystemKeySetupCompleted)
	if err != nil && err != sql.ErrNoRows {
		return false, fmt.Errorf("failed to check setup status: %w", err)
	}
	if setupCompleted == "true" {
		return false, nil
	}

	// Check if any feeds exist
	var feedCount int
	err = s.DB.QueryRowContext(ctx,
		"SELECT COUNT(*) FROM feeds WHERE 1=1").Scan(&feedCount)
	if err != nil {
		// If feeds table doesn't exist, consider it a first run
		if strings.Contains(err.Error(), "no such table: feeds") {
			return true, nil
		}
		return false, fmt.Errorf("failed to count feeds: %w", err)
	}

	// If no feeds exist and setup not completed, it's a first run
	return feedCount == 0, nil
}

// GetSystemMetadata retrieves a system metadata value by key.
// TASK 160.1: Key-value storage for system settings.
// SECURITY: Returns sql.ErrNoRows if key doesn't exist (callers must handle).
func (s *SQLite) GetSystemMetadata(ctx context.Context, key SystemMetadataKey) (string, error) {
	var value string
	err := s.DB.QueryRowContext(ctx,
		"SELECT value FROM system_metadata WHERE key = ?",
		string(key)).Scan(&value)
	if err != nil {
		if err == sql.ErrNoRows {
			return "", sql.ErrNoRows
		}
		return "", fmt.Errorf("failed to get system metadata: %w", err)
	}
	return value, nil
}

// SetSystemMetadata sets a system metadata value.
// TASK 160.1: Upserts (insert or update) the key-value pair.
// PRODUCTION: Uses UPSERT pattern for atomic operation.
func (s *SQLite) SetSystemMetadata(ctx context.Context, key SystemMetadataKey, value string) error {
	_, err := s.DB.ExecContext(ctx, `
		INSERT INTO system_metadata (key, value, created_at, updated_at)
		VALUES (?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
		ON CONFLICT(key) DO UPDATE SET
			value = excluded.value,
			updated_at = CURRENT_TIMESTAMP
	`, string(key), value)
	if err != nil {
		return fmt.Errorf("failed to set system metadata: %w", err)
	}
	return nil
}

// SetSetupCompleted marks the setup wizard as completed.
// TASK 160.1: Called when user completes or skips the first-run wizard.
func (s *SQLite) SetSetupCompleted(ctx context.Context) error {
	return s.SetSystemMetadata(ctx, SystemKeySetupCompleted, "true")
}

// GetSetupCompletedTime retrieves when setup was completed.
// TASK 160.1: Optional method for audit logging.
func (s *SQLite) GetSetupCompletedTime(ctx context.Context) (*time.Time, error) {
	var updatedAt time.Time
	err := s.DB.QueryRowContext(ctx,
		"SELECT updated_at FROM system_metadata WHERE key = ?",
		string(SystemKeySetupCompleted)).Scan(&updatedAt)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil // Not completed yet
		}
		return nil, fmt.Errorf("failed to get setup completion time: %w", err)
	}
	return &updatedAt, nil
}
