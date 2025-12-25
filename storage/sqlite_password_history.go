package storage

import (
	"context"
	"errors"
	"fmt"
	"time"

	"go.uber.org/zap"
)

// SQLitePasswordHistoryStorage implements password history tracking
// TASK 38.3: Password history storage for preventing password reuse
type SQLitePasswordHistoryStorage struct {
	sqlite *SQLite
	logger *zap.SugaredLogger
}

// NewSQLitePasswordHistoryStorage creates a new password history storage
func NewSQLitePasswordHistoryStorage(sqlite *SQLite, logger *zap.SugaredLogger) *SQLitePasswordHistoryStorage {
	return &SQLitePasswordHistoryStorage{
		sqlite: sqlite,
		logger: logger,
	}
}

// AddPasswordToHistory adds a password hash to the user's password history
// TASK 38.3: Store password hash in history to prevent reuse
func (s *SQLitePasswordHistoryStorage) AddPasswordToHistory(ctx context.Context, userID, passwordHash string) error {
	if userID == "" {
		return errors.New("user ID cannot be empty")
	}
	if passwordHash == "" {
		return errors.New("password hash cannot be empty")
	}

	query := `
		INSERT INTO password_history (user_id, password_hash, created_at)
		VALUES (?, ?, ?)
	`

	_, err := s.sqlite.DB.ExecContext(ctx, query, userID, passwordHash, time.Now().UTC())
	if err != nil {
		return fmt.Errorf("failed to add password to history: %w", err)
	}

	s.logger.Debugf("Added password to history for user: %s", userID)

	// Automatically prune history to keep only MaxHistory entries
	// This is done asynchronously to avoid blocking the request
	go func() {
		pruneCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		// Get max history from config (default 5)
		// For now, use default of 5. In production, this should come from config
		maxHistory := 5
		if err := s.PruneHistory(pruneCtx, userID, maxHistory); err != nil {
			s.logger.Warnf("Failed to prune password history for user %s: %v", userID, err)
		}
	}()

	return nil
}

// GetPasswordHistory retrieves the last N password hashes for a user
// TASK 38.3: Get password history for validation
func (s *SQLitePasswordHistoryStorage) GetPasswordHistory(ctx context.Context, userID string, limit int) ([]string, error) {
	if userID == "" {
		return nil, errors.New("user ID cannot be empty")
	}

	if limit <= 0 {
		limit = 5 // Default limit
	}

	query := `
		SELECT password_hash
		FROM password_history
		WHERE user_id = ?
		ORDER BY created_at DESC
		LIMIT ?
	`

	rows, err := s.sqlite.ReadDB.QueryContext(ctx, query, userID, limit)
	if err != nil {
		return nil, fmt.Errorf("failed to get password history: %w", err)
	}
	defer rows.Close()

	var history []string
	for rows.Next() {
		var hash string
		if err := rows.Scan(&hash); err != nil {
			return nil, fmt.Errorf("failed to scan password history: %w", err)
		}
		history = append(history, hash)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating password history: %w", err)
	}

	return history, nil
}

// PruneHistory removes old password history entries, keeping only the most recent N entries
// TASK 38.3: Automatically prune history to MaxHistory entries
func (s *SQLitePasswordHistoryStorage) PruneHistory(ctx context.Context, userID string, maxHistory int) error {
	if userID == "" {
		return errors.New("user ID cannot be empty")
	}

	if maxHistory <= 0 {
		return nil // No pruning if maxHistory is 0 or negative
	}

	// Delete all entries except the most recent maxHistory entries
	// SQLite doesn't support DELETE with LIMIT directly, so we use a subquery
	query := `
		DELETE FROM password_history
		WHERE user_id = ?
		AND id NOT IN (
			SELECT id
			FROM password_history
			WHERE user_id = ?
			ORDER BY created_at DESC
			LIMIT ?
		)
	`

	result, err := s.sqlite.DB.ExecContext(ctx, query, userID, userID, maxHistory)
	if err != nil {
		return fmt.Errorf("failed to prune password history: %w", err)
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected > 0 {
		s.logger.Debugf("Pruned %d old password history entries for user: %s", rowsAffected, userID)
	}

	return nil
}

// CheckPasswordInHistory checks if a password hash exists in the user's password history
// TASK 38.3: Check if password was used recently (helper function for validation)
func (s *SQLitePasswordHistoryStorage) CheckPasswordInHistory(ctx context.Context, userID, passwordHash string, maxHistory int) (bool, error) {
	if userID == "" || passwordHash == "" {
		return false, errors.New("user ID and password hash cannot be empty")
	}

	history, err := s.GetPasswordHistory(ctx, userID, maxHistory)
	if err != nil {
		return false, err
	}

	// Check if the password hash exists in history
	for _, hash := range history {
		if hash == passwordHash {
			return true, nil
		}
	}

	return false, nil
}

// PasswordHistoryChecker interface for password history validation
// TASK 38.3: Interface for checking password history (used by util.PasswordPolicy)
type PasswordHistoryChecker interface {
	GetPasswordHistory(ctx context.Context, userID string, limit int) ([]string, error)
	CheckPasswordInHistory(ctx context.Context, userID, passwordHash string, maxHistory int) (bool, error)
}
