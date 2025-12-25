package storage

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"cerberus/core"
	"go.uber.org/zap"
)

// SQLiteActionStorage handles action persistence in SQLite
type SQLiteActionStorage struct {
	sqlite *SQLite
	logger *zap.SugaredLogger
}

// NewSQLiteActionStorage creates a new SQLite action storage handler
func NewSQLiteActionStorage(sqlite *SQLite, logger *zap.SugaredLogger) *SQLiteActionStorage {
	return &SQLiteActionStorage{
		sqlite: sqlite,
		logger: logger,
	}
}

// GetActions retrieves all actions
func (sas *SQLiteActionStorage) GetActions() ([]core.Action, error) {
	query := `
		SELECT id, type, config, created_at, updated_at
		FROM actions
		ORDER BY created_at DESC
	`

	rows, err := sas.sqlite.ReadDB.Query(query)
	if err != nil {
		return nil, fmt.Errorf("failed to query actions: %w", err)
	}
	defer rows.Close()

	// Initialize with make() to ensure non-nil slice for JSON serialization.
	// nil slices serialize to null, breaking frontend contract expecting [].
	actions := make([]core.Action, 0)
	for rows.Next() {
		var action core.Action
		var configJSON string
		var createdAt, updatedAt string

		err := rows.Scan(
			&action.ID,
			&action.Type,
			&configJSON,
			&createdAt,
			&updatedAt,
		)

		if err != nil {
			return nil, fmt.Errorf("failed to scan action: %w", err)
		}

		// Parse JSON config
		if err := json.Unmarshal([]byte(configJSON), &action.Config); err != nil {
			sas.logger.Warnf("Failed to parse config for action %s: %v", action.ID, err)
			continue
		}

		// Parse timestamps
		action.CreatedAt, _ = time.Parse(time.RFC3339, createdAt)
		action.UpdatedAt, _ = time.Parse(time.RFC3339, updatedAt)

		actions = append(actions, action)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating actions: %w", err)
	}

	return actions, nil
}

// GetAction retrieves a single action by ID
func (sas *SQLiteActionStorage) GetAction(id string) (*core.Action, error) {
	query := `
		SELECT id, type, config, created_at, updated_at
		FROM actions
		WHERE id = ?
	`

	var action core.Action
	var configJSON string
	var createdAt, updatedAt string

	err := sas.sqlite.ReadDB.QueryRow(query, id).Scan(
		&action.ID,
		&action.Type,
		&configJSON,
		&createdAt,
		&updatedAt,
	)

	if err == sql.ErrNoRows {
		return nil, ErrActionNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get action: %w", err)
	}

	// Parse JSON config
	if err := json.Unmarshal([]byte(configJSON), &action.Config); err != nil {
		return nil, fmt.Errorf("failed to parse config: %w", err)
	}

	// Parse timestamps
	action.CreatedAt, _ = time.Parse(time.RFC3339, createdAt)
	action.UpdatedAt, _ = time.Parse(time.RFC3339, updatedAt)

	return &action, nil
}

// CreateAction creates a new action
func (sas *SQLiteActionStorage) CreateAction(action *core.Action) error {
	// Check if action already exists
	existing, err := sas.GetAction(action.ID)
	if err != nil && !errors.Is(err, ErrActionNotFound) {
		return fmt.Errorf("failed to check existing action: %w", err)
	}
	if existing != nil {
		return fmt.Errorf("action with ID %s already exists", action.ID)
	}

	// Serialize config
	configJSON, err := json.Marshal(action.Config)
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}

	// Set timestamps
	now := time.Now()
	action.CreatedAt = now
	action.UpdatedAt = now

	query := `
		INSERT INTO actions (id, type, config, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?)
	`

	// TASK 143.2: Use write pool for INSERT operations
	_, err = sas.sqlite.WriteDB.Exec(query,
		action.ID,
		action.Type,
		string(configJSON),
		action.CreatedAt.Format(time.RFC3339),
		action.UpdatedAt.Format(time.RFC3339),
	)

	if err != nil {
		return fmt.Errorf("failed to insert action: %w", err)
	}

	sas.logger.Infof("Created action %s", action.ID)
	return nil
}

// UpdateAction updates an existing action
func (sas *SQLiteActionStorage) UpdateAction(id string, action *core.Action) error {
	// Check if action exists
	existing, err := sas.GetAction(id)
	if err != nil {
		if errors.Is(err, ErrActionNotFound) {
			return ErrActionNotFound
		}
		return fmt.Errorf("failed to check existing action: %w", err)
	}

	// Preserve creation time
	action.CreatedAt = existing.CreatedAt
	action.UpdatedAt = time.Now()

	// Serialize config
	configJSON, err := json.Marshal(action.Config)
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}

	query := `
		UPDATE actions
		SET type = ?, config = ?, updated_at = ?
		WHERE id = ?
	`

	// TASK 143.2: Use write pool for UPDATE operations
	result, err := sas.sqlite.WriteDB.Exec(query,
		action.Type,
		string(configJSON),
		action.UpdatedAt.Format(time.RFC3339),
		id,
	)

	if err != nil {
		return fmt.Errorf("failed to update action: %w", err)
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return ErrActionNotFound
	}

	sas.logger.Infof("Updated action %s", id)
	return nil
}

// DeleteAction deletes an action
// TASK 143.2: Use write pool for DELETE operations
func (sas *SQLiteActionStorage) DeleteAction(id string) error {
	result, err := sas.sqlite.WriteDB.Exec("DELETE FROM actions WHERE id = ?", id)
	if err != nil {
		return fmt.Errorf("failed to delete action: %w", err)
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return ErrActionNotFound
	}

	sas.logger.Infof("Deleted action %s", id)
	return nil
}

// EnsureIndexes ensures database indexes exist (indexes created in schema)
func (sas *SQLiteActionStorage) EnsureIndexes() error {
	// Indexes are created in the schema during table creation
	return nil
}
