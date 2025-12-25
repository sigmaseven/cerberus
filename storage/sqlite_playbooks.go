package storage

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"cerberus/soar"

	"go.uber.org/zap"
)

// SQLitePlaybookStorage handles playbook persistence in SQLite
type SQLitePlaybookStorage struct {
	db     *SQLite
	logger *zap.SugaredLogger
}

// NewSQLitePlaybookStorage creates a new SQLite playbook storage handler
func NewSQLitePlaybookStorage(db *SQLite, logger *zap.SugaredLogger) (*SQLitePlaybookStorage, error) {
	storage := &SQLitePlaybookStorage{
		db:     db,
		logger: logger,
	}

	if err := storage.ensureTable(); err != nil {
		return nil, fmt.Errorf("failed to ensure playbooks table: %w", err)
	}

	return storage, nil
}

// ensureTable creates the playbooks table if it doesn't exist
func (sps *SQLitePlaybookStorage) ensureTable() error {
	query := `
	CREATE TABLE IF NOT EXISTS playbooks (
		id TEXT PRIMARY KEY,
		name TEXT NOT NULL UNIQUE,
		description TEXT,
		enabled INTEGER NOT NULL DEFAULT 1,
		priority INTEGER NOT NULL DEFAULT 0,
		triggers TEXT,    -- JSON array
		steps TEXT,       -- JSON array
		tags TEXT,        -- JSON array
		created_by TEXT,
		created_at DATETIME NOT NULL,
		updated_at DATETIME NOT NULL
	);

	CREATE INDEX IF NOT EXISTS idx_playbooks_enabled ON playbooks(enabled);
	CREATE INDEX IF NOT EXISTS idx_playbooks_priority ON playbooks(priority DESC);
	CREATE INDEX IF NOT EXISTS idx_playbooks_created_at ON playbooks(created_at DESC);
	CREATE INDEX IF NOT EXISTS idx_playbooks_name ON playbooks(name);
	`

	_, err := sps.db.DB.Exec(query)
	if err != nil {
		return fmt.Errorf("failed to create playbooks table: %w", err)
	}

	sps.logger.Info("Playbooks table ensured in SQLite")
	return nil
}

// CreatePlaybook creates a new playbook
func (sps *SQLitePlaybookStorage) CreatePlaybook(playbook *soar.Playbook) error {
	// Validate ID is non-empty
	if playbook.ID == "" {
		return errors.New("playbook ID cannot be empty")
	}

	// Use transaction for atomicity
	return sps.db.WithTransaction(func(tx *sql.Tx) error {
		// Check name uniqueness within transaction
		var count int
		err := tx.QueryRow("SELECT COUNT(*) FROM playbooks WHERE name = ?", playbook.Name).Scan(&count)
		if err != nil {
			return fmt.Errorf("failed to check name uniqueness: %w", err)
		}
		if count > 0 {
			return ErrPlaybookNameExists
		}

		// Set timestamps
		now := time.Now()
		playbook.CreatedAt = now
		playbook.UpdatedAt = now

		// Serialize JSON fields
		triggersJSON, err := json.Marshal(playbook.Triggers)
		if err != nil {
			return fmt.Errorf("failed to marshal triggers: %w", err)
		}
		stepsJSON, err := json.Marshal(playbook.Steps)
		if err != nil {
			return fmt.Errorf("failed to marshal steps: %w", err)
		}
		tagsJSON, err := json.Marshal(playbook.Tags)
		if err != nil {
			return fmt.Errorf("failed to marshal tags: %w", err)
		}

		query := `
			INSERT INTO playbooks (id, name, description, enabled, priority, triggers, steps, tags, created_by, created_at, updated_at)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		`

		_, err = tx.Exec(query,
			playbook.ID,
			playbook.Name,
			playbook.Description,
			playbook.Enabled,
			playbook.Priority,
			nullIfEmpty(string(triggersJSON)),
			nullIfEmpty(string(stepsJSON)),
			nullIfEmpty(string(tagsJSON)),
			nullIfEmpty(playbook.CreatedBy),
			playbook.CreatedAt.Format(time.RFC3339),
			playbook.UpdatedAt.Format(time.RFC3339),
		)

		if err != nil {
			// Check for UNIQUE constraint violation
			if strings.Contains(err.Error(), "UNIQUE constraint failed") {
				return ErrPlaybookNameExists
			}
			return fmt.Errorf("failed to insert playbook: %w", err)
		}

		sps.logger.Infof("Created playbook %s (%s)", playbook.Name, playbook.ID)
		return nil
	})
}

// GetPlaybook retrieves a single playbook by ID
func (sps *SQLitePlaybookStorage) GetPlaybook(id string) (*soar.Playbook, error) {
	// Validate ID is non-empty
	if id == "" {
		return nil, errors.New("playbook ID cannot be empty")
	}

	query := `
		SELECT id, name, description, enabled, priority, triggers, steps, tags, created_by, created_at, updated_at
		FROM playbooks
		WHERE id = ?
	`

	var playbook soar.Playbook
	var triggersJSON, stepsJSON, tagsJSON, createdBy sql.NullString
	var createdAt, updatedAt string

	err := sps.db.ReadDB.QueryRow(query, id).Scan(
		&playbook.ID,
		&playbook.Name,
		&playbook.Description,
		&playbook.Enabled,
		&playbook.Priority,
		&triggersJSON,
		&stepsJSON,
		&tagsJSON,
		&createdBy,
		&createdAt,
		&updatedAt,
	)

	if err == sql.ErrNoRows {
		return nil, ErrPlaybookNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get playbook: %w", err)
	}

	// Parse JSON fields
	if triggersJSON.Valid && triggersJSON.String != "" {
		if err := json.Unmarshal([]byte(triggersJSON.String), &playbook.Triggers); err != nil {
			return nil, fmt.Errorf("failed to parse triggers: %w", err)
		}
	}
	if stepsJSON.Valid && stepsJSON.String != "" {
		if err := json.Unmarshal([]byte(stepsJSON.String), &playbook.Steps); err != nil {
			return nil, fmt.Errorf("failed to parse steps: %w", err)
		}
	}
	if tagsJSON.Valid && tagsJSON.String != "" {
		if err := json.Unmarshal([]byte(tagsJSON.String), &playbook.Tags); err != nil {
			return nil, fmt.Errorf("failed to parse tags: %w", err)
		}
	}
	if createdBy.Valid {
		playbook.CreatedBy = createdBy.String
	}

	// Parse timestamps with error handling
	parsedCreatedAt, err := time.Parse(time.RFC3339, createdAt)
	if err != nil {
		return nil, fmt.Errorf("corrupted created_at timestamp for playbook %s: %w", playbook.ID, err)
	}
	playbook.CreatedAt = parsedCreatedAt

	parsedUpdatedAt, err := time.Parse(time.RFC3339, updatedAt)
	if err != nil {
		return nil, fmt.Errorf("corrupted updated_at timestamp for playbook %s: %w", playbook.ID, err)
	}
	playbook.UpdatedAt = parsedUpdatedAt

	return &playbook, nil
}

// GetPlaybooks retrieves playbooks with pagination
func (sps *SQLitePlaybookStorage) GetPlaybooks(limit, offset int) ([]soar.Playbook, error) {
	query := `
		SELECT id, name, description, enabled, priority, triggers, steps, tags, created_by, created_at, updated_at
		FROM playbooks
		ORDER BY priority DESC, created_at DESC
		LIMIT ? OFFSET ?
	`

	rows, err := sps.db.ReadDB.Query(query, limit, offset)
	if err != nil {
		return nil, fmt.Errorf("failed to query playbooks: %w", err)
	}
	defer rows.Close()

	return sps.scanPlaybooks(rows)
}

// GetAllPlaybooks retrieves all playbooks
func (sps *SQLitePlaybookStorage) GetAllPlaybooks() ([]soar.Playbook, error) {
	query := `
		SELECT id, name, description, enabled, priority, triggers, steps, tags, created_by, created_at, updated_at
		FROM playbooks
		ORDER BY priority DESC, created_at DESC
	`

	rows, err := sps.db.ReadDB.Query(query)
	if err != nil {
		return nil, fmt.Errorf("failed to query all playbooks: %w", err)
	}
	defer rows.Close()

	return sps.scanPlaybooks(rows)
}

// GetPlaybookCount returns total playbook count
func (sps *SQLitePlaybookStorage) GetPlaybookCount() (int64, error) {
	var count int64
	err := sps.db.ReadDB.QueryRow("SELECT COUNT(*) FROM playbooks").Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("failed to count playbooks: %w", err)
	}
	return count, nil
}

// UpdatePlaybook updates an existing playbook
func (sps *SQLitePlaybookStorage) UpdatePlaybook(id string, playbook *soar.Playbook) error {
	// Validate ID is non-empty
	if id == "" {
		return errors.New("playbook ID cannot be empty")
	}

	return sps.db.WithTransaction(func(tx *sql.Tx) error {
		// Check if playbook exists
		var existingCreatedAt string
		err := tx.QueryRow("SELECT created_at FROM playbooks WHERE id = ?", id).Scan(&existingCreatedAt)
		if err == sql.ErrNoRows {
			return ErrPlaybookNotFound
		}
		if err != nil {
			return fmt.Errorf("failed to check existing playbook: %w", err)
		}

		// Check name uniqueness (excluding current playbook)
		var count int
		err = tx.QueryRow("SELECT COUNT(*) FROM playbooks WHERE name = ? AND id != ?", playbook.Name, id).Scan(&count)
		if err != nil {
			return fmt.Errorf("failed to check name uniqueness: %w", err)
		}
		if count > 0 {
			return ErrPlaybookNameExists
		}

		// Preserve creation time - fail fast on corrupted data
		parsedCreatedAt, err := time.Parse(time.RFC3339, existingCreatedAt)
		if err != nil {
			return fmt.Errorf("corrupted created_at timestamp in existing playbook %s: %w", id, err)
		}
		playbook.CreatedAt = parsedCreatedAt
		playbook.UpdatedAt = time.Now()

		// Serialize JSON fields
		triggersJSON, err := json.Marshal(playbook.Triggers)
		if err != nil {
			return fmt.Errorf("failed to marshal triggers: %w", err)
		}
		stepsJSON, err := json.Marshal(playbook.Steps)
		if err != nil {
			return fmt.Errorf("failed to marshal steps: %w", err)
		}
		tagsJSON, err := json.Marshal(playbook.Tags)
		if err != nil {
			return fmt.Errorf("failed to marshal tags: %w", err)
		}

		query := `
			UPDATE playbooks
			SET name = ?, description = ?, enabled = ?, priority = ?,
			    triggers = ?, steps = ?, tags = ?, created_by = ?, updated_at = ?
			WHERE id = ?
		`

		result, err := tx.Exec(query,
			playbook.Name,
			playbook.Description,
			playbook.Enabled,
			playbook.Priority,
			nullIfEmpty(string(triggersJSON)),
			nullIfEmpty(string(stepsJSON)),
			nullIfEmpty(string(tagsJSON)),
			nullIfEmpty(playbook.CreatedBy),
			playbook.UpdatedAt.Format(time.RFC3339),
			id,
		)

		if err != nil {
			if strings.Contains(err.Error(), "UNIQUE constraint failed") {
				return ErrPlaybookNameExists
			}
			return fmt.Errorf("failed to update playbook: %w", err)
		}

		rowsAffected, _ := result.RowsAffected()
		if rowsAffected == 0 {
			return ErrPlaybookNotFound
		}

		sps.logger.Infof("Updated playbook %s", id)
		return nil
	})
}

// DeletePlaybook deletes a playbook within a transaction for FK cascade safety
func (sps *SQLitePlaybookStorage) DeletePlaybook(id string) error {
	// Validate ID is non-empty
	if id == "" {
		return errors.New("playbook ID cannot be empty")
	}

	return sps.db.WithTransaction(func(tx *sql.Tx) error {
		result, err := tx.Exec("DELETE FROM playbooks WHERE id = ?", id)
		if err != nil {
			return fmt.Errorf("failed to delete playbook: %w", err)
		}

		rowsAffected, _ := result.RowsAffected()
		if rowsAffected == 0 {
			return ErrPlaybookNotFound
		}

		sps.logger.Infof("Deleted playbook %s", id)
		return nil
	})
}

// EnablePlaybook enables a playbook by ID within a transaction
func (sps *SQLitePlaybookStorage) EnablePlaybook(id string) error {
	// Validate ID is non-empty
	if id == "" {
		return errors.New("playbook ID cannot be empty")
	}

	return sps.db.WithTransaction(func(tx *sql.Tx) error {
		result, err := tx.Exec(
			"UPDATE playbooks SET enabled = 1, updated_at = ? WHERE id = ?",
			time.Now().Format(time.RFC3339),
			id,
		)
		if err != nil {
			return fmt.Errorf("failed to enable playbook: %w", err)
		}

		rowsAffected, _ := result.RowsAffected()
		if rowsAffected == 0 {
			return ErrPlaybookNotFound
		}

		sps.logger.Infof("Enabled playbook %s", id)
		return nil
	})
}

// DisablePlaybook disables a playbook by ID within a transaction
func (sps *SQLitePlaybookStorage) DisablePlaybook(id string) error {
	// Validate ID is non-empty
	if id == "" {
		return errors.New("playbook ID cannot be empty")
	}

	return sps.db.WithTransaction(func(tx *sql.Tx) error {
		result, err := tx.Exec(
			"UPDATE playbooks SET enabled = 0, updated_at = ? WHERE id = ?",
			time.Now().Format(time.RFC3339),
			id,
		)
		if err != nil {
			return fmt.Errorf("failed to disable playbook: %w", err)
		}

		rowsAffected, _ := result.RowsAffected()
		if rowsAffected == 0 {
			return ErrPlaybookNotFound
		}

		sps.logger.Infof("Disabled playbook %s", id)
		return nil
	})
}

// GetPlaybooksByStatus retrieves playbooks filtered by enabled status
func (sps *SQLitePlaybookStorage) GetPlaybooksByStatus(enabled bool) ([]soar.Playbook, error) {
	query := `
		SELECT id, name, description, enabled, priority, triggers, steps, tags, created_by, created_at, updated_at
		FROM playbooks
		WHERE enabled = ?
		ORDER BY priority DESC, created_at DESC
	`

	enabledInt := 0
	if enabled {
		enabledInt = 1
	}

	rows, err := sps.db.ReadDB.Query(query, enabledInt)
	if err != nil {
		return nil, fmt.Errorf("failed to query playbooks by status: %w", err)
	}
	defer rows.Close()

	return sps.scanPlaybooks(rows)
}

// GetPlaybooksByTag retrieves playbooks that have a specific tag
func (sps *SQLitePlaybookStorage) GetPlaybooksByTag(tag string) ([]soar.Playbook, error) {
	// Escape LIKE special characters
	escapedTag := tag
	escapedTag = strings.ReplaceAll(escapedTag, "\\", "\\\\")
	escapedTag = strings.ReplaceAll(escapedTag, "%", "\\%")
	escapedTag = strings.ReplaceAll(escapedTag, "_", "\\_")

	// Search for tag in JSON array
	query := `
		SELECT id, name, description, enabled, priority, triggers, steps, tags, created_by, created_at, updated_at
		FROM playbooks
		WHERE tags LIKE ? ESCAPE '\'
		ORDER BY priority DESC, created_at DESC
	`

	// Match tag as JSON string element
	pattern := "%\"" + escapedTag + "\"%"

	rows, err := sps.db.ReadDB.Query(query, pattern)
	if err != nil {
		return nil, fmt.Errorf("failed to query playbooks by tag: %w", err)
	}
	defer rows.Close()

	return sps.scanPlaybooks(rows)
}

// SearchPlaybooks searches playbooks by name or description
func (sps *SQLitePlaybookStorage) SearchPlaybooks(query string) ([]soar.Playbook, error) {
	// Escape LIKE special characters
	escapedQuery := query
	escapedQuery = strings.ReplaceAll(escapedQuery, "\\", "\\\\")
	escapedQuery = strings.ReplaceAll(escapedQuery, "%", "\\%")
	escapedQuery = strings.ReplaceAll(escapedQuery, "_", "\\_")

	searchQuery := `
		SELECT id, name, description, enabled, priority, triggers, steps, tags, created_by, created_at, updated_at
		FROM playbooks
		WHERE name LIKE ? ESCAPE '\' OR description LIKE ? ESCAPE '\'
		ORDER BY priority DESC, created_at DESC
	`

	searchPattern := "%" + escapedQuery + "%"

	rows, err := sps.db.ReadDB.Query(searchQuery, searchPattern, searchPattern)
	if err != nil {
		return nil, fmt.Errorf("failed to search playbooks: %w", err)
	}
	defer rows.Close()

	return sps.scanPlaybooks(rows)
}

// PlaybookNameExists checks if a playbook with the given name exists
func (sps *SQLitePlaybookStorage) PlaybookNameExists(name string, excludeID string) (bool, error) {
	var query string
	var args []interface{}

	if excludeID == "" {
		query = "SELECT COUNT(*) FROM playbooks WHERE name = ?"
		args = []interface{}{name}
	} else {
		query = "SELECT COUNT(*) FROM playbooks WHERE name = ? AND id != ?"
		args = []interface{}{name, excludeID}
	}

	var count int
	err := sps.db.ReadDB.QueryRow(query, args...).Scan(&count)
	if err != nil {
		return false, fmt.Errorf("failed to check playbook name: %w", err)
	}

	return count > 0, nil
}

// GetPlaybookStats returns aggregated playbook statistics
func (sps *SQLitePlaybookStorage) GetPlaybookStats() (*PlaybookStats, error) {
	stats := &PlaybookStats{}

	// Get total count
	err := sps.db.ReadDB.QueryRow("SELECT COUNT(*) FROM playbooks").Scan(&stats.TotalPlaybooks)
	if err != nil {
		return nil, fmt.Errorf("failed to count total playbooks: %w", err)
	}

	// Get enabled count
	err = sps.db.ReadDB.QueryRow("SELECT COUNT(*) FROM playbooks WHERE enabled = 1").Scan(&stats.EnabledPlaybooks)
	if err != nil {
		return nil, fmt.Errorf("failed to count enabled playbooks: %w", err)
	}

	// Calculate disabled count
	stats.DisabledPlaybooks = stats.TotalPlaybooks - stats.EnabledPlaybooks

	return stats, nil
}

// EnsureIndexes ensures database indexes exist (indexes created in schema)
func (sps *SQLitePlaybookStorage) EnsureIndexes() error {
	// Indexes are created in the schema during table creation
	return nil
}

// scanPlaybooks is a helper to scan multiple playbooks from query results
func (sps *SQLitePlaybookStorage) scanPlaybooks(rows *sql.Rows) ([]soar.Playbook, error) {
	// Initialize with make() to ensure non-nil slice for JSON serialization
	playbooks := make([]soar.Playbook, 0)

	for rows.Next() {
		var playbook soar.Playbook
		var triggersJSON, stepsJSON, tagsJSON, createdBy sql.NullString
		var createdAt, updatedAt string

		err := rows.Scan(
			&playbook.ID,
			&playbook.Name,
			&playbook.Description,
			&playbook.Enabled,
			&playbook.Priority,
			&triggersJSON,
			&stepsJSON,
			&tagsJSON,
			&createdBy,
			&createdAt,
			&updatedAt,
		)

		if err != nil {
			return nil, fmt.Errorf("failed to scan playbook: %w", err)
		}

		// Parse JSON fields - fail-fast on corruption to maintain data integrity
		if triggersJSON.Valid && triggersJSON.String != "" {
			if err := json.Unmarshal([]byte(triggersJSON.String), &playbook.Triggers); err != nil {
				return nil, fmt.Errorf("corrupted triggers field for playbook %s: %w", playbook.ID, err)
			}
		}
		if stepsJSON.Valid && stepsJSON.String != "" {
			if err := json.Unmarshal([]byte(stepsJSON.String), &playbook.Steps); err != nil {
				return nil, fmt.Errorf("corrupted steps field for playbook %s: %w", playbook.ID, err)
			}
		}
		if tagsJSON.Valid && tagsJSON.String != "" {
			if err := json.Unmarshal([]byte(tagsJSON.String), &playbook.Tags); err != nil {
				return nil, fmt.Errorf("corrupted tags field for playbook %s: %w", playbook.ID, err)
			}
		}
		if createdBy.Valid {
			playbook.CreatedBy = createdBy.String
		}

		// Parse timestamps with error handling
		parsedCreatedAt, err := time.Parse(time.RFC3339, createdAt)
		if err != nil {
			return nil, fmt.Errorf("corrupted created_at timestamp for playbook %s: %w", playbook.ID, err)
		}
		playbook.CreatedAt = parsedCreatedAt

		parsedUpdatedAt, err := time.Parse(time.RFC3339, updatedAt)
		if err != nil {
			return nil, fmt.Errorf("corrupted updated_at timestamp for playbook %s: %w", playbook.ID, err)
		}
		playbook.UpdatedAt = parsedUpdatedAt

		playbooks = append(playbooks, playbook)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating playbooks: %w", err)
	}

	return playbooks, nil
}

// Verify interface implementation at compile time
var _ PlaybookStorageInterface = (*SQLitePlaybookStorage)(nil)

// Ensure sentinel errors are properly used
var (
	_ = errors.Is(ErrPlaybookNotFound, ErrPlaybookNotFound)
	_ = errors.Is(ErrPlaybookNameExists, ErrPlaybookNameExists)
)
