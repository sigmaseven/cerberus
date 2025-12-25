package storage

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"
)

// SQLiteSavedSearch represents a saved search query
type SQLiteSavedSearch struct {
	ID          string                 `json:"id" db:"id"`
	Name        string                 `json:"name" db:"name"`
	Description string                 `json:"description" db:"description"`
	Query       string                 `json:"query" db:"query"`
	Filters     map[string]interface{} `json:"filters" db:"filters"`
	CreatedBy   string                 `json:"created_by" db:"created_by"`
	CreatedAt   time.Time              `json:"created_at" db:"created_at"`
	UpdatedAt   time.Time              `json:"updated_at" db:"updated_at"`
	IsPublic    bool                   `json:"is_public" db:"is_public"`
	Tags        []string               `json:"tags" db:"tags"`
	UsageCount  int                    `json:"usage_count" db:"usage_count"`
}

// SavedSearch is a type alias for SQLiteSavedSearch for API compatibility
type SavedSearch = SQLiteSavedSearch

// SQLiteSavedSearchStorage interface for saved search operations
type SQLiteSavedSearchStorageInterface interface {
	GetAll(isPublic bool, createdBy string) ([]SQLiteSavedSearch, error)
	Get(id string) (*SQLiteSavedSearch, error)
	Create(search *SQLiteSavedSearch) error
	Update(id string, search *SQLiteSavedSearch) error
	Delete(id string) error
	IncrementUsageCount(id string) error
}

// SQLiteSavedSearchStorage handles saved search CRUD operations in SQLite
type SQLiteSavedSearchStorage struct {
	db     *SQLite
	logger *zap.SugaredLogger
}

// NewSQLiteSavedSearchStorage creates a new SQLite saved search storage handler
func NewSQLiteSavedSearchStorage(db *SQLite, logger *zap.SugaredLogger) (*SQLiteSavedSearchStorage, error) {
	storage := &SQLiteSavedSearchStorage{
		db:     db,
		logger: logger,
	}

	// Ensure table exists
	if err := storage.ensureTable(); err != nil {
		return nil, fmt.Errorf("failed to ensure saved_searches table: %w", err)
	}

	return storage, nil
}

// ensureTable creates the saved_searches table if it doesn't exist
func (s *SQLiteSavedSearchStorage) ensureTable() error {
	query := `
	CREATE TABLE IF NOT EXISTS saved_searches (
		id TEXT PRIMARY KEY,
		name TEXT NOT NULL,
		description TEXT,
		query TEXT,
		filters TEXT,
		created_by TEXT NOT NULL,
		created_at DATETIME NOT NULL,
		updated_at DATETIME NOT NULL,
		is_public BOOLEAN NOT NULL DEFAULT 0,
		tags TEXT,
		usage_count INTEGER NOT NULL DEFAULT 0
	);

	CREATE INDEX IF NOT EXISTS idx_saved_searches_created_by ON saved_searches(created_by);
	CREATE INDEX IF NOT EXISTS idx_saved_searches_is_public ON saved_searches(is_public);
	CREATE INDEX IF NOT EXISTS idx_saved_searches_created_at ON saved_searches(created_at DESC);
	`

	_, err := s.db.DB.Exec(query)
	if err != nil {
		return fmt.Errorf("failed to create saved_searches table: %w", err)
	}

	s.logger.Info("Saved searches table ensured in SQLite")
	return nil
}

// GetAll retrieves all saved searches with optional filtering
func (s *SQLiteSavedSearchStorage) GetAll(isPublic bool, createdBy string) ([]SQLiteSavedSearch, error) {
	query := "SELECT id, name, description, query, filters, created_by, created_at, updated_at, is_public, tags, usage_count FROM saved_searches WHERE 1=1"
	args := []interface{}{}

	if isPublic {
		query += " AND is_public = ?"
		args = append(args, 1)
	}
	if createdBy != "" {
		query += " AND created_by = ?"
		args = append(args, createdBy)
	}

	query += " ORDER BY created_at DESC"

	rows, err := s.db.ReadDB.Query(query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to query saved searches: %w", err)
	}
	defer rows.Close()

	// Initialize with make() to ensure non-nil slice for JSON serialization.
	// nil slices serialize to null, breaking frontend contract expecting [].
	searches := make([]SQLiteSavedSearch, 0)
	for rows.Next() {
		var search SQLiteSavedSearch
		var filtersJSON, tagsJSON string

		err := rows.Scan(
			&search.ID,
			&search.Name,
			&search.Description,
			&search.Query,
			&filtersJSON,
			&search.CreatedBy,
			&search.CreatedAt,
			&search.UpdatedAt,
			&search.IsPublic,
			&tagsJSON,
			&search.UsageCount,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan saved search: %w", err)
		}

		// Deserialize filters
		if filtersJSON != "" {
			if err := json.Unmarshal([]byte(filtersJSON), &search.Filters); err != nil {
				s.logger.Warnf("Failed to unmarshal filters for search %s: %v", search.ID, err)
			}
		}

		// Deserialize tags
		if tagsJSON != "" {
			if err := json.Unmarshal([]byte(tagsJSON), &search.Tags); err != nil {
				s.logger.Warnf("Failed to unmarshal tags for search %s: %v", search.ID, err)
			}
		}

		searches = append(searches, search)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating saved searches: %w", err)
	}

	return searches, nil
}

// Get retrieves a single saved search by ID
func (s *SQLiteSavedSearchStorage) Get(id string) (*SQLiteSavedSearch, error) {
	query := "SELECT id, name, description, query, filters, created_by, created_at, updated_at, is_public, tags, usage_count FROM saved_searches WHERE id = ?"

	var search SQLiteSavedSearch
	var filtersJSON, tagsJSON string

	err := s.db.ReadDB.QueryRow(query, id).Scan(
		&search.ID,
		&search.Name,
		&search.Description,
		&search.Query,
		&filtersJSON,
		&search.CreatedBy,
		&search.CreatedAt,
		&search.UpdatedAt,
		&search.IsPublic,
		&tagsJSON,
		&search.UsageCount,
	)

	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("saved search not found")
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get saved search: %w", err)
	}

	// Deserialize filters
	if filtersJSON != "" {
		if err := json.Unmarshal([]byte(filtersJSON), &search.Filters); err != nil {
			s.logger.Warnf("Failed to unmarshal filters for search %s: %v", search.ID, err)
		}
	}

	// Deserialize tags
	if tagsJSON != "" {
		if err := json.Unmarshal([]byte(tagsJSON), &search.Tags); err != nil {
			s.logger.Warnf("Failed to unmarshal tags for search %s: %v", search.ID, err)
		}
	}

	return &search, nil
}

// Create creates a new saved search
func (s *SQLiteSavedSearchStorage) Create(search *SQLiteSavedSearch) error {
	// Generate ID if not provided
	if search.ID == "" {
		search.ID = uuid.New().String()
	}

	// Set timestamps
	now := time.Now()
	search.CreatedAt = now
	search.UpdatedAt = now
	search.UsageCount = 0

	// Serialize filters and tags
	filtersJSON, err := json.Marshal(search.Filters)
	if err != nil {
		return fmt.Errorf("failed to marshal filters: %w", err)
	}

	tagsJSON, err := json.Marshal(search.Tags)
	if err != nil {
		return fmt.Errorf("failed to marshal tags: %w", err)
	}

	query := `
		INSERT INTO saved_searches (id, name, description, query, filters, created_by, created_at, updated_at, is_public, tags, usage_count)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`

	_, err = s.db.DB.Exec(query,
		search.ID,
		search.Name,
		search.Description,
		search.Query,
		string(filtersJSON),
		search.CreatedBy,
		search.CreatedAt,
		search.UpdatedAt,
		search.IsPublic,
		string(tagsJSON),
		search.UsageCount,
	)

	if err != nil {
		return fmt.Errorf("failed to create saved search: %w", err)
	}

	return nil
}

// Update updates an existing saved search
func (s *SQLiteSavedSearchStorage) Update(id string, search *SQLiteSavedSearch) error {
	// Update timestamp
	search.UpdatedAt = time.Now()

	// Serialize filters and tags
	filtersJSON, err := json.Marshal(search.Filters)
	if err != nil {
		return fmt.Errorf("failed to marshal filters: %w", err)
	}

	tagsJSON, err := json.Marshal(search.Tags)
	if err != nil {
		return fmt.Errorf("failed to marshal tags: %w", err)
	}

	query := `
		UPDATE saved_searches
		SET name = ?, description = ?, query = ?, filters = ?, is_public = ?, tags = ?, updated_at = ?
		WHERE id = ?
	`

	result, err := s.db.DB.Exec(query,
		search.Name,
		search.Description,
		search.Query,
		string(filtersJSON),
		search.IsPublic,
		string(tagsJSON),
		search.UpdatedAt,
		id,
	)

	if err != nil {
		return fmt.Errorf("failed to update saved search: %w", err)
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rows == 0 {
		return fmt.Errorf("saved search not found")
	}

	return nil
}

// Delete deletes a saved search by ID
func (s *SQLiteSavedSearchStorage) Delete(id string) error {
	query := "DELETE FROM saved_searches WHERE id = ?"

	result, err := s.db.DB.Exec(query, id)
	if err != nil {
		return fmt.Errorf("failed to delete saved search: %w", err)
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rows == 0 {
		return fmt.Errorf("saved search not found")
	}

	return nil
}

// IncrementUsageCount increments the usage count for a saved search
func (s *SQLiteSavedSearchStorage) IncrementUsageCount(id string) error {
	query := "UPDATE saved_searches SET usage_count = usage_count + 1 WHERE id = ?"

	_, err := s.db.DB.Exec(query, id)
	if err != nil {
		return fmt.Errorf("failed to increment usage count: %w", err)
	}

	return nil
}
