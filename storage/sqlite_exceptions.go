package storage

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"cerberus/core"

	"github.com/google/uuid"
)

// SQLiteExceptionStorage implements ExceptionStorageInterface for SQLite
type SQLiteExceptionStorage struct {
	sqlite *SQLite
}

// NewSQLiteExceptionStorage creates a new SQLite exception storage
func NewSQLiteExceptionStorage(sqlite *SQLite) *SQLiteExceptionStorage {
	return &SQLiteExceptionStorage{sqlite: sqlite}
}

// EnsureIndexes creates necessary indexes for exception table
func (s *SQLiteExceptionStorage) EnsureIndexes() error {
	indexes := []string{
		`CREATE INDEX IF NOT EXISTS idx_exceptions_rule_id ON exceptions(rule_id)`,
		`CREATE INDEX IF NOT EXISTS idx_exceptions_enabled ON exceptions(enabled)`,
		`CREATE INDEX IF NOT EXISTS idx_exceptions_priority ON exceptions(priority)`,
		`CREATE INDEX IF NOT EXISTS idx_exceptions_type ON exceptions(type)`,
		`CREATE INDEX IF NOT EXISTS idx_exceptions_expires_at ON exceptions(expires_at)`,
	}

	for _, indexSQL := range indexes {
		if _, err := s.sqlite.WriteDB.Exec(indexSQL); err != nil {
			return fmt.Errorf("failed to create index: %w", err)
		}
	}

	return nil
}

// CreateException creates a new exception
func (s *SQLiteExceptionStorage) CreateException(exception *core.Exception) error {
	if exception.ID == "" {
		exception.ID = uuid.New().String()
	}

	now := time.Now()
	exception.CreatedAt = now
	exception.UpdatedAt = now

	if err := exception.Validate(); err != nil {
		return err
	}

	tagsJSON, err := json.Marshal(exception.Tags)
	if err != nil {
		return fmt.Errorf("failed to marshal tags: %w", err)
	}

	query := `
		INSERT INTO exceptions (
			id, name, description, rule_id, type, condition_type, condition,
			new_severity, enabled, priority, expires_at, hit_count, last_hit,
			created_at, updated_at, created_by, justification, tags
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`

	_, err = s.sqlite.WriteDB.Exec(query,
		exception.ID,
		exception.Name,
		exception.Description,
		exception.RuleID,
		string(exception.Type),
		string(exception.ConditionType),
		exception.Condition,
		exception.NewSeverity,
		exception.Enabled,
		exception.Priority,
		exception.ExpiresAt,
		exception.HitCount,
		exception.LastHit,
		exception.CreatedAt,
		exception.UpdatedAt,
		exception.CreatedBy,
		exception.Justification,
		string(tagsJSON),
	)

	if err != nil {
		return fmt.Errorf("failed to create exception: %w", err)
	}

	return nil
}

// GetException retrieves a single exception by ID
func (s *SQLiteExceptionStorage) GetException(id string) (*core.Exception, error) {
	query := `
		SELECT id, name, description, rule_id, type, condition_type, condition,
			   new_severity, enabled, priority, expires_at, hit_count, last_hit,
			   created_at, updated_at, created_by, justification, tags
		FROM exceptions
		WHERE id = ?
	`

	exception, err := s.scanException(s.sqlite.ReadDB.QueryRow(query, id))
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("exception not found")
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get exception: %w", err)
	}

	return exception, nil
}

// GetAllExceptions retrieves all exceptions with optional filtering
func (s *SQLiteExceptionStorage) GetAllExceptions(filters *core.ExceptionFilters) ([]core.Exception, int64, error) {
	if filters == nil {
		filters = &core.ExceptionFilters{
			Page:  1,
			Limit: 100,
		}
	}

	// Build WHERE clause
	whereClauses := []string{"1=1"}
	args := []interface{}{}

	if filters.RuleID != "" {
		whereClauses = append(whereClauses, "rule_id = ?")
		args = append(args, filters.RuleID)
	}

	if filters.Type != "" {
		whereClauses = append(whereClauses, "type = ?")
		args = append(args, string(filters.Type))
	}

	if filters.Enabled != nil {
		whereClauses = append(whereClauses, "enabled = ?")
		args = append(args, *filters.Enabled)
	}

	if filters.Expired != nil {
		if *filters.Expired {
			whereClauses = append(whereClauses, "expires_at IS NOT NULL AND expires_at < ?")
			args = append(args, time.Now())
		} else {
			whereClauses = append(whereClauses, "(expires_at IS NULL OR expires_at >= ?)")
			args = append(args, time.Now())
		}
	}

	if filters.Search != "" {
		whereClauses = append(whereClauses, "(name LIKE ? OR description LIKE ? OR justification LIKE ?)")
		searchPattern := "%" + filters.Search + "%"
		args = append(args, searchPattern, searchPattern, searchPattern)
	}

	whereClause := strings.Join(whereClauses, " AND ")

	// Get total count
	// #nosec G201 - whereClause is built from static SQL fragments; user inputs are parameterized in args
	countQuery := fmt.Sprintf("SELECT COUNT(*) FROM exceptions WHERE %s", whereClause)
	var total int64
	err := s.sqlite.ReadDB.QueryRow(countQuery, args...).Scan(&total)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to count exceptions: %w", err)
	}

	// Build ORDER BY clause with whitelist validation to prevent SQL injection
	sortBy := "priority" // safe default
	switch filters.SortBy {
	case "name", "priority", "created_at", "updated_at", "last_hit", "hit_count", "enabled":
		sortBy = filters.SortBy
	default:
		// Invalid sort field, use default
		sortBy = "priority"
	}

	sortOrder := "asc" // safe default
	if strings.ToLower(filters.SortOrder) == "desc" {
		sortOrder = "desc"
	} else {
		// Invalid sort order, use default
		sortOrder = "asc"
	}

	// Build main query with pagination - safe to concatenate since values are from whitelists
	// #nosec G202 - sortBy/sortOrder are from switch whitelist; whereClause contains static SQL; user inputs are parameterized
	query := `
		SELECT id, name, description, rule_id, type, condition_type, condition,
			   new_severity, enabled, priority, expires_at, hit_count, last_hit,
			   created_at, updated_at, created_by, justification, tags
		FROM exceptions
		WHERE ` + whereClause + `
		ORDER BY ` + sortBy + ` ` + sortOrder + `
		LIMIT ? OFFSET ?
	`

	offset := (filters.Page - 1) * filters.Limit
	// Prevent excessive offset to avoid resource exhaustion and integer overflow
	const maxOffset = 100000
	if offset > maxOffset {
		return nil, 0, fmt.Errorf("pagination offset too large: %d (maximum %d records)", offset, maxOffset)
	}
	args = append(args, filters.Limit, offset)

	rows, err := s.sqlite.ReadDB.Query(query, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to query exceptions: %w", err)
	}
	defer rows.Close()

	exceptions := []core.Exception{}
	for rows.Next() {
		exception, err := s.scanException(rows)
		if err != nil {
			return nil, 0, fmt.Errorf("failed to scan exception: %w", err)
		}
		exceptions = append(exceptions, *exception)
	}

	if err = rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("error iterating exceptions: %w", err)
	}

	return exceptions, total, nil
}

// GetExceptionsByRuleID retrieves all exceptions for a specific rule
func (s *SQLiteExceptionStorage) GetExceptionsByRuleID(ruleID string) ([]core.Exception, error) {
	query := `
		SELECT id, name, description, rule_id, type, condition_type, condition,
			   new_severity, enabled, priority, expires_at, hit_count, last_hit,
			   created_at, updated_at, created_by, justification, tags
		FROM exceptions
		WHERE rule_id = ?
		ORDER BY priority ASC
	`

	rows, err := s.sqlite.ReadDB.Query(query, ruleID)
	if err != nil {
		return nil, fmt.Errorf("failed to query exceptions: %w", err)
	}
	defer rows.Close()

	exceptions := []core.Exception{}
	for rows.Next() {
		exception, err := s.scanException(rows)
		if err != nil {
			return nil, fmt.Errorf("failed to scan exception: %w", err)
		}
		exceptions = append(exceptions, *exception)
	}

	return exceptions, nil
}

// GetGlobalExceptions retrieves all global exceptions (rule_id is empty)
func (s *SQLiteExceptionStorage) GetGlobalExceptions() ([]core.Exception, error) {
	query := `
		SELECT id, name, description, rule_id, type, condition_type, condition,
			   new_severity, enabled, priority, expires_at, hit_count, last_hit,
			   created_at, updated_at, created_by, justification, tags
		FROM exceptions
		WHERE rule_id = '' OR rule_id IS NULL
		ORDER BY priority ASC
	`

	rows, err := s.sqlite.ReadDB.Query(query)
	if err != nil {
		return nil, fmt.Errorf("failed to query global exceptions: %w", err)
	}
	defer rows.Close()

	exceptions := []core.Exception{}
	for rows.Next() {
		exception, err := s.scanException(rows)
		if err != nil {
			return nil, fmt.Errorf("failed to scan exception: %w", err)
		}
		exceptions = append(exceptions, *exception)
	}

	return exceptions, nil
}

// GetActiveExceptions retrieves all active (enabled and not expired) exceptions
func (s *SQLiteExceptionStorage) GetActiveExceptions() ([]core.Exception, error) {
	query := `
		SELECT id, name, description, rule_id, type, condition_type, condition,
			   new_severity, enabled, priority, expires_at, hit_count, last_hit,
			   created_at, updated_at, created_by, justification, tags
		FROM exceptions
		WHERE enabled = 1 AND (expires_at IS NULL OR expires_at >= ?)
		ORDER BY priority ASC
	`

	rows, err := s.sqlite.ReadDB.Query(query, time.Now())
	if err != nil {
		return nil, fmt.Errorf("failed to query active exceptions: %w", err)
	}
	defer rows.Close()

	exceptions := []core.Exception{}
	for rows.Next() {
		exception, err := s.scanException(rows)
		if err != nil {
			return nil, fmt.Errorf("failed to scan exception: %w", err)
		}
		exceptions = append(exceptions, *exception)
	}

	return exceptions, nil
}

// UpdateException updates an existing exception
func (s *SQLiteExceptionStorage) UpdateException(id string, exception *core.Exception) error {
	if err := exception.Validate(); err != nil {
		return err
	}

	exception.UpdatedAt = time.Now()

	tagsJSON, err := json.Marshal(exception.Tags)
	if err != nil {
		return fmt.Errorf("failed to marshal tags: %w", err)
	}

	query := `
		UPDATE exceptions
		SET name = ?, description = ?, rule_id = ?, type = ?, condition_type = ?,
			condition = ?, new_severity = ?, enabled = ?, priority = ?, expires_at = ?,
			updated_at = ?, created_by = ?, justification = ?, tags = ?
		WHERE id = ?
	`

	result, err := s.sqlite.WriteDB.Exec(query,
		exception.Name,
		exception.Description,
		exception.RuleID,
		string(exception.Type),
		string(exception.ConditionType),
		exception.Condition,
		exception.NewSeverity,
		exception.Enabled,
		exception.Priority,
		exception.ExpiresAt,
		exception.UpdatedAt,
		exception.CreatedBy,
		exception.Justification,
		string(tagsJSON),
		id,
	)

	if err != nil {
		return fmt.Errorf("failed to update exception: %w", err)
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rows == 0 {
		return fmt.Errorf("exception not found")
	}

	return nil
}

// DeleteException deletes an exception by ID
func (s *SQLiteExceptionStorage) DeleteException(id string) error {
	query := `DELETE FROM exceptions WHERE id = ?`

	result, err := s.sqlite.WriteDB.Exec(query, id)
	if err != nil {
		return fmt.Errorf("failed to delete exception: %w", err)
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rows == 0 {
		return fmt.Errorf("exception not found")
	}

	return nil
}

// IncrementHitCount increments the hit count for an exception
func (s *SQLiteExceptionStorage) IncrementHitCount(id string) error {
	query := `UPDATE exceptions SET hit_count = hit_count + 1 WHERE id = ?`

	_, err := s.sqlite.WriteDB.Exec(query, id)
	if err != nil {
		return fmt.Errorf("failed to increment hit count: %w", err)
	}

	return nil
}

// UpdateLastHit updates the last hit timestamp for an exception
func (s *SQLiteExceptionStorage) UpdateLastHit(id string, timestamp time.Time) error {
	query := `UPDATE exceptions SET last_hit = ? WHERE id = ?`

	_, err := s.sqlite.WriteDB.Exec(query, timestamp, id)
	if err != nil {
		return fmt.Errorf("failed to update last hit: %w", err)
	}

	return nil
}

// scanException is a helper function to scan a row into an Exception
func (s *SQLiteExceptionStorage) scanException(scanner interface {
	Scan(dest ...interface{}) error
}) (*core.Exception, error) {
	exception := &core.Exception{}
	var tagsJSON string
	var ruleID sql.NullString
	var expiresAt sql.NullTime
	var lastHit sql.NullTime
	var newSeverity sql.NullString

	err := scanner.Scan(
		&exception.ID,
		&exception.Name,
		&exception.Description,
		&ruleID,
		&exception.Type,
		&exception.ConditionType,
		&exception.Condition,
		&newSeverity,
		&exception.Enabled,
		&exception.Priority,
		&expiresAt,
		&exception.HitCount,
		&lastHit,
		&exception.CreatedAt,
		&exception.UpdatedAt,
		&exception.CreatedBy,
		&exception.Justification,
		&tagsJSON,
	)

	if err != nil {
		return nil, err
	}

	if ruleID.Valid {
		exception.RuleID = ruleID.String
	}

	if newSeverity.Valid {
		exception.NewSeverity = newSeverity.String
	}

	if expiresAt.Valid {
		exception.ExpiresAt = &expiresAt.Time
	}

	if lastHit.Valid {
		exception.LastHit = &lastHit.Time
	}

	// Unmarshal tags
	if tagsJSON != "" {
		if err := json.Unmarshal([]byte(tagsJSON), &exception.Tags); err != nil {
			return nil, fmt.Errorf("failed to unmarshal tags: %w", err)
		}
	}

	return exception, nil
}
