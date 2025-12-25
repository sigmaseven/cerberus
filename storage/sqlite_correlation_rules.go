package storage

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"cerberus/core"

	"go.uber.org/zap"
)

// SQLiteCorrelationRuleStorage handles correlation rule persistence in SQLite
type SQLiteCorrelationRuleStorage struct {
	sqlite *SQLite
	logger *zap.SugaredLogger
}

// NewSQLiteCorrelationRuleStorage creates a new SQLite correlation rule storage handler
func NewSQLiteCorrelationRuleStorage(sqlite *SQLite, logger *zap.SugaredLogger) *SQLiteCorrelationRuleStorage {
	return &SQLiteCorrelationRuleStorage{
		sqlite: sqlite,
		logger: logger,
	}
}

// GetCorrelationRules retrieves correlation rules with pagination
// TASK #184: Conditions field removed from CorrelationRule - ignoring conditions column for backward compatibility
func (scrs *SQLiteCorrelationRuleStorage) GetCorrelationRules(limit int, offset int) ([]core.CorrelationRule, error) {
	query := `
		SELECT id, name, description, severity, version, window,
		       sequence, actions, created_at, updated_at
		FROM correlation_rules
		ORDER BY created_at DESC
		LIMIT ? OFFSET ?
	`

	rows, err := scrs.sqlite.ReadDB.Query(query, limit, offset)
	if err != nil {
		return nil, fmt.Errorf("failed to query correlation rules: %w", err)
	}
	defer rows.Close()

	// Initialize with make() to ensure non-nil slice for JSON serialization.
	// nil slices serialize to null, breaking frontend contract expecting [].
	rules := make([]core.CorrelationRule, 0)
	for rows.Next() {
		var rule core.CorrelationRule
		var sequenceJSON, actionsJSON string
		var createdAt, updatedAt string
		var windowNs int64

		err := rows.Scan(
			&rule.ID,
			&rule.Name,
			&rule.Description,
			&rule.Severity,
			&rule.Version,
			&windowNs,
			&sequenceJSON,
			&actionsJSON,
			&createdAt,
			&updatedAt,
		)

		if err != nil {
			return nil, fmt.Errorf("failed to scan correlation rule: %w", err)
		}

		// Parse JSON fields
		// TASK #184: Conditions unmarshal removed - field deleted from CorrelationRule
		if err := json.Unmarshal([]byte(sequenceJSON), &rule.Sequence); err != nil {
			scrs.logger.Warnf("Failed to parse sequence for correlation rule %s: %v", rule.ID, err)
			continue
		}

		if actionsJSON != "" {
			if err := json.Unmarshal([]byte(actionsJSON), &rule.Actions); err != nil {
				scrs.logger.Warnf("Failed to parse actions for correlation rule %s: %v", rule.ID, err)
			}
		}

		// Parse timestamps and window
		rule.Window = time.Duration(windowNs)
		rule.CreatedAt, _ = time.Parse(time.RFC3339, createdAt)
		rule.UpdatedAt, _ = time.Parse(time.RFC3339, updatedAt)

		rules = append(rules, rule)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating correlation rules: %w", err)
	}

	return rules, nil
}

// GetAllCorrelationRules retrieves all correlation rules without pagination
// TASK #184: Conditions field removed from CorrelationRule
func (scrs *SQLiteCorrelationRuleStorage) GetAllCorrelationRules() ([]core.CorrelationRule, error) {
	query := `
		SELECT id, name, description, severity, version, window,
		       sequence, actions, created_at, updated_at
		FROM correlation_rules
		ORDER BY created_at DESC
	`

	rows, err := scrs.sqlite.ReadDB.Query(query)
	if err != nil {
		return nil, fmt.Errorf("failed to query correlation rules: %w", err)
	}
	defer rows.Close()

	// Initialize with make() to ensure non-nil slice for JSON serialization.
	// nil slices serialize to null, breaking frontend contract expecting [].
	rules := make([]core.CorrelationRule, 0)
	for rows.Next() {
		var rule core.CorrelationRule
		var sequenceJSON, actionsJSON string
		var createdAt, updatedAt string
		var windowNs int64

		err := rows.Scan(
			&rule.ID,
			&rule.Name,
			&rule.Description,
			&rule.Severity,
			&rule.Version,
			&windowNs,
			&sequenceJSON,
			&actionsJSON,
			&createdAt,
			&updatedAt,
		)

		if err != nil {
			return nil, fmt.Errorf("failed to scan correlation rule: %w", err)
		}

		// Parse JSON fields - TASK #184: Conditions removed
		if err := json.Unmarshal([]byte(sequenceJSON), &rule.Sequence); err != nil {
			scrs.logger.Warnf("Failed to parse sequence for correlation rule %s: %v", rule.ID, err)
			continue
		}

		if actionsJSON != "" {
			if err := json.Unmarshal([]byte(actionsJSON), &rule.Actions); err != nil {
				scrs.logger.Warnf("Failed to parse actions for correlation rule %s: %v", rule.ID, err)
			}
		}

		// Parse timestamps and window
		rule.Window = time.Duration(windowNs)
		rule.CreatedAt, _ = time.Parse(time.RFC3339, createdAt)
		rule.UpdatedAt, _ = time.Parse(time.RFC3339, updatedAt)

		rules = append(rules, rule)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating correlation rules: %w", err)
	}

	return rules, nil
}

// GetCorrelationRuleCount returns the total number of correlation rules
func (scrs *SQLiteCorrelationRuleStorage) GetCorrelationRuleCount() (int64, error) {
	var count int64
	err := scrs.sqlite.ReadDB.QueryRow("SELECT COUNT(*) FROM correlation_rules").Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("failed to count correlation rules: %w", err)
	}
	return count, nil
}

// GetCorrelationRule retrieves a single correlation rule by ID
// TASK #184: Conditions field removed from CorrelationRule
func (scrs *SQLiteCorrelationRuleStorage) GetCorrelationRule(id string) (*core.CorrelationRule, error) {
	query := `
		SELECT id, name, description, severity, version, window,
		       sequence, actions, created_at, updated_at
		FROM correlation_rules
		WHERE id = ?
	`

	var rule core.CorrelationRule
	var sequenceJSON, actionsJSON string
	var createdAt, updatedAt string
	var windowNs int64

	err := scrs.sqlite.ReadDB.QueryRow(query, id).Scan(
		&rule.ID,
		&rule.Name,
		&rule.Description,
		&rule.Severity,
		&rule.Version,
		&windowNs,
		&sequenceJSON,
		&actionsJSON,
		&createdAt,
		&updatedAt,
	)

	if err == sql.ErrNoRows {
		return nil, ErrCorrelationRuleNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get correlation rule: %w", err)
	}

	// Parse JSON fields - TASK #184: Conditions removed
	if err := json.Unmarshal([]byte(sequenceJSON), &rule.Sequence); err != nil {
		return nil, fmt.Errorf("failed to parse sequence: %w", err)
	}

	if actionsJSON != "" {
		if err := json.Unmarshal([]byte(actionsJSON), &rule.Actions); err != nil {
			return nil, fmt.Errorf("failed to parse actions: %w", err)
		}
	}

	// Parse timestamps and window
	rule.Window = time.Duration(windowNs)
	rule.CreatedAt, _ = time.Parse(time.RFC3339, createdAt)
	rule.UpdatedAt, _ = time.Parse(time.RFC3339, updatedAt)

	return &rule, nil
}

// CreateCorrelationRule creates a new correlation rule
// TASK #184: Conditions field removed from CorrelationRule
func (scrs *SQLiteCorrelationRuleStorage) CreateCorrelationRule(rule *core.CorrelationRule) error {
	// Check if rule already exists
	existing, err := scrs.GetCorrelationRule(rule.ID)
	if err != nil && !errors.Is(err, ErrCorrelationRuleNotFound) {
		return fmt.Errorf("failed to check existing correlation rule: %w", err)
	}
	if existing != nil {
		return fmt.Errorf("correlation rule with ID %s already exists", rule.ID)
	}

	// Serialize JSON fields - TASK #184: Conditions removed
	sequenceJSON, err := json.Marshal(rule.Sequence)
	if err != nil {
		return fmt.Errorf("failed to marshal sequence: %w", err)
	}

	actionsJSON, err := json.Marshal(rule.Actions)
	if err != nil {
		return fmt.Errorf("failed to marshal actions: %w", err)
	}

	// Set timestamps
	now := time.Now()
	rule.CreatedAt = now
	rule.UpdatedAt = now

	query := `
		INSERT INTO correlation_rules (id, name, description, severity, version, window,
		                                conditions, sequence, actions, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`

	// TASK #184: conditions field removed from CorrelationRule but schema still requires it
	// Insert empty JSON array for backward compatibility with NOT NULL constraint
	_, err = scrs.sqlite.WriteDB.Exec(query,
		rule.ID,
		rule.Name,
		rule.Description,
		rule.Severity,
		rule.Version,
		int64(rule.Window),
		"[]", // Empty conditions array for schema compatibility
		string(sequenceJSON),
		string(actionsJSON),
		rule.CreatedAt.Format(time.RFC3339),
		rule.UpdatedAt.Format(time.RFC3339),
	)

	if err != nil {
		return fmt.Errorf("failed to insert correlation rule: %w", err)
	}

	scrs.logger.Infof("Created correlation rule %s", rule.ID)
	return nil
}

// UpdateCorrelationRule updates an existing correlation rule
func (scrs *SQLiteCorrelationRuleStorage) UpdateCorrelationRule(id string, rule *core.CorrelationRule) error {
	// Check if rule exists
	existing, err := scrs.GetCorrelationRule(id)
	if err != nil {
		if errors.Is(err, ErrCorrelationRuleNotFound) {
			return ErrCorrelationRuleNotFound
		}
		return fmt.Errorf("failed to check existing correlation rule: %w", err)
	}

	// Preserve creation time
	rule.CreatedAt = existing.CreatedAt
	rule.UpdatedAt = time.Now()

	// Serialize JSON fields - TASK #184: Conditions removed
	sequenceJSON, err := json.Marshal(rule.Sequence)
	if err != nil {
		return fmt.Errorf("failed to marshal sequence: %w", err)
	}

	actionsJSON, err := json.Marshal(rule.Actions)
	if err != nil {
		return fmt.Errorf("failed to marshal actions: %w", err)
	}

	query := `
		UPDATE correlation_rules
		SET name = ?, description = ?, severity = ?, version = ?, window = ?,
		    sequence = ?, actions = ?, updated_at = ?
		WHERE id = ?
	`

	result, err := scrs.sqlite.WriteDB.Exec(query,
		rule.Name,
		rule.Description,
		rule.Severity,
		rule.Version,
		int64(rule.Window),
		string(sequenceJSON),
		string(actionsJSON),
		rule.UpdatedAt.Format(time.RFC3339),
		id,
	)

	if err != nil {
		return fmt.Errorf("failed to update correlation rule: %w", err)
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return ErrCorrelationRuleNotFound
	}

	scrs.logger.Infof("Updated correlation rule %s", id)
	return nil
}

// DeleteCorrelationRule deletes a correlation rule
func (scrs *SQLiteCorrelationRuleStorage) DeleteCorrelationRule(id string) error {
	result, err := scrs.sqlite.WriteDB.Exec("DELETE FROM correlation_rules WHERE id = ?", id)
	if err != nil {
		return fmt.Errorf("failed to delete correlation rule: %w", err)
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return ErrCorrelationRuleNotFound
	}

	scrs.logger.Infof("Deleted correlation rule %s", id)
	return nil
}

// EnsureIndexes ensures database indexes exist (indexes created in schema)
func (scrs *SQLiteCorrelationRuleStorage) EnsureIndexes() error {
	// Indexes are created in the schema during table creation
	return nil
}

// SearchCorrelationRules searches correlation rules by name or description
func (scrs *SQLiteCorrelationRuleStorage) SearchCorrelationRules(query string, limit, offset int) ([]core.CorrelationRule, int64, error) {
	if query == "" {
		rules, err := scrs.GetCorrelationRules(limit, offset)
		if err != nil {
			return nil, 0, err
		}
		count, err := scrs.GetCorrelationRuleCount()
		if err != nil {
			return nil, 0, err
		}
		return rules, count, nil
	}

	// Escape LIKE wildcards in the search query
	escapedQuery := strings.ReplaceAll(query, "%", "\\%")
	escapedQuery = strings.ReplaceAll(escapedQuery, "_", "\\_")
	searchPattern := "%" + escapedQuery + "%"

	// Count total matching
	var total int64
	countQuery := `SELECT COUNT(*) FROM correlation_rules WHERE name LIKE ? ESCAPE '\' OR description LIKE ? ESCAPE '\'`
	err := scrs.sqlite.ReadDB.QueryRow(countQuery, searchPattern, searchPattern).Scan(&total)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to count correlation rules: %w", err)
	}

	// Get matching rules with pagination (using same schema as GetCorrelationRules)
	selectQuery := `
		SELECT id, name, description, severity, version, window,
		       sequence, actions, created_at, updated_at
		FROM correlation_rules
		WHERE name LIKE ? ESCAPE '\' OR description LIKE ? ESCAPE '\'
		ORDER BY created_at DESC
		LIMIT ? OFFSET ?`

	rows, err := scrs.sqlite.ReadDB.Query(selectQuery, searchPattern, searchPattern, limit, offset)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to search correlation rules: %w", err)
	}
	defer rows.Close()

	// Initialize with make() to ensure non-nil slice for JSON serialization
	rules := make([]core.CorrelationRule, 0)
	for rows.Next() {
		var rule core.CorrelationRule
		var sequenceJSON, actionsJSON string
		var createdAt, updatedAt string
		var windowNs int64

		err := rows.Scan(
			&rule.ID,
			&rule.Name,
			&rule.Description,
			&rule.Severity,
			&rule.Version,
			&windowNs,
			&sequenceJSON,
			&actionsJSON,
			&createdAt,
			&updatedAt,
		)
		if err != nil {
			scrs.logger.Warnw("Failed to scan correlation rule", "error", err)
			continue
		}

		// Parse JSON fields
		if err := json.Unmarshal([]byte(sequenceJSON), &rule.Sequence); err != nil {
			scrs.logger.Warnf("Failed to parse sequence for correlation rule %s: %v", rule.ID, err)
			continue
		}

		if actionsJSON != "" {
			if err := json.Unmarshal([]byte(actionsJSON), &rule.Actions); err != nil {
				scrs.logger.Warnf("Failed to parse actions for correlation rule %s: %v", rule.ID, err)
			}
		}

		// Parse timestamps and window
		rule.Window = time.Duration(windowNs)
		rule.CreatedAt, _ = time.Parse(time.RFC3339, createdAt)
		rule.UpdatedAt, _ = time.Parse(time.RFC3339, updatedAt)

		rules = append(rules, rule)
	}

	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("error iterating correlation rules: %w", err)
	}

	return rules, total, nil
}
