package storage

import (
	"database/sql"
	"fmt"
	"time"

	"go.uber.org/zap"
)

// RulePerformance represents performance metrics for a rule
type RulePerformance struct {
	RuleID             string    `json:"rule_id"`
	AvgEvalTimeMs      float64   `json:"avg_eval_time_ms"`
	MaxEvalTimeMs      float64   `json:"max_eval_time_ms"`
	P99EvalTimeMs      float64   `json:"p99_eval_time_ms"`
	TotalEvaluations   int64     `json:"total_evaluations"`
	TotalMatches       int64     `json:"total_matches"`
	FalsePositiveCount int64     `json:"false_positive_count"`
	LastEvaluated      time.Time `json:"last_evaluated"`
	UpdatedAt          time.Time `json:"updated_at"`
}

// RulePerformanceStorage defines the interface for rule performance tracking
type RulePerformanceStorage interface {
	GetPerformance(ruleID string) (*RulePerformance, error)
	UpdatePerformance(stats *RulePerformance) error
	BatchUpdatePerformance(stats []*RulePerformance) error
	GetSlowRules(thresholdMs float64, limit int) ([]*RulePerformance, error)
	ReportFalsePositive(ruleID string) error
	DeletePerformance(ruleID string) error
}

// SQLiteRulePerformanceStorage implements rule performance tracking
// PRODUCTION: Thread-safe storage for rule evaluation metrics
// SECURITY: Uses parameterized queries to prevent SQL injection
type SQLiteRulePerformanceStorage struct {
	sqlite *SQLite
	logger *zap.SugaredLogger
}

// NewSQLiteRulePerformanceStorage creates a new rule performance storage
func NewSQLiteRulePerformanceStorage(sqlite *SQLite, logger *zap.SugaredLogger) *SQLiteRulePerformanceStorage {
	return &SQLiteRulePerformanceStorage{
		sqlite: sqlite,
		logger: logger,
	}
}

// GetPerformance retrieves performance metrics for a rule
// PERFORMANCE: Uses read pool for non-blocking access
// Returns nil if no performance data exists (not an error)
func (s *SQLiteRulePerformanceStorage) GetPerformance(ruleID string) (*RulePerformance, error) {
	if ruleID == "" {
		return nil, fmt.Errorf("rule_id is required")
	}

	query := `
		SELECT
			rule_id,
			avg_eval_time_ms,
			max_eval_time_ms,
			p99_eval_time_ms,
			total_evaluations,
			total_matches,
			false_positive_count,
			last_evaluated,
			updated_at
		FROM rule_performance
		WHERE rule_id = ?
	`

	var perf RulePerformance
	var lastEvalStr, updatedAtStr sql.NullString

	err := s.sqlite.ReadDB.QueryRow(query, ruleID).Scan(
		&perf.RuleID,
		&perf.AvgEvalTimeMs,
		&perf.MaxEvalTimeMs,
		&perf.P99EvalTimeMs,
		&perf.TotalEvaluations,
		&perf.TotalMatches,
		&perf.FalsePositiveCount,
		&lastEvalStr,
		&updatedAtStr,
	)

	if err == sql.ErrNoRows {
		return nil, nil // No data yet, not an error
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get performance: %w", err)
	}

	// Parse timestamps (handle NULL)
	// BLOCKING-2 FIX: Return errors on time parsing failures
	if lastEvalStr.Valid {
		var err error
		perf.LastEvaluated, err = time.Parse(time.RFC3339, lastEvalStr.String)
		if err != nil {
			return nil, fmt.Errorf("failed to parse last_evaluated timestamp: %w", err)
		}
	}
	if updatedAtStr.Valid {
		var err error
		perf.UpdatedAt, err = time.Parse(time.RFC3339, updatedAtStr.String)
		if err != nil {
			return nil, fmt.Errorf("failed to parse updated_at timestamp: %w", err)
		}
	}

	return &perf, nil
}

// UpdatePerformance updates or inserts performance metrics for a rule
// PERFORMANCE: Single upsert operation for efficiency
// SECURITY: Parameterized query prevents SQL injection
func (s *SQLiteRulePerformanceStorage) UpdatePerformance(stats *RulePerformance) error {
	if stats == nil {
		return fmt.Errorf("stats cannot be nil")
	}
	if stats.RuleID == "" {
		return fmt.Errorf("rule_id is required")
	}

	// Set updated timestamp
	stats.UpdatedAt = time.Now().UTC()

	query := `
		INSERT INTO rule_performance (
			rule_id,
			avg_eval_time_ms,
			max_eval_time_ms,
			p99_eval_time_ms,
			total_evaluations,
			total_matches,
			false_positive_count,
			last_evaluated,
			updated_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(rule_id) DO UPDATE SET
			avg_eval_time_ms = excluded.avg_eval_time_ms,
			max_eval_time_ms = excluded.max_eval_time_ms,
			p99_eval_time_ms = excluded.p99_eval_time_ms,
			total_evaluations = excluded.total_evaluations,
			total_matches = excluded.total_matches,
			false_positive_count = excluded.false_positive_count,
			last_evaluated = excluded.last_evaluated,
			updated_at = excluded.updated_at
	`

	_, err := s.sqlite.WriteDB.Exec(
		query,
		stats.RuleID,
		stats.AvgEvalTimeMs,
		stats.MaxEvalTimeMs,
		stats.P99EvalTimeMs,
		stats.TotalEvaluations,
		stats.TotalMatches,
		stats.FalsePositiveCount,
		stats.LastEvaluated.Format(time.RFC3339),
		stats.UpdatedAt.Format(time.RFC3339),
	)

	if err != nil {
		return fmt.Errorf("failed to update performance: %w", err)
	}

	return nil
}

// BatchUpdatePerformance updates multiple rule performance records
// PERFORMANCE: Uses transaction for atomic batch updates
// OPTIMIZATION: Single transaction reduces overhead for bulk updates
// BLOCKING-3 FIX: Refactored to be under 50 lines by extracting helper functions
func (s *SQLiteRulePerformanceStorage) BatchUpdatePerformance(stats []*RulePerformance) error {
	if len(stats) == 0 {
		return nil // Nothing to do
	}

	// Start transaction for atomic batch update
	tx, err := s.sqlite.WriteDB.Begin()
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback() // Safe to call even after commit

	stmt, err := s.preparePerformanceStatement(tx)
	if err != nil {
		return err
	}
	defer stmt.Close()

	if err := s.executeBatchUpdates(stmt, stats); err != nil {
		return err
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	s.logger.Infof("Batch updated %d rule performance records", len(stats))
	return nil
}

// preparePerformanceStatement prepares the upsert statement for batch updates
// BLOCKING-3 FIX: Extracted from BatchUpdatePerformance to reduce function length
func (s *SQLiteRulePerformanceStorage) preparePerformanceStatement(tx *sql.Tx) (*sql.Stmt, error) {
	query := `
		INSERT INTO rule_performance (
			rule_id,
			avg_eval_time_ms,
			max_eval_time_ms,
			p99_eval_time_ms,
			total_evaluations,
			total_matches,
			false_positive_count,
			last_evaluated,
			updated_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(rule_id) DO UPDATE SET
			avg_eval_time_ms = excluded.avg_eval_time_ms,
			max_eval_time_ms = excluded.max_eval_time_ms,
			p99_eval_time_ms = excluded.p99_eval_time_ms,
			total_evaluations = excluded.total_evaluations,
			total_matches = excluded.total_matches,
			false_positive_count = excluded.false_positive_count,
			last_evaluated = excluded.last_evaluated,
			updated_at = excluded.updated_at
	`

	stmt, err := tx.Prepare(query)
	if err != nil {
		return nil, fmt.Errorf("failed to prepare statement: %w", err)
	}
	return stmt, nil
}

// executeBatchUpdates executes the batch update for all stats
// BLOCKING-3 FIX: Extracted from BatchUpdatePerformance to reduce function length
func (s *SQLiteRulePerformanceStorage) executeBatchUpdates(stmt *sql.Stmt, stats []*RulePerformance) error {
	updateTime := time.Now().UTC()

	for _, stat := range stats {
		if stat == nil || stat.RuleID == "" {
			continue // Skip invalid entries
		}

		stat.UpdatedAt = updateTime

		_, err := stmt.Exec(
			stat.RuleID,
			stat.AvgEvalTimeMs,
			stat.MaxEvalTimeMs,
			stat.P99EvalTimeMs,
			stat.TotalEvaluations,
			stat.TotalMatches,
			stat.FalsePositiveCount,
			stat.LastEvaluated.Format(time.RFC3339),
			stat.UpdatedAt.Format(time.RFC3339),
		)
		if err != nil {
			return fmt.Errorf("failed to execute batch update: %w", err)
		}
	}
	return nil
}

// GetSlowRules retrieves rules exceeding evaluation time threshold
// PERFORMANCE: Uses index on avg_eval_time_ms for efficient query
// OBSERVABILITY: Identifies performance bottlenecks for optimization
// CRITICAL-3 FIX: Added minimum threshold validation to prevent resource exhaustion
func (s *SQLiteRulePerformanceStorage) GetSlowRules(thresholdMs float64, limit int) ([]*RulePerformance, error) {
	// Validate inputs
	if thresholdMs < 0 {
		return nil, fmt.Errorf("threshold must be non-negative")
	}
	// CRITICAL-3 FIX: Enforce minimum threshold to prevent resource exhaustion
	if thresholdMs < 1.0 {
		thresholdMs = 1.0 // Enforce minimum
	}
	if limit <= 0 || limit > 1000 {
		limit = 20 // Default limit
	}

	query := `
		SELECT
			rule_id,
			avg_eval_time_ms,
			max_eval_time_ms,
			p99_eval_time_ms,
			total_evaluations,
			total_matches,
			false_positive_count,
			last_evaluated,
			updated_at
		FROM rule_performance
		WHERE avg_eval_time_ms >= ?
		ORDER BY avg_eval_time_ms DESC
		LIMIT ?
	`

	rows, err := s.sqlite.ReadDB.Query(query, thresholdMs, limit)
	if err != nil {
		return nil, fmt.Errorf("failed to query slow rules: %w", err)
	}
	defer rows.Close()

	return s.scanPerformanceRows(rows)
}

// ReportFalsePositive increments false positive count for a rule
// PERFORMANCE: Single atomic update operation
// OBSERVABILITY: Tracks rule accuracy for tuning
func (s *SQLiteRulePerformanceStorage) ReportFalsePositive(ruleID string) error {
	if ruleID == "" {
		return fmt.Errorf("rule_id is required")
	}

	query := `
		INSERT INTO rule_performance (
			rule_id,
			false_positive_count,
			updated_at
		) VALUES (?, 1, ?)
		ON CONFLICT(rule_id) DO UPDATE SET
			false_positive_count = false_positive_count + 1,
			updated_at = excluded.updated_at
	`

	updateTime := time.Now().UTC()
	_, err := s.sqlite.WriteDB.Exec(query, ruleID, updateTime.Format(time.RFC3339))
	if err != nil {
		return fmt.Errorf("failed to report false positive: %w", err)
	}

	s.logger.Infow("False positive reported", "rule_id", ruleID)
	return nil
}

// DeletePerformance removes performance metrics for a rule
// CLEANUP: Called when a rule is deleted
func (s *SQLiteRulePerformanceStorage) DeletePerformance(ruleID string) error {
	if ruleID == "" {
		return fmt.Errorf("rule_id is required")
	}

	query := "DELETE FROM rule_performance WHERE rule_id = ?"
	_, err := s.sqlite.WriteDB.Exec(query, ruleID)
	if err != nil {
		return fmt.Errorf("failed to delete performance: %w", err)
	}

	return nil
}

// scanPerformanceRows scans database rows into RulePerformance slice
// HELPER: Extracts common scanning logic to reduce duplication
func (s *SQLiteRulePerformanceStorage) scanPerformanceRows(rows *sql.Rows) ([]*RulePerformance, error) {
	var results []*RulePerformance

	for rows.Next() {
		var perf RulePerformance
		var lastEvalStr, updatedAtStr sql.NullString

		err := rows.Scan(
			&perf.RuleID,
			&perf.AvgEvalTimeMs,
			&perf.MaxEvalTimeMs,
			&perf.P99EvalTimeMs,
			&perf.TotalEvaluations,
			&perf.TotalMatches,
			&perf.FalsePositiveCount,
			&lastEvalStr,
			&updatedAtStr,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan row: %w", err)
		}

		// Parse timestamps (handle NULL)
		// BLOCKING-2 FIX: Return errors on time parsing failures
		if lastEvalStr.Valid {
			var err error
			perf.LastEvaluated, err = time.Parse(time.RFC3339, lastEvalStr.String)
			if err != nil {
				return nil, fmt.Errorf("failed to parse last_evaluated timestamp: %w", err)
			}
		}
		if updatedAtStr.Valid {
			var err error
			perf.UpdatedAt, err = time.Parse(time.RFC3339, updatedAtStr.String)
			if err != nil {
				return nil, fmt.Errorf("failed to parse updated_at timestamp: %w", err)
			}
		}

		results = append(results, &perf)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating rows: %w", err)
	}

	return results, nil
}
