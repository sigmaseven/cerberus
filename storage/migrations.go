package storage

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"time"

	"go.uber.org/zap"
)

// Migration represents a database migration with up and down operations
type Migration struct {
	Version     string              // Semantic version (e.g., "1.0.0")
	Name        string              // Descriptive name (e.g., "add_rule_type_column")
	Description string              // Human-readable description
	Up          func(*sql.Tx) error // Apply migration
	Down        func(*sql.Tx) error // Rollback migration (optional)
	Checksum    string              // SHA256 of migration content for drift detection
	AppliedAt   time.Time           // When migration was applied (populated from DB)
	Database    string              // "sqlite" or "clickhouse"
}

// MigrationRecord represents a row in the schema_migrations table
type MigrationRecord struct {
	ID        int64
	Version   string
	Name      string
	Checksum  string
	AppliedAt time.Time
	Duration  int64 // milliseconds
}

// MigrationRunner manages database migrations
type MigrationRunner struct {
	db         *sql.DB
	logger     *zap.SugaredLogger
	migrations []Migration
}

// NewMigrationRunner creates a new migration runner
func NewMigrationRunner(db *sql.DB, logger *zap.SugaredLogger) (*MigrationRunner, error) {
	runner := &MigrationRunner{
		db:         db,
		logger:     logger,
		migrations: make([]Migration, 0),
	}

	// Ensure schema_migrations table exists
	if err := runner.ensureMigrationsTable(); err != nil {
		return nil, fmt.Errorf("failed to create migrations table: %w", err)
	}

	return runner, nil
}

// ensureMigrationsTable creates the schema_migrations table if it doesn't exist
func (r *MigrationRunner) ensureMigrationsTable() error {
	schema := `
	CREATE TABLE IF NOT EXISTS schema_migrations (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		version TEXT NOT NULL UNIQUE,
		name TEXT NOT NULL,
		checksum TEXT NOT NULL,
		applied_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
		duration_ms INTEGER NOT NULL DEFAULT 0,
		rolled_back_at DATETIME,
		rollback_reason TEXT
	);
	CREATE INDEX IF NOT EXISTS idx_schema_migrations_version ON schema_migrations(version);
	CREATE INDEX IF NOT EXISTS idx_schema_migrations_applied_at ON schema_migrations(applied_at);
	`
	_, err := r.db.Exec(schema)
	return err
}

// Register adds a migration to the runner
func (r *MigrationRunner) Register(m Migration) {
	// Calculate checksum if not provided
	if m.Checksum == "" {
		m.Checksum = r.calculateChecksum(m)
	}
	r.migrations = append(r.migrations, m)
}

// calculateChecksum generates a SHA256 hash for migration drift detection
func (r *MigrationRunner) calculateChecksum(m Migration) string {
	// Use version + name as checksum input (Up/Down functions can't be hashed)
	content := fmt.Sprintf("%s:%s", m.Version, m.Name)
	hash := sha256.Sum256([]byte(content))
	return hex.EncodeToString(hash[:8]) // Use first 8 bytes for brevity
}

// GetAppliedMigrations returns all migrations that have been applied
func (r *MigrationRunner) GetAppliedMigrations() ([]MigrationRecord, error) {
	rows, err := r.db.Query(`
		SELECT id, version, name, checksum, applied_at, duration_ms
		FROM schema_migrations
		WHERE rolled_back_at IS NULL
		ORDER BY version ASC
	`)
	if err != nil {
		return nil, fmt.Errorf("failed to query applied migrations: %w", err)
	}
	defer rows.Close()

	var records []MigrationRecord
	for rows.Next() {
		var rec MigrationRecord
		if err := rows.Scan(&rec.ID, &rec.Version, &rec.Name, &rec.Checksum, &rec.AppliedAt, &rec.Duration); err != nil {
			return nil, fmt.Errorf("failed to scan migration record: %w", err)
		}
		records = append(records, rec)
	}

	return records, rows.Err()
}

// GetPendingMigrations returns migrations that haven't been applied yet
func (r *MigrationRunner) GetPendingMigrations() ([]Migration, error) {
	applied, err := r.GetAppliedMigrations()
	if err != nil {
		return nil, err
	}

	// Build set of applied versions
	appliedSet := make(map[string]bool)
	for _, rec := range applied {
		appliedSet[rec.Version] = true
	}

	// Filter registered migrations
	var pending []Migration
	for _, m := range r.migrations {
		if !appliedSet[m.Version] {
			pending = append(pending, m)
		}
	}

	// Sort by version
	sort.Slice(pending, func(i, j int) bool {
		return compareVersions(pending[i].Version, pending[j].Version) < 0
	})

	return pending, nil
}

// RunMigrations applies all pending migrations
func (r *MigrationRunner) RunMigrations() error {
	pending, err := r.GetPendingMigrations()
	if err != nil {
		return err
	}

	if len(pending) == 0 {
		r.logger.Debug("No pending migrations")
		return nil
	}

	r.logger.Infof("Running %d pending migrations", len(pending))

	for _, m := range pending {
		if err := r.runMigration(m); err != nil {
			return fmt.Errorf("migration %s (%s) failed: %w", m.Version, m.Name, err)
		}
	}

	r.logger.Info("All migrations completed successfully")
	return nil
}

// runMigration applies a single migration within a transaction
// TASK 137: Uses named return value to capture panic errors instead of re-panicking
func (r *MigrationRunner) runMigration(m Migration) (err error) {
	r.logger.Infof("Running migration %s: %s", m.Version, m.Name)
	start := time.Now()

	var tx *sql.Tx
	tx, err = r.db.Begin()
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}

	// Ensure transaction is rolled back on panic
	// TASK 137: Return error instead of re-panicking for better error handling
	defer func() {
		if p := recover(); p != nil {
			_ = tx.Rollback()
			// Convert panic to error instead of re-panicking
			if panicAsErr, ok := p.(error); ok {
				err = fmt.Errorf("migration panicked: %w", panicAsErr)
			} else {
				err = fmt.Errorf("migration panicked: %v", p)
			}
		}
	}()

	// Run the migration
	if err := m.Up(tx); err != nil {
		_ = tx.Rollback()
		return fmt.Errorf("migration Up() failed: %w", err)
	}

	// Record the migration
	duration := time.Since(start).Milliseconds()
	_, err = tx.Exec(`
		INSERT INTO schema_migrations (version, name, checksum, applied_at, duration_ms)
		VALUES (?, ?, ?, ?, ?)
	`, m.Version, m.Name, m.Checksum, time.Now().UTC(), duration)
	if err != nil {
		_ = tx.Rollback()
		return fmt.Errorf("failed to record migration: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit migration: %w", err)
	}

	r.logger.Infof("Migration %s completed in %dms", m.Version, duration)
	return nil
}

// RollbackMigration rolls back a specific migration by version
// TASK 137: Uses named return value to capture panic errors instead of re-panicking
func (r *MigrationRunner) RollbackMigration(version string, reason string) (err error) {
	// Find the migration
	var migration *Migration
	for i := range r.migrations {
		if r.migrations[i].Version == version {
			migration = &r.migrations[i]
			break
		}
	}

	if migration == nil {
		return fmt.Errorf("migration %s not found in registry", version)
	}

	if migration.Down == nil {
		return fmt.Errorf("migration %s does not support rollback (no Down function)", version)
	}

	// Verify migration was applied
	var appliedAt sql.NullTime
	err = r.db.QueryRow(`
		SELECT applied_at FROM schema_migrations
		WHERE version = ? AND rolled_back_at IS NULL
	`, version).Scan(&appliedAt)
	if err == sql.ErrNoRows {
		return fmt.Errorf("migration %s has not been applied or was already rolled back", version)
	}
	if err != nil {
		return fmt.Errorf("failed to check migration status: %w", err)
	}

	r.logger.Infof("Rolling back migration %s: %s (reason: %s)", version, migration.Name, reason)

	var tx *sql.Tx
	tx, err = r.db.Begin()
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}

	// Ensure transaction is rolled back on panic
	// TASK 137: Return error instead of re-panicking for better error handling
	defer func() {
		if p := recover(); p != nil {
			_ = tx.Rollback()
			// Convert panic to error instead of re-panicking
			if panicAsErr, ok := p.(error); ok {
				err = fmt.Errorf("rollback panicked: %w", panicAsErr)
			} else {
				err = fmt.Errorf("rollback panicked: %v", p)
			}
		}
	}()

	// Run the rollback
	if err := migration.Down(tx); err != nil {
		_ = tx.Rollback()
		return fmt.Errorf("rollback Down() failed: %w", err)
	}

	// Mark as rolled back (soft delete)
	_, err = tx.Exec(`
		UPDATE schema_migrations
		SET rolled_back_at = ?, rollback_reason = ?
		WHERE version = ?
	`, time.Now().UTC(), reason, version)
	if err != nil {
		_ = tx.Rollback()
		return fmt.Errorf("failed to mark migration as rolled back: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit rollback: %w", err)
	}

	r.logger.Infof("Migration %s rolled back successfully", version)
	return nil
}

// VerifyIntegrity checks for migration drift (modified applied migrations)
func (r *MigrationRunner) VerifyIntegrity() ([]string, error) {
	applied, err := r.GetAppliedMigrations()
	if err != nil {
		return nil, err
	}

	// Build map of registered migrations
	registered := make(map[string]Migration)
	for _, m := range r.migrations {
		registered[m.Version] = m
	}

	var issues []string

	// Check each applied migration against registered ones
	for _, rec := range applied {
		if m, ok := registered[rec.Version]; ok {
			// Skip checksum validation for reconciled migrations (applied before framework existed)
			if rec.Checksum == "reconciled" {
				continue
			}
			if m.Checksum != rec.Checksum {
				issues = append(issues, fmt.Sprintf(
					"Migration %s checksum mismatch: applied=%s, registered=%s (possible code drift)",
					rec.Version, rec.Checksum, m.Checksum,
				))
			}
		} else {
			issues = append(issues, fmt.Sprintf(
				"Migration %s was applied but is not registered (orphaned migration)",
				rec.Version,
			))
		}
	}

	return issues, nil
}

// GetMigrationStatus returns a summary of migration state
func (r *MigrationRunner) GetMigrationStatus() (map[string]interface{}, error) {
	applied, err := r.GetAppliedMigrations()
	if err != nil {
		return nil, err
	}

	pending, err := r.GetPendingMigrations()
	if err != nil {
		return nil, err
	}

	issues, err := r.VerifyIntegrity()
	if err != nil {
		return nil, err
	}

	return map[string]interface{}{
		"total_registered": len(r.migrations),
		"applied_count":    len(applied),
		"pending_count":    len(pending),
		"integrity_issues": issues,
		"latest_applied":   getLatestVersion(applied),
	}, nil
}

// getLatestVersion returns the highest version from applied migrations
func getLatestVersion(applied []MigrationRecord) string {
	if len(applied) == 0 {
		return ""
	}
	return applied[len(applied)-1].Version
}

// compareVersions compares two semantic versions
// Returns -1 if a < b, 0 if a == b, 1 if a > b
func compareVersions(a, b string) int {
	partsA := strings.Split(a, ".")
	partsB := strings.Split(b, ".")

	maxLen := len(partsA)
	if len(partsB) > maxLen {
		maxLen = len(partsB)
	}

	for i := 0; i < maxLen; i++ {
		var numA, numB int
		if i < len(partsA) {
			fmt.Sscanf(partsA[i], "%d", &numA)
		}
		if i < len(partsB) {
			fmt.Sscanf(partsB[i], "%d", &numB)
		}

		if numA < numB {
			return -1
		}
		if numA > numB {
			return 1
		}
	}
	return 0
}

// validateSQLIdentifier validates that a string is a safe SQL identifier
// to prevent SQL injection in dynamic schema operations.
// Valid identifiers must start with a letter or underscore and contain only
// alphanumeric characters and underscores.
func validateSQLIdentifier(name string) error {
	if name == "" {
		return fmt.Errorf("SQL identifier cannot be empty")
	}
	// Must start with letter or underscore
	if !(name[0] >= 'a' && name[0] <= 'z' || name[0] >= 'A' && name[0] <= 'Z' || name[0] == '_') {
		return fmt.Errorf("invalid SQL identifier %q: must start with letter or underscore", name)
	}
	// Remaining characters must be alphanumeric or underscore
	for i := 1; i < len(name); i++ {
		c := name[i]
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_') {
			return fmt.Errorf("invalid SQL identifier %q: contains invalid character at position %d", name, i)
		}
	}
	return nil
}

// Helper function to check if a column exists in a table
func columnExists(tx *sql.Tx, table, column string) (bool, error) {
	// Validate identifiers to prevent SQL injection
	if err := validateSQLIdentifier(table); err != nil {
		return false, fmt.Errorf("invalid table name: %w", err)
	}
	if err := validateSQLIdentifier(column); err != nil {
		return false, fmt.Errorf("invalid column name: %w", err)
	}

	var count int
	err := tx.QueryRow(
		"SELECT COUNT(*) FROM pragma_table_info(?) WHERE name=?",
		table, column,
	).Scan(&count)
	if err != nil {
		return false, err
	}
	return count > 0, nil
}

// Helper function to add a column if it doesn't exist
func addColumnIfNotExists(tx *sql.Tx, table, column, definition string) error {
	// Validate identifiers to prevent SQL injection
	if err := validateSQLIdentifier(table); err != nil {
		return fmt.Errorf("invalid table name: %w", err)
	}
	if err := validateSQLIdentifier(column); err != nil {
		return fmt.Errorf("invalid column name: %w", err)
	}

	exists, err := columnExists(tx, table, column)
	if err != nil {
		return err
	}
	if exists {
		return nil
	}
	// Safe to use fmt.Sprintf here since identifiers are validated
	_, err = tx.Exec(fmt.Sprintf("ALTER TABLE %s ADD COLUMN %s %s", table, column, definition))
	return err
}

// Helper function to create an index if it doesn't exist
func createIndexIfNotExists(tx *sql.Tx, indexName, table, columns string) error {
	// Validate identifiers to prevent SQL injection
	if err := validateSQLIdentifier(indexName); err != nil {
		return fmt.Errorf("invalid index name: %w", err)
	}
	if err := validateSQLIdentifier(table); err != nil {
		return fmt.Errorf("invalid table name: %w", err)
	}
	// Columns may contain commas for composite indexes, validate each part
	columnParts := strings.Split(columns, ",")
	for _, col := range columnParts {
		trimmed := strings.TrimSpace(col)
		if err := validateSQLIdentifier(trimmed); err != nil {
			return fmt.Errorf("invalid column name in index: %w", err)
		}
	}

	// Safe to use fmt.Sprintf here since identifiers are validated
	query := fmt.Sprintf("CREATE INDEX IF NOT EXISTS %s ON %s(%s)", indexName, table, columns)
	_, err := tx.Exec(query)
	return err
}
