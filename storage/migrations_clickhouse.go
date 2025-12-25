package storage

import (
	"context"
	"fmt"
	"time"

	"github.com/ClickHouse/clickhouse-go/v2/lib/driver"
	"go.uber.org/zap"
)

// ClickHouseMigration represents a ClickHouse-specific migration
type ClickHouseMigration struct {
	Version     string
	Name        string
	Description string
	Up          func(context.Context, driver.Conn) error
	Down        func(context.Context, driver.Conn) error // Optional
}

// ClickHouseMigrationRunner manages ClickHouse migrations
type ClickHouseMigrationRunner struct {
	conn       driver.Conn
	logger     *zap.SugaredLogger
	migrations []ClickHouseMigration
}

// NewClickHouseMigrationRunner creates a new ClickHouse migration runner
func NewClickHouseMigrationRunner(conn driver.Conn, logger *zap.SugaredLogger) (*ClickHouseMigrationRunner, error) {
	runner := &ClickHouseMigrationRunner{
		conn:       conn,
		logger:     logger,
		migrations: make([]ClickHouseMigration, 0),
	}

	// Ensure schema_migrations table exists in ClickHouse
	if err := runner.ensureMigrationsTable(context.Background()); err != nil {
		return nil, fmt.Errorf("failed to create migrations table: %w", err)
	}

	return runner, nil
}

// ensureMigrationsTable creates the schema_migrations table in ClickHouse
func (r *ClickHouseMigrationRunner) ensureMigrationsTable(ctx context.Context) error {
	query := `
	CREATE TABLE IF NOT EXISTS schema_migrations (
		version String,
		name String,
		applied_at DateTime64(3, 'UTC'),
		duration_ms UInt64,
		rolled_back_at Nullable(DateTime64(3, 'UTC')),
		rollback_reason String DEFAULT ''
	) ENGINE = MergeTree()
	ORDER BY (applied_at, version)
	`
	return r.conn.Exec(ctx, query)
}

// Register adds a migration to the runner
func (r *ClickHouseMigrationRunner) Register(m ClickHouseMigration) {
	r.migrations = append(r.migrations, m)
}

// GetAppliedMigrations returns all migrations that have been applied
func (r *ClickHouseMigrationRunner) GetAppliedMigrations(ctx context.Context) ([]string, error) {
	rows, err := r.conn.Query(ctx, `
		SELECT version FROM schema_migrations
		WHERE rolled_back_at IS NULL
		ORDER BY version ASC
	`)
	if err != nil {
		return nil, fmt.Errorf("failed to query applied migrations: %w", err)
	}
	defer rows.Close()

	var versions []string
	for rows.Next() {
		var version string
		if err := rows.Scan(&version); err != nil {
			return nil, fmt.Errorf("failed to scan migration version: %w", err)
		}
		versions = append(versions, version)
	}

	return versions, nil
}

// GetPendingMigrations returns migrations that haven't been applied yet
func (r *ClickHouseMigrationRunner) GetPendingMigrations(ctx context.Context) ([]ClickHouseMigration, error) {
	applied, err := r.GetAppliedMigrations(ctx)
	if err != nil {
		return nil, err
	}

	// Build set of applied versions
	appliedSet := make(map[string]bool)
	for _, v := range applied {
		appliedSet[v] = true
	}

	// Filter registered migrations
	var pending []ClickHouseMigration
	for _, m := range r.migrations {
		if !appliedSet[m.Version] {
			pending = append(pending, m)
		}
	}

	return pending, nil
}

// RunMigrations applies all pending migrations
func (r *ClickHouseMigrationRunner) RunMigrations(ctx context.Context) error {
	pending, err := r.GetPendingMigrations(ctx)
	if err != nil {
		return err
	}

	if len(pending) == 0 {
		r.logger.Debug("No pending ClickHouse migrations")
		return nil
	}

	r.logger.Infof("Running %d pending ClickHouse migrations", len(pending))

	for _, m := range pending {
		if err := r.runMigration(ctx, m); err != nil {
			return fmt.Errorf("migration %s (%s) failed: %w", m.Version, m.Name, err)
		}
	}

	r.logger.Info("All ClickHouse migrations completed successfully")
	return nil
}

// runMigration applies a single migration
func (r *ClickHouseMigrationRunner) runMigration(ctx context.Context, m ClickHouseMigration) error {
	r.logger.Infof("Running ClickHouse migration %s: %s", m.Version, m.Name)
	start := time.Now()

	// Run the migration (ClickHouse doesn't support transactions for DDL)
	if err := m.Up(ctx, r.conn); err != nil {
		return fmt.Errorf("migration Up() failed: %w", err)
	}

	// Record the migration
	duration := time.Since(start).Milliseconds()
	err := r.conn.Exec(ctx, `
		INSERT INTO schema_migrations (version, name, applied_at, duration_ms)
		VALUES (?, ?, ?, ?)
	`, m.Version, m.Name, time.Now().UTC(), duration)
	if err != nil {
		return fmt.Errorf("failed to record migration: %w", err)
	}

	r.logger.Infof("ClickHouse migration %s completed in %dms", m.Version, duration)
	return nil
}

// RegisterClickHouseMigrations registers all ClickHouse migrations with the runner
func RegisterClickHouseMigrations(runner *ClickHouseMigrationRunner) {
	// Migration 1.0.0: Base schema (events and alerts tables)
	runner.Register(ClickHouseMigration{
		Version:     "1.0.0",
		Name:        "initial_schema",
		Description: "Base schema with events and alerts tables",
		Up: func(ctx context.Context, conn driver.Conn) error {
			// No-op: Base tables created by CreateTablesIfNotExist()
			return nil
		},
	})

	// Migration 1.1.0: Add alert disposition fields
	runner.Register(ClickHouseMigration{
		Version:     "1.1.0",
		Name:        "add_alert_disposition_fields",
		Description: "Add disposition, disposition_reason, disposition_set_at, disposition_set_by, investigation_id columns to alerts table",
		Up: func(ctx context.Context, conn driver.Conn) error {
			migrations := []string{
				`ALTER TABLE alerts ADD COLUMN IF NOT EXISTS disposition LowCardinality(String) DEFAULT 'undetermined'`,
				`ALTER TABLE alerts ADD COLUMN IF NOT EXISTS disposition_reason String DEFAULT ''`,
				`ALTER TABLE alerts ADD COLUMN IF NOT EXISTS disposition_set_at Nullable(DateTime64(3, 'UTC'))`,
				`ALTER TABLE alerts ADD COLUMN IF NOT EXISTS disposition_set_by String DEFAULT ''`,
				`ALTER TABLE alerts ADD COLUMN IF NOT EXISTS investigation_id String DEFAULT ''`,
			}

			for _, migration := range migrations {
				if err := conn.Exec(ctx, migration); err != nil {
					// Check if it's an expected error (column already exists)
					if !isExpectedMigrationError(err) {
						return err
					}
				}
			}

			// Add index for disposition filtering
			indexMigration := `ALTER TABLE alerts ADD INDEX IF NOT EXISTS idx_disposition disposition TYPE set(0) GRANULARITY 1`
			if err := conn.Exec(ctx, indexMigration); err != nil {
				if !isExpectedMigrationError(err) {
					return err
				}
			}

			return nil
		},
		Down: func(ctx context.Context, conn driver.Conn) error {
			// Rollback: drop disposition columns
			dropColumns := []string{
				`ALTER TABLE alerts DROP COLUMN IF EXISTS disposition`,
				`ALTER TABLE alerts DROP COLUMN IF EXISTS disposition_reason`,
				`ALTER TABLE alerts DROP COLUMN IF EXISTS disposition_set_at`,
				`ALTER TABLE alerts DROP COLUMN IF EXISTS disposition_set_by`,
				`ALTER TABLE alerts DROP COLUMN IF EXISTS investigation_id`,
			}

			for _, drop := range dropColumns {
				if err := conn.Exec(ctx, drop); err != nil {
					return err
				}
			}

			return nil
		},
	})

	// Migration 1.2.0: Add soar_audit_log table (if doesn't exist from initial setup)
	runner.Register(ClickHouseMigration{
		Version:     "1.2.0",
		Name:        "create_soar_audit_log",
		Description: "Create soar_audit_log table for SOAR playbook execution auditing",
		Up: func(ctx context.Context, conn driver.Conn) error {
			// This is idempotent due to IF NOT EXISTS
			query := `
			CREATE TABLE IF NOT EXISTS soar_audit_log (
				execution_id String,
				playbook_id String,
				playbook_name String,
				alert_id String,
				action_name String,
				action_type String,
				status String,
				input_data String,
				output_data String,
				error_message String,
				started_at DateTime64(3, 'UTC'),
				completed_at Nullable(DateTime64(3, 'UTC')),
				duration_ms UInt64,
				INDEX idx_playbook_id playbook_id TYPE bloom_filter(0.01) GRANULARITY 1,
				INDEX idx_alert_id alert_id TYPE bloom_filter(0.01) GRANULARITY 1,
				INDEX idx_status status TYPE set(0) GRANULARITY 1
			) ENGINE = MergeTree()
			PARTITION BY toYYYYMM(started_at)
			ORDER BY (started_at, playbook_id, alert_id)
			TTL started_at + INTERVAL 90 DAY
			SETTINGS index_granularity = 8192
			`
			return conn.Exec(ctx, query)
		},
		Down: func(ctx context.Context, conn driver.Conn) error {
			return conn.Exec(ctx, "DROP TABLE IF EXISTS soar_audit_log")
		},
	})

	// Migration 1.3.0: Backfill empty disposition values to 'undetermined'
	runner.Register(ClickHouseMigration{
		Version:     "1.3.0",
		Name:        "backfill_empty_dispositions",
		Description: "Set empty disposition values to 'undetermined' for legacy alerts",
		Up: func(ctx context.Context, conn driver.Conn) error {
			// Update all alerts with empty disposition to 'undetermined'
			// This fixes legacy data created before disposition was properly defaulted
			query := `
			ALTER TABLE alerts
			UPDATE disposition = 'undetermined'
			WHERE disposition = ''
			`
			return conn.Exec(ctx, query)
		},
		Down: func(ctx context.Context, conn driver.Conn) error {
			// No rollback needed - 'undetermined' is the correct default
			return nil
		},
	})

	// Migration 1.4.0: Create alert_status_history table for timeline display
	runner.Register(ClickHouseMigration{
		Version:     "1.4.0",
		Name:        "create_alert_status_history",
		Description: "Create alert_status_history table for tracking status changes over time",
		Up: func(ctx context.Context, conn driver.Conn) error {
			query := `
			CREATE TABLE IF NOT EXISTS alert_status_history (
				alert_id String,
				from_status LowCardinality(String),
				to_status LowCardinality(String),
				changed_by String,
				changed_at DateTime64(3, 'UTC'),
				note String DEFAULT '',
				INDEX idx_alert_id alert_id TYPE bloom_filter(0.01) GRANULARITY 1
			) ENGINE = MergeTree()
			PARTITION BY toYYYYMM(changed_at)
			ORDER BY (alert_id, changed_at)
			TTL changed_at + INTERVAL 365 DAY
			SETTINGS index_granularity = 8192
			`
			return conn.Exec(ctx, query)
		},
		Down: func(ctx context.Context, conn driver.Conn) error {
			return conn.Exec(ctx, "DROP TABLE IF EXISTS alert_status_history")
		},
	})

	// Migration 1.5.0: Fix double-encoded raw_data in events table
	// BUG FIX: raw_data was stored as JSON-encoded strings (e.g., "{\"key\": \"value\"}")
	// instead of raw JSON (e.g., {"key": "value"})
	runner.Register(ClickHouseMigration{
		Version:     "1.5.0",
		Name:        "fix_double_encoded_raw_data",
		Description: "Unescape double-encoded JSON in raw_data field for events table",
		Up: func(ctx context.Context, conn driver.Conn) error {
			// Fix events where raw_data is a double-encoded JSON string
			// Pattern: starts with "{ and ends with }" (JSON object wrapped in quotes)
			// The escape sequences are: \" -> ", \r\n -> newline, \\ -> \
			query := `
			ALTER TABLE events UPDATE raw_data =
				replaceAll(
					replaceAll(
						replaceAll(
							substring(raw_data, 2, length(raw_data) - 2),
							'\\"', '"'
						),
						'\\r\\n', '\n'
					),
					'\\n', '\n'
				)
			WHERE startsWith(raw_data, '"{') AND endsWith(raw_data, '}"')
			`
			if err := conn.Exec(ctx, query); err != nil {
				return fmt.Errorf("failed to fix double-encoded events: %w", err)
			}

			// Also fix any double-encoded JSON arrays (starts with "[ and ends with ]")
			queryArrays := `
			ALTER TABLE events UPDATE raw_data =
				replaceAll(
					replaceAll(
						replaceAll(
							substring(raw_data, 2, length(raw_data) - 2),
							'\\"', '"'
						),
						'\\r\\n', '\n'
					),
					'\\n', '\n'
				)
			WHERE startsWith(raw_data, '"[') AND endsWith(raw_data, ']"')
			`
			if err := conn.Exec(ctx, queryArrays); err != nil {
				return fmt.Errorf("failed to fix double-encoded arrays: %w", err)
			}

			return nil
		},
		Down: func(ctx context.Context, conn driver.Conn) error {
			// No rollback - the unescaped data is the correct format
			return nil
		},
	})

	// Migration 1.5.1: Fix double-encoded raw_data in alerts table (embedded event_data)
	runner.Register(ClickHouseMigration{
		Version:     "1.5.1",
		Name:        "fix_double_encoded_alert_event_data",
		Description: "Unescape double-encoded JSON in event_data field for alerts table",
		Up: func(ctx context.Context, conn driver.Conn) error {
			// The alerts table stores event data in event_data column
			// Check if the column exists and fix it
			query := `
			ALTER TABLE alerts UPDATE event_data =
				replaceAll(
					replaceAll(
						replaceAll(
							substring(event_data, 2, length(event_data) - 2),
							'\\"', '"'
						),
						'\\r\\n', '\n'
					),
					'\\n', '\n'
				)
			WHERE startsWith(event_data, '"{') AND endsWith(event_data, '}"')
			`
			if err := conn.Exec(ctx, query); err != nil {
				// Column might not exist in older schemas, that's OK
				if !isExpectedMigrationError(err) {
					return fmt.Errorf("failed to fix double-encoded alert event_data: %w", err)
				}
			}

			return nil
		},
		Down: func(ctx context.Context, conn driver.Conn) error {
			return nil
		},
	})

	// Migration 1.6.0: Add correlation tracking fields to alerts table
	// Enables distinguishing alert sources (SIGMA, correlation, CQL, ML) and tracking correlated alerts
	runner.Register(ClickHouseMigration{
		Version:     "1.6.0",
		Name:        "add_alert_correlation_fields",
		Description: "Add rule_type, correlated_alert_ids, correlation_rule_id columns to alerts table for correlation tracking",
		Up: func(ctx context.Context, conn driver.Conn) error {
			migrations := []string{
				// rule_type: Distinguishes alert source (sigma, correlation, cql, ml)
				`ALTER TABLE alerts ADD COLUMN IF NOT EXISTS rule_type LowCardinality(String) DEFAULT 'sigma'`,
				// correlated_alert_ids: For correlation alerts, IDs of contributing alerts (JSON array)
				`ALTER TABLE alerts ADD COLUMN IF NOT EXISTS correlated_alert_ids String DEFAULT '[]'`,
				// correlation_rule_id: For contributing alerts, which correlation rule they fed into
				`ALTER TABLE alerts ADD COLUMN IF NOT EXISTS correlation_rule_id String DEFAULT ''`,
			}

			for _, migration := range migrations {
				if err := conn.Exec(ctx, migration); err != nil {
					if !isExpectedMigrationError(err) {
						return fmt.Errorf("failed to add correlation field: %w", err)
					}
				}
			}

			// Add index for rule_type filtering (useful for filtering correlation alerts)
			indexMigration := `ALTER TABLE alerts ADD INDEX IF NOT EXISTS idx_rule_type rule_type TYPE set(0) GRANULARITY 1`
			if err := conn.Exec(ctx, indexMigration); err != nil {
				if !isExpectedMigrationError(err) {
					return fmt.Errorf("failed to add rule_type index: %w", err)
				}
			}

			return nil
		},
		Down: func(ctx context.Context, conn driver.Conn) error {
			dropColumns := []string{
				`ALTER TABLE alerts DROP COLUMN IF EXISTS rule_type`,
				`ALTER TABLE alerts DROP COLUMN IF EXISTS correlated_alert_ids`,
				`ALTER TABLE alerts DROP COLUMN IF EXISTS correlation_rule_id`,
			}

			for _, drop := range dropColumns {
				if err := conn.Exec(ctx, drop); err != nil {
					return err
				}
			}

			return nil
		},
	})

	// Migration 1.7.0: Add alert overview metadata fields
	// Supports the Alert Info Modal with category, source, confidence_score, risk_score, occurrence_count, sla_breached
	runner.Register(ClickHouseMigration{
		Version:     "1.7.0",
		Name:        "add_alert_overview_metadata_fields",
		Description: "Add alert overview metadata fields (category, source, confidence_score, risk_score, occurrence_count, sla_breached)",
		Up: func(ctx context.Context, conn driver.Conn) error {
			migrations := []string{
				// category: Alert classification (malware, phishing, intrusion, etc.)
				`ALTER TABLE alerts ADD COLUMN IF NOT EXISTS category LowCardinality(String) DEFAULT ''`,
				// source: System that generated the alert (Windows Security, Splunk, etc.)
				`ALTER TABLE alerts ADD COLUMN IF NOT EXISTS source String DEFAULT ''`,
				// confidence_score: Detection confidence 0-100
				`ALTER TABLE alerts ADD COLUMN IF NOT EXISTS confidence_score Float64 DEFAULT 0`,
				// risk_score: Calculated risk 0-100
				`ALTER TABLE alerts ADD COLUMN IF NOT EXISTS risk_score UInt8 DEFAULT 0`,
				// occurrence_count: How many times this alert pattern triggered
				`ALTER TABLE alerts ADD COLUMN IF NOT EXISTS occurrence_count UInt32 DEFAULT 1`,
				// sla_breached: Whether response SLA was violated
				`ALTER TABLE alerts ADD COLUMN IF NOT EXISTS sla_breached UInt8 DEFAULT 0`,
			}

			for _, migration := range migrations {
				if err := conn.Exec(ctx, migration); err != nil {
					if !isExpectedMigrationError(err) {
						return fmt.Errorf("failed to add alert overview field: %w", err)
					}
				}
			}

			// Add index for category filtering
			indexMigration := `ALTER TABLE alerts ADD INDEX IF NOT EXISTS idx_category category TYPE set(0) GRANULARITY 1`
			if err := conn.Exec(ctx, indexMigration); err != nil {
				if !isExpectedMigrationError(err) {
					return fmt.Errorf("failed to add category index: %w", err)
				}
			}

			return nil
		},
		Down: func(ctx context.Context, conn driver.Conn) error {
			dropColumns := []string{
				`ALTER TABLE alerts DROP COLUMN IF EXISTS category`,
				`ALTER TABLE alerts DROP COLUMN IF EXISTS source`,
				`ALTER TABLE alerts DROP COLUMN IF EXISTS confidence_score`,
				`ALTER TABLE alerts DROP COLUMN IF EXISTS risk_score`,
				`ALTER TABLE alerts DROP COLUMN IF EXISTS occurrence_count`,
				`ALTER TABLE alerts DROP COLUMN IF EXISTS sla_breached`,
			}

			for _, drop := range dropColumns {
				if err := conn.Exec(ctx, drop); err != nil {
					return err
				}
			}

			return nil
		},
	})
}
