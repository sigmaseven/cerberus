package storage

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"regexp"
	"strings"
	"time"

	"cerberus/config"

	"github.com/ClickHouse/clickhouse-go/v2"
	"github.com/ClickHouse/clickhouse-go/v2/lib/driver"
	"go.uber.org/zap"
)

var (
	// validDatabaseNameRegex ensures database names are safe from SQL injection
	validDatabaseNameRegex = regexp.MustCompile(`^[a-zA-Z0-9_]+$`)
)

// ClickHouse holds the ClickHouse connection
type ClickHouse struct {
	Conn   driver.Conn
	Config *config.Config
	Logger *zap.SugaredLogger
}

// NewClickHouse creates a new ClickHouse connection
func NewClickHouse(cfg *config.Config, logger *zap.SugaredLogger) (*ClickHouse, error) {
	// RELIABILITY FIX: Set appropriate timeouts and connection pool settings
	// Production ClickHouse systems may have network latency and need reasonable timeouts
	options := &clickhouse.Options{
		Addr: []string{cfg.ClickHouse.Addr},
		Auth: clickhouse.Auth{
			Database: cfg.ClickHouse.Database,
			Username: cfg.ClickHouse.Username,
			Password: cfg.ClickHouse.Password,
		},
		Settings: clickhouse.Settings{
			"max_execution_time": 60, // 60 second query timeout
		},
		DialTimeout: 10 * time.Second, // Increased from 5s for slower networks
		Compression: &clickhouse.Compression{
			Method: clickhouse.CompressionLZ4, // Fast compression
		},
		MaxOpenConns:     cfg.ClickHouse.MaxPoolSize,
		MaxIdleConns:     cfg.ClickHouse.MaxPoolSize / 2,
		ConnMaxLifetime:  1 * time.Hour,              // PERFORMANCE: Prevent stale connections
		ConnOpenStrategy: clickhouse.ConnOpenInOrder, // RELIABILITY: Use connection pool efficiently
		DialContext: func(ctx context.Context, addr string) (net.Conn, error) {
			// RELIABILITY: Add TCP keepalive to detect broken connections
			var d net.Dialer
			d.Timeout = 10 * time.Second
			d.KeepAlive = 30 * time.Second
			return d.DialContext(ctx, "tcp", addr)
		},
	}

	// TLS if enabled with secure defaults
	if cfg.ClickHouse.TLS {
		options.TLS = &tls.Config{
			MinVersion:         tls.VersionTLS13,
			InsecureSkipVerify: false, // SECURITY: Always verify certificates in production
			CipherSuites: []uint16{
				tls.TLS_AES_128_GCM_SHA256,
				tls.TLS_AES_256_GCM_SHA384,
				tls.TLS_CHACHA20_POLY1305_SHA256,
			},
			PreferServerCipherSuites: true,
		}
	}

	conn, err := clickhouse.Open(options)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to ClickHouse: %w", err)
	}

	// Ping to verify connection
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := conn.Ping(ctx); err != nil {
		return nil, fmt.Errorf("failed to ping ClickHouse: %w", err)
	}

	logger.Info("Connected to ClickHouse successfully")

	// Ensure database exists
	if err := ensureDatabase(ctx, conn, cfg.ClickHouse.Database, logger); err != nil {
		return nil, fmt.Errorf("failed to ensure database exists: %w", err)
	}

	return &ClickHouse{
		Conn:   conn,
		Config: cfg,
		Logger: logger,
	}, nil
}

// validateDatabaseName ensures the database name is safe from SQL injection
func validateDatabaseName(database string) error {
	if database == "" {
		return fmt.Errorf("database name cannot be empty")
	}
	if len(database) > 64 {
		return fmt.Errorf("database name too long (max 64 characters)")
	}
	if !validDatabaseNameRegex.MatchString(database) {
		return fmt.Errorf("database name contains invalid characters (only alphanumeric and underscore allowed)")
	}
	return nil
}

// ensureDatabase creates the database if it doesn't exist
func ensureDatabase(ctx context.Context, conn driver.Conn, database string, logger *zap.SugaredLogger) error {
	// Validate database name to prevent SQL injection
	if err := validateDatabaseName(database); err != nil {
		return fmt.Errorf("invalid database name: %w", err)
	}

	// Use backtick quoting for identifier safety (defense-in-depth)
	// Even though validation passed, this adds an extra layer of security
	query := fmt.Sprintf("CREATE DATABASE IF NOT EXISTS `%s`", database)
	if err := conn.Exec(ctx, query); err != nil {
		return fmt.Errorf("failed to create database: %w", err)
	}
	logger.Infof("Database '%s' is ready", database)
	return nil
}

// HealthCheck performs a health check on the ClickHouse connection
func (ch *ClickHouse) HealthCheck(ctx context.Context) error {
	return ch.Conn.Ping(ctx)
}

// Close closes the ClickHouse connection
func (ch *ClickHouse) Close() error {
	return ch.Conn.Close()
}

// GetVersion returns the ClickHouse server version
func (ch *ClickHouse) GetVersion(ctx context.Context) (string, error) {
	var version string
	err := ch.Conn.QueryRow(ctx, "SELECT version()").Scan(&version)
	if err != nil {
		return "", fmt.Errorf("failed to get version: %w", err)
	}
	return version, nil
}

// CreateTablesIfNotExist creates the events and alerts tables if they don't exist
func (ch *ClickHouse) CreateTablesIfNotExist(ctx context.Context) error {
	// Create events table
	eventsTable := `
	CREATE TABLE IF NOT EXISTS events (
		event_id String,
		timestamp DateTime64(3, 'UTC'),
		ingested_at DateTime64(3, 'UTC'),
		listener_id LowCardinality(String),
		listener_name LowCardinality(String),
		source LowCardinality(String),
		source_format LowCardinality(String),
		raw_data String,
		fields String,
		INDEX idx_listener_id listener_id TYPE bloom_filter(0.01) GRANULARITY 1,
		INDEX idx_listener_name listener_name TYPE bloom_filter(0.01) GRANULARITY 1,
		INDEX idx_source source TYPE bloom_filter(0.01) GRANULARITY 1,
		INDEX idx_source_format source_format TYPE set(0) GRANULARITY 1
	) ENGINE = MergeTree()
	PARTITION BY toYYYYMM(timestamp)
	ORDER BY (timestamp, listener_id, source)
	TTL timestamp + INTERVAL 30 DAY
	SETTINGS index_granularity = 8192
	`

	if err := ch.Conn.Exec(ctx, eventsTable); err != nil {
		return fmt.Errorf("failed to create events table: %w", err)
	}

	ch.Logger.Info("Events table created/verified")

	// Create alerts table
	// TASK 101: Added disposition fields for alert workflow management
	alertsTable := `
	CREATE TABLE IF NOT EXISTS alerts (
		alert_id String,
		rule_id String,
		event_id String,
		created_at DateTime64(3, 'UTC'),
		severity LowCardinality(String),
		status LowCardinality(String),
		jira_ticket_id String,
		fingerprint String,
		duplicate_count UInt32,
		last_seen DateTime64(3, 'UTC'),
		event_ids Array(String),
		assigned_to String,
		event_data String,
		threat_intel String,
		-- TASK 101: Disposition workflow fields
		disposition LowCardinality(String) DEFAULT 'undetermined',
		disposition_reason String DEFAULT '',
		disposition_set_at Nullable(DateTime64(3, 'UTC')),
		disposition_set_by String DEFAULT '',
		investigation_id String DEFAULT '',
		INDEX idx_rule_id rule_id TYPE bloom_filter(0.01) GRANULARITY 1,
		INDEX idx_status status TYPE set(0) GRANULARITY 1,
		INDEX idx_severity severity TYPE set(0) GRANULARITY 1,
		INDEX idx_event_id event_id TYPE bloom_filter(0.01) GRANULARITY 1,
		INDEX idx_fingerprint fingerprint TYPE bloom_filter(0.01) GRANULARITY 1,
		INDEX idx_disposition disposition TYPE set(0) GRANULARITY 1
	) ENGINE = MergeTree()
	PARTITION BY toYYYYMM(created_at)
	ORDER BY (created_at, severity, status, rule_id)
	TTL created_at + INTERVAL 90 DAY
	SETTINGS index_granularity = 8192
	`

	if err := ch.Conn.Exec(ctx, alertsTable); err != nil {
		return fmt.Errorf("failed to create alerts table: %w", err)
	}

	ch.Logger.Info("Alerts table created/verified")

	// Create alert_links table for bi-directional alert relationships
	alertLinksTable := `
	CREATE TABLE IF NOT EXISTS alert_links (
		id String,
		alert_id String,
		linked_alert_id String,
		link_type LowCardinality(String) DEFAULT 'related',
		description String DEFAULT '',
		created_by String,
		created_at DateTime64(3, 'UTC'),
		INDEX idx_alert_id alert_id TYPE bloom_filter(0.01) GRANULARITY 1,
		INDEX idx_linked_alert_id linked_alert_id TYPE bloom_filter(0.01) GRANULARITY 1
	) ENGINE = ReplacingMergeTree()
	ORDER BY (alert_id, linked_alert_id)
	SETTINGS index_granularity = 8192
	`

	if err := ch.Conn.Exec(ctx, alertLinksTable); err != nil {
		return fmt.Errorf("failed to create alert_links table: %w", err)
	}

	ch.Logger.Info("Alert links table created/verified")

	// Run migrations using the centralized migration framework
	if err := ch.RunMigrations(ctx); err != nil {
		return fmt.Errorf("failed to run ClickHouse migrations: %w", err)
	}

	return nil
}

// RunMigrations runs all pending ClickHouse migrations using the centralized framework
func (ch *ClickHouse) RunMigrations(ctx context.Context) error {
	// Create migration runner
	runner, err := NewClickHouseMigrationRunner(ch.Conn, ch.Logger)
	if err != nil {
		return fmt.Errorf("failed to create ClickHouse migration runner: %w", err)
	}

	// Register all ClickHouse migrations
	RegisterClickHouseMigrations(runner)

	// Reconcile existing migrations (databases migrated before framework was introduced)
	if err := ch.reconcileExistingMigrations(ctx, runner); err != nil {
		ch.Logger.Warnf("Failed to reconcile existing migrations: %v", err)
		// Continue anyway - migrations will be idempotent
	}

	// Run pending migrations
	if err := runner.RunMigrations(ctx); err != nil {
		return fmt.Errorf("failed to run migrations: %w", err)
	}

	return nil
}

// reconcileExistingMigrations marks migrations as applied if their changes already exist
func (ch *ClickHouse) reconcileExistingMigrations(ctx context.Context, runner *ClickHouseMigrationRunner) error {
	applied, err := runner.GetAppliedMigrations(ctx)
	if err != nil {
		return err
	}

	// If we have applied migrations, the framework is already in use
	if len(applied) > 0 {
		return nil
	}

	ch.Logger.Info("Reconciling existing ClickHouse database state with migration framework")

	// Check which migrations were already applied based on schema state
	migrationsToMark := []struct {
		version   string
		name      string
		checkFunc func() (bool, error)
	}{
		{
			version: "1.0.0",
			name:    "initial_schema",
			checkFunc: func() (bool, error) {
				// Check if events table exists
				var count uint64
				err := ch.Conn.QueryRow(ctx,
					`SELECT count() FROM system.tables WHERE database = currentDatabase() AND name = 'events'`).Scan(&count)
				return count > 0, err
			},
		},
		{
			version: "1.1.0",
			name:    "add_alert_disposition_fields",
			checkFunc: func() (bool, error) {
				// Check if disposition column exists in alerts table
				var count uint64
				err := ch.Conn.QueryRow(ctx,
					`SELECT count() FROM system.columns WHERE database = currentDatabase() AND table = 'alerts' AND name = 'disposition'`).Scan(&count)
				return count > 0, err
			},
		},
		{
			version: "1.2.0",
			name:    "create_soar_audit_log",
			checkFunc: func() (bool, error) {
				// Check if soar_audit_log table exists
				var count uint64
				err := ch.Conn.QueryRow(ctx,
					`SELECT count() FROM system.tables WHERE database = currentDatabase() AND name = 'soar_audit_log'`).Scan(&count)
				return count > 0, err
			},
		},
	}

	for _, m := range migrationsToMark {
		exists, err := m.checkFunc()
		if err != nil {
			ch.Logger.Warnf("Failed to check migration %s: %v", m.version, err)
			continue
		}

		if exists {
			// Mark migration as applied (it was done by the old inline system)
			err = ch.Conn.Exec(ctx, `
				INSERT INTO schema_migrations (version, name, applied_at, duration_ms)
				VALUES (?, ?, now(), 0)
			`, m.version, m.name)
			if err != nil {
				// Might already exist if reconciliation was partially done
				if !isExpectedMigrationError(err) {
					ch.Logger.Warnf("Failed to mark migration %s as applied: %v", m.version, err)
				}
			} else {
				ch.Logger.Debugf("Reconciled migration %s: %s (already applied)", m.version, m.name)
			}
		}
	}

	return nil
}

// MigrateAlertsDispositionFields adds disposition columns to existing alerts table.
// This is idempotent - safe to run multiple times as ClickHouse's ADD COLUMN IF NOT EXISTS
// will skip if column already exists.
//
// TASK 101: Migration for existing deployments
//
// MIGRATION: v1.0.0 -> v1.1.0 (TASK 101 - Alert Disposition Fields)
//
// ROLLBACK PROCEDURE (if needed):
//  1. Stop all Cerberus instances
//  2. Run: ALTER TABLE alerts DROP COLUMN IF EXISTS disposition
//  3. Run: ALTER TABLE alerts DROP COLUMN IF EXISTS disposition_reason
//  4. Run: ALTER TABLE alerts DROP COLUMN IF EXISTS disposition_set_at
//  5. Run: ALTER TABLE alerts DROP COLUMN IF EXISTS disposition_set_by
//  6. Run: ALTER TABLE alerts DROP COLUMN IF EXISTS investigation_id
//  7. Run: ALTER TABLE alerts DROP INDEX IF EXISTS idx_disposition
//  8. Restart Cerberus with version < v1.1.0
//
// COMPATIBILITY: Forward-compatible (old code ignores new columns).
//
//	NOT backward-compatible (new code requires columns).
func (ch *ClickHouse) MigrateAlertsDispositionFields(ctx context.Context) error {
	migrations := []string{
		`ALTER TABLE alerts ADD COLUMN IF NOT EXISTS disposition LowCardinality(String) DEFAULT 'undetermined'`,
		`ALTER TABLE alerts ADD COLUMN IF NOT EXISTS disposition_reason String DEFAULT ''`,
		`ALTER TABLE alerts ADD COLUMN IF NOT EXISTS disposition_set_at Nullable(DateTime64(3, 'UTC'))`,
		`ALTER TABLE alerts ADD COLUMN IF NOT EXISTS disposition_set_by String DEFAULT ''`,
		`ALTER TABLE alerts ADD COLUMN IF NOT EXISTS investigation_id String DEFAULT ''`,
	}

	for _, migration := range migrations {
		if err := ch.Conn.Exec(ctx, migration); err != nil {
			// BLOCKER #2 FIX: Distinguish expected errors from genuine failures
			// ClickHouse with IF NOT EXISTS should not error if column exists,
			// but other errors (connection, permission) should be treated as failures
			if isExpectedMigrationError(err) {
				ch.Logger.Debugw("Migration statement skipped (column may exist)",
					"migration", migration,
					"error", err)
			} else {
				// Genuine error - fail fast
				return fmt.Errorf("migration failed: %w (sql: %s)", err, migration)
			}
		}
	}

	// Add index
	indexMigration := `ALTER TABLE alerts ADD INDEX IF NOT EXISTS idx_disposition disposition TYPE set(0) GRANULARITY 1`
	if err := ch.Conn.Exec(ctx, indexMigration); err != nil {
		if !isExpectedMigrationError(err) {
			return fmt.Errorf("index migration failed: %w", err)
		}
		ch.Logger.Debugw("Index already exists", "error", err)
	}

	// BLOCKER #3 FIX: Materialize index to ensure it's usable
	materializeIndex := `ALTER TABLE alerts MATERIALIZE INDEX idx_disposition`
	if err := ch.Conn.Exec(ctx, materializeIndex); err != nil {
		// Materialization may fail if already done or index doesn't need it
		ch.Logger.Debugw("Index materialization may have completed previously", "error", err)
	}

	// BLOCKER #2 FIX: Verify columns exist with correct types
	if err := ch.verifyDispositionColumns(ctx); err != nil {
		return fmt.Errorf("disposition columns verification failed: %w", err)
	}

	// Verify index exists
	var indexCount uint64
	err := ch.Conn.QueryRow(ctx,
		`SELECT count() FROM system.data_skipping_indices
		 WHERE database = currentDatabase() AND table = 'alerts' AND name = 'idx_disposition'`).Scan(&indexCount)
	if err != nil {
		return fmt.Errorf("failed to verify disposition index: %w", err)
	}
	if indexCount == 0 {
		ch.Logger.Warn("idx_disposition index not found after migration - may need manual creation")
	}

	ch.Logger.Info("Alert disposition fields migration completed and verified")
	return nil
}

// isExpectedMigrationError checks if the error is expected during idempotent migrations
// (e.g., column/index already exists). Returns false for genuine errors like
// connection failures or permission denied.
func isExpectedMigrationError(err error) bool {
	if err == nil {
		return false
	}
	errStr := err.Error()

	// Expected errors that indicate the migration was already applied
	expectedPatterns := []string{
		"already exists",
		"duplicate column",
		"column already exists",
		"COLUMN_ALREADY_EXISTS",
		"index already exists",
		"INDEX_ALREADY_EXISTS",
	}

	for _, pattern := range expectedPatterns {
		if containsIgnoreCase(errStr, pattern) {
			return true
		}
	}

	return false
}

// containsIgnoreCase performs a case-insensitive substring check
func containsIgnoreCase(s, substr string) bool {
	return strings.Contains(strings.ToLower(s), strings.ToLower(substr))
}

// verifyDispositionColumns checks that all disposition columns exist with correct types
func (ch *ClickHouse) verifyDispositionColumns(ctx context.Context) error {
	expectedColumns := map[string]string{
		"disposition":        "LowCardinality(String)",
		"disposition_reason": "String",
		"disposition_set_at": "Nullable(DateTime64(3, 'UTC'))",
		"disposition_set_by": "String",
		"investigation_id":   "String",
	}

	for colName, expectedType := range expectedColumns {
		var actualType string
		err := ch.Conn.QueryRow(ctx,
			`SELECT type FROM system.columns
			 WHERE database = currentDatabase() AND table = 'alerts' AND name = ?`,
			colName).Scan(&actualType)
		if err != nil {
			return fmt.Errorf("column %s not found in alerts table: %w", colName, err)
		}
		if actualType != expectedType {
			return fmt.Errorf("column %s has type %s, expected %s", colName, actualType, expectedType)
		}
	}

	return nil
}

// IPv4StringToNum converts an IPv4 string to uint32 for ClickHouse
func IPv4StringToNum(ip string) uint32 {
	if ip == "" {
		return 0
	}

	// Parse IP
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return 0
	}

	// Get IPv4 representation
	ipv4 := parsedIP.To4()
	if ipv4 == nil {
		return 0 // Not an IPv4 address
	}

	// Convert to uint32 (big-endian)
	return uint32(ipv4[0])<<24 | uint32(ipv4[1])<<16 | uint32(ipv4[2])<<8 | uint32(ipv4[3])
}

// IPv4NumToString converts a uint32 to IPv4 string
func IPv4NumToString(num uint32) string {
	if num == 0 {
		return "0.0.0.0"
	}

	return fmt.Sprintf("%d.%d.%d.%d",
		(num>>24)&0xFF,
		(num>>16)&0xFF,
		(num>>8)&0xFF,
		num&0xFF,
	)
}
